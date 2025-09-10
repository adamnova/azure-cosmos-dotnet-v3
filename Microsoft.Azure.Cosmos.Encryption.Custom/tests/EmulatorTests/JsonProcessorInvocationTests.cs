//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------
#if ENCRYPTION_CUSTOM_PREVIEW && NET8_0_OR_GREATER
namespace Microsoft.Azure.Cosmos.Encryption.Custom.EmulatorTests
{
    using System.Collections.Generic;
    using System.Threading.Tasks;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Data.Encryption.Cryptography;

    /// <summary>
    /// Verifies processor routing by capturing stack traces inside Encryptor.DecryptAsync and
    /// asserting the presence of method name markers unique to each path (legacy vs streaming).
    /// </summary>
    [TestClass]
    public class JsonProcessorInvocationTests
    {
        private static CosmosClient client;
        private static Database database;
        private static Container keyContainer;
        private static Container plainContainer;
        private static Container encContainer;
        private const string DekId = "invocationDek";
        private static CosmosDataEncryptionKeyProvider dekProvider;
    private static Encryptor encryptor;

        private class Doc
        {
            [Newtonsoft.Json.JsonProperty(PropertyName = "id")]
            public string Id { get; set; }
            [Newtonsoft.Json.JsonProperty(PropertyName = "pk")]
            public string Pk { get; set; }
            public string Secret { get; set; }
        }

        [ClassInitialize]
        public static async Task Init(TestContext ctx)
        {
            _ = ctx;
            client = Utils.TestCommon.CreateCosmosClient();
            database = await client.CreateDatabaseAsync(System.Guid.NewGuid().ToString());
            keyContainer = await database.CreateContainerAsync(System.Guid.NewGuid().ToString(), "/id", 400);
            plainContainer = await database.CreateContainerAsync(System.Guid.NewGuid().ToString(), "/pk", 400);
            dekProvider = new CosmosDataEncryptionKeyProvider(new TestEncryptionKeyStoreProvider());
            await dekProvider.InitializeAsync(database, keyContainer.Id);
            await dekProvider.DataEncryptionKeyContainer.CreateDataEncryptionKeyAsync(
                DekId,
                CosmosEncryptionAlgorithm.MdeAeadAes256CbcHmac256Randomized,
                new EncryptionKeyWrapMetadata("meta", "v1"));
            encryptor = new TestEncryptor(dekProvider);
            encContainer = plainContainer.WithEncryptor(encryptor);
        }

        [ClassCleanup]
        public static async Task Cleanup()
        {
            if (database != null)
            {
                using (await database.DeleteStreamAsync()) { }
            }
            client?.Dispose();
        }

        private static EncryptionOptions Options(JsonProcessor p)
        {
            return new EncryptionOptions
            {
                DataEncryptionKeyId = DekId,
                EncryptionAlgorithm = CosmosEncryptionAlgorithm.MdeAeadAes256CbcHmac256Randomized,
                JsonProcessor = p,
                PathsToEncrypt = new []{"/Secret"},
            };
        }

        private static Doc NewDoc(string pk, string secret)
        {
            return new Doc { Id = System.Guid.NewGuid().ToString(), Pk = pk, Secret = secret };
        }

    [TestMethod]
    public async Task FeedIterator_ProcessorSelection_InvokesCorrectPath()
        {
            string pk = "invocation";
            // Seed items with both processors
            for (int i = 0; i < 2; i++)
            {
        await encContainer.CreateItemAsync(NewDoc(pk, "legacy"+i), new PartitionKey(pk), new EncryptionItemRequestOptions{ EncryptionOptions = Options(JsonProcessor.Newtonsoft)});
        await encContainer.CreateItemAsync(NewDoc(pk, "stream"+i), new PartitionKey(pk), new EncryptionItemRequestOptions{ EncryptionOptions = Options(JsonProcessor.Stream)});
            }
        QueryDefinition qd = new QueryDefinition("SELECT * FROM c WHERE c.pk = @pk").WithParameter("@pk", pk);
            FeedIterator legacyIt = encContainer.GetItemQueryStreamIterator(qd, null, new EncryptionQueryRequestOptions{ JsonProcessor = JsonProcessor.Newtonsoft });
            FeedIterator streamIt = encContainer.GetItemQueryStreamIterator(qd, null, new EncryptionQueryRequestOptions{ JsonProcessor = JsonProcessor.Stream });

            ResponseMessage legacyResp = await legacyIt.ReadNextAsync();
            ResponseMessage streamResp = await streamIt.ReadNextAsync();
            string legacyDiag = legacyResp.Diagnostics.ToString();
            string streamDiag = streamResp.Diagnostics.ToString();
            Assert.IsTrue(legacyDiag.Contains("\"encryptionFeedDecryptPath\":\"Legacy\""), "Legacy decrypt path marker missing. Diagnostics: " + legacyDiag);
            Assert.IsFalse(legacyDiag.Contains("\"encryptionFeedDecryptPath\":\"Stream\""), "Legacy diagnostics incorrectly show Stream marker. Diagnostics: " + legacyDiag);
            Assert.IsTrue(streamDiag.Contains("\"encryptionFeedDecryptPath\":\"Stream\""), "Stream decrypt path marker missing. Diagnostics: " + streamDiag);
            Assert.IsFalse(streamDiag.Contains("\"encryptionFeedDecryptPath\":\"Legacy\""), "Stream diagnostics incorrectly show Legacy marker. Diagnostics: " + streamDiag);
        }

        private static async Task DrainAsync(FeedIterator it)
        {
            while (it.HasMoreResults)
            {
                using ResponseMessage rm = await it.ReadNextAsync();
                if (!rm.IsSuccessStatusCode) break;
            }
        }

        private sealed class TestEncryptor : Encryptor
        {
            private readonly CosmosEncryptor inner;
            public TestEncryptor(DataEncryptionKeyProvider provider)
            {
                this.inner = new CosmosEncryptor(provider);
            }

            public override Task<byte[]> DecryptAsync(byte[] cipherText, string dataEncryptionKeyId, string encryptionAlgorithm, System.Threading.CancellationToken cancellationToken = default)
            {
                return this.inner.DecryptAsync(cipherText, dataEncryptionKeyId, encryptionAlgorithm, cancellationToken);
            }

            public override Task<byte[]> EncryptAsync(byte[] plainText, string dataEncryptionKeyId, string encryptionAlgorithm, System.Threading.CancellationToken cancellationToken = default)
            {
                return this.inner.EncryptAsync(plainText, dataEncryptionKeyId, encryptionAlgorithm, cancellationToken);
            }

            public override Task<Custom.DataEncryptionKey> GetEncryptionKeyAsync(string dataEncryptionKeyId, string encryptionAlgorithm, System.Threading.CancellationToken cancellationToken = default)
            {
                return this.inner.GetEncryptionKeyAsync(dataEncryptionKeyId, encryptionAlgorithm, cancellationToken);
            }
        }

    private sealed class TestEncryptionKeyStoreProvider : EncryptionKeyStoreProvider
        {
            public override string ProviderName => "LOCAL";

            public override byte[] UnwrapKey(string masterKeyPath, KeyEncryptionKeyAlgorithm encryptionAlgorithm, byte[] encryptedKey)
            {
                return encryptedKey;
            }

            public override byte[] WrapKey(string masterKeyPath, KeyEncryptionKeyAlgorithm encryptionAlgorithm, byte[] key)
            {
                return key;
            }

            public override byte[] Sign(string masterKeyPath, bool allowEnclaveComputations)
            {
                return new byte[32];
            }

            public override bool Verify(string masterKeyPath, bool allowEnclaveComputations, byte[] signature)
            {
                return true;
            }
        }

    // Removed reflection helper; diagnostics scopes now validate routing.
    }
}
#endif
