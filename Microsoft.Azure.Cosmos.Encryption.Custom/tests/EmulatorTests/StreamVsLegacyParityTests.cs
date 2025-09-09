//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

#if ENCRYPTION_CUSTOM_PREVIEW && NET8_0_OR_GREATER
namespace Microsoft.Azure.Cosmos.Encryption.Custom.EmulatorTests
{
    using System;
    using System.Net;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.Azure.Cosmos.Encryption.Custom.EmulatorTests.Utils;
    using Microsoft.Data.Encryption.Cryptography;
    using Newtonsoft.Json;
    using VisualStudio.TestTools.UnitTesting;

    /// <summary>
    /// Parity assertions for Streaming vs Newtonsoft encryption paths: RU, ETag, diagnostics markers.
    /// </summary>
    [TestClass]
    public class StreamVsLegacyParityTests
    {
        private const string DekId = "parityDek";
        private static CosmosClient client;
        private static Database database;
        private static Container keyContainer;
        private static Container plainContainer;
        private static Container encContainer;
        private static CosmosDataEncryptionKeyProvider dekProvider;
        private static Encryptor encryptor;

        private class Doc
        {
            [JsonProperty(PropertyName = "id")] public string Id { get; set; }
            [JsonProperty(PropertyName = "pk")] public string Pk { get; set; }
            public string Secret { get; set; }
            public string Plain { get; set; }
        }

        private sealed class TestEncryptor : Encryptor
        {
            private readonly CosmosEncryptor inner;
            public TestEncryptor(DataEncryptionKeyProvider provider)
            {
                this.inner = new CosmosEncryptor(provider);
            }

            public override Task<byte[]> DecryptAsync(byte[] cipherText, string dataEncryptionKeyId, string encryptionAlgorithm, CancellationToken cancellationToken = default)
            {
                return this.inner.DecryptAsync(cipherText, dataEncryptionKeyId, encryptionAlgorithm, cancellationToken);
            }

            public override Task<byte[]> EncryptAsync(byte[] plainText, string dataEncryptionKeyId, string encryptionAlgorithm, CancellationToken cancellationToken = default)
            {
                return this.inner.EncryptAsync(plainText, dataEncryptionKeyId, encryptionAlgorithm, cancellationToken);
            }

            public override Task<Custom.DataEncryptionKey> GetEncryptionKeyAsync(string dataEncryptionKeyId, string encryptionAlgorithm, CancellationToken cancellationToken = default)
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

        [ClassInitialize]
        public static async Task Init(TestContext ctx)
        {
            _ = ctx;
            client = TestCommon.CreateCosmosClient();
            database = await client.CreateDatabaseAsync(Guid.NewGuid().ToString());
            keyContainer = await database.CreateContainerAsync(Guid.NewGuid().ToString(), "/id", 400);
            plainContainer = await database.CreateContainerAsync(Guid.NewGuid().ToString(), "/pk", 400);

            dekProvider = new CosmosDataEncryptionKeyProvider(new TestEncryptionKeyStoreProvider());
            await dekProvider.InitializeAsync(database, keyContainer.Id);
            ItemResponse<DataEncryptionKeyProperties> dekResp = await dekProvider.DataEncryptionKeyContainer.CreateDataEncryptionKeyAsync(
                DekId,
                CosmosEncryptionAlgorithm.MdeAeadAes256CbcHmac256Randomized,
                new EncryptionKeyWrapMetadata("metadata1", "value1"));
            Assert.IsTrue(dekResp.RequestCharge > 0);

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

        private static EncryptionOptions StreamingOptions()
        {
            return new EncryptionOptions
            {
                DataEncryptionKeyId = DekId,
                EncryptionAlgorithm = CosmosEncryptionAlgorithm.MdeAeadAes256CbcHmac256Randomized,
                JsonProcessor = JsonProcessor.Stream,
                PathsToEncrypt = new[] { "/Secret" }
            };
        }

        private static EncryptionOptions LegacyOptions()
        {
            return new EncryptionOptions
            {
                DataEncryptionKeyId = DekId,
                EncryptionAlgorithm = CosmosEncryptionAlgorithm.MdeAeadAes256CbcHmac256Randomized,
                JsonProcessor = JsonProcessor.Newtonsoft,
                PathsToEncrypt = new[] { "/Secret" }
            };
        }

        [TestMethod]
        public async Task CreateAndRead_Parity_Etag_Ru_Diagnostics()
        {
            string pk = "p";

            Doc legacyDoc = new Doc { Id = Guid.NewGuid().ToString(), Pk = pk, Secret = "legacySecret", Plain = "plain" };
            ItemResponse<Doc> legacyCreate = await encContainer.CreateItemAsync(
                legacyDoc,
                new PartitionKey(pk),
                new EncryptionItemRequestOptions { EncryptionOptions = LegacyOptions() });
            Assert.AreEqual(HttpStatusCode.Created, legacyCreate.StatusCode);
            Assert.IsFalse(string.IsNullOrEmpty(legacyCreate.ETag));
            Assert.IsTrue(legacyCreate.RequestCharge > 0);

            Doc streamDoc = new Doc { Id = Guid.NewGuid().ToString(), Pk = pk, Secret = "streamSecret", Plain = "plain2" };
            ItemResponse<Doc> streamCreate = await encContainer.CreateItemAsync(
                streamDoc,
                new PartitionKey(pk),
                new EncryptionItemRequestOptions { EncryptionOptions = StreamingOptions() });
            Assert.AreEqual(HttpStatusCode.Created, streamCreate.StatusCode);
            Assert.IsFalse(string.IsNullOrEmpty(streamCreate.ETag));
            Assert.IsTrue(streamCreate.RequestCharge > 0);

            double createRatio = streamCreate.RequestCharge / legacyCreate.RequestCharge;
            Assert.IsTrue(createRatio > 0.5 && createRatio < 1.5, $"Create RU ratio out of expected band: {createRatio}");

            ItemResponse<Doc> legacyRead = await encContainer.ReadItemAsync<Doc>(legacyDoc.Id, new PartitionKey(pk));
            ItemResponse<Doc> streamRead = await encContainer.ReadItemAsync<Doc>(streamDoc.Id, new PartitionKey(pk));
            Assert.AreEqual(legacyDoc.Secret, legacyRead.Resource.Secret);
            Assert.AreEqual(streamDoc.Secret, streamRead.Resource.Secret);
            Assert.IsFalse(string.IsNullOrEmpty(legacyRead.ETag));
            Assert.IsFalse(string.IsNullOrEmpty(streamRead.ETag));
            Assert.IsTrue(legacyRead.RequestCharge > 0);
            Assert.IsTrue(streamRead.RequestCharge > 0);

            double readRatio = streamRead.RequestCharge / legacyRead.RequestCharge;
            Assert.IsTrue(readRatio > 0.5 && readRatio < 1.6, $"Read RU ratio out of expected band: {readRatio}");

            string legacyDiag = legacyCreate.Diagnostics.ToString();
            string streamDiag = streamCreate.Diagnostics.ToString();
            Assert.IsTrue(legacyDiag.Contains("Create"));
            Assert.IsTrue(streamDiag.Contains("Create"));
            Assert.IsTrue(legacyDiag.IndexOf("Encrypt", StringComparison.OrdinalIgnoreCase) >= 0);
            Assert.IsTrue(streamDiag.IndexOf("Encrypt", StringComparison.OrdinalIgnoreCase) >= 0);
        }
    }
}
#endif
