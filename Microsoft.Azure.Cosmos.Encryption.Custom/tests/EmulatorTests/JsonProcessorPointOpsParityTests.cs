//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------
#if ENCRYPTION_CUSTOM_PREVIEW && NET8_0_OR_GREATER
namespace Microsoft.Azure.Cosmos.Encryption.Custom.EmulatorTests
{
    using System;
    using System.Net;
    using System.Threading.Tasks;
    using Data.Encryption.Cryptography; // for encryption algorithms and key metadata
    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;
    using Utils;
    using VisualStudio.TestTools.UnitTesting;
    using DataEncryptionKey = Custom.DataEncryptionKey;

    /// <summary>
    /// Focused minimal point-operation (Create/Read/Replace) parity tests for JsonProcessor selection.
    /// Keeps scope narrow so failures here isolate basic end-to-end correctness.
    /// </summary>
    [TestClass]
    public class JsonProcessorPointOpsParityTests
    {
        private const string DekId = "pointOpsDek";
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
            await dekProvider.DataEncryptionKeyContainer.CreateDataEncryptionKeyAsync(
                DekId,
                CosmosEncryptionAlgorithm.MdeAeadAes256CbcHmac256Randomized,
                new EncryptionKeyWrapMetadata("metadata1", "value1"));
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

        private static EncryptionOptions Options(JsonProcessor processor)
        {
            return new EncryptionOptions
            {
                DataEncryptionKeyId = DekId,
                EncryptionAlgorithm = CosmosEncryptionAlgorithm.MdeAeadAes256CbcHmac256Randomized,
                JsonProcessor = processor,
                PathsToEncrypt = new[] { "/Secret" },
            };
        }

        private static Doc NewDoc(string pk, string secret, string plain)
        {
            return new Doc
            {
                Id = Guid.NewGuid().ToString(),
                Pk = pk,
                Secret = secret,
                Plain = plain,
            };
        }

        [TestMethod]
        public async Task Create_Read_Replace_Parity()
        {
            string pk = "pointOps";
            Doc legacy = NewDoc(pk, "legacySecret", "plain1");
            Doc streamDoc = NewDoc(pk, "streamSecret", "plain2");

            ItemResponse<Doc> legacyCreate = await encContainer.CreateItemAsync(legacy, new PartitionKey(pk), new EncryptionItemRequestOptions { EncryptionOptions = Options(JsonProcessor.Newtonsoft) });
            ItemResponse<Doc> streamCreate = await encContainer.CreateItemAsync(streamDoc, new PartitionKey(pk), new EncryptionItemRequestOptions { EncryptionOptions = Options(JsonProcessor.Stream) });
            Assert.AreEqual(HttpStatusCode.Created, legacyCreate.StatusCode);
            Assert.AreEqual(HttpStatusCode.Created, streamCreate.StatusCode);
            await ValidateRawEncryptedAsync(legacy);
            await ValidateRawEncryptedAsync(streamDoc);

            // Basic RU sanity: they should both be > 0 and within a loose parity band (allow wide variability early in preview)
            Assert.IsTrue(legacyCreate.RequestCharge > 0, "Legacy create RU should be positive");
            Assert.IsTrue(streamCreate.RequestCharge > 0, "Stream create RU should be positive");
            double createRatio = streamCreate.RequestCharge / legacyCreate.RequestCharge;
            Assert.IsTrue(createRatio > 0.4 && createRatio < 1.8, $"Create RU ratio out of band: {createRatio}");

            // Replace both
            legacy.Secret = "legacySecret2"; legacy.Plain = "plain1b";
            streamDoc.Secret = "streamSecret2"; streamDoc.Plain = "plain2b";

            ItemResponse<Doc> legacyReplace = await encContainer.ReplaceItemAsync(legacy, legacy.Id, new PartitionKey(pk), new EncryptionItemRequestOptions { EncryptionOptions = Options(JsonProcessor.Newtonsoft) });
            ItemResponse<Doc> streamReplace = await encContainer.ReplaceItemAsync(streamDoc, streamDoc.Id, new PartitionKey(pk), new EncryptionItemRequestOptions { EncryptionOptions = Options(JsonProcessor.Stream) });
            Assert.AreEqual(HttpStatusCode.OK, legacyReplace.StatusCode);
            Assert.AreEqual(HttpStatusCode.OK, streamReplace.StatusCode);

            Assert.IsTrue(legacyReplace.RequestCharge > 0, "Legacy replace RU should be positive");
            Assert.IsTrue(streamReplace.RequestCharge > 0, "Stream replace RU should be positive");
            double replaceRatio = streamReplace.RequestCharge / legacyReplace.RequestCharge;
            Assert.IsTrue(replaceRatio > 0.4 && replaceRatio < 1.9, $"Replace RU ratio out of band: {replaceRatio}");

            // Read back
            ItemResponse<Doc> legacyRead = await encContainer.ReadItemAsync<Doc>(legacy.Id, new PartitionKey(pk));
            ItemResponse<Doc> streamRead = await encContainer.ReadItemAsync<Doc>(streamDoc.Id, new PartitionKey(pk));
            Assert.AreEqual(legacy.Secret, legacyRead.Resource.Secret);
            Assert.AreEqual(streamDoc.Secret, streamRead.Resource.Secret);
            Assert.AreEqual(legacy.Plain, legacyRead.Resource.Plain);
            Assert.AreEqual(streamDoc.Plain, streamRead.Resource.Plain);

            // Diagnostics currently vary; skip strict assertions to keep parity test stable.
        }

        [TestMethod]
        public async Task Upsert_Parity_CreateThenUpdate()
        {
            string pk = "upsertPk";
            Doc legacy = NewDoc(pk, "legacySecret", "plainL");
            Doc streamDoc = NewDoc(pk, "streamSecret", "plainS");

            // Initial upserts act like creates
            ItemResponse<Doc> legacyUpsertCreate = await encContainer.UpsertItemAsync(legacy, new PartitionKey(pk), new EncryptionItemRequestOptions { EncryptionOptions = Options(JsonProcessor.Newtonsoft) });
            ItemResponse<Doc> streamUpsertCreate = await encContainer.UpsertItemAsync(streamDoc, new PartitionKey(pk), new EncryptionItemRequestOptions { EncryptionOptions = Options(JsonProcessor.Stream) });
            Assert.AreEqual(HttpStatusCode.Created, legacyUpsertCreate.StatusCode);
            Assert.AreEqual(HttpStatusCode.Created, streamUpsertCreate.StatusCode);
            await ValidateRawEncryptedAsync(legacy);
            await ValidateRawEncryptedAsync(streamDoc);

            // Modify and upsert again (acts like replace)
            legacy.Secret = "legacySecretUpdated"; legacy.Plain = "plainL2";
            streamDoc.Secret = "streamSecretUpdated"; streamDoc.Plain = "plainS2";
            ItemResponse<Doc> legacyUpsertReplace = await encContainer.UpsertItemAsync(legacy, new PartitionKey(pk), new EncryptionItemRequestOptions { EncryptionOptions = Options(JsonProcessor.Newtonsoft) });
            ItemResponse<Doc> streamUpsertReplace = await encContainer.UpsertItemAsync(streamDoc, new PartitionKey(pk), new EncryptionItemRequestOptions { EncryptionOptions = Options(JsonProcessor.Stream) });
            Assert.AreEqual(HttpStatusCode.OK, legacyUpsertReplace.StatusCode);
            Assert.AreEqual(HttpStatusCode.OK, streamUpsertReplace.StatusCode);

            // Read back and verify
            ItemResponse<Doc> legacyRead = await encContainer.ReadItemAsync<Doc>(legacy.Id, new PartitionKey(pk));
            ItemResponse<Doc> streamRead = await encContainer.ReadItemAsync<Doc>(streamDoc.Id, new PartitionKey(pk));
            Assert.AreEqual(legacy.Secret, legacyRead.Resource.Secret);
            Assert.AreEqual(streamDoc.Secret, streamRead.Resource.Secret);
            Assert.AreEqual(legacy.Plain, legacyRead.Resource.Plain);
            Assert.AreEqual(streamDoc.Plain, streamRead.Resource.Plain);
            await ValidateRawEncryptedAsync(legacy);
            await ValidateRawEncryptedAsync(streamDoc);

            // RU sanity (second upsert vs first per processor)
            double legacyRatio = legacyUpsertReplace.RequestCharge / legacyUpsertCreate.RequestCharge;
            double streamRatio = streamUpsertReplace.RequestCharge / streamUpsertCreate.RequestCharge;
            Assert.IsTrue(legacyRatio > 0.3 && legacyRatio < 2.5, $"Legacy upsert RU ratio unexpected: {legacyRatio}");
            Assert.IsTrue(streamRatio > 0.3 && streamRatio < 2.5, $"Stream upsert RU ratio unexpected: {streamRatio}");
        }

        [TestMethod]
        public async Task Replace_With_Wrong_Etag_Fails_Parity()
        {
            string pk = "etagPk";
            Doc legacy = NewDoc(pk, "legacySecret", "plainL");
            Doc streamDoc = NewDoc(pk, "streamSecret", "plainS");

            ItemResponse<Doc> legacyCreate = await encContainer.CreateItemAsync(legacy, new PartitionKey(pk), new EncryptionItemRequestOptions { EncryptionOptions = Options(JsonProcessor.Newtonsoft) });
            ItemResponse<Doc> streamCreate = await encContainer.CreateItemAsync(streamDoc, new PartitionKey(pk), new EncryptionItemRequestOptions { EncryptionOptions = Options(JsonProcessor.Stream) });
            Assert.AreEqual(HttpStatusCode.Created, legacyCreate.StatusCode);
            Assert.AreEqual(HttpStatusCode.Created, streamCreate.StatusCode);

            // Stale copies (simulate concurrent update by changing local object then using wrong ETag)
            string staleLegacyEtag = legacyCreate.ETag;
            string staleStreamEtag = streamCreate.ETag;

            // Perform legitimate replace to advance etag
            legacy.Secret = "updated1"; streamDoc.Secret = "updated2";
            await encContainer.ReplaceItemAsync(legacy, legacy.Id, new PartitionKey(pk), new EncryptionItemRequestOptions { EncryptionOptions = Options(JsonProcessor.Newtonsoft) });
            await encContainer.ReplaceItemAsync(streamDoc, streamDoc.Id, new PartitionKey(pk), new EncryptionItemRequestOptions { EncryptionOptions = Options(JsonProcessor.Stream) });

            // Use stale etag with access condition expecting PreconditionFailed
            legacy.Secret = "shouldFail"; streamDoc.Secret = "shouldFail";
            try
            {
                await encContainer.ReplaceItemAsync(
                    legacy,
                    legacy.Id,
                    new PartitionKey(pk),
                    new EncryptionItemRequestOptions { EncryptionOptions = Options(JsonProcessor.Newtonsoft), IfMatchEtag = staleLegacyEtag });
                Assert.Fail("Expected PreconditionFailed for legacy replace with stale etag");
            }
            catch (CosmosException ce)
            {
                Assert.AreEqual(HttpStatusCode.PreconditionFailed, ce.StatusCode, "Legacy stale etag should return 412");
            }

            try
            {
                await encContainer.ReplaceItemAsync(
                    streamDoc,
                    streamDoc.Id,
                    new PartitionKey(pk),
                    new EncryptionItemRequestOptions { EncryptionOptions = Options(JsonProcessor.Stream), IfMatchEtag = staleStreamEtag });
                Assert.Fail("Expected PreconditionFailed for stream replace with stale etag");
            }
            catch (CosmosException ce)
            {
                Assert.AreEqual(HttpStatusCode.PreconditionFailed, ce.StatusCode, "Stream stale etag should return 412");
            }
        }

        private static async Task ValidateRawEncryptedAsync(Doc original)
        {
            ItemResponse<JObject> raw = await plainContainer.ReadItemAsync<JObject>(original.Id, new PartitionKey(original.Pk));
            JObject jobj = raw.Resource;
            Assert.IsNotNull(jobj);
            JToken secretToken = jobj["Secret"]; // encrypted
            JToken plainToken = jobj["Plain"];  // plaintext
            Assert.IsNotNull(secretToken);
            Assert.IsNotNull(plainToken);
            Assert.AreNotEqual(original.Secret, secretToken.Type == JTokenType.String ? (string)secretToken : secretToken.ToString(), "Secret field stored in plaintext unexpectedly.");
            Assert.AreEqual(original.Plain, plainToken.Type == JTokenType.String ? (string)plainToken : plainToken.ToString(), "Plain property altered unexpectedly.");
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

            public override Task<DataEncryptionKey> GetEncryptionKeyAsync(string dataEncryptionKeyId, string encryptionAlgorithm, System.Threading.CancellationToken cancellationToken = default)
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
    }
}
#endif