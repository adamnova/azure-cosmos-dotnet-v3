//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

#if ENCRYPTION_CUSTOM_PREVIEW && NET8_0_OR_GREATER
namespace Microsoft.Azure.Cosmos.Encryption.Custom.EmulatorTests
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net;
    using System.Threading.Tasks;
    using Data.Encryption.Cryptography;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;
    using Utils;
    using VisualStudio.TestTools.UnitTesting;
    using DataEncryptionKey = Custom.DataEncryptionKey;

    /// <summary>
    /// Parity tests exercising every public API surface that can select a JsonProcessor (Newtonsoft vs Stream) and validating:
    /// 1. Successful roundtrip (decrypt matches original Plain/Secret values).
    /// 2. Reasonable RU parity (ratio within band) where meaningful.
    /// 3. Consistent item counts / change feed visibility.
    /// </summary>
    [TestClass]
    public class JsonProcessorApiParityTests
    {
        private const string DekId = "apiParityDek";
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
        public async Task Items_Create_Read_Parity()
        {
            string pk = "itemParity";
            Doc legacy = NewDoc(pk, "legacySecret", "plain1");
            Doc streaming = NewDoc(pk, "streamSecret", "plain2");

            ItemResponse<Doc> legacyCreate = await encContainer.CreateItemAsync(
                legacy,
                new PartitionKey(pk),
                new EncryptionItemRequestOptions { EncryptionOptions = Options(JsonProcessor.Newtonsoft) });
            ItemResponse<Doc> streamCreate = await encContainer.CreateItemAsync(
                streaming,
                new PartitionKey(pk),
                new EncryptionItemRequestOptions { EncryptionOptions = Options(JsonProcessor.Stream) });

            Assert.AreEqual(HttpStatusCode.Created, legacyCreate.StatusCode);
            Assert.AreEqual(HttpStatusCode.Created, streamCreate.StatusCode);
            Assert.AreEqual(legacy.Secret, legacyCreate.Resource.Secret);
            Assert.AreEqual(streaming.Secret, streamCreate.Resource.Secret);
            Assert.AreEqual(legacy.Plain, legacyCreate.Resource.Plain);
            Assert.AreEqual(streaming.Plain, streamCreate.Resource.Plain);
            Assert.IsFalse(string.IsNullOrEmpty(legacyCreate.Resource.Secret));
            Assert.IsFalse(string.IsNullOrEmpty(streamCreate.Resource.Secret));

            // Validate encryption at rest (raw container read bypassing Encryptor)
            await ValidateRawEncryptedAsync(legacy);
            await ValidateRawEncryptedAsync(streaming);

            double createRatio = streamCreate.RequestCharge / legacyCreate.RequestCharge;
            Assert.IsTrue(createRatio > 0.5 && createRatio < 1.6, $"Create RU ratio out of band: {createRatio}");

            ItemResponse<Doc> legacyRead = await encContainer.ReadItemAsync<Doc>(legacy.Id, new PartitionKey(pk));
            ItemResponse<Doc> streamRead = await encContainer.ReadItemAsync<Doc>(streaming.Id, new PartitionKey(pk));
            Assert.AreEqual(legacy.Secret, legacyRead.Resource.Secret);
            Assert.AreEqual(streaming.Secret, streamRead.Resource.Secret);
            Assert.AreEqual(legacy.Plain, legacyRead.Resource.Plain);
            Assert.AreEqual(streaming.Plain, streamRead.Resource.Plain);
            Assert.IsFalse(string.IsNullOrEmpty(legacyRead.Resource.Secret));
            Assert.IsFalse(string.IsNullOrEmpty(streamRead.Resource.Secret));
        }

        [TestMethod]
        public async Task Items_Replace_Parity()
        {
            string pk = "replaceParity";
            Doc legacy = NewDoc(pk, "legacySecret", "plainL1");
            Doc streaming = NewDoc(pk, "streamSecret", "plainS1");

            // Create initial items (legacy + streaming)
            ItemResponse<Doc> legacyCreate = await encContainer.CreateItemAsync(
                legacy,
                new PartitionKey(pk),
                new EncryptionItemRequestOptions { EncryptionOptions = Options(JsonProcessor.Newtonsoft) });
            ItemResponse<Doc> streamCreate = await encContainer.CreateItemAsync(
                streaming,
                new PartitionKey(pk),
                new EncryptionItemRequestOptions { EncryptionOptions = Options(JsonProcessor.Stream) });

            Assert.AreEqual(HttpStatusCode.Created, legacyCreate.StatusCode);
            Assert.AreEqual(HttpStatusCode.Created, streamCreate.StatusCode);

            // Mutate documents
            legacy.Secret = "legacySecretReplaced";
            legacy.Plain = "plainL2";
            streaming.Secret = "streamSecretReplaced";
            streaming.Plain = "plainS2";

            // Replace with same processor selections
            ItemResponse<Doc> legacyReplace = await encContainer.ReplaceItemAsync(
                legacy,
                legacy.Id,
                new PartitionKey(pk),
                new EncryptionItemRequestOptions { EncryptionOptions = Options(JsonProcessor.Newtonsoft) });
            ItemResponse<Doc> streamReplace = await encContainer.ReplaceItemAsync(
                streaming,
                streaming.Id,
                new PartitionKey(pk),
                new EncryptionItemRequestOptions { EncryptionOptions = Options(JsonProcessor.Stream) });

            Assert.AreEqual(HttpStatusCode.OK, legacyReplace.StatusCode);
            Assert.AreEqual(HttpStatusCode.OK, streamReplace.StatusCode);

            // Validate returned resources reflect new values
            Assert.AreEqual(legacy.Secret, legacyReplace.Resource.Secret);
            Assert.AreEqual(streaming.Secret, streamReplace.Resource.Secret);
            Assert.AreEqual(legacy.Plain, legacyReplace.Resource.Plain);
            Assert.AreEqual(streaming.Plain, streamReplace.Resource.Plain);

            // Read back and validate round-trip
            ItemResponse<Doc> legacyRead = await encContainer.ReadItemAsync<Doc>(legacy.Id, new PartitionKey(pk));
            ItemResponse<Doc> streamRead = await encContainer.ReadItemAsync<Doc>(streaming.Id, new PartitionKey(pk));
            Assert.AreEqual(legacy.Secret, legacyRead.Resource.Secret);
            Assert.AreEqual(streaming.Secret, streamRead.Resource.Secret);
            Assert.AreEqual(legacy.Plain, legacyRead.Resource.Plain);
            Assert.AreEqual(streaming.Plain, streamRead.Resource.Plain);

            // Validate encryption at rest (raw read should not have plaintext secret)
            await ValidateRawEncryptedAsync(legacy);
            await ValidateRawEncryptedAsync(streaming);

            // Optional RU ratio sanity (avoid strictness; just ensure not pathological)
            if (streamReplace.RequestCharge > 0 && legacyReplace.RequestCharge > 0)
            {
                double ratio = streamReplace.RequestCharge / legacyReplace.RequestCharge;
                Assert.IsTrue(ratio > 0.4 && ratio < 1.7, $"Replace RU ratio out of band: {ratio}");
            }
        }

        [TestMethod]
        public async Task QueryIterator_Typed_Parity()
        {
            string pk = "queryTyped";
            // Insert 4 docs (2 each processor) and validate encryption at rest
            List<Doc> inserted = new();
            for (int i = 0; i < 2; i++)
            {
                Doc l = NewDoc(pk, $"legacy_{i}", "p");
                Doc s = NewDoc(pk, $"stream_{i}", "p");
                await encContainer.CreateItemAsync(l, new PartitionKey(pk), new EncryptionItemRequestOptions { EncryptionOptions = Options(JsonProcessor.Newtonsoft) });
                await encContainer.CreateItemAsync(s, new PartitionKey(pk), new EncryptionItemRequestOptions { EncryptionOptions = Options(JsonProcessor.Stream) });
                inserted.Add(l);
                inserted.Add(s);
            }
            foreach (Doc d in inserted)
            {
                await ValidateRawEncryptedAsync(d);
            }

            QueryDefinition qd = new QueryDefinition("SELECT * FROM c WHERE c.pk = @pk").WithParameter("@pk", pk);
            FeedIterator<Doc> legacyIt = encContainer.GetItemQueryIterator<Doc>(
                qd,
                requestOptions: new EncryptionQueryRequestOptions { JsonProcessor = JsonProcessor.Newtonsoft });
            FeedIterator<Doc> streamIt = encContainer.GetItemQueryIterator<Doc>(
                qd,
                requestOptions: new EncryptionQueryRequestOptions { JsonProcessor = JsonProcessor.Stream });

            List<string> legacySecrets = new();
            List<string> streamSecrets = new();
            while (legacyIt.HasMoreResults)
            {
                foreach (Doc d in await legacyIt.ReadNextAsync()) legacySecrets.Add(d.Secret);
            }
            while (streamIt.HasMoreResults)
            {
                foreach (Doc d in await streamIt.ReadNextAsync()) streamSecrets.Add(d.Secret);
            }

            Assert.AreEqual(4, legacySecrets.Count);
            Assert.AreEqual(4, streamSecrets.Count);
            CollectionAssert.AreEquivalent(legacySecrets, streamSecrets);
            // Ensure plaintext was restored (secrets match originals) and plain property remained
            foreach (Doc d in inserted)
            {
                Assert.IsTrue(legacySecrets.Contains(d.Secret));
                Assert.IsTrue(streamSecrets.Contains(d.Secret));
            }
        }

        [TestMethod]
        public async Task QueryIterator_StreamApi_Parity()
        {
            string pk = "queryStream";
            Doc legacy = NewDoc(pk, "legacyQS", "p");
            Doc streamDoc = NewDoc(pk, "streamQS", "p");
            await encContainer.CreateItemAsync(legacy, new PartitionKey(pk), new EncryptionItemRequestOptions { EncryptionOptions = Options(JsonProcessor.Newtonsoft) });
            await encContainer.CreateItemAsync(streamDoc, new PartitionKey(pk), new EncryptionItemRequestOptions { EncryptionOptions = Options(JsonProcessor.Stream) });
            await ValidateRawEncryptedAsync(legacy);
            await ValidateRawEncryptedAsync(streamDoc);

            QueryDefinition qd = new QueryDefinition("SELECT * FROM c WHERE c.pk = @pk").WithParameter("@pk", pk);
            FeedIterator legacyStream = encContainer.GetItemQueryStreamIterator(
                qd,
                continuationToken: null,
                requestOptions: new EncryptionQueryRequestOptions { JsonProcessor = JsonProcessor.Newtonsoft });
            FeedIterator streamStream = encContainer.GetItemQueryStreamIterator(
                qd,
                continuationToken: null,
                requestOptions: new EncryptionQueryRequestOptions { JsonProcessor = JsonProcessor.Stream });

            int legacyCount = await CountDocumentsAsync(legacyStream);
            int streamCount = await CountDocumentsAsync(streamStream);
            Assert.AreEqual(2, legacyCount);
            Assert.AreEqual(2, streamCount);
        }

        [TestMethod]
        public async Task Linq_ToEncryptionStreamIterator_Parity()
        {
            string pk = "linqPk";
            Doc legacy = NewDoc(pk, "legacyLinq", "p");
            Doc streamDoc = NewDoc(pk, "streamLinq", "p");
            await encContainer.CreateItemAsync(legacy, new PartitionKey(pk), new EncryptionItemRequestOptions { EncryptionOptions = Options(JsonProcessor.Newtonsoft) });
            await encContainer.CreateItemAsync(streamDoc, new PartitionKey(pk), new EncryptionItemRequestOptions { EncryptionOptions = Options(JsonProcessor.Stream) });
            await ValidateRawEncryptedAsync(legacy);
            await ValidateRawEncryptedAsync(streamDoc);

            IQueryable<Doc> queryable = encContainer.GetItemLinqQueryable<Doc>(allowSynchronousQueryExecution: true).Where(d => d.Pk == pk);
            FeedIterator legacyIterator = encContainer.ToEncryptionStreamIterator<Doc>(queryable, JsonProcessor.Newtonsoft);
            FeedIterator streamIterator = encContainer.ToEncryptionStreamIterator<Doc>(queryable, JsonProcessor.Stream);

            int lCount = await CountDocumentsAsync(legacyIterator);
            int sCount = await CountDocumentsAsync(streamIterator);
            Assert.AreEqual(2, lCount);
            Assert.AreEqual(2, sCount);
        }

        [TestMethod]
        public async Task TransactionalBatch_Parity()
        {
            string pk = "batchParity";
            Doc d1 = NewDoc(pk, "legacyBatch", "p1");
            Doc d2 = NewDoc(pk, "streamBatch", "p2");

            TransactionalBatch batch = encContainer.CreateTransactionalBatch(new PartitionKey(pk))
                .CreateItem(d1, new EncryptionTransactionalBatchItemRequestOptions { EncryptionOptions = Options(JsonProcessor.Newtonsoft) })
                .CreateItem(d2, new EncryptionTransactionalBatchItemRequestOptions { EncryptionOptions = Options(JsonProcessor.Stream) });

            TransactionalBatchResponse resp = await batch.ExecuteAsync();
            Assert.IsTrue(resp.IsSuccessStatusCode);
            Assert.AreEqual(2, resp.Count);

            ItemResponse<Doc> read1 = await encContainer.ReadItemAsync<Doc>(d1.Id, new PartitionKey(pk));
            ItemResponse<Doc> read2 = await encContainer.ReadItemAsync<Doc>(d2.Id, new PartitionKey(pk));
            Assert.AreEqual(d1.Secret, read1.Resource.Secret);
            Assert.AreEqual(d2.Secret, read2.Resource.Secret);
            Assert.AreEqual(d1.Plain, read1.Resource.Plain);
            Assert.AreEqual(d2.Plain, read2.Resource.Plain);
            await ValidateRawEncryptedAsync(d1);
            await ValidateRawEncryptedAsync(d2);
        }

        private static async Task ValidateRawEncryptedAsync(Doc original)
        {
            // Read the stored document through the raw (non-encrypting) container to ensure the encrypted field is not in plaintext
            ItemResponse<JObject> raw = await plainContainer.ReadItemAsync<JObject>(original.Id, new PartitionKey(original.Pk));
            JObject jobj = raw.Resource;
            Assert.IsNotNull(jobj, "Raw document should not be null.");
            JToken secretToken = jobj["Secret"];
            JToken plainToken = jobj["Plain"];
            Assert.IsNotNull(secretToken, "Encrypted Secret token missing.");
            Assert.IsNotNull(plainToken, "Plain token missing.");
            // Plain property must equal original
            Assert.AreEqual(original.Plain, plainToken.Type == JTokenType.String ? (string)plainToken : plainToken.ToString(), "Plaintext property altered unexpectedly.");
            // Secret should NOT equal original plaintext secret
            if (secretToken.Type == JTokenType.String)
            {
                Assert.AreNotEqual(original.Secret, (string)secretToken, "Secret field stored in plaintext unexpectedly.");
                Assert.IsFalse(string.IsNullOrEmpty((string)secretToken), "Encrypted secret shouldn't be empty.");
            }
            else
            {
                // Non-string token also implies it's not the original plaintext value
                Assert.AreNotEqual(original.Secret, secretToken.ToString(), "Secret field stored in plaintext (non-string token check)." );
            }
        }

        private static async Task<int> CountDocumentsAsync(FeedIterator iterator)
        {
            int count = 0;
            while (iterator.HasMoreResults)
            {
                using ResponseMessage rm = await iterator.ReadNextAsync();
                if (!rm.IsSuccessStatusCode) break;
                rm.Content.Position = 0;
                Newtonsoft.Json.Linq.JObject obj = EncryptionProcessor.BaseSerializer.FromStream<Newtonsoft.Json.Linq.JObject>(rm.Content);
                if (obj.SelectToken("Documents") is Newtonsoft.Json.Linq.JArray arr)
                {
                    count += arr.Count;
                }
            }
            return count;
        }

        private static async Task<List<string>> DrainChangeFeedAsync(FeedIterator<Doc> iterator, string pk, int expectedMin)
        {
            List<string> secrets = new();
            for (int i = 0; i < 10 && iterator.HasMoreResults && secrets.Count < expectedMin; i++)
            {
                FeedResponse<Doc> fr = await iterator.ReadNextAsync();
                foreach (Doc d in fr)
                {
                    if (d.Pk == pk)
                    {
                        secrets.Add(d.Secret);
                    }
                }
                if (secrets.Count < expectedMin)
                {
                    await Task.Delay(250);
                }
            }
            return secrets;
        }
        // Local minimal encryptor implementation (duplicated to keep test self-contained)
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
