//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

namespace Microsoft.Azure.Cosmos.Encryption.Tests
{
    using System.Collections.Generic;
    using System.IO;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.Azure.Cosmos.Encryption.Custom;
    using Microsoft.Azure.Cosmos.Encryption.Custom.Tests;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Moq;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;

    [TestClass]
    public sealed class EncryptionDataPreservationContractTests
    {
        private const string DekId = "data-preservation-dek";
        private const string PayloadJson =
            "{\"id\":\"date-preservation\",\"PK\":\"pk\",\"Sensitive\":{\"utc\":\"2026-09-07T09:54:44.238Z\",\"offset\":\"2026-09-07T11:54:44.2381234+02:00\",\"dateOnly\":\"2026-09-07\",\"nested\":{\"timestamp\":\"1999-12-31T23:59:59.9999999-07:30\",\"control\":\"not-a-date\"},\"array\":[\"2020-01-02T03:04:05.6789012Z\",{\"timestamp\":\"2038-01-19T03:14:07.0000001+05:45\"},\"plain-control\"],\"largeInteger\":9007199254740993},\"NonSensitive\":\"control\"}";

        private static Mock<Encryptor> legacyEncryptor;
        private static TestEncryptorFactory.MdeConcreteEncryptor mdeEncryptor;

        [ClassInitialize]
        public static void ClassInitialize(TestContext context)
        {
            _ = context;
            legacyEncryptor = TestEncryptorFactory.CreateLegacy(DekId);
            mdeEncryptor = TestEncryptorFactory.CreateMde(DekId, out _);
        }

        [DataTestMethod]
        [DynamicData(nameof(JsonProcessorPairs))]
        public async Task LegacyReadThenMdeRewrite_PreservesNestedDateLikeStrings(
            int readerProcessorValue,
            int writerProcessorValue)
        {
            JsonProcessor readerProcessor = (JsonProcessor)readerProcessorValue;
            JsonProcessor writerProcessor = (JsonProcessor)writerProcessorValue;
            JObject expected = ParseExact(PayloadJson);

            using Stream legacyInput = new MemoryStream(Encoding.UTF8.GetBytes(PayloadJson));
            using Stream legacyEncrypted = await EncryptionProcessor.EncryptAsync(
                legacyInput,
                legacyEncryptor.Object,
                RequestOptionsOverrideHelper.Create(
                    CreateLegacyOptions(),
                    JsonProcessor.Newtonsoft),
                new CosmosDiagnosticsContext(),
                CancellationToken.None);

            (Stream legacyRead, DecryptionContext legacyContext) = await EncryptionProcessor.DecryptAsync(
                legacyEncrypted,
                legacyEncryptor.Object,
                new CosmosDiagnosticsContext(),
                RequestOptionsOverrideHelper.Create(readerProcessor),
                CancellationToken.None);

            JObject readDocument;
            using (legacyRead)
            {
                readDocument = ParseExact(legacyRead);
            }

            Assert.IsNotNull(legacyContext);
            AssertExactPayload(expected, readDocument);

            using Stream rewriteInput = new MemoryStream(
                Encoding.UTF8.GetBytes(readDocument.ToString(Formatting.None)));
            using Stream mdeEncrypted = await EncryptionProcessor.EncryptAsync(
                rewriteInput,
                mdeEncryptor.Object,
                RequestOptionsOverrideHelper.Create(
                    CreateMdeOptions(),
                    writerProcessor),
                new CosmosDiagnosticsContext(),
                CancellationToken.None);
            (Stream migratedRead, DecryptionContext migratedContext) = await EncryptionProcessor.DecryptAsync(
                mdeEncrypted,
                mdeEncryptor.Object,
                new CosmosDiagnosticsContext(),
                RequestOptionsOverrideHelper.Create(readerProcessor),
                CancellationToken.None);

            using (migratedRead)
            {
                Assert.IsNotNull(migratedContext);
                AssertExactPayload(expected, ParseExact(migratedRead));
            }
        }

        [DataTestMethod]
        [DynamicData(nameof(JsonProcessors))]
        public async Task CurrentMdeRoundTrip_PreservesNestedDateLikeStrings(int jsonProcessorValue)
        {
            JsonProcessor jsonProcessor = (JsonProcessor)jsonProcessorValue;
            JObject expected = ParseExact(PayloadJson);
            using Stream input = new MemoryStream(Encoding.UTF8.GetBytes(PayloadJson));
            using Stream encrypted = await EncryptionProcessor.EncryptAsync(
                input,
                mdeEncryptor.Object,
                RequestOptionsOverrideHelper.Create(
                    CreateMdeOptions(),
                    jsonProcessor),
                new CosmosDiagnosticsContext(),
                CancellationToken.None);
            (Stream decrypted, DecryptionContext context) = await EncryptionProcessor.DecryptAsync(
                encrypted,
                mdeEncryptor.Object,
                new CosmosDiagnosticsContext(),
                RequestOptionsOverrideHelper.Create(jsonProcessor),
                CancellationToken.None);

            using (decrypted)
            {
                Assert.IsNotNull(context);
                AssertExactPayload(expected, ParseExact(decrypted));
            }
        }

        public static IEnumerable<object[]> JsonProcessorPairs
        {
            get
            {
                yield return new object[]
                {
                    (int)JsonProcessor.Newtonsoft,
                    (int)JsonProcessor.Newtonsoft,
                };
#if NET8_0_OR_GREATER
                yield return new object[]
                {
                    (int)JsonProcessor.Newtonsoft,
                    (int)JsonProcessor.Stream,
                };
                yield return new object[]
                {
                    (int)JsonProcessor.Stream,
                    (int)JsonProcessor.Newtonsoft,
                };
                yield return new object[]
                {
                    (int)JsonProcessor.Stream,
                    (int)JsonProcessor.Stream,
                };
#endif
            }
        }

        public static IEnumerable<object[]> JsonProcessors
        {
            get
            {
                yield return new object[] { (int)JsonProcessor.Newtonsoft };
#if NET8_0_OR_GREATER
                yield return new object[] { (int)JsonProcessor.Stream };
#endif
            }
        }

        private static EncryptionOptions CreateLegacyOptions()
        {
#pragma warning disable CS0618
            return new EncryptionOptions
            {
                DataEncryptionKeyId = DekId,
                EncryptionAlgorithm = CosmosEncryptionAlgorithm.AEAes256CbcHmacSha256Randomized,
                PathsToEncrypt = new[] { "/Sensitive" },
            };
#pragma warning restore CS0618
        }

        private static EncryptionOptions CreateMdeOptions()
        {
            return new EncryptionOptions
            {
                DataEncryptionKeyId = DekId,
                EncryptionAlgorithm = CosmosEncryptionAlgorithm.MdeAeadAes256CbcHmac256Randomized,
                PathsToEncrypt = new[] { "/Sensitive" },
            };
        }

        private static JObject ParseExact(string json)
        {
            using StringReader stringReader = new StringReader(json);
            using JsonTextReader jsonReader = new JsonTextReader(stringReader)
            {
                DateParseHandling = DateParseHandling.None,
            };
            return JObject.Load(jsonReader);
        }

        private static JObject ParseExact(Stream stream)
        {
            stream.Position = 0;
            using StreamReader streamReader = new StreamReader(
                stream,
                Encoding.UTF8,
                detectEncodingFromByteOrderMarks: true,
                bufferSize: 1024,
                leaveOpen: true);
            using JsonTextReader jsonReader = new JsonTextReader(streamReader)
            {
                DateParseHandling = DateParseHandling.None,
            };
            return JObject.Load(jsonReader);
        }

        private static void AssertExactPayload(JObject expected, JObject actual)
        {
            Assert.AreEqual(JTokenType.String, actual["Sensitive"]["utc"].Type);
            Assert.AreEqual(JTokenType.String, actual["Sensitive"]["offset"].Type);
            Assert.AreEqual(JTokenType.String, actual["Sensitive"]["dateOnly"].Type);
            Assert.AreEqual(JTokenType.String, actual["Sensitive"]["nested"]["timestamp"].Type);
            Assert.AreEqual(JTokenType.String, actual["Sensitive"]["array"][0].Type);
            Assert.AreEqual(JTokenType.String, actual["Sensitive"]["array"][1]["timestamp"].Type);
            Assert.AreEqual(9007199254740993L, actual["Sensitive"]["largeInteger"].Value<long>());
            Assert.IsTrue(
                JToken.DeepEquals(expected, actual),
                $"Expected: {expected.ToString(Formatting.None)} Actual: {actual.ToString(Formatting.None)}");
        }
    }
}
