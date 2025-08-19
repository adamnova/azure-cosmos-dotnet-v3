//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

#if ENCRYPTION_CUSTOM_PREVIEW && NET8_0_OR_GREATER
namespace Microsoft.Azure.Cosmos.Encryption.Tests.Transformation
{
    using System;
    using System.IO;
    using System.IO.Compression;
    using System.Linq;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.Azure.Cosmos.Encryption.Custom;
    using Microsoft.Azure.Cosmos.Encryption.Custom.Transformation;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Moq;
    using Newtonsoft.Json.Linq;
    using TestCommon = Microsoft.Azure.Cosmos.Encryption.Tests.TestCommon;

    [TestClass]
    public partial class StreamProcessorTests
    {
        private const string DekId = "dekId";

        private static Mock<Encryptor> mockEncryptor;

        [ClassInitialize]
        public static void ClassInitialize(TestContext context)
        {
            _ = context;

            // Use default buffer size to avoid undue parser stress during normal runs
            Microsoft.Azure.Cosmos.Encryption.Custom.Transformation.StreamProcessor.InitialBufferSize = 16384;

            Mock<DataEncryptionKey> DekMock = new();
            DekMock.Setup(m => m.EncryptData(It.IsAny<byte[]>()));
            DekMock.Setup(m => m.GetEncryptByteCount(It.IsAny<int>())).Returns((int l) => l);
            DekMock.Setup(m => m.EncryptData(It.IsAny<byte[]>(), It.IsAny<int>(), It.IsAny<int>(), It.IsAny<byte[]>(), It.IsAny<int>()))
                .Returns((byte[] plainText, int plainTextOffset, int plainTextLength, byte[] output, int outputOffset) => TestCommon.EncryptData(plainText, plainTextOffset, plainTextLength, output, outputOffset));
            DekMock.Setup(m => m.DecryptData(It.IsAny<byte[]>(), It.IsAny<int>(), It.IsAny<int>(), It.IsAny<byte[]>(), It.IsAny<int>()))
                .Returns((byte[] plainText, int plainTextOffset, int plainTextLength, byte[] output, int outputOffset) => TestCommon.DecryptData(plainText, plainTextOffset, plainTextLength, output, outputOffset));
            DekMock.Setup(m => m.GetDecryptByteCount(It.IsAny<int>())).Returns((int l) => l);

            mockEncryptor = new Mock<Encryptor>();
            mockEncryptor.Setup(m => m.GetEncryptionKeyAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync((string dekId, string algorithm, CancellationToken token) =>
                {
                    if (!string.Equals(algorithm, CosmosEncryptionAlgorithm.MdeAeadAes256CbcHmac256Randomized, StringComparison.Ordinal))
                    {
                        throw new NotSupportedException($"Unsupported algorithm: {algorithm}");
                    }

                    return dekId == DekId ? DekMock.Object : throw new InvalidOperationException("DEK not found.");
                });
        }

        private static EncryptionOptions CreateOptions(JsonProcessor processor, CompressionOptions.CompressionAlgorithm algo, CompressionLevel level)
        {
            return new EncryptionOptions
            {
                DataEncryptionKeyId = DekId,
                EncryptionAlgorithm = CosmosEncryptionAlgorithm.MdeAeadAes256CbcHmac256Randomized,
                PathsToEncrypt = TestCommon.TestDoc.PathsToEncrypt,
                JsonProcessor = processor,
                CompressionOptions = new CompressionOptions
                {
                    Algorithm = algo,
                    CompressionLevel = level,
                }
            };
        }

        [TestMethod]
        public async Task EncryptDecrypt_RoundTrip_AllTypes_NoCompression()
        {
            var options = CreateOptions(JsonProcessor.Stream, CompressionOptions.CompressionAlgorithm.None, CompressionLevel.NoCompression);
            await this.RoundTripAsync(options);
        }

        [TestMethod]
        public async Task EncryptDecrypt_RoundTrip_AllTypes_Brotli()
        {
            var options = CreateOptions(JsonProcessor.Stream, CompressionOptions.CompressionAlgorithm.Brotli, CompressionLevel.Fastest);
            await this.RoundTripAsync(options);
        }

        [TestMethod]
        public async Task Encrypt_InvalidAndMissingPaths_Behavior()
        {
            var doc = TestCommon.TestDoc.Create();
            var options = new EncryptionOptions
            {
                DataEncryptionKeyId = DekId,
                EncryptionAlgorithm = CosmosEncryptionAlgorithm.MdeAeadAes256CbcHmac256Randomized,
                PathsToEncrypt = new[] { "/SensitiveStr", "/DoesNotExist" },
                JsonProcessor = JsonProcessor.Stream,
            };

            MemoryStream output = new();
            await EncryptionProcessor.EncryptAsync(doc.ToStream(), output, mockEncryptor.Object, options, new CosmosDiagnosticsContext(), CancellationToken.None);
            output.Position = 0;

            // Validate metadata exists and lists only actually encrypted paths
            JObject encrypted = EncryptionProcessor.BaseSerializer.FromStream<JObject>(output);
            JObject ei = encrypted[Constants.EncryptedInfo] as JObject;
            Assert.IsNotNull(ei);
            var props = ei.ToObject<EncryptionProperties>();
            CollectionAssert.Contains(props.EncryptedPaths.ToArray(), "/SensitiveStr");
            CollectionAssert.DoesNotContain(props.EncryptedPaths.ToArray(), "/DoesNotExist");
        }

        [TestMethod]
        public async Task Encrypt_CompressionThreshold_Flip()
        {
            // Craft a value near the threshold
            var options = CreateOptions(JsonProcessor.Stream, CompressionOptions.CompressionAlgorithm.Brotli, CompressionLevel.Fastest);
            options.CompressionOptions.MinimalCompressedLength = 128;

            var doc = TestCommon.TestDoc.Create();

            // Make SensitiveStr length just below threshold
            doc.SensitiveStr = new string('a', 120);
            MemoryStream below = new();
            await EncryptionProcessor.EncryptAsync(doc.ToStream(), below, mockEncryptor.Object, options, new CosmosDiagnosticsContext(), CancellationToken.None);
            var eiBelow = (EncryptionProcessor.BaseSerializer.FromStream<JObject>(below))[Constants.EncryptedInfo] as JObject;
            Assert.IsNotNull(eiBelow);
            var propsBelow = eiBelow.ToObject<EncryptionProperties>();
            Assert.IsTrue(propsBelow.EncryptedPaths.Contains("/SensitiveStr"));
            Assert.IsTrue(propsBelow.CompressedEncryptedPaths == null || !propsBelow.CompressedEncryptedPaths.ContainsKey("/SensitiveStr"));

            // Now above threshold
            doc.SensitiveStr = new string('a', 256);
            MemoryStream above = new();
            await EncryptionProcessor.EncryptAsync(doc.ToStream(), above, mockEncryptor.Object, options, new CosmosDiagnosticsContext(), CancellationToken.None);
            var eiAbove = (EncryptionProcessor.BaseSerializer.FromStream<JObject>(above))[Constants.EncryptedInfo] as JObject;
            var propsAbove = eiAbove.ToObject<EncryptionProperties>();
            Assert.IsTrue(propsAbove.CompressedEncryptedPaths.ContainsKey("/SensitiveStr"));
            Assert.IsTrue(propsAbove.CompressedEncryptedPaths["/SensitiveStr"] >= 256);
        }

        [TestMethod]
        public async Task Encrypt_ArraysAndObjects_BecomeBase64Strings_And_RoundTrip()
        {
            var options = CreateOptions(JsonProcessor.Stream, CompressionOptions.CompressionAlgorithm.None, CompressionLevel.NoCompression);
            var doc = TestCommon.TestDoc.Create();

            using var input = doc.ToStream();
            using MemoryStream output = new();
            await EncryptionProcessor.EncryptAsync(input, output, mockEncryptor.Object, options, new CosmosDiagnosticsContext(), CancellationToken.None);

            // Work on a copy of the bytes to avoid disposed-position issues
            byte[] encryptedBytes = output.ToArray();
            JObject encrypted = EncryptionProcessor.BaseSerializer.FromStream<JObject>(new MemoryStream(encryptedBytes));
            Assert.AreEqual(JTokenType.String, encrypted[nameof(TestCommon.TestDoc.SensitiveArr)].Type);
            Assert.AreEqual(JTokenType.String, encrypted[nameof(TestCommon.TestDoc.SensitiveDict)].Type);

            // Round-trip back
            using MemoryStream encryptedCopy = new(encryptedBytes);
            using MemoryStream decrypted = new();
            var ctx = await EncryptionProcessor.DecryptAsync(encryptedCopy, decrypted, mockEncryptor.Object, new CosmosDiagnosticsContext(), JsonProcessor.Stream, CancellationToken.None);
            decrypted.Position = 0;
            var roundTripped = TestCommon.FromStream<TestCommon.TestDoc>(decrypted);

            CollectionAssert.AreEqual(doc.SensitiveArr, roundTripped.SensitiveArr);
            CollectionAssert.AreEquivalent(doc.SensitiveDict.ToArray(), roundTripped.SensitiveDict.ToArray());
            Assert.IsNotNull(ctx);
        }

        [TestMethod]
        public async Task EncryptDecrypt_NumericEdgeCases_RoundTrip()
        {
            // Build a JSON object with explicit numeric properties
            var j = new JObject
            {
                ["id"] = Guid.NewGuid().ToString(),
                ["PK"] = Guid.NewGuid().ToString(),
                ["NonSensitive"] = "x",
                ["DLong"] = long.MaxValue,
                ["DLongNeg"] = long.MinValue + 1, // avoid overflow on abs
                ["DDouble"] = 1.23456789012345e123,
                ["DDoubleSmall"] = -9.87654321e-45,
            };

            var paths = new[] { "/DLong", "/DLongNeg", "/DDouble", "/DDoubleSmall" };
            var options = new EncryptionOptions
            {
                DataEncryptionKeyId = DekId,
                EncryptionAlgorithm = CosmosEncryptionAlgorithm.MdeAeadAes256CbcHmac256Randomized,
                PathsToEncrypt = paths,
                JsonProcessor = JsonProcessor.Stream,
            };

            using var input = EncryptionProcessor.BaseSerializer.ToStream(j);
            using MemoryStream encrypted = new();
            await EncryptionProcessor.EncryptAsync(input, encrypted, mockEncryptor.Object, options, new CosmosDiagnosticsContext(), CancellationToken.None);

            // Ensure encrypted numeric values are strings (opaque)
            byte[] encBytes = encrypted.ToArray();
            JObject ej = EncryptionProcessor.BaseSerializer.FromStream<JObject>(new MemoryStream(encBytes));
            Assert.AreEqual(JTokenType.String, ej["DLong"].Type);
            Assert.AreEqual(JTokenType.String, ej["DLongNeg"].Type);
            Assert.AreEqual(JTokenType.String, ej["DDouble"].Type);
            Assert.AreEqual(JTokenType.String, ej["DDoubleSmall"].Type);

            // Decrypt and verify numeric equivalence
            using MemoryStream encryptedCopy2 = new(encBytes);
            using MemoryStream decrypted = new();
            var ctx = await EncryptionProcessor.DecryptAsync(encryptedCopy2, decrypted, mockEncryptor.Object, new CosmosDiagnosticsContext(), JsonProcessor.Stream, CancellationToken.None);
            decrypted.Position = 0;
            JObject dj = EncryptionProcessor.BaseSerializer.FromStream<JObject>(decrypted);

            Assert.AreEqual((long)j["DLong"], (long)dj["DLong"]);
            Assert.AreEqual((long)j["DLongNeg"], (long)dj["DLongNeg"]);
            Assert.AreEqual((double)j["DDouble"], (double)dj["DDouble"], 0.0);
            Assert.AreEqual((double)j["DDoubleSmall"], (double)dj["DDoubleSmall"], 0.0);
            Assert.IsNotNull(ctx);
        }

        [TestMethod]
        public async Task Encrypt_ArraysAndObjects_WithCompression_MetadataAndRoundTrip()
        {
            var options = CreateOptions(JsonProcessor.Stream, CompressionOptions.CompressionAlgorithm.Brotli, CompressionLevel.Fastest);
            var doc = TestCommon.TestDoc.Create();

            using var input = doc.ToStream();
            using MemoryStream output = new();
            await EncryptionProcessor.EncryptAsync(input, output, mockEncryptor.Object, options, new CosmosDiagnosticsContext(), CancellationToken.None);

            byte[] encryptedBytes2 = output.ToArray();
            JObject encrypted = EncryptionProcessor.BaseSerializer.FromStream<JObject>(new MemoryStream(encryptedBytes2));
            var ei = (JObject)encrypted[Constants.EncryptedInfo];
            var props = ei.ToObject<EncryptionProperties>();

            // Array/object paths should be recorded as possibly compressed (depending on length), at least keys exist in EncryptedPaths
            CollectionAssert.Contains(props.EncryptedPaths.ToArray(), "/SensitiveArr");
            CollectionAssert.Contains(props.EncryptedPaths.ToArray(), "/SensitiveDict");

            // Round-trip back
            using MemoryStream encryptedCopy3 = new(encryptedBytes2);
            using MemoryStream decrypted = new();
            var ctx = await EncryptionProcessor.DecryptAsync(encryptedCopy3, decrypted, mockEncryptor.Object, new CosmosDiagnosticsContext(), JsonProcessor.Stream, CancellationToken.None);
            decrypted.Position = 0;
            var roundTripped = TestCommon.FromStream<TestCommon.TestDoc>(decrypted);

            CollectionAssert.AreEqual(doc.SensitiveArr, roundTripped.SensitiveArr);
            CollectionAssert.AreEquivalent(doc.SensitiveDict.ToArray(), roundTripped.SensitiveDict.ToArray());
            Assert.IsNotNull(ctx);
        }

        [TestMethod]
        public async Task Encrypt_Accepts_Comments_And_TrailingCommas_RoundTrip()
        {
                        string jsonWithComments = @"{
    ""id"": ""1"", // inline comment
    ""PK"": ""p"",
    /* multi-line */
    ""NonSensitive"": ""n"",
    ""SensitiveStr"": ""value"", // will be encrypted
    ""SensitiveInt"": 42,
    ""SensitiveArr"": [1,2,3,], // trailing comma
    ""SensitiveDict"": { ""a"": ""b"", }, // trailing comma
}";

            var options = new EncryptionOptions
            {
                DataEncryptionKeyId = DekId,
                EncryptionAlgorithm = CosmosEncryptionAlgorithm.MdeAeadAes256CbcHmac256Randomized,
                PathsToEncrypt = TestCommon.TestDoc.PathsToEncrypt,
                JsonProcessor = JsonProcessor.Stream,
            };

            using var input = new MemoryStream(Encoding.UTF8.GetBytes(jsonWithComments));
            using MemoryStream output = new();
            await EncryptionProcessor.EncryptAsync(input, output, mockEncryptor.Object, options, new CosmosDiagnosticsContext(), CancellationToken.None);

            using MemoryStream encryptedCopy4 = new(output.ToArray());
            using MemoryStream decrypted = new();
            var ctx = await EncryptionProcessor.DecryptAsync(encryptedCopy4, decrypted, mockEncryptor.Object, new CosmosDiagnosticsContext(), JsonProcessor.Stream, CancellationToken.None);
            decrypted.Position = 0;

            // Verify decrypt produced valid JSON and values match expected
            var j = EncryptionProcessor.BaseSerializer.FromStream<JObject>(decrypted);
            Assert.AreEqual("1", (string)j["id"]);
            Assert.AreEqual("p", (string)j["PK"]);
            Assert.AreEqual("n", (string)j["NonSensitive"]);
            Assert.AreEqual("value", (string)j[nameof(TestCommon.TestDoc.SensitiveStr)]);
            Assert.AreEqual(42, (int)j[nameof(TestCommon.TestDoc.SensitiveInt)]);
            Assert.IsNotNull(ctx);
        }

        [TestMethod]
        public async Task EncryptDecrypt_LargeDocument_Succeeds()
        {
            var options = CreateOptions(JsonProcessor.Stream, CompressionOptions.CompressionAlgorithm.Brotli, CompressionLevel.Fastest);
            var doc = TestCommon.TestDoc.Create();
            // Inflate content to ~300KB
            doc.SensitiveStr = new string('x', 300 * 1024);

            using var input = doc.ToStream();
            using MemoryStream output = new();
            await EncryptionProcessor.EncryptAsync(input, output, mockEncryptor.Object, options, new CosmosDiagnosticsContext(), CancellationToken.None);

            using MemoryStream encryptedCopy5 = new(output.ToArray());
            using MemoryStream decrypted = new();
            var ctx = await EncryptionProcessor.DecryptAsync(encryptedCopy5, decrypted, mockEncryptor.Object, new CosmosDiagnosticsContext(), JsonProcessor.Stream, CancellationToken.None);
            decrypted.Position = 0;
            var roundTripped = TestCommon.FromStream<TestCommon.TestDoc>(decrypted);

            Assert.AreEqual(doc.SensitiveStr.Length, roundTripped.SensitiveStr.Length);
            Assert.IsNotNull(ctx);
        }

        private async Task RoundTripAsync(EncryptionOptions options)
        {
            var doc = TestCommon.TestDoc.Create();

            // Use chunked input stream to simulate streaming boundaries on encrypt
            using var input = new ChunkedReadStream(doc.ToStream(), 16);
            using MemoryStream output = new();

            await EncryptionProcessor.EncryptAsync(input, output, mockEncryptor.Object, options, new CosmosDiagnosticsContext(), CancellationToken.None);

            output.Position = 0;
            Assert.IsTrue(output.CanSeek);

            // Decrypt back via stream API and verify basic invariants
            using MemoryStream decrypted = new();
            var context = await EncryptionProcessor.DecryptAsync(output, decrypted, mockEncryptor.Object, new CosmosDiagnosticsContext(), JsonProcessor.Stream, CancellationToken.None);
            decrypted.Position = 0;
            var roundTripped = TestCommon.FromStream<TestCommon.TestDoc>(decrypted);

            Assert.AreEqual(doc.Id, roundTripped.Id);
            Assert.AreEqual(doc.PK, roundTripped.PK);
            Assert.AreEqual(doc.NonSensitive, roundTripped.NonSensitive);
            Assert.AreEqual(doc.SensitiveStr, roundTripped.SensitiveStr);
            Assert.AreEqual(doc.SensitiveInt, roundTripped.SensitiveInt);
            CollectionAssert.AreEqual(doc.SensitiveArr, roundTripped.SensitiveArr);
            CollectionAssert.AreEquivalent(doc.SensitiveDict.ToArray(), roundTripped.SensitiveDict.ToArray());

            Assert.IsNotNull(context);
        }
    }
}
#endif
