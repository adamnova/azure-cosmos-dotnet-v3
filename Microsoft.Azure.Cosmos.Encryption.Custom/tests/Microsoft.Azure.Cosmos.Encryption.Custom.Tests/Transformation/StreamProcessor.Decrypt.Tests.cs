//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

#if ENCRYPTION_CUSTOM_PREVIEW && NET8_0_OR_GREATER
namespace Microsoft.Azure.Cosmos.Encryption.Tests.Transformation
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.Azure.Cosmos.Encryption.Custom;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Newtonsoft.Json.Linq;
    using TestCommon = Microsoft.Azure.Cosmos.Encryption.Tests.TestCommon;

    public partial class StreamProcessorTests
    {
    // ClassInitialize is declared in the Encrypt partial; avoid duplicate here
        [TestMethod]
        public async Task Decrypt_NoMetadata_ReturnsOriginalStream()
        {
            var doc = TestCommon.TestDoc.Create();
            var stream = doc.ToStream();
            var (decrypted, ctx) = await EncryptionProcessor.DecryptStreamAsync(stream, mockEncryptor.Object, new CosmosDiagnosticsContext(), CancellationToken.None);

            Assert.AreSame(stream, decrypted);
            Assert.AreEqual(0, decrypted.Position);
            Assert.IsNull(ctx);
        }

        [TestMethod]
        public async Task Decrypt_StripsMetadata_AndRestoresValues()
        {
            var doc = TestCommon.TestDoc.Create();
            var options = new EncryptionOptions
            {
                DataEncryptionKeyId = DekId,
                EncryptionAlgorithm = CosmosEncryptionAlgorithm.MdeAeadAes256CbcHmac256Randomized,
                PathsToEncrypt = TestCommon.TestDoc.PathsToEncrypt,
                JsonProcessor = JsonProcessor.Stream,
            };

            var encrypted = await EncryptionProcessor.EncryptAsync(doc.ToStream(), mockEncryptor.Object, options, new CosmosDiagnosticsContext(), CancellationToken.None);
            var (decrypted, ctx) = await EncryptionProcessor.DecryptStreamAsync(encrypted, mockEncryptor.Object, new CosmosDiagnosticsContext(), CancellationToken.None);

            Assert.IsNotNull(ctx);

            var j = EncryptionProcessor.BaseSerializer.FromStream<JObject>(decrypted);
            Assert.IsNull(j[Constants.EncryptedInfo]);

            var roundTripped = j.ToObject<TestCommon.TestDoc>();
            Assert.AreEqual(doc.SensitiveStr, roundTripped.SensitiveStr);
            Assert.AreEqual(doc.SensitiveInt, roundTripped.SensitiveInt);
        }

        [TestMethod]
        public async Task Decrypt_Tampered_Base64_Throws()
        {
            var doc = TestCommon.TestDoc.Create();
            var options = new EncryptionOptions
            {
                DataEncryptionKeyId = DekId,
                EncryptionAlgorithm = CosmosEncryptionAlgorithm.MdeAeadAes256CbcHmac256Randomized,
                PathsToEncrypt = TestCommon.TestDoc.PathsToEncrypt,
                JsonProcessor = JsonProcessor.Stream,
            };

            var encrypted = await EncryptionProcessor.EncryptAsync(doc.ToStream(), mockEncryptor.Object, options, new CosmosDiagnosticsContext(), CancellationToken.None);
            var jobj = EncryptionProcessor.BaseSerializer.FromStream<JObject>(encrypted);

            // Replace encrypted value with invalid base64 at one path
            var pathName = TestCommon.TestDoc.PathsToEncrypt.First();
            var propName = pathName.TrimStart('/');
            jobj[propName] = "%%%not-base64%%%";

            var tampered = EncryptionProcessor.BaseSerializer.ToStream(jobj);
            _ = await Assert.ThrowsExceptionAsync<InvalidOperationException>(async () =>
            {
                await EncryptionProcessor.DecryptStreamAsync(tampered, mockEncryptor.Object, new CosmosDiagnosticsContext(), CancellationToken.None);
            });
        }

        [TestMethod]
        public async Task Decrypt_Tampered_Metadata_UnknownVersion_Throws()
        {
            var doc = TestCommon.TestDoc.Create();
            var options = new EncryptionOptions
            {
                DataEncryptionKeyId = DekId,
                EncryptionAlgorithm = CosmosEncryptionAlgorithm.MdeAeadAes256CbcHmac256Randomized,
                PathsToEncrypt = TestCommon.TestDoc.PathsToEncrypt,
                JsonProcessor = JsonProcessor.Stream,
            };

            var encrypted = await EncryptionProcessor.EncryptAsync(doc.ToStream(), mockEncryptor.Object, options, new CosmosDiagnosticsContext(), CancellationToken.None);
            var jobj = EncryptionProcessor.BaseSerializer.FromStream<JObject>(encrypted);
            var props = (JObject)jobj[Constants.EncryptedInfo];
            props[Constants.EncryptionFormatVersion] = 999; // unknown

            var tampered = EncryptionProcessor.BaseSerializer.ToStream(jobj);
            _ = await Assert.ThrowsExceptionAsync<NotSupportedException>(async () =>
            {
                await EncryptionProcessor.DecryptStreamAsync(tampered, mockEncryptor.Object, new CosmosDiagnosticsContext(), CancellationToken.None);
            });
        }

        [TestMethod]
        public async Task Decrypt_Tampered_Metadata_UnsupportedAlgorithm_Throws()
        {
            var doc = TestCommon.TestDoc.Create();
            var options = new EncryptionOptions
            {
                DataEncryptionKeyId = DekId,
                EncryptionAlgorithm = CosmosEncryptionAlgorithm.MdeAeadAes256CbcHmac256Randomized,
                PathsToEncrypt = TestCommon.TestDoc.PathsToEncrypt,
                JsonProcessor = JsonProcessor.Stream,
            };

            var encrypted = await EncryptionProcessor.EncryptAsync(doc.ToStream(), mockEncryptor.Object, options, new CosmosDiagnosticsContext(), CancellationToken.None);
            var jobj = EncryptionProcessor.BaseSerializer.FromStream<JObject>(encrypted);
            var props = (JObject)jobj[Constants.EncryptedInfo];
            props[Constants.EncryptionAlgorithm] = "UnknownAlgo";

            var tampered = EncryptionProcessor.BaseSerializer.ToStream(jobj);
            _ = await Assert.ThrowsExceptionAsync<NotSupportedException>(async () =>
            {
                await EncryptionProcessor.DecryptStreamAsync(tampered, mockEncryptor.Object, new CosmosDiagnosticsContext(), CancellationToken.None);
            });
        }

        [TestMethod]
        public async Task Decrypt_Tampered_Metadata_CompressionMismatch_Throws()
        {
            var doc = TestCommon.TestDoc.Create();
            var options = new EncryptionOptions
            {
                DataEncryptionKeyId = DekId,
                EncryptionAlgorithm = CosmosEncryptionAlgorithm.MdeAeadAes256CbcHmac256Randomized,
                PathsToEncrypt = TestCommon.TestDoc.PathsToEncrypt,
                JsonProcessor = JsonProcessor.Stream,
                CompressionOptions = new CompressionOptions { Algorithm = CompressionOptions.CompressionAlgorithm.Brotli }
            };

            var encrypted = await EncryptionProcessor.EncryptAsync(doc.ToStream(), mockEncryptor.Object, options, new CosmosDiagnosticsContext(), CancellationToken.None);
            var jobj = EncryptionProcessor.BaseSerializer.FromStream<JObject>(encrypted);
            var props = (JObject)jobj[Constants.EncryptedInfo];
            // Claim compressed paths exist, but set algorithm to None
            props[Constants.CompressionAlgorithm] = (int)CompressionOptions.CompressionAlgorithm.None;

            var tampered = EncryptionProcessor.BaseSerializer.ToStream(jobj);
            _ = await Assert.ThrowsExceptionAsync<NotSupportedException>(async () =>
            {
                await EncryptionProcessor.DecryptStreamAsync(tampered, mockEncryptor.Object, new CosmosDiagnosticsContext(), CancellationToken.None);
            });
        }

        [TestMethod]
        public async Task Decrypt_WithChunkedReads_RoundTrip()
        {
            var doc = TestCommon.TestDoc.Create();
            var options = new EncryptionOptions
            {
                DataEncryptionKeyId = DekId,
                EncryptionAlgorithm = CosmosEncryptionAlgorithm.MdeAeadAes256CbcHmac256Randomized,
                PathsToEncrypt = TestCommon.TestDoc.PathsToEncrypt,
                JsonProcessor = JsonProcessor.Stream,
            };

            var encrypted = await EncryptionProcessor.EncryptAsync(doc.ToStream(), mockEncryptor.Object, options, new CosmosDiagnosticsContext(), CancellationToken.None);

            using var chunked = new ChunkedReadStream(encrypted, 16);
            var (decrypted, ctx) = await EncryptionProcessor.DecryptStreamAsync(chunked, mockEncryptor.Object, new CosmosDiagnosticsContext(), CancellationToken.None);

            Assert.IsNotNull(ctx);
            var roundTripped = EncryptionProcessor.BaseSerializer.FromStream<JObject>(decrypted).ToObject<TestCommon.TestDoc>();
            Assert.AreEqual(doc.SensitiveStr, roundTripped.SensitiveStr);
            Assert.AreEqual(doc.SensitiveInt, roundTripped.SensitiveInt);
        }

        [TestMethod]
        public async Task Decrypt_Tampered_CompressedPath_WrongSize_Fails()
        {
            var doc = TestCommon.TestDoc.Create();
            var options = new EncryptionOptions
            {
                DataEncryptionKeyId = DekId,
                EncryptionAlgorithm = CosmosEncryptionAlgorithm.MdeAeadAes256CbcHmac256Randomized,
                PathsToEncrypt = TestCommon.TestDoc.PathsToEncrypt,
                JsonProcessor = JsonProcessor.Stream,
                CompressionOptions = new CompressionOptions { Algorithm = CompressionOptions.CompressionAlgorithm.Brotli, MinimalCompressedLength = 128 }
            };

            // Ensure compression is applied by making a large value
            doc.SensitiveStr = new string('a', 1024);
            var encrypted = await EncryptionProcessor.EncryptAsync(doc.ToStream(), mockEncryptor.Object, options, new CosmosDiagnosticsContext(), CancellationToken.None);
            var jobj = EncryptionProcessor.BaseSerializer.FromStream<JObject>(encrypted);
            var props = (JObject)jobj[Constants.EncryptedInfo];
            var compressedMap = (JObject)props[Constants.CompressedEncryptedPaths];
            if (compressedMap != null && compressedMap.ContainsKey("/SensitiveStr"))
            {
                // Corrupt the expected decompressed size
                compressedMap["/SensitiveStr"] = 4; // far too small
                var tampered = EncryptionProcessor.BaseSerializer.ToStream(jobj);
                _ = await Assert.ThrowsExceptionAsync<InvalidOperationException>(async () =>
                {
                    await EncryptionProcessor.DecryptStreamAsync(tampered, mockEncryptor.Object, new CosmosDiagnosticsContext(), CancellationToken.None);
                });
            }
        }

        [TestMethod]
        public async Task Decrypt_WithChunkedReadsAndCompression_RoundTrip()
        {
            var doc = TestCommon.TestDoc.Create();
            var options = new EncryptionOptions
            {
                DataEncryptionKeyId = DekId,
                EncryptionAlgorithm = CosmosEncryptionAlgorithm.MdeAeadAes256CbcHmac256Randomized,
                PathsToEncrypt = TestCommon.TestDoc.PathsToEncrypt,
                JsonProcessor = JsonProcessor.Stream,
                CompressionOptions = new CompressionOptions { Algorithm = CompressionOptions.CompressionAlgorithm.Brotli, MinimalCompressedLength = 64 }
            };

            // Inflate a value so compression is likely applied
            doc.SensitiveStr = new string('y', 512);
            var encrypted = await EncryptionProcessor.EncryptAsync(doc.ToStream(), mockEncryptor.Object, options, new CosmosDiagnosticsContext(), CancellationToken.None);
            using var chunked = new ChunkedReadStream(encrypted, 16);
            var (decrypted, ctx) = await EncryptionProcessor.DecryptStreamAsync(chunked, mockEncryptor.Object, new CosmosDiagnosticsContext(), CancellationToken.None);

            Assert.IsNotNull(ctx);
            var roundTripped = EncryptionProcessor.BaseSerializer.FromStream<JObject>(decrypted).ToObject<TestCommon.TestDoc>();
            Assert.AreEqual(doc.SensitiveStr, roundTripped.SensitiveStr);
        }

        [TestMethod]
        public async Task Decrypt_Tampered_Metadata_PathPresentButBodyMissing_BestEffort_Succeeds()
        {
            var doc = TestCommon.TestDoc.Create();
            var options = new EncryptionOptions
            {
                DataEncryptionKeyId = DekId,
                EncryptionAlgorithm = CosmosEncryptionAlgorithm.MdeAeadAes256CbcHmac256Randomized,
                PathsToEncrypt = TestCommon.TestDoc.PathsToEncrypt,
                JsonProcessor = JsonProcessor.Stream,
            };

            var encrypted = await EncryptionProcessor.EncryptAsync(doc.ToStream(), mockEncryptor.Object, options, new CosmosDiagnosticsContext(), CancellationToken.None);
            var jobj = EncryptionProcessor.BaseSerializer.FromStream<JObject>(encrypted);

            // Remove an encrypted property from the body while keeping metadata listing it
            jobj.Remove(nameof(TestCommon.TestDoc.SensitiveStr));

            var tampered = EncryptionProcessor.BaseSerializer.ToStream(jobj);
            var (decrypted, ctx) = await EncryptionProcessor.DecryptStreamAsync(tampered, mockEncryptor.Object, new CosmosDiagnosticsContext(), CancellationToken.None);

            Assert.IsNotNull(ctx);
            var roundTripped = EncryptionProcessor.BaseSerializer.FromStream<JObject>(decrypted);
            Assert.IsNull(roundTripped[Constants.EncryptedInfo]);
            Assert.IsNull(roundTripped[nameof(TestCommon.TestDoc.SensitiveStr)]); // still missing

            var info = ctx.DecryptionInfoList[0];
            CollectionAssert.DoesNotContain(info.PathsDecrypted.ToList(), "/SensitiveStr");
            CollectionAssert.Contains(info.PathsDecrypted.ToList(), "/SensitiveInt");
            CollectionAssert.Contains(info.PathsDecrypted.ToList(), "/SensitiveArr");
            CollectionAssert.Contains(info.PathsDecrypted.ToList(), "/SensitiveDict");
        }

        [TestMethod]
        public async Task Decrypt_WrongDekId_Throws()
        {
            var doc = TestCommon.TestDoc.Create();
            var options = new EncryptionOptions
            {
                DataEncryptionKeyId = DekId,
                EncryptionAlgorithm = CosmosEncryptionAlgorithm.MdeAeadAes256CbcHmac256Randomized,
                PathsToEncrypt = TestCommon.TestDoc.PathsToEncrypt,
                JsonProcessor = JsonProcessor.Stream,
            };

            var encrypted = await EncryptionProcessor.EncryptAsync(doc.ToStream(), mockEncryptor.Object, options, new CosmosDiagnosticsContext(), CancellationToken.None);
            var jobj = EncryptionProcessor.BaseSerializer.FromStream<JObject>(encrypted);

            // Tamper: set wrong DEK id in metadata
            var props = (JObject)jobj[Constants.EncryptedInfo];
            props[Constants.EncryptionDekId] = "wrong-dek";

            var tampered = EncryptionProcessor.BaseSerializer.ToStream(jobj);
            _ = await Assert.ThrowsExceptionAsync<InvalidOperationException>(async () =>
            {
                await EncryptionProcessor.DecryptStreamAsync(tampered, mockEncryptor.Object, new CosmosDiagnosticsContext(), CancellationToken.None);
            });
        }
    }
}
#endif
