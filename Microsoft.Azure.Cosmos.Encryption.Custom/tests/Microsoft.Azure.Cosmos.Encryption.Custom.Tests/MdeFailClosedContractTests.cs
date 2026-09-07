//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

namespace Microsoft.Azure.Cosmos.Encryption.Tests
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.Azure.Cosmos.Encryption.Custom;
    using Microsoft.Azure.Cosmos.Encryption.Custom.Tests;
    using Microsoft.Azure.Cosmos.Encryption.Custom.Transformation;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Moq;
    using Newtonsoft.Json.Linq;
    using EncryptionCrypto = Microsoft.Data.Encryption.Cryptography;

    [TestClass]
    public sealed class MdeFailClosedContractTests
    {
        private const string DekId = "fail-closed-dek";

        [DataTestMethod]
        [DynamicData(nameof(JsonProcessors))]
        public async Task UnknownTypeMarker_FailsWithoutPublishingPlaintextOrRemovingEnvelope(
            int jsonProcessorValue)
        {
            Encryptor encryptor = await CreateAuthenticatingEncryptorAsync();
            JObject encryptedDocument = await EncryptAsync(
                encryptor,
                new JObject
                {
                    ["id"] = "unknown-marker",
                    ["Sensitive"] = new JObject
                    {
                        ["nested"] = "authenticated plaintext",
                    },
                });
            ReplaceTypeMarker(encryptedDocument, 0x7F);

            Exception exception = await CaptureFailureWithoutPublishingAsync(
                encryptor,
                encryptedDocument,
                (JsonProcessor)jsonProcessorValue);

            AssertUnknownTypeMarkerFailure(exception);
        }

        [TestMethod]
        public async Task UnknownTypeMarker_JObjectFailsWithoutRemovingEnvelopeOrReplacingCiphertext()
        {
            Encryptor encryptor = await CreateAuthenticatingEncryptorAsync();
            JObject encryptedDocument = await EncryptAsync(
                encryptor,
                new JObject
                {
                    ["id"] = "unknown-marker-jobject",
                    ["Sensitive"] = new JObject
                    {
                        ["nested"] = "authenticated plaintext",
                    },
                });
            ReplaceTypeMarker(encryptedDocument, 0x7F);
            JObject original = (JObject)encryptedDocument.DeepClone();
            Exception exception = null;

            try
            {
                await EncryptionProcessor.DecryptAsync(
                    encryptedDocument,
                    encryptor,
                    new CosmosDiagnosticsContext(),
                    CancellationToken.None);
            }
            catch (Exception caught)
            {
                exception = caught;
            }

            Assert.IsNotNull(exception, "Unknown type marker must not report successful JObject decryption.");
            AssertUnknownTypeMarkerFailure(exception);
            Assert.IsTrue(JToken.DeepEquals(original, encryptedDocument));
        }

        [DataTestMethod]
        [DynamicData(nameof(JsonProcessors))]
        public async Task EmptyCiphertext_FailsWithoutPublishingPartialResponse(int jsonProcessorValue)
        {
            Encryptor encryptor = await CreateAuthenticatingEncryptorAsync();
            JObject encryptedDocument = await EncryptAsync(
                encryptor,
                new JObject
                {
                    ["id"] = "empty-ciphertext",
                    ["Sensitive"] = "authenticated plaintext",
                });
            encryptedDocument["Sensitive"] = string.Empty;

            Exception exception = await CaptureFailureWithoutPublishingAsync(
                encryptor,
                encryptedDocument,
                (JsonProcessor)jsonProcessorValue);

            Assert.IsFalse(
                exception is IndexOutOfRangeException,
                "Empty ciphertext must be rejected explicitly before reading a type marker.");
            Assert.IsFalse(string.IsNullOrWhiteSpace(exception.Message));
        }

        [DataTestMethod]
        [DynamicData(nameof(JsonProcessors))]
        public async Task InvalidKnownStructuredPayload_FailsWithoutPublishingPartialResponse(
            int jsonProcessorValue)
        {
            Encryptor encryptor = await CreateAuthenticatingEncryptorAsync();
            JObject encryptedDocument = await EncryptAsync(
                encryptor,
                new JObject
                {
                    ["id"] = "invalid-object-payload",
                    ["Sensitive"] = "not-json",
                });
            ReplaceTypeMarker(encryptedDocument, (byte)TypeMarker.Object);

            Exception exception = await CaptureFailureWithoutPublishingAsync(
                encryptor,
                encryptedDocument,
                (JsonProcessor)jsonProcessorValue);

            Assert.IsTrue(
                exception is Newtonsoft.Json.JsonException ||
                    exception is System.Text.Json.JsonException ||
                    exception is InvalidOperationException,
                $"Invalid structured plaintext must fail explicitly: {exception?.GetType()}.");
        }

        [DataTestMethod]
        [DynamicData(nameof(MalformedEnvelopeRows))]
        public async Task MalformedNonNullEnvelope_FailsWithoutTreatingCiphertextAsPlaintext(
            int jsonProcessorValue,
            string envelopeJson)
        {
            Encryptor encryptor = await CreateAuthenticatingEncryptorAsync();
            JObject document = JObject.Parse(
                "{\"id\":\"malformed-envelope\",\"Sensitive\":\"ciphertext\",\"_ei\":" +
                envelopeJson +
                "}");

            Exception exception = await CaptureFailureWithoutPublishingAsync(
                encryptor,
                document,
                (JsonProcessor)jsonProcessorValue);

            Assert.IsTrue(
                exception is Newtonsoft.Json.JsonException ||
                    exception is System.Text.Json.JsonException ||
                    exception is NotSupportedException ||
                    exception is InvalidOperationException,
                $"Malformed non-null encryption metadata must fail explicitly: {exception?.GetType()}.");
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

        public static IEnumerable<object[]> MalformedEnvelopeRows
        {
            get
            {
                foreach (object[] processor in JsonProcessors)
                {
                    yield return new object[]
                    {
                        processor[0],
                        "\"stale-non-object-envelope\"",
                    };
                    yield return new object[]
                    {
                        processor[0],
                        "{\"_ef\":3,\"_ea\":{\"malformed\":true},\"_en\":\"fail-closed-dek\",\"_ep\":[\"/Sensitive\"]}",
                    };
                }
            }
        }

        private static async Task<Encryptor> CreateAuthenticatingEncryptorAsync()
        {
            DataEncryptionKeyProperties dekProperties = new DataEncryptionKeyProperties(
                DekId,
                CosmosEncryptionAlgorithm.MdeAeadAes256CbcHmac256Randomized,
                Enumerable.Range(0, 32).Select(i => (byte)i).ToArray(),
                new EncryptionKeyWrapMetadata("name", "value"),
                DateTime.UtcNow);
            MdeEncryptionAlgorithm algorithm = await MdeEncryptionAlgorithm.CreateAsync(
                dekProperties,
                EncryptionCrypto.EncryptionType.Randomized,
                new TestEncryptionKeyStoreProvider(),
                cacheTimeToLive: TimeSpan.MaxValue,
                withRawKey: false,
                cancellationToken: CancellationToken.None);
            Mock<DataEncryptionKeyProvider> keyProvider = new Mock<DataEncryptionKeyProvider>();
            keyProvider
                .Setup(provider => provider.FetchDataEncryptionKeyWithoutRawKeyAsync(
                    It.IsAny<string>(),
                    It.IsAny<string>(),
                    It.IsAny<CancellationToken>()))
                .ReturnsAsync(algorithm);
            return new CosmosEncryptor(keyProvider.Object);
        }

        private static async Task<JObject> EncryptAsync(
            Encryptor encryptor,
            JObject plaintext)
        {
            using Stream input = EncryptionProcessor.BaseSerializer.ToStream(plaintext);
            using Stream encrypted = await EncryptionProcessor.EncryptAsync(
                input,
                encryptor,
                RequestOptionsOverrideHelper.Create(
                    new EncryptionOptions
                    {
                        DataEncryptionKeyId = DekId,
                        EncryptionAlgorithm = CosmosEncryptionAlgorithm.MdeAeadAes256CbcHmac256Randomized,
                        PathsToEncrypt = new[] { "/Sensitive" },
                    },
                    JsonProcessor.Newtonsoft),
                new CosmosDiagnosticsContext(),
                CancellationToken.None);
            return EncryptionProcessor.BaseSerializer.FromStream<JObject>(encrypted);
        }

        private static void ReplaceTypeMarker(JObject encryptedDocument, byte typeMarker)
        {
            byte[] payload = Convert.FromBase64String(encryptedDocument["Sensitive"].Value<string>());
            Assert.IsTrue(payload.Length > 1);
            payload[0] = typeMarker;
            encryptedDocument["Sensitive"] = Convert.ToBase64String(payload);
        }

        private static async Task<Exception> CaptureFailureWithoutPublishingAsync(
            Encryptor encryptor,
            JObject encryptedDocument,
            JsonProcessor jsonProcessor)
        {
            byte[] encryptedBytes;
            using (Stream serialized = EncryptionProcessor.BaseSerializer.ToStream(encryptedDocument))
            {
                encryptedBytes = ((MemoryStream)serialized).ToArray();
            }

            using MemoryStream input = new MemoryStream(encryptedBytes);
            using MemoryStream output = new MemoryStream();
            Exception exception = null;
            try
            {
                await EncryptionProcessor.DecryptAsync(
                    input,
                    output,
                    encryptor,
                    new CosmosDiagnosticsContext(),
                    RequestOptionsOverrideHelper.Create(jsonProcessor),
                    CancellationToken.None);
            }
            catch (Exception caught)
            {
                exception = caught;
            }

            Assert.IsNotNull(exception, "Decryption must fail instead of reporting success.");
            Assert.IsTrue(input.CanRead, "Ciphertext input must remain available after failure.");
            CollectionAssert.AreEqual(encryptedBytes, input.ToArray());
            Assert.AreEqual(0, output.Length, "No partial response may be published on failure.");
            return exception;
        }

        private static void AssertUnknownTypeMarkerFailure(Exception exception)
        {
            Assert.IsTrue(
                exception is NotSupportedException ||
                    exception is InvalidOperationException,
                $"Unknown type marker must fail explicitly, not return plaintext: {exception?.GetType()}.");
            StringAssert.Contains(exception.Message.ToLowerInvariant(), "type");
        }
    }
}
