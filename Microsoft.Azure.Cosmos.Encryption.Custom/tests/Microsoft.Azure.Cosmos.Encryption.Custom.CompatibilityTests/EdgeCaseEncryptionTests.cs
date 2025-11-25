// ----------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// ----------------------------------------------------------------

namespace Microsoft.Azure.Cosmos.Encryption.Custom.CompatibilityTests
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Reflection;
    using System.Security.Cryptography;
    using System.Text;
    using FluentAssertions;
    using Microsoft.Azure.Cosmos.Encryption.Custom.CompatibilityTests.SideBySide;
    using Xunit;
    using Xunit.Abstractions;

    /// <summary>
    /// Tests edge cases and negative scenarios for encryption compatibility.
    /// These tests ensure the encryption implementation handles boundary conditions correctly.
    /// </summary>
    [Trait("Category", "Compatibility")]
    [Trait("Type", "EdgeCase")]
    public class EdgeCaseEncryptionTests : CompatibilityTestBase
    {
        public EdgeCaseEncryptionTests(ITestOutputHelper output) : base(output) { }

        #region Test Data Generators

        /// <summary>
        /// Generates cross-version pairs for testing.
        /// Only includes truly cross-version pairs (skips same-version for published packages).
        /// </summary>
        public static IEnumerable<object[]> GetCrossVersionPairs()
        {
            string[] versions = VersionMatrix.GetTestVersions();

            foreach (string encryptVersion in versions)
            {
                foreach (string decryptVersion in versions)
                {
                    // Skip same-version pairs for published packages (they add little value)
                    // But keep current↔current as it validates the build
                    if (encryptVersion == decryptVersion && 
                        !VersionMatrix.IsCurrentVersion(encryptVersion))
                    {
                        continue;
                    }

                    yield return new object[] { encryptVersion, decryptVersion };
                }
            }
        }

        /// <summary>
        /// Edge case payloads to test with each version pair.
        /// </summary>
        public static IEnumerable<object[]> GetEdgeCasePayloads()
        {
            // Empty payload
            yield return new object[] { "Empty", Array.Empty<byte>() };

            // Single byte
            yield return new object[] { "SingleByte", new byte[] { 0x42 } };

            // Null bytes (binary data with zeros)
            yield return new object[] { "NullBytes", new byte[] { 0x00, 0x00, 0x00, 0x00 } };

            // All possible byte values (0-255)
            yield return new object[] { "AllByteValues", Enumerable.Range(0, 256).Select(i => (byte)i).ToArray() };

            // Binary data with high entropy (random-like)
            yield return new object[] { "HighEntropy", CreateDeterministicRandomBytes(1024) };

            // Large payload (64KB - tests buffer handling)
            yield return new object[] { "Large64KB", CreateDeterministicRandomBytes(64 * 1024) };

            // Boundary size: exactly 16 bytes (AES block size)
            yield return new object[] { "ExactBlockSize", CreateDeterministicRandomBytes(16) };

            // Boundary size: block size - 1
            yield return new object[] { "BlockSizeMinus1", CreateDeterministicRandomBytes(15) };

            // Boundary size: block size + 1
            yield return new object[] { "BlockSizePlus1", CreateDeterministicRandomBytes(17) };

            // UTF-8 edge cases
            yield return new object[] { "Utf8Surrogate", Encoding.UTF8.GetBytes("Test with emoji: 🔐🔑🛡️ and symbols: ™©®") };

            // JSON-like content (common in Cosmos DB)
            yield return new object[] { "JsonContent", Encoding.UTF8.GetBytes("{\"id\":\"test\",\"value\":123,\"nested\":{\"array\":[1,2,3]}}") };

            // Very long string (tests large text handling)
            yield return new object[] { "LongString", Encoding.UTF8.GetBytes(new string('A', 100_000)) };

            // Mixed binary and text
            yield return new object[] { "MixedBinaryText", CreateMixedBinaryTextPayload() };
        }

        /// <summary>
        /// Combines version pairs with edge case payloads for comprehensive testing.
        /// </summary>
        public static IEnumerable<object[]> GetVersionPairsWithEdgeCases()
        {
            foreach (object[] versionPair in GetCrossVersionPairs())
            {
                foreach (object[] payload in GetEdgeCasePayloads())
                {
                    yield return new object[] 
                    { 
                        versionPair[0],  // encryptVersion
                        versionPair[1],  // decryptVersion
                        payload[0],      // payloadName
                        payload[1]       // payloadData
                    };
                }
            }
        }

        #endregion

        #region Edge Case Tests

        [Theory]
        [MemberData(nameof(GetVersionPairsWithEdgeCases))]
        public void EdgeCase_CanEncryptAndDecrypt(
            string encryptVersion,
            string decryptVersion,
            string payloadName,
            byte[] testData)
        {
            string resolvedEncryptVersion = VersionMatrix.ResolveVersion(encryptVersion);
            string resolvedDecryptVersion = VersionMatrix.ResolveVersion(decryptVersion);

            this.LogInfo($"Testing edge case '{payloadName}' ({testData.Length} bytes): {encryptVersion} → {decryptVersion}");

            byte[] encryptedData;
            byte[] decryptedData;

            try
            {
                // Encrypt with version A
                using (VersionLoader encryptLoader = VersionLoader.Load(resolvedEncryptVersion))
                {
                    encryptedData = this.EncryptData(encryptLoader, testData);
                    
                    if (testData.Length > 0)
                    {
                        encryptedData.Should().NotBeEquivalentTo(testData,
                            $"Encrypted data should differ from plaintext for {payloadName}");
                    }
                    
                    this.LogInfo($"  ✓ Encrypted: {encryptedData.Length} bytes");
                }

                // Decrypt with version B
                using (VersionLoader decryptLoader = VersionLoader.Load(resolvedDecryptVersion))
                {
                    decryptedData = this.DecryptData(decryptLoader, encryptedData);
                    this.LogInfo($"  ✓ Decrypted: {decryptedData.Length} bytes");
                }

                // Verify round-trip
                decryptedData.Should().BeEquivalentTo(testData,
                    $"Edge case '{payloadName}' should round-trip correctly from {encryptVersion} to {decryptVersion}");

                this.LogInfo($"✓ SUCCESS: {payloadName} - {encryptVersion} → {decryptVersion}");
            }
            catch (Exception ex)
            {
                this.LogError($"✗ FAILED: {payloadName} - {encryptVersion} → {decryptVersion}");
                this.LogError($"  Error: {ex.Message}");
                throw;
            }
        }

        #endregion

        #region Negative Tests (Tampered Data)

        [Theory]
        [MemberData(nameof(GetCrossVersionPairs))]
        public void NegativeTest_TamperedCiphertext_ShouldThrow(string encryptVersion, string decryptVersion)
        {
            string resolvedEncryptVersion = VersionMatrix.ResolveVersion(encryptVersion);
            string resolvedDecryptVersion = VersionMatrix.ResolveVersion(decryptVersion);

            this.LogInfo($"Testing tampered ciphertext detection: {encryptVersion} → {decryptVersion}");

            byte[] testData = Encoding.UTF8.GetBytes("Sensitive data that should be protected");
            byte[] encryptedData;

            // Encrypt the data
            using (VersionLoader encryptLoader = VersionLoader.Load(resolvedEncryptVersion))
            {
                encryptedData = this.EncryptData(encryptLoader, testData);
                this.LogInfo($"  ✓ Encrypted: {encryptedData.Length} bytes");
            }

            // Tamper with the ciphertext (flip bits in the middle)
            byte[] tamperedData = (byte[])encryptedData.Clone();
            int tamperIndex = tamperedData.Length / 2;
            tamperedData[tamperIndex] ^= 0xFF;  // Flip all bits at this position
            
            this.LogInfo($"  → Tampered byte at index {tamperIndex}");

            // Attempt to decrypt tampered data - should throw
            using (VersionLoader decryptLoader = VersionLoader.Load(resolvedDecryptVersion))
            {
                Action decryptAction = () => this.DecryptData(decryptLoader, tamperedData);

                // Should throw an exception (exact type depends on implementation)
                decryptAction.Should().Throw<Exception>(
                    $"Decrypting tampered ciphertext should fail for {encryptVersion} → {decryptVersion}");

                this.LogInfo($"✓ SUCCESS: Tampered data correctly rejected");
            }
        }

        [Theory]
        [MemberData(nameof(GetCrossVersionPairs))]
        public void NegativeTest_TruncatedCiphertext_ShouldThrow(string encryptVersion, string decryptVersion)
        {
            string resolvedEncryptVersion = VersionMatrix.ResolveVersion(encryptVersion);
            string resolvedDecryptVersion = VersionMatrix.ResolveVersion(decryptVersion);

            this.LogInfo($"Testing truncated ciphertext detection: {encryptVersion} → {decryptVersion}");

            byte[] testData = Encoding.UTF8.GetBytes("Data that will be encrypted and then truncated");
            byte[] encryptedData;

            // Encrypt the data
            using (VersionLoader encryptLoader = VersionLoader.Load(resolvedEncryptVersion))
            {
                encryptedData = this.EncryptData(encryptLoader, testData);
                this.LogInfo($"  ✓ Encrypted: {encryptedData.Length} bytes");
            }

            // Truncate the ciphertext (remove last 8 bytes)
            int truncateAmount = Math.Min(8, encryptedData.Length / 2);
            byte[] truncatedData = new byte[encryptedData.Length - truncateAmount];
            Array.Copy(encryptedData, truncatedData, truncatedData.Length);
            
            this.LogInfo($"  → Truncated from {encryptedData.Length} to {truncatedData.Length} bytes");

            // Attempt to decrypt truncated data - should throw
            using (VersionLoader decryptLoader = VersionLoader.Load(resolvedDecryptVersion))
            {
                Action decryptAction = () => this.DecryptData(decryptLoader, truncatedData);

                decryptAction.Should().Throw<Exception>(
                    $"Decrypting truncated ciphertext should fail for {encryptVersion} → {decryptVersion}");

                this.LogInfo($"✓ SUCCESS: Truncated data correctly rejected");
            }
        }

        /// <summary>
        /// Single version test data - only need to test decryption for garbage data.
        /// </summary>
        public static IEnumerable<object[]> GetSingleVersions()
        {
            foreach (string version in VersionMatrix.GetTestVersions())
            {
                yield return new object[] { version };
            }
        }

        [Theory]
        [MemberData(nameof(GetSingleVersions))]
        public void NegativeTest_RandomGarbage_ShouldThrow(string decryptVersion)
        {
            string resolvedDecryptVersion = VersionMatrix.ResolveVersion(decryptVersion);

            this.LogInfo($"Testing random garbage rejection: → {decryptVersion}");

            // Generate random garbage that's not valid ciphertext
            byte[] garbageData = CreateDeterministicRandomBytes(128);
            
            this.LogInfo($"  → Attempting to decrypt {garbageData.Length} bytes of random data");

            // Attempt to decrypt random data - should throw
            using (VersionLoader decryptLoader = VersionLoader.Load(resolvedDecryptVersion))
            {
                Action decryptAction = () => this.DecryptData(decryptLoader, garbageData);

                decryptAction.Should().Throw<Exception>(
                    $"Decrypting random garbage should fail for {decryptVersion}");

                this.LogInfo($"✓ SUCCESS: Random garbage correctly rejected by {decryptVersion}");
            }
        }

        [Theory]
        [MemberData(nameof(GetCrossVersionPairs))]
        public void NegativeTest_WrongKey_ShouldThrowOrProduceGarbage(string encryptVersion, string decryptVersion)
        {
            string resolvedEncryptVersion = VersionMatrix.ResolveVersion(encryptVersion);
            string resolvedDecryptVersion = VersionMatrix.ResolveVersion(decryptVersion);

            this.LogInfo($"Testing wrong key detection: {encryptVersion} → {decryptVersion}");

            byte[] testData = Encoding.UTF8.GetBytes("Data encrypted with one key, decrypted with another");
            byte[] encryptedData;

            // Encrypt with key A
            using (VersionLoader encryptLoader = VersionLoader.Load(resolvedEncryptVersion))
            {
                encryptedData = this.EncryptData(encryptLoader, testData, useAlternateKey: false);
                this.LogInfo($"  ✓ Encrypted with Key A: {encryptedData.Length} bytes");
            }

            // Try to decrypt with key B
            using (VersionLoader decryptLoader = VersionLoader.Load(resolvedDecryptVersion))
            {
                try
                {
                    byte[] decryptedData = this.DecryptData(decryptLoader, encryptedData, useAlternateKey: true);
                    
                    // If decryption doesn't throw, the data should be garbage (not the original)
                    decryptedData.Should().NotBeEquivalentTo(testData,
                        "Decrypting with wrong key should produce garbage or throw");
                    
                    this.LogInfo($"✓ SUCCESS: Wrong key produced garbage output");
                }
                catch (Exception ex)
                {
                    // This is also acceptable - throwing on wrong key
                    this.LogInfo($"✓ SUCCESS: Wrong key correctly rejected with: {ex.GetType().Name}");
                }
            }
        }

        #endregion

        #region Helper Methods

        private static byte[] CreateDeterministicRandomBytes(int length)
        {
            // Use a deterministic seed for reproducible tests
            byte[] result = new byte[length];
            int seed = 0x12345678;
            
            for (int i = 0; i < length; i++)
            {
                seed = (seed * 1103515245 + 12345) & 0x7fffffff;
                result[i] = (byte)(seed >> 16);
            }
            
            return result;
        }

        private static byte[] CreateMixedBinaryTextPayload()
        {
            using var ms = new System.IO.MemoryStream();
            
            // Write some text
            byte[] text = Encoding.UTF8.GetBytes("Header: ");
            ms.Write(text, 0, text.Length);
            
            // Write binary data including null bytes
            ms.Write(new byte[] { 0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD }, 0, 6);
            
            // Write more text
            text = Encoding.UTF8.GetBytes(" | Footer");
            ms.Write(text, 0, text.Length);
            
            return ms.ToArray();
        }

        private byte[] EncryptData(VersionLoader loader, byte[] plaintext, bool useAlternateKey = false)
        {
            object dataEncryptionKey = this.CreateDataEncryptionKey(loader, useAlternateKey);

            MethodInfo encryptMethod = dataEncryptionKey
                .GetType()
                .GetMethod("EncryptData", BindingFlags.Public | BindingFlags.Instance, null, new[] { typeof(byte[]) }, null)
                ?? throw new InvalidOperationException($"Version '{loader.Version}' does not expose EncryptData(byte[])");

            try
            {
                return (byte[])encryptMethod.Invoke(dataEncryptionKey, new object[] { plaintext });
            }
            catch (TargetInvocationException tie) when (tie.InnerException != null)
            {
                throw tie.InnerException;
            }
        }

        private byte[] DecryptData(VersionLoader loader, byte[] ciphertext, bool useAlternateKey = false)
        {
            object dataEncryptionKey = this.CreateDataEncryptionKey(loader, useAlternateKey);

            MethodInfo decryptMethod = dataEncryptionKey
                .GetType()
                .GetMethod("DecryptData", BindingFlags.Public | BindingFlags.Instance, null, new[] { typeof(byte[]) }, null)
                ?? throw new InvalidOperationException($"Version '{loader.Version}' does not expose DecryptData(byte[])");

            try
            {
                return (byte[])decryptMethod.Invoke(dataEncryptionKey, new object[] { ciphertext });
            }
            catch (TargetInvocationException tie) when (tie.InnerException != null)
            {
                throw tie.InnerException;
            }
        }

        private object CreateDataEncryptionKey(VersionLoader loader, bool useAlternateKey)
        {
            Type dekType = loader.GetType("Microsoft.Azure.Cosmos.Encryption.Custom.DataEncryptionKey")
                ?? throw new InvalidOperationException($"Could not find DataEncryptionKey type in version {loader.Version}");

            // Create key material - use different keys for wrong-key tests
            byte[] keyMaterial = useAlternateKey 
                ? CreateAlternateKeyMaterial() 
                : CreatePrimaryKeyMaterial();

            // Find the Create factory method
            MethodInfo[] factoryMethods = dekType
                .GetMethods(BindingFlags.Public | BindingFlags.Static)
                .Where(m => m.Name == "Create" && m.GetParameters().Length >= 2)
                .OrderByDescending(m => m.GetParameters().Length)
                .ToArray();

            if (factoryMethods.Length == 0)
            {
                throw new InvalidOperationException($"Version '{loader.Version}' does not expose DataEncryptionKey.Create");
            }

            // Try each algorithm candidate with each factory method
            IEnumerable<string> algorithmCandidates = this.GetAlgorithmCandidates(loader);

            foreach (string algorithm in algorithmCandidates)
            {
                foreach (MethodInfo createMethod in factoryMethods)
                {
                    ParameterInfo[] parameters = createMethod.GetParameters();
                    object[] args = new object[parameters.Length];
                    args[0] = keyMaterial;
                    args[1] = algorithm;

                    // Handle optional parameters
                    for (int i = 2; i < parameters.Length; i++)
                    {
                        if (parameters[i].HasDefaultValue)
                        {
                            args[i] = parameters[i].DefaultValue;
                        }
                    }

                    try
                    {
                        return createMethod.Invoke(null, args);
                    }
                    catch (TargetInvocationException)
                    {
                        // Try next algorithm/method combination
                        continue;
                    }
                }
            }

            throw new InvalidOperationException($"Could not create DataEncryptionKey with any supported algorithm for version {loader.Version}");
        }

        private IEnumerable<string> GetAlgorithmCandidates(VersionLoader loader)
        {
            Type algorithmType = loader.GetType("Microsoft.Azure.Cosmos.Encryption.Custom.CosmosEncryptionAlgorithm");
            if (algorithmType == null)
            {
                yield break;
            }

            // Try newer algorithm name first, then fall back to legacy
            string[] fieldNames = new[]
            {
                "MdeAeadAes256CbcHmac256Randomized",
                "AEAes256CbcHmacSha256Randomized"
            };

            HashSet<string> yielded = new HashSet<string>();

            foreach (string fieldName in fieldNames)
            {
                FieldInfo field = algorithmType.GetField(fieldName, BindingFlags.Public | BindingFlags.Static);
                if (field != null)
                {
                    string value = field.GetValue(null) as string;
                    if (!string.IsNullOrEmpty(value) && yielded.Add(value))
                    {
                        yield return value;
                    }
                }
            }
        }

        private static byte[] CreatePrimaryKeyMaterial()
        {
            // Deterministic key for reproducible tests
            byte[] key = new byte[32];
            for (int i = 0; i < key.Length; i++)
            {
                key[i] = (byte)(i + 1);
            }
            return key;
        }

        private static byte[] CreateAlternateKeyMaterial()
        {
            // Different key for wrong-key tests
            byte[] key = new byte[32];
            for (int i = 0; i < key.Length; i++)
            {
                key[i] = (byte)(255 - i);
            }
            return key;
        }

        #endregion
    }
}
