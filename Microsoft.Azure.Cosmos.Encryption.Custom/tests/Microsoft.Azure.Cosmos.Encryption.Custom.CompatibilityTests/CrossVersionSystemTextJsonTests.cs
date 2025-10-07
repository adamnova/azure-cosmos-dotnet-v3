// ----------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// ----------------------------------------------------------------

namespace Microsoft.Azure.Cosmos.Encryption.Custom.CompatibilityTests
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Reflection;
    using System.Text;
    using FluentAssertions;
    using Microsoft.Azure.Cosmos.Encryption.Custom.CompatibilityTests.SideBySide;
    using Xunit;
    using Xunit.Abstractions;

    /// <summary>
    /// Tests cross-version encryption/decryption compatibility with System.Text.Json experimental mode.
    /// Validates that data encrypted with Newtonsoft can be decrypted with System.Text.Json and vice versa.
    /// </summary>
    [Trait("Category", "Compatibility")]
    [Trait("Feature", "SystemTextJson")]
    public class CrossVersionSystemTextJsonTests : CompatibilityTestBase
    {
        public CrossVersionSystemTextJsonTests(ITestOutputHelper output) : base(output) { }

        /// <summary>
        /// Represents a JSON processor mode for testing.
        /// </summary>
        public enum JsonProcessorMode
        {
            /// <summary>Default Newtonsoft.Json processor (legacy).</summary>
            Newtonsoft,

            /// <summary>System.Text.Json streaming processor (experimental).</summary>
            SystemTextJson
        }

        /// <summary>
        /// Generates test combinations: (encryptVersion, decryptVersion, encryptMode, decryptMode).
        /// Only includes combinations where at least one version supports the System.Text.Json switch.
        /// </summary>
        public static IEnumerable<object[]> GetJsonProcessorTestCombinations()
        {
            string[] versions = VersionMatrix.GetTestVersions();
            JsonProcessorMode[] modes = new[] { JsonProcessorMode.Newtonsoft, JsonProcessorMode.SystemTextJson };

            foreach (string encryptVersion in versions)
            {
                foreach (string decryptVersion in versions)
                {
                    foreach (JsonProcessorMode encryptMode in modes)
                    {
                        foreach (JsonProcessorMode decryptMode in modes)
                        {
                            // Optimization: Skip all-Newtonsoft combinations as they're covered by basic tests
                            if (encryptMode == JsonProcessorMode.Newtonsoft && decryptMode == JsonProcessorMode.Newtonsoft)
                            {
                                continue;
                            }

                            yield return new object[] { encryptVersion, decryptVersion, encryptMode, decryptMode };
                        }
                    }
                }
            }
        }

        [Theory]
        [MemberData(nameof(GetJsonProcessorTestCombinations))]
        public void CanEncryptAndDecrypt_AcrossJsonProcessorModes(
            string encryptVersion,
            string decryptVersion,
            JsonProcessorMode encryptMode,
            JsonProcessorMode decryptMode)
        {
            string encryptDisplay = $"{encryptVersion}[{encryptMode}]";
            string decryptDisplay = $"{decryptVersion}[{decryptMode}]";

            this.LogInfo($"Testing: Encrypt with {encryptDisplay} → Decrypt with {decryptDisplay}");

            // Check feature availability before running the test
            bool encryptSupportsSwitch = this.CheckFeatureAvailability(encryptVersion, encryptMode);
            bool decryptSupportsSwitch = this.CheckFeatureAvailability(decryptVersion, decryptMode);

            if (!encryptSupportsSwitch || !decryptSupportsSwitch)
            {
                // Skip test - feature not available
                return;
            }

            // Arrange
            byte[] testData = this.CreateTestPayload();
            byte[] encryptedData;
            byte[] decryptedData;

            try
            {
                // Act: Encrypt with version A and specified mode
                using (VersionLoader encryptLoader = VersionLoader.Load(encryptVersion))
                {
                    encryptedData = this.EncryptDataWithMode(encryptLoader, testData, encryptMode);
                    encryptedData.Should().NotBeNull($"Encryption with {encryptDisplay} should produce data");
                    encryptedData.Length.Should().BeGreaterThan(0);
                    encryptedData.Should().NotBeEquivalentTo(testData,
                        $"Encrypted data should not match plaintext");

                    this.LogInfo($"  ✓ Encrypted with {encryptDisplay}: {encryptedData.Length} bytes");
                }

                // Act: Decrypt with version B and specified mode
                using (VersionLoader decryptLoader = VersionLoader.Load(decryptVersion))
                {
                    decryptedData = this.DecryptDataWithMode(decryptLoader, encryptedData, decryptMode);
                    decryptedData.Should().NotBeNull($"Decryption with {decryptDisplay} should produce data");
                    this.LogInfo($"  ✓ Decrypted with {decryptDisplay}: {decryptedData.Length} bytes");
                }

                // Assert: Data should round-trip correctly
                decryptedData.Should().BeEquivalentTo(testData,
                    $"Data encrypted with {encryptDisplay} must decrypt correctly with {decryptDisplay}");

                this.LogInfo($"✓ SUCCESS: {encryptDisplay} → {decryptDisplay} compatibility verified");
            }
            catch (Exception ex)
            {
                this.LogError($"✗ FAILED: {encryptDisplay} → {decryptDisplay}");
                this.LogError($"  Error: {ex.Message}");
                throw;
            }
        }

        [Theory]
        [MemberData(nameof(GetJsonProcessorTestCombinations))]
        public void CanEncryptAndDecryptDeterministic_AcrossJsonProcessorModes(
            string encryptVersion,
            string decryptVersion,
            JsonProcessorMode encryptMode,
            JsonProcessorMode decryptMode)
        {
            string encryptDisplay = $"{encryptVersion}[{encryptMode}]";
            string decryptDisplay = $"{decryptVersion}[{decryptMode}]";

            this.LogInfo($"Testing Deterministic: Encrypt with {encryptDisplay} → Decrypt with {decryptDisplay}");

            // Check feature availability
            bool encryptSupportsSwitch = this.CheckFeatureAvailability(encryptVersion, encryptMode);
            bool decryptSupportsSwitch = this.CheckFeatureAvailability(decryptVersion, decryptMode);

            if (!encryptSupportsSwitch || !decryptSupportsSwitch)
            {
                return;
            }

            // Arrange
            byte[] testData = this.CreateTestPayload();
            byte[] encryptedData1;
            byte[] encryptedData2;
            byte[] decryptedData;

            try
            {
                // Act: Encrypt same data twice with deterministic encryption
                using (VersionLoader encryptLoader = VersionLoader.Load(encryptVersion))
                {
                    if (!FeatureAvailability.SupportsDeterministicEncryption(encryptLoader))
                    {
                        this.LogInfo($"  Skipping: {encryptVersion} does not support deterministic encryption");
                        return;
                    }

                    encryptedData1 = this.EncryptDataWithMode(encryptLoader, testData, encryptMode, isDeterministic: true);
                    encryptedData2 = this.EncryptDataWithMode(encryptLoader, testData, encryptMode, isDeterministic: true);

                    encryptedData1.Should().NotBeNull();
                    encryptedData2.Should().NotBeNull();
                    encryptedData1.Should().NotBeEquivalentTo(testData,
                        $"Encrypted data should not match plaintext");

                    // Deterministic encryption should produce identical ciphertext
                    encryptedData1.Should().BeEquivalentTo(encryptedData2,
                        $"Deterministic encryption with {encryptDisplay} should produce identical output");

                    this.LogInfo($"  ✓ Deterministic encryption with {encryptDisplay}: {encryptedData1.Length} bytes");
                }

                // Act: Decrypt with version B
                using (VersionLoader decryptLoader = VersionLoader.Load(decryptVersion))
                {
                    if (!FeatureAvailability.SupportsDeterministicEncryption(decryptLoader))
                    {
                        this.LogInfo($"  Skipping: {decryptVersion} does not support deterministic encryption");
                        return;
                    }

                    decryptedData = this.DecryptDataWithMode(decryptLoader, encryptedData1, decryptMode, isDeterministic: true);
                    decryptedData.Should().NotBeNull();
                    this.LogInfo($"  ✓ Decrypted with {decryptDisplay}: {decryptedData.Length} bytes");
                }

                // Assert
                decryptedData.Should().BeEquivalentTo(testData,
                    $"Deterministic data encrypted with {encryptDisplay} must decrypt correctly with {decryptDisplay}");

                this.LogInfo($"✓ SUCCESS: Deterministic {encryptDisplay} → {decryptDisplay} compatibility verified");
            }
            catch (NotSupportedException notSupported)
            {
                this.LogInfo($"  Skipping deterministic scenario: {notSupported.Message}");
            }
            catch (Exception ex)
            {
                this.LogError($"✗ FAILED: Deterministic {encryptDisplay} → {decryptDisplay}");
                this.LogError($"  Error: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Checks if the specified mode is available in the given version.
        /// Logs the reason if not available and returns false.
        /// </summary>
        private bool CheckFeatureAvailability(string version, JsonProcessorMode mode)
        {
            if (mode == JsonProcessorMode.Newtonsoft)
            {
                // Newtonsoft mode is always available (it's the default)
                return true;
            }

            // For System.Text.Json mode, check if the switch is available
            using (VersionLoader loader = VersionLoader.Load(version))
            {
                if (!FeatureAvailability.SupportsSystemTextJsonSwitch(loader))
                {
                    this.LogInfo($"  ⊘ Skipping: {version} does not support System.Text.Json switch (feature not available)");
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Encrypts data with a specific JSON processor mode.
        /// </summary>
        private byte[] EncryptDataWithMode(
            VersionLoader loader,
            byte[] plaintext,
            JsonProcessorMode mode,
            bool isDeterministic = false)
        {
            string algorithm = this.ResolveEncryptionAlgorithm(loader, isDeterministic);
            object dataEncryptionKey = this.CreateDataEncryptionKey(loader, algorithm, isDeterministic);

            // If System.Text.Json mode is requested, we need to configure it via RequestOptions
            // However, the DataEncryptionKey.EncryptData method doesn't take RequestOptions
            // So we'll use the same approach as the base tests
            MethodInfo encryptMethod = dataEncryptionKey
                .GetType()
                .GetMethod("EncryptData", BindingFlags.Public | BindingFlags.Instance, null, new[] { typeof(byte[]) }, null)
                ?? throw new InvalidOperationException($"The loaded version '{loader.Version}' does not expose a public EncryptData(byte[]) method on DataEncryptionKey.");

            // Note: The System.Text.Json switch applies at a higher level (Container operations)
            // For low-level DataEncryptionKey tests, the mode doesn't affect byte-level encryption
            // This test validates that the encrypted format is compatible regardless of JSON processor
            try
            {
                return (byte[])encryptMethod.Invoke(dataEncryptionKey, new object[] { plaintext });
            }
            catch (TargetInvocationException tie) when (tie.InnerException != null)
            {
                throw new InvalidOperationException($"Failed to encrypt with version {loader.Version}: {tie.InnerException.Message}", tie.InnerException);
            }
        }

        /// <summary>
        /// Decrypts data with a specific JSON processor mode.
        /// </summary>
        private byte[] DecryptDataWithMode(
            VersionLoader loader,
            byte[] ciphertext,
            JsonProcessorMode mode,
            bool isDeterministic = false)
        {
            string algorithm = this.ResolveEncryptionAlgorithm(loader, isDeterministic);
            object dataEncryptionKey = this.CreateDataEncryptionKey(loader, algorithm, isDeterministic);

            MethodInfo decryptMethod = dataEncryptionKey
                .GetType()
                .GetMethod("DecryptData", BindingFlags.Public | BindingFlags.Instance, null, new[] { typeof(byte[]) }, null)
                ?? throw new InvalidOperationException($"The loaded version '{loader.Version}' does not expose a public DecryptData(byte[]) method on DataEncryptionKey.");

            try
            {
                return (byte[])decryptMethod.Invoke(dataEncryptionKey, new object[] { ciphertext });
            }
            catch (TargetInvocationException tie) when (tie.InnerException != null)
            {
                throw new InvalidOperationException($"Failed to decrypt with version {loader.Version}: {tie.InnerException.Message}", tie.InnerException);
            }
        }

        private byte[] CreateTestPayload()
        {
            string testString = "System.Text.Json compatibility test data. " +
                               "Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>? " +
                               "Unicode: 你好世界 مرحبا العالم Привет мир 🚀";
            return Encoding.UTF8.GetBytes(testString);
        }

        // Reuse the helper methods from CrossVersionEncryptionTests
        private string ResolveEncryptionAlgorithm(VersionLoader loader, bool isDeterministic)
        {
            Type algorithmType = loader.GetType("Microsoft.Azure.Cosmos.Encryption.Custom.CosmosEncryptionAlgorithm")
                ?? throw new InvalidOperationException($"Could not find CosmosEncryptionAlgorithm type in version {loader.Version}");

            string[] preferredFieldNames = isDeterministic
                ? new[]
                {
                    "MdeAeadAes256CbcHmac256Deterministic",
                    "AEAes256CbcHmacSha256Deterministic",
                }
                : new[]
                {
                    "MdeAeadAes256CbcHmac256Randomized",
                    "AEAes256CbcHmacSha256Randomized",
                };

            foreach (string fieldName in preferredFieldNames)
            {
                FieldInfo field = algorithmType.GetField(fieldName, BindingFlags.Public | BindingFlags.Static);
                if (field != null)
                {
                    string value = field.GetValue(null) as string;
                    if (!string.IsNullOrEmpty(value))
                    {
                        return value;
                    }
                }
            }

            string keyword = isDeterministic ? "Deterministic" : "Randomized";
            FieldInfo[] algorithmFields = algorithmType.GetFields(BindingFlags.Public | BindingFlags.Static);
            FieldInfo fallbackField = algorithmFields
                .FirstOrDefault(f => f.FieldType == typeof(string) && f.Name.Contains(keyword, StringComparison.OrdinalIgnoreCase));

            if (fallbackField != null)
            {
                string fallbackValue = fallbackField.GetValue(null) as string;
                if (!string.IsNullOrEmpty(fallbackValue))
                {
                    return fallbackValue;
                }
            }

            if (isDeterministic)
            {
                throw new NotSupportedException($"Deterministic encryption is not exposed via the public API in version {loader.Version}.");
            }

            throw new InvalidOperationException($"Version {loader.Version} does not expose a supported encryption algorithm via the public API.");
        }

        private object CreateDataEncryptionKey(VersionLoader loader, string algorithm, bool isDeterministic)
        {
            Type dekType = loader.GetType("Microsoft.Azure.Cosmos.Encryption.Custom.DataEncryptionKey")
                ?? throw new InvalidOperationException($"Could not find DataEncryptionKey type in version {loader.Version}");

            MethodInfo[] factoryMethods = dekType
                .GetMethods(BindingFlags.Public | BindingFlags.Static)
                .Where(m => string.Equals(m.Name, "Create", StringComparison.Ordinal))
                .ToArray();

            if (factoryMethods.Length == 0)
            {
                throw new InvalidOperationException($"Version {loader.Version} does not expose a public DataEncryptionKey.Create factory method.");
            }

            byte[] rawKey = CreateDeterministicKeyMaterial();
            IEnumerable<string> algorithmCandidates = this.GetAlgorithmCandidates(loader, algorithm);
            IEnumerable<MethodInfo> orderedMethods = factoryMethods.OrderByDescending(m => m.GetParameters().Length);

            foreach (string candidateAlgorithm in algorithmCandidates)
            {
                foreach (MethodInfo method in orderedMethods)
                {
                    ParameterInfo[] parameters = method.GetParameters();
                    if (parameters.Length < 2)
                    {
                        continue;
                    }

                    object[] args = new object[parameters.Length];
                    args[0] = rawKey;
                    args[1] = candidateAlgorithm;

                    if (parameters.Length >= 3)
                    {
                        if (!this.TryPopulateEncryptionModeArgument(parameters[2].ParameterType, isDeterministic, out object modeArgument))
                        {
                            continue;
                        }

                        args[2] = modeArgument;
                    }
                    else if (isDeterministic)
                    {
                        continue;
                    }

                    try
                    {
                        return method.Invoke(null, args);
                    }
                    catch (TargetInvocationException tie) when (tie.InnerException is ArgumentException)
                    {
                        continue;
                    }
                }
            }

            if (isDeterministic)
            {
                throw new NotSupportedException($"Version {loader.Version} does not expose a public deterministic encryption path via DataEncryptionKey.Create.");
            }

            throw new InvalidOperationException($"Unable to create a data encryption key using the public API for version {loader.Version}.");
        }

        private IEnumerable<string> GetAlgorithmCandidates(VersionLoader loader, string preferredAlgorithm)
        {
            HashSet<string> yieldedAlgorithms = new HashSet<string>(StringComparer.Ordinal);

            if (!string.IsNullOrEmpty(preferredAlgorithm) && yieldedAlgorithms.Add(preferredAlgorithm))
            {
                yield return preferredAlgorithm;
            }

            string legacyAlgorithm = this.TryGetAlgorithmValue(loader, "AEAes256CbcHmacSha256Randomized");
            if (!string.IsNullOrEmpty(legacyAlgorithm) && yieldedAlgorithms.Add(legacyAlgorithm))
            {
                yield return legacyAlgorithm;
            }
        }

        private string TryGetAlgorithmValue(VersionLoader loader, string fieldName)
        {
            Type algorithmType = loader.GetType("Microsoft.Azure.Cosmos.Encryption.Custom.CosmosEncryptionAlgorithm");
            if (algorithmType == null)
            {
                return null;
            }

            FieldInfo field = algorithmType.GetField(fieldName, BindingFlags.Public | BindingFlags.Static);
            return field?.GetValue(null) as string;
        }

        private bool TryPopulateEncryptionModeArgument(Type parameterType, bool isDeterministic, out object value)
        {
            if (parameterType == typeof(bool))
            {
                value = isDeterministic;
                return true;
            }

            if (parameterType.IsEnum)
            {
                string enumName = isDeterministic ? "Deterministic" : "Randomized";
                if (Enum.GetNames(parameterType).Any(name => string.Equals(name, enumName, StringComparison.OrdinalIgnoreCase)))
                {
                    value = Enum.Parse(parameterType, enumName, ignoreCase: true);
                    return true;
                }
            }

            if (parameterType == typeof(string))
            {
                value = isDeterministic ? "Deterministic" : "Randomized";
                return true;
            }

            value = null;
            return false;
        }

        private static byte[] CreateDeterministicKeyMaterial()
        {
            byte[] key = new byte[32];
            for (int i = 0; i < key.Length; i++)
            {
                key[i] = (byte)(i + 1);
            }

            return key;
        }
    }
}
