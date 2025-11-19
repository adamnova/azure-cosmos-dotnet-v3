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
    /// Tests JSON processor mode compatibility across versions.
    /// Validates that data encrypted/decrypted with Newtonsoft.Json can be processed with System.Text.Json and vice versa.
    /// Handles graceful skipping when System.Text.Json mode is not available in older versions.
    /// </summary>
    [Trait("Category", "Compatibility")]
    [Trait("Feature", "JsonProcessor")]
    public class JsonProcessorCompatibilityTests : CompatibilityTestBase
    {
        public JsonProcessorCompatibilityTests(ITestOutputHelper output) : base(output) { }

        /// <summary>
        /// Represents JSON processor modes for testing.
        /// </summary>
        public enum JsonProcessorMode
        {
            /// <summary>Default Newtonsoft.Json processor (always available).</summary>
            Newtonsoft,

            /// <summary>System.Text.Json streaming processor (experimental, requires PREVIEW build and .NET 8.0+).</summary>
            SystemTextJson
        }

        /// <summary>
        /// Generates all test combinations of (encryptVersion, decryptVersion, encryptMode, decryptMode).
        /// Only includes combinations where at least one mode is SystemTextJson to avoid redundant testing.
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
                            // Skip all-Newtonsoft combinations as they're covered by basic compatibility tests
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

        /// <summary>
        /// Tests that data can be encrypted and decrypted across different JSON processor modes.
        /// This is the primary compatibility test for the System.Text.Json feature.
        /// </summary>
        [Theory]
        [MemberData(nameof(GetJsonProcessorTestCombinations))]
        public void CanEncryptAndDecrypt_AcrossJsonProcessorModes(
            string encryptVersion,
            string decryptVersion,
            JsonProcessorMode encryptMode,
            JsonProcessorMode decryptMode)
        {
            string resolvedEncryptVersion = VersionMatrix.ResolveVersion(encryptVersion);
            string resolvedDecryptVersion = VersionMatrix.ResolveVersion(decryptVersion);

            string encryptDisplay = VersionMatrix.IsCurrentVersion(encryptVersion)
                ? $"{encryptVersion} ({resolvedEncryptVersion})[{encryptMode}]"
                : $"{encryptVersion}[{encryptMode}]";
            string decryptDisplay = VersionMatrix.IsCurrentVersion(decryptVersion)
                ? $"{decryptVersion} ({resolvedDecryptVersion})[{decryptMode}]"
                : $"{decryptVersion}[{decryptMode}]";

            this.LogInfo($"Testing: Encrypt with {encryptDisplay} → Decrypt with {decryptDisplay}");

            // Check if the required features are available in each version
            bool encryptSupportsMode = this.CheckModeAvailability(encryptVersion, encryptMode, out string encryptSkipReason);
            bool decryptSupportsMode = this.CheckModeAvailability(decryptVersion, decryptMode, out string decryptSkipReason);

            if (!encryptSupportsMode)
            {
                this.LogInfo($"  ⊘ Skipping: {encryptSkipReason}");
                return;
            }

            if (!decryptSupportsMode)
            {
                this.LogInfo($"  ⊘ Skipping: {decryptSkipReason}");
                return;
            }

            // Arrange
            byte[] testData = this.CreateTestPayload();
            byte[] encryptedData;
            byte[] decryptedData;

            try
            {
                // Act: Encrypt with version A and specified mode
                using (VersionLoader encryptLoader = VersionLoader.Load(resolvedEncryptVersion))
                {
                    encryptedData = this.EncryptDataWithMode(encryptLoader, testData, encryptMode);
                    encryptedData.Should().NotBeNull($"Encryption with {encryptDisplay} should produce data");
                    encryptedData.Length.Should().BeGreaterThan(0);
                    encryptedData.Should().NotBeEquivalentTo(testData,
                        $"Encrypted data should not match plaintext");

                    this.LogInfo($"  ✓ Encrypted with {encryptDisplay}: {encryptedData.Length} bytes");
                }

                // Act: Decrypt with version B and specified mode
                using (VersionLoader decryptLoader = VersionLoader.Load(resolvedDecryptVersion))
                {
                    decryptedData = this.DecryptDataWithMode(decryptLoader, encryptedData, decryptMode);
                    decryptedData.Should().NotBeNull($"Decryption with {decryptDisplay} should produce data");
                    this.LogInfo($"  ✓ Decrypted with {decryptDisplay}: {decryptedData.Length} bytes");
                }

                // Assert: Data should round-trip correctly regardless of JSON processor mode
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

        /// <summary>
        /// Tests deterministic encryption across JSON processor modes.
        /// Validates that deterministic encryption produces identical ciphertext regardless of JSON processor.
        /// </summary>
        [Theory]
        [MemberData(nameof(GetJsonProcessorTestCombinations))]
        public void CanEncryptAndDecryptDeterministic_AcrossJsonProcessorModes(
            string encryptVersion,
            string decryptVersion,
            JsonProcessorMode encryptMode,
            JsonProcessorMode decryptMode)
        {
            string resolvedEncryptVersion = VersionMatrix.ResolveVersion(encryptVersion);
            string resolvedDecryptVersion = VersionMatrix.ResolveVersion(decryptVersion);

            string encryptDisplay = VersionMatrix.IsCurrentVersion(encryptVersion)
                ? $"{encryptVersion} ({resolvedEncryptVersion})[{encryptMode}]"
                : $"{encryptVersion}[{encryptMode}]";
            string decryptDisplay = VersionMatrix.IsCurrentVersion(decryptVersion)
                ? $"{decryptVersion} ({resolvedDecryptVersion})[{decryptMode}]"
                : $"{decryptVersion}[{decryptMode}]";

            this.LogInfo($"Testing Deterministic: Encrypt with {encryptDisplay} → Decrypt with {decryptDisplay}");

            // Check feature availability
            bool encryptSupportsMode = this.CheckModeAvailability(encryptVersion, encryptMode, out string encryptSkipReason);
            bool decryptSupportsMode = this.CheckModeAvailability(decryptVersion, decryptMode, out string decryptSkipReason);

            if (!encryptSupportsMode)
            {
                this.LogInfo($"  ⊘ Skipping: {encryptSkipReason}");
                return;
            }

            if (!decryptSupportsMode)
            {
                this.LogInfo($"  ⊘ Skipping: {decryptSkipReason}");
                return;
            }

            // Check if deterministic encryption is supported
            bool encryptSupportsDeterministic;
            bool decryptSupportsDeterministic;

            using (VersionLoader encryptLoader = VersionLoader.Load(resolvedEncryptVersion))
            {
                encryptSupportsDeterministic = FeatureAvailability.SupportsDeterministicEncryption(encryptLoader);
            }

            using (VersionLoader decryptLoader = VersionLoader.Load(resolvedDecryptVersion))
            {
                decryptSupportsDeterministic = FeatureAvailability.SupportsDeterministicEncryption(decryptLoader);
            }

            if (!encryptSupportsDeterministic)
            {
                this.LogInfo($"  ⊘ Skipping: {encryptVersion} does not support deterministic encryption");
                return;
            }

            if (!decryptSupportsDeterministic)
            {
                this.LogInfo($"  ⊘ Skipping: {decryptVersion} does not support deterministic encryption");
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
                using (VersionLoader encryptLoader = VersionLoader.Load(resolvedEncryptVersion))
                {
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
                using (VersionLoader decryptLoader = VersionLoader.Load(resolvedDecryptVersion))
                {
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
                this.LogInfo($"  ⊘ Skipping deterministic scenario: {notSupported.Message}");
            }
            catch (Exception ex)
            {
                this.LogError($"✗ FAILED: Deterministic {encryptDisplay} → {decryptDisplay}");
                this.LogError($"  Error: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Checks if the specified JSON processor mode is available in the given version.
        /// Returns false and provides a skip reason if not available.
        /// </summary>
        private bool CheckModeAvailability(string version, JsonProcessorMode mode, out string skipReason)
        {
            if (mode == JsonProcessorMode.Newtonsoft)
            {
                // Newtonsoft mode is always available (it's the default)
                skipReason = null;
                return true;
            }

            // Resolve "current" to actual version
            string resolvedVersion = VersionMatrix.ResolveVersion(version);

            // For System.Text.Json mode, check if the switch API and enum value are available
            using (VersionLoader loader = VersionLoader.Load(resolvedVersion))
            {
                if (!FeatureAvailability.SupportsSystemTextJsonSwitch(loader))
                {
                    skipReason = $"{version} does not have EncryptionRequestOptionsExperimental.ConfigureJsonProcessor API";
                    return false;
                }

                if (!FeatureAvailability.HasStreamJsonProcessorValue(loader))
                {
                    skipReason = $"{version} does not have JsonProcessor.Stream enum value (requires PREVIEW build + .NET 8.0+)";
                    return false;
                }
            }

            skipReason = null;
            return true;
        }

        /// <summary>
        /// Encrypts data with a specific JSON processor mode.
        /// Note: The JSON processor mode affects high-level operations (Container operations with JSON payloads).
        /// For low-level byte[] encryption via DataEncryptionKey, the mode doesn't affect the encryption algorithm,
        /// but we configure it for completeness and future-proofing.
        /// </summary>
        private byte[] EncryptDataWithMode(
            VersionLoader loader,
            byte[] plaintext,
            JsonProcessorMode mode,
            bool isDeterministic = false)
        {
            string algorithm = this.ResolveEncryptionAlgorithm(loader, isDeterministic);
            object dataEncryptionKey = this.CreateDataEncryptionKey(loader, algorithm, isDeterministic);

            MethodInfo encryptMethod = dataEncryptionKey
                .GetType()
                .GetMethod("EncryptData", BindingFlags.Public | BindingFlags.Instance, null, new[] { typeof(byte[]) }, null)
                ?? throw new InvalidOperationException($"The loaded version '{loader.Version}' does not expose a public EncryptData(byte[]) method on DataEncryptionKey.");

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
            string testString = "JsonProcessor compatibility test data. " +
                               "Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>? " +
                               "Unicode: 你好世界 مرحبا العالم Привет мир 🚀 " +
                               "Timestamp: " + DateTime.UtcNow.ToString("O");
            return Encoding.UTF8.GetBytes(testString);
        }

        // Reuse helper methods from CompatibilityTestBase
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

            byte[] rawKey = this.CreateDeterministicKeyMaterial();
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

        private byte[] CreateDeterministicKeyMaterial()
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
