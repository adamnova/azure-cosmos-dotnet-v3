// ----------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// ----------------------------------------------------------------

namespace Microsoft.Azure.Cosmos.Encryption.Custom.CompatibilityTests
{
    using System;
    using System.Linq;
    using System.Reflection;
    using Microsoft.Azure.Cosmos.Encryption.Custom.CompatibilityTests.SideBySide;

    /// <summary>
    /// Determines feature availability across different versions of the Encryption.Custom library.
    /// This allows compatibility tests to gracefully skip unsupported features in older versions.
    /// </summary>
    internal static class FeatureAvailability
    {
        /// <summary>
        /// Checks if the experimental System.Text.Json processor switch is available.
        /// This feature was introduced in PR #5403 via EncryptionRequestOptionsExperimental.ConfigureJsonProcessor.
        /// </summary>
        public static bool SupportsSystemTextJsonSwitch(VersionLoader loader)
        {
            if (loader == null)
            {
                throw new ArgumentNullException(nameof(loader));
            }

            // Look for the EncryptionRequestOptionsExperimental class and ConfigureJsonProcessor method
            Type experimentalType = loader.GetType("Microsoft.Azure.Cosmos.Encryption.Custom.EncryptionRequestOptionsExperimental");
            if (experimentalType == null)
            {
                return false;
            }

            // Check for the ConfigureJsonProcessor extension method
            MethodInfo[] methods = experimentalType.GetMethods(BindingFlags.Public | BindingFlags.Static);
            foreach (MethodInfo method in methods)
            {
                if (method.Name == "ConfigureJsonProcessor" && method.GetParameters().Length == 2)
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Checks if the JsonProcessor enum is available (needed for System.Text.Json support).
        /// </summary>
        public static bool HasJsonProcessorEnum(VersionLoader loader)
        {
            if (loader == null)
            {
                throw new ArgumentNullException(nameof(loader));
            }

            Type jsonProcessorType = loader.GetType("Microsoft.Azure.Cosmos.Encryption.Custom.JsonProcessor");
            return jsonProcessorType != null && jsonProcessorType.IsEnum;
        }

        /// <summary>
        /// Checks if the JsonProcessor.Stream enum value is available.
        /// This is conditional on ENCRYPTION_CUSTOM_PREVIEW and NET8_0_OR_GREATER.
        /// </summary>
        public static bool HasStreamJsonProcessorValue(VersionLoader loader)
        {
            if (loader == null)
            {
                throw new ArgumentNullException(nameof(loader));
            }

            Type jsonProcessorType = loader.GetType("Microsoft.Azure.Cosmos.Encryption.Custom.JsonProcessor");
            if (jsonProcessorType == null || !jsonProcessorType.IsEnum)
            {
                return false;
            }

            // Check if "Stream" value exists in the enum
            string[] enumNames = Enum.GetNames(jsonProcessorType);
            return enumNames.Any(name => string.Equals(name, "Stream", StringComparison.Ordinal));
        }

        /// <summary>
        /// Checks if deterministic encryption is exposed via the public API.
        /// Some older versions may not support this feature.
        /// </summary>
        public static bool SupportsDeterministicEncryption(VersionLoader loader)
        {
            if (loader == null)
            {
                throw new ArgumentNullException(nameof(loader));
            }

            Type algorithmType = loader.GetType("Microsoft.Azure.Cosmos.Encryption.Custom.CosmosEncryptionAlgorithm");
            if (algorithmType == null)
            {
                return false;
            }

            // Check for deterministic algorithm fields
            string[] deterministicFields = new[]
            {
                "MdeAeadAes256CbcHmac256Deterministic",
                "AEAes256CbcHmacSha256Deterministic",
            };

            return deterministicFields.Any(fieldName =>
            {
                FieldInfo field = algorithmType.GetField(fieldName, BindingFlags.Public | BindingFlags.Static);
                return field != null;
            });
        }

        /// <summary>
        /// Gets a description of available features for logging purposes.
        /// </summary>
        public static string GetFeatureSummary(VersionLoader loader)
        {
            if (loader == null)
            {
                throw new ArgumentNullException(nameof(loader));
            }

            (string, bool)[] features = new[]
            {
                ("SystemTextJsonSwitch", SupportsSystemTextJsonSwitch(loader)),
                ("StreamJsonProcessorValue", HasStreamJsonProcessorValue(loader)),
                ("DeterministicEncryption", SupportsDeterministicEncryption(loader)),
            };

            string enabled = string.Join(", ", features.Where(f => f.Item2).Select(f => f.Item1));
            string disabled = string.Join(", ", features.Where(f => !f.Item2).Select(f => f.Item1));

            if (string.IsNullOrEmpty(disabled))
            {
                return $"All features available: {enabled}";
            }

            if (string.IsNullOrEmpty(enabled))
            {
                return $"No features available: {disabled}";
            }

            return $"Available: {enabled}; Unavailable: {disabled}";
        }
    }
}
