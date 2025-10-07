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
        /// This feature was introduced in PR #5403 via EncryptionRequestOptionsExperimental.SetExperimentalJsonProcessorMode.
        /// </summary>
        public static bool SupportsSystemTextJsonSwitch(VersionLoader loader)
        {
            if (loader == null)
            {
                throw new ArgumentNullException(nameof(loader));
            }

            // Look for the EncryptionRequestOptionsExperimental class and SetExperimentalJsonProcessorMode method
            Type experimentalType = loader.GetType("Microsoft.Azure.Cosmos.Encryption.Custom.EncryptionRequestOptionsExperimental");
            if (experimentalType == null)
            {
                return false;
            }

            MethodInfo method = experimentalType.GetMethod(
                "SetExperimentalJsonProcessorMode",
                BindingFlags.Public | BindingFlags.Static,
                null,
                new[] { typeof(object), typeof(bool) }, // RequestOptions is not available, so use object
                null);

            return method != null;
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

            var features = new[]
            {
                ("SystemTextJsonSwitch", SupportsSystemTextJsonSwitch(loader)),
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
