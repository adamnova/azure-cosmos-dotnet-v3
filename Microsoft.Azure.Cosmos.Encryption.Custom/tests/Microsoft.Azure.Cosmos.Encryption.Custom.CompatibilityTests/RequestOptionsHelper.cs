// ----------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// ----------------------------------------------------------------

namespace Microsoft.Azure.Cosmos.Encryption.Custom.CompatibilityTests
{
    using System;
    using System.Reflection;
    using Microsoft.Azure.Cosmos.Encryption.Custom.CompatibilityTests.SideBySide;

    /// <summary>
    /// Helper class to configure RequestOptions with experimental features across different versions.
    /// Uses reflection to invoke version-specific APIs.
    /// </summary>
    internal static class RequestOptionsHelper
    {
        /// <summary>
        /// Configures the experimental System.Text.Json processor mode on a RequestOptions instance.
        /// Only applies if the feature is available in the loaded version.
        /// </summary>
        /// <param name="loader">The version loader containing the API to invoke.</param>
        /// <param name="requestOptions">The RequestOptions instance to configure (from the loaded version).</param>
        /// <param name="useSystemTextJsonStreamProcessor">Whether to enable System.Text.Json streaming processor.</param>
        /// <returns>True if the feature was configured; false if not available in this version.</returns>
        public static bool TryConfigureJsonProcessor(VersionLoader loader, object requestOptions, bool useSystemTextJsonStreamProcessor)
        {
            if (loader == null)
            {
                throw new ArgumentNullException(nameof(loader));
            }

            if (requestOptions == null)
            {
                throw new ArgumentNullException(nameof(requestOptions));
            }

            if (!FeatureAvailability.SupportsSystemTextJsonSwitch(loader))
            {
                return false;
            }

            if (!FeatureAvailability.HasStreamJsonProcessorValue(loader))
            {
                // Even if the experimental API exists, the Stream enum value might not be available
                // (e.g., in non-PREVIEW builds or .NET Standard builds)
                return false;
            }

            Type experimentalType = loader.GetType("Microsoft.Azure.Cosmos.Encryption.Custom.EncryptionRequestOptionsExperimental");
            if (experimentalType == null)
            {
                return false;
            }

            Type jsonProcessorType = loader.GetType("Microsoft.Azure.Cosmos.Encryption.Custom.JsonProcessor");
            if (jsonProcessorType == null || !jsonProcessorType.IsEnum)
            {
                return false;
            }

            // Find the ConfigureJsonProcessor extension method
            // Extension methods appear as static methods with the first parameter being the type they extend
            MethodInfo configureMethod = null;
            MethodInfo[] methods = experimentalType.GetMethods(BindingFlags.Public | BindingFlags.Static);

            foreach (MethodInfo method in methods)
            {
                if (method.Name == "ConfigureJsonProcessor")
                {
                    ParameterInfo[] parameters = method.GetParameters();
                    if (parameters.Length == 2 && parameters[1].ParameterType == jsonProcessorType)
                    {
                        configureMethod = method;
                        break;
                    }
                }
            }

            if (configureMethod == null)
            {
                return false;
            }

            try
            {
                // Determine which JsonProcessor enum value to use
                string enumValueName = useSystemTextJsonStreamProcessor ? "Stream" : "Newtonsoft";
                object jsonProcessorValue = Enum.Parse(jsonProcessorType, enumValueName, ignoreCase: false);

                // Invoke: ConfigureJsonProcessor(requestOptions, JsonProcessor.Stream or JsonProcessor.Newtonsoft)
                object result = configureMethod.Invoke(null, new object[] { requestOptions, jsonProcessorValue });

                // The method returns the requestOptions for fluent chaining, but we don't need the return value
                return true;
            }
            catch (ArgumentException)
            {
                // Enum value doesn't exist (e.g., Stream not available in this build)
                return false;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException(
                    $"Failed to configure JSON processor on version {loader.Version}: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Legacy method name for backward compatibility with existing tests.
        /// </summary>
        [Obsolete("Use TryConfigureJsonProcessor instead")]
        public static bool TrySetSystemTextJsonMode(VersionLoader loader, object requestOptions, bool useSystemTextJsonStreamProcessor)
        {
            return TryConfigureJsonProcessor(loader, requestOptions, useSystemTextJsonStreamProcessor);
        }

        /// <summary>
        /// Creates a RequestOptions instance from the loaded version's assembly.
        /// </summary>
        /// <param name="loader">The version loader.</param>
        /// <param name="requestOptionsTypeName">The full type name of the RequestOptions type (e.g., "Microsoft.Azure.Cosmos.ItemRequestOptions").</param>
        /// <returns>A new RequestOptions instance.</returns>
        public static object CreateRequestOptions(VersionLoader loader, string requestOptionsTypeName = "Microsoft.Azure.Cosmos.ItemRequestOptions")
        {
            if (loader == null)
            {
                throw new ArgumentNullException(nameof(loader));
            }

            Type requestOptionsType = loader.GetType(requestOptionsTypeName);
            if (requestOptionsType == null)
            {
                throw new InvalidOperationException($"Type {requestOptionsTypeName} not found in version {loader.Version}");
            }

            return Activator.CreateInstance(requestOptionsType);
        }
    }
}
