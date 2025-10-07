// ----------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// ----------------------------------------------------------------

namespace Microsoft.Azure.Cosmos.Encryption.Custom.CompatibilityTests
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Reflection;
    using FluentAssertions;
    using Microsoft.Azure.Cosmos.Encryption.Custom.CompatibilityTests.SideBySide;
    using Xunit;
    using Xunit.Abstractions;

    /// <summary>
    /// Base class for compatibility tests that validates version uniqueness before each test.
    /// </summary>
    public abstract class CompatibilityTestBase : IDisposable
    {
        private static readonly object ValidationLock = new object();
        private static bool versionValidationCompleted = false;
        private static Dictionary<string, string> validatedVersionInfo;

        protected readonly ITestOutputHelper Output;

        protected CompatibilityTestBase(ITestOutputHelper output)
        {
            this.Output = output;
            this.ValidateVersionUniqueness();
        }

        /// <summary>
        /// Validates that all versions in the test matrix are truly distinct.
        /// This runs once per test class and caches the results.
        /// </summary>
        private void ValidateVersionUniqueness()
        {
            lock (ValidationLock)
            {
                if (versionValidationCompleted)
                {
                    // Already validated, just log the cached results
                    this.LogVersionInfo(validatedVersionInfo);
                    return;
                }

                string[] versions = VersionMatrix.GetTestVersions();
                
                if (versions.Length < 2)
                {
                    this.Output.WriteLine("⚠️  Only one version in matrix, skipping version uniqueness validation");
                    versionValidationCompleted = true;
                    validatedVersionInfo = new Dictionary<string, string>();
                    return;
                }

                Dictionary<string, string> versionInfo = new Dictionary<string, string>();
                Dictionary<string, string> featureInfo = new Dictionary<string, string>();

                // Load each version and get its informational version
                foreach (string packageVersion in versions)
                {
                    string resolvedVersion = VersionMatrix.ResolveVersion(packageVersion);
                    using (VersionLoader loader = VersionLoader.Load(resolvedVersion))
                    {
                        Assembly assembly = loader.Assembly;
                        System.Reflection.AssemblyInformationalVersionAttribute infoAttr = 
                            assembly.GetCustomAttributes(typeof(AssemblyInformationalVersionAttribute), false)
                                .OfType<AssemblyInformationalVersionAttribute>()
                                .FirstOrDefault();

                        string actualVersion = infoAttr?.InformationalVersion 
                            ?? assembly.GetName().Version?.ToString() 
                            ?? "unknown";

                        versionInfo[packageVersion] = actualVersion;

                        // Capture feature availability for this version
                        featureInfo[packageVersion] = FeatureAvailability.GetFeatureSummary(loader);
                    }
                }

                // Validate all versions are distinct
                List<string> distinctVersions = versionInfo.Values.Distinct().ToList();
                
                versionInfo.Values.Count.Should().Be(distinctVersions.Count,
                    because: "compatibility tests require distinct versions to be meaningful. " +
                             $"Found {versionInfo.Count} package versions but only {distinctVersions.Count} distinct assemblies.");

                // Cache the validated results
                validatedVersionInfo = versionInfo;
                versionValidationCompleted = true;

                // Log the validation results
                this.Output.WriteLine("🔍 Version Validation:");
                this.LogVersionInfo(versionInfo);
                this.LogFeatureInfo(featureInfo);
                this.Output.WriteLine("✅ All versions are distinct - compatibility testing is valid");
                this.Output.WriteLine("");
            }
        }

        private void LogVersionInfo(Dictionary<string, string> versionInfo)
        {
            if (versionInfo == null || !versionInfo.Any())
            {
                return;
            }

            this.Output.WriteLine($"   Testing {versionInfo.Count} version(s):");
            foreach (KeyValuePair<string, string> kvp in versionInfo)
            {
                this.Output.WriteLine($"   • {kvp.Key} → {kvp.Value}");
            }
        }

        private void LogFeatureInfo(Dictionary<string, string> featureInfo)
        {
            if (featureInfo == null || !featureInfo.Any())
            {
                return;
            }

            this.Output.WriteLine("");
            this.Output.WriteLine("   Feature Availability:");
            foreach (KeyValuePair<string, string> kvp in featureInfo)
            {
                this.Output.WriteLine($"   • {kvp.Key}: {kvp.Value}");
            }
        }

        /// <summary>
        /// Helper method to log informational messages with a consistent format.
        /// </summary>
        protected void LogInfo(string message)
        {
            this.Output.WriteLine(message);
        }

        /// <summary>
        /// Helper method to log error messages with a consistent format.
        /// </summary>
        protected void LogError(string message)
        {
            this.Output.WriteLine($"❌ ERROR: {message}");
        }

        public virtual void Dispose()
        {
            // Cleanup if needed by derived classes
        }
    }
}
