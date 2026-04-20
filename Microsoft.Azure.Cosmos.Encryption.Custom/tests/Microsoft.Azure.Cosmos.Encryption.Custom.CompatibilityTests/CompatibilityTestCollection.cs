// ----------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// ----------------------------------------------------------------

namespace Microsoft.Azure.Cosmos.Encryption.Custom.CompatibilityTests
{
    using System;
    using System.Collections.Generic;
    using Xunit;

    /// <summary>
    /// Test collection for compatibility tests that share the same version loader cache.
    /// Tests in this collection run sequentially to avoid resource contention when loading
    /// multiple versions of assemblies simultaneously.
    /// </summary>
    [CollectionDefinition(Name)]
    public class CompatibilityTestCollection : ICollectionFixture<VersionLoaderFixture>
    {
        public const string Name = "Compatibility Tests";
    }

    /// <summary>
    /// Fixture that manages shared state across compatibility tests.
    /// Initializes the version loader cache once and provides it to all tests.
    /// </summary>
    public class VersionLoaderFixture : IDisposable
    {
        /// <summary>
        /// Gets the versions that will be tested in this run.
        /// Cached to avoid repeated file I/O and package resolution.
        /// </summary>
        public string[] TestVersions { get; }

        /// <summary>
        /// Gets a dictionary mapping version aliases to resolved version numbers.
        /// </summary>
        public Dictionary<string, string> ResolvedVersions { get; }

        public VersionLoaderFixture()
        {
            this.TestVersions = VersionMatrix.GetTestVersions();
            this.ResolvedVersions = new Dictionary<string, string>();

            // Pre-resolve all versions to cache the results
            foreach (string version in this.TestVersions)
            {
                this.ResolvedVersions[version] = VersionMatrix.ResolveVersion(version);
            }
        }

        public void Dispose()
        {
            // Cleanup any cached resources if needed
            GC.SuppressFinalize(this);
        }
    }
}
