namespace Microsoft.Azure.Cosmos.Encryption.Custom.CompatibilityTests
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using FluentAssertions;
    using Microsoft.Azure.Cosmos.Encryption.Custom.CompatibilityTests.SideBySide;
    using Xunit;
    using Xunit.Abstractions;

    /// <summary>
    /// Tests to validate that we're actually testing different versions
    /// and not accidentally testing the same version twice.
    /// </summary>
    [Collection(CompatibilityTestCollection.Name)]
    [Trait("Category", "Compatibility")]
    [Trait("Type", "Validation")]
    public class VersionValidationTests : CompatibilityTestBase
    {
        public VersionValidationTests(ITestOutputHelper output) : base(output)
        {
        }

        [Fact]
        public void VersionMatrix_ShouldContainDistinctVersions()
        {
            // Arrange
            var versions = VersionMatrix.GetTestVersions();
            
            this.Output.WriteLine($"Version matrix contains {versions.Length} version(s):");
            foreach (var version in versions)
            {
                this.Output.WriteLine($"  - {version}");
            }

            // Act & Assert
            var distinctVersions = versions.Distinct().ToArray();
            
            versions.Length.Should().Be(distinctVersions.Length, 
                "version matrix should not contain duplicate versions");
        }

        [Fact]
        public void LoadedVersions_ShouldHaveDifferentAssemblyVersions()
        {
            // Arrange
            var versions = VersionMatrix.GetTestVersions();

            if (versions.Length < 2)
            {
                this.Output.WriteLine("⚠️  Only one version in matrix, skipping cross-version validation");
                return;
            }

            var loadedVersionInfo = new Dictionary<string, string>();

            // Act - Load each version and get its assembly version
            foreach (var packageVersion in versions)
            {
                var resolvedVersion = VersionMatrix.ResolveVersion(packageVersion);
                using (var loader = VersionLoader.Load(resolvedVersion))
                {
                    var assembly = loader.Assembly;
                    var assemblyVersion = assembly.GetName().Version?.ToString() ?? "unknown";
                    var infoVersion = assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
                        .OfType<System.Reflection.AssemblyInformationalVersionAttribute>()
                        .FirstOrDefault()?.InformationalVersion ?? assemblyVersion;

                    loadedVersionInfo[packageVersion] = infoVersion;
                    
                    this.Output.WriteLine($"Package {packageVersion} (resolved to {resolvedVersion}):");
                    this.Output.WriteLine($"  Assembly Version: {assemblyVersion}");
                    this.Output.WriteLine($"  Informational Version: {infoVersion}");
                }
            }

            // Assert - Verify all versions are different
            var distinctActualVersions = loadedVersionInfo.Values.Distinct().ToList();
            
            loadedVersionInfo.Values.Count.Should().Be(distinctActualVersions.Count,
                because: "each package version should load a different assembly version");

            this.Output.WriteLine("");
            this.Output.WriteLine("✅ Validation Result:");
            this.Output.WriteLine($"   Testing {loadedVersionInfo.Count} distinct version(s)");
            
            foreach (var kvp in loadedVersionInfo)
            {
                this.Output.WriteLine($"   • {kvp.Key} → {kvp.Value}");
            }
        }

        [Fact]
        public void Preview07_And_Preview08_ShouldBeDistinct()
        {
            // Arrange
            var versions = VersionMatrix.GetTestVersions();

            var preview07 = versions.FirstOrDefault(v => v.Contains("preview07"));
            var preview08 = versions.FirstOrDefault(v => v.Contains("preview08"));

            if (preview07 == null || preview08 == null)
            {
                this.Output.WriteLine("⚠️  Both preview07 and preview08 not found in version matrix");
                this.Output.WriteLine($"   Versions in matrix: {string.Join(", ", versions)}");
                return; // Skip if we don't have both versions
            }

            // Act
            string version07Info;
            string version08Info;

            var resolved07 = VersionMatrix.ResolveVersion(preview07);
            var resolved08 = VersionMatrix.ResolveVersion(preview08);

            using (var loader07 = VersionLoader.Load(resolved07))
            {
                var infoAttr = loader07.Assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
                    .OfType<System.Reflection.AssemblyInformationalVersionAttribute>()
                    .FirstOrDefault();
                version07Info = infoAttr?.InformationalVersion ?? loader07.Assembly.GetName().Version?.ToString() ?? "unknown";
            }

            using (var loader08 = VersionLoader.Load(resolved08))
            {
                var infoAttr = loader08.Assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
                    .OfType<System.Reflection.AssemblyInformationalVersionAttribute>()
                    .FirstOrDefault();
                version08Info = infoAttr?.InformationalVersion ?? loader08.Assembly.GetName().Version?.ToString() ?? "unknown";
            }

            // Assert
            this.Output.WriteLine($"Preview07 ({preview07}) resolved to: {resolved07}");
            this.Output.WriteLine($"  Actual version: {version07Info}");
            this.Output.WriteLine($"Preview08 ({preview08}) resolved to: {resolved08}");
            this.Output.WriteLine($"  Actual version: {version08Info}");

            version07Info.Should().NotBe(version08Info, 
                because: $"preview07 and preview08 must be different versions. Got preview07={version07Info}, preview08={version08Info}");

            this.Output.WriteLine("✅ Confirmed: preview07 and preview08 are distinct versions");
        }

        [Fact]
        public void AssemblyBinaryValidation_AllVersionsShouldBePhysicallyDistinct()
        {
            // Arrange
            var versions = VersionMatrix.GetTestVersions();

            if (versions.Length < 2)
            {
                this.Output.WriteLine("⚠️  Only one version in matrix, skipping binary distinctness validation");
                return;
            }

            var binaryInfo = new Dictionary<string, AssemblyBinaryInfo>();

            this.Output.WriteLine("========================================");
            this.Output.WriteLine("🔍 Binary Validation - Deep Dive");
            this.Output.WriteLine("========================================");
            this.Output.WriteLine("");

            // Act - Load each version and extract comprehensive binary information
            foreach (var packageVersion in versions)
            {
                var resolvedVersion = VersionMatrix.ResolveVersion(packageVersion);
                using (var loader = VersionLoader.Load(resolvedVersion))
                {
                    var assembly = loader.Assembly;
                    var assemblyPath = loader.AssemblyPath;

                    // Get file hash (SHA256)
                    string fileHash;
                    long fileSize;
                    using (var stream = File.OpenRead(assemblyPath))
                    {
                        using (var sha256 = SHA256.Create())
                        {
                            byte[] hashBytes = sha256.ComputeHash(stream);
                            fileHash = BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
                        }
                        fileSize = stream.Length;
                    }

                    // Get version information
                    var assemblyName = assembly.GetName();
                    var assemblyVersion = assemblyName.Version?.ToString() ?? "unknown";
                    var publicKeyToken = assemblyName.GetPublicKeyToken();
                    var publicKeyTokenString = publicKeyToken != null && publicKeyToken.Length > 0
                        ? BitConverter.ToString(publicKeyToken).Replace("-", "").ToLowerInvariant()
                        : "none";

                    var infoVersionAttr = assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
                        .OfType<System.Reflection.AssemblyInformationalVersionAttribute>()
                        .FirstOrDefault();
                    var informationalVersion = infoVersionAttr?.InformationalVersion ?? assemblyVersion;

                    var fileVersionAttr = assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyFileVersionAttribute), false)
                        .OfType<System.Reflection.AssemblyFileVersionAttribute>()
                        .FirstOrDefault();
                    var fileVersion = fileVersionAttr?.Version ?? assemblyVersion;

                    var info = new AssemblyBinaryInfo
                    {
                        PackageVersion = packageVersion,
                        ResolvedVersion = resolvedVersion,
                        AssemblyPath = assemblyPath,
                        FileHash = fileHash,
                        FileSize = fileSize,
                        AssemblyVersion = assemblyVersion,
                        FileVersion = fileVersion,
                        InformationalVersion = informationalVersion,
                        PublicKeyToken = publicKeyTokenString
                    };

                    binaryInfo[packageVersion] = info;

                    // Output detailed information
                    this.Output.WriteLine($"📦 Package: {packageVersion}");
                    this.Output.WriteLine($"   Resolved: {resolvedVersion}");
                    this.Output.WriteLine($"   Path: {assemblyPath}");
                    this.Output.WriteLine($"   File Size: {fileSize:N0} bytes");
                    this.Output.WriteLine($"   SHA256: {fileHash.Substring(0, 16)}...{fileHash.Substring(fileHash.Length - 16)}");
                    this.Output.WriteLine($"   Assembly Version: {assemblyVersion}");
                    this.Output.WriteLine($"   File Version: {fileVersion}");
                    this.Output.WriteLine($"   Informational Version: {informationalVersion}");
                    this.Output.WriteLine($"   Public Key Token: {publicKeyTokenString}");
                    this.Output.WriteLine("");
                }
            }

            // Assert - Verify all binaries are distinct
            this.Output.WriteLine("========================================");
            this.Output.WriteLine("🔬 Binary Comparison Matrix");
            this.Output.WriteLine("========================================");
            this.Output.WriteLine("");

            // Check file hashes are unique (most reliable indicator)
            var hashGroups = binaryInfo.GroupBy(x => x.Value.FileHash).ToList();
            this.Output.WriteLine($"Unique binary hashes: {hashGroups.Count} / {binaryInfo.Count}");
            
            foreach (var group in hashGroups)
            {
                var versionsWithSameHash = group.Select(x => x.Key).ToList();
                if (versionsWithSameHash.Count > 1)
                {
                    this.Output.WriteLine($"❌ WARNING: Multiple versions share the same binary hash:");
                    this.Output.WriteLine($"   Hash: {group.Key}");
                    this.Output.WriteLine($"   Versions: {string.Join(", ", versionsWithSameHash)}");
                }
            }

            hashGroups.Count.Should().Be(binaryInfo.Count,
                because: "each version should have a unique binary (different SHA256 hash)");

            // Check assembly paths are different
            var pathGroups = binaryInfo.GroupBy(x => x.Value.AssemblyPath).ToList();
            pathGroups.Count.Should().Be(binaryInfo.Count,
                because: "each version should be loaded from a different path");

            // Check file sizes (they should likely be different, but not guaranteed)
            var sizeGroups = binaryInfo.GroupBy(x => x.Value.FileSize).ToList();
            this.Output.WriteLine($"Unique file sizes: {sizeGroups.Count} / {binaryInfo.Count}");

            // Verify public key tokens are consistent (if signed)
            var tokens = binaryInfo.Select(x => x.Value.PublicKeyToken).Distinct().ToList();
            if (tokens.Count == 1 && tokens[0] != "none")
            {
                this.Output.WriteLine($"✅ All assemblies signed with same key: {tokens[0]}");
            }
            else if (tokens.All(t => t == "none"))
            {
                this.Output.WriteLine("ℹ️  Assemblies are not strongly named");
            }
            else
            {
                this.Output.WriteLine($"⚠️  Mixed signing: {string.Join(", ", tokens)}");
            }

            // Summary
            this.Output.WriteLine("");
            this.Output.WriteLine("========================================");
            this.Output.WriteLine("✅ Binary Validation Results");
            this.Output.WriteLine("========================================");
            this.Output.WriteLine($"Total versions tested: {binaryInfo.Count}");
            this.Output.WriteLine($"Unique binary hashes: {hashGroups.Count} ✓");
            this.Output.WriteLine($"Unique assembly paths: {pathGroups.Count} ✓");
            this.Output.WriteLine($"Unique file sizes: {sizeGroups.Count}");
            this.Output.WriteLine("");
            this.Output.WriteLine("🎯 Conclusion: All versions are physically distinct binaries");
            this.Output.WriteLine("========================================");
        }

        private class AssemblyBinaryInfo
        {
            public string PackageVersion { get; set; }
            public string ResolvedVersion { get; set; }
            public string AssemblyPath { get; set; }
            public string FileHash { get; set; }
            public long FileSize { get; set; }
            public string AssemblyVersion { get; set; }
            public string FileVersion { get; set; }
            public string InformationalVersion { get; set; }
            public string PublicKeyToken { get; set; }
        }
    }
}
