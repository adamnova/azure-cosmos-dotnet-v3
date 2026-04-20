using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;

namespace Microsoft.Azure.Cosmos.Encryption.Custom.CompatibilityTests.SideBySide
{
    /// <summary>
    /// Loads a specific version of the Encryption.Custom library from NuGet packages cache.
    /// Enables cross-version testing by loading different versions side-by-side.
    /// </summary>
    public sealed class VersionLoader : IDisposable
    {
        private readonly IsolatedLoadContext loadContext;

        public Assembly Assembly { get; }
        public string Version { get; }
        public string AssemblyPath { get; }

        private VersionLoader(string version, Assembly assembly, IsolatedLoadContext context, string assemblyPath)
        {
            this.Version = version;
            this.Assembly = assembly;
            this.loadContext = context;
            this.AssemblyPath = assemblyPath;
        }

        /// <summary>
        /// Loads a specific version from the NuGet packages cache.
        /// </summary>
        public static VersionLoader Load(string version)
        {
            if (string.IsNullOrWhiteSpace(version))
            {
                throw new ArgumentException("Version cannot be null or empty", nameof(version));
            }

            string packagePath = GetPackagePath(version);
            if (!Directory.Exists(packagePath))
            {
                throw new InvalidOperationException(
                    $"Package version {version} not found at {packagePath}. " +
                    "Ensure the package is restored before running tests.");
            }

            // Find the assembly DLL (prefer netstandard2.0)
            string assemblyPath = FindAssemblyPath(packagePath);
            if (!File.Exists(assemblyPath))
            {
                throw new InvalidOperationException(
                    $"Assembly not found for version {version} at {assemblyPath}");
            }

            // Load in isolated context
            IsolatedLoadContext context = new IsolatedLoadContext(assemblyPath, $"CompatTest-{version}");
            Assembly assembly = context.LoadFromAssemblyPath(assemblyPath);

            return new VersionLoader(version, assembly, context, assemblyPath);
        }

        /// <summary>
        /// Gets a type from the loaded assembly by full name.
        /// </summary>
        public Type GetType(string fullTypeName)
        {
            if (string.IsNullOrWhiteSpace(fullTypeName))
            {
                throw new ArgumentException("Type name cannot be null or empty", nameof(fullTypeName));
            }

            var type = this.Assembly.GetType(fullTypeName);
            if (type == null)
            {
                // Try to find it in exported types
                type = this.Assembly.GetExportedTypes()
                    .FirstOrDefault(t => t.FullName == fullTypeName);
            }

            return type;
        }

        private static string GetPackagePath(string version)
        {
            Console.WriteLine($"[VersionLoader] Looking for version {version}");
            Console.WriteLine($"[VersionLoader] AppContext.BaseDirectory = {AppContext.BaseDirectory}");
            
            // First, always check local packages folder (for CI-built or locally-built packages)
            // Dynamically find repository root by crawling up looking for .git or .sln file
            string repoRoot = FindRepositoryRoot(AppContext.BaseDirectory);
            
            if (repoRoot != null)
            {
                string localPackagesPath = Path.Combine(repoRoot, "artifacts", "local-packages");
                Console.WriteLine($"[VersionLoader] Found repository root: {repoRoot}");
                Console.WriteLine($"[VersionLoader] Checking local path: {localPackagesPath}");
                Console.WriteLine($"[VersionLoader] Local path exists: {Directory.Exists(localPackagesPath)}");
                
                if (Directory.Exists(localPackagesPath))
                {
                    Console.WriteLine($"[VersionLoader] Local packages folder contents:");
                    foreach (string file in Directory.GetFiles(localPackagesPath, "*.nupkg"))
                    {
                        Console.WriteLine($"[VersionLoader]   - {Path.GetFileName(file)}");
                    }
                    
                    // Look for exact version match in local packages
                    string[] packageFiles = Directory.GetFiles(localPackagesPath, $"Microsoft.Azure.Cosmos.Encryption.Custom.{version}.nupkg")
                        .Where(f => !f.EndsWith(".symbols.nupkg"))
                        .ToArray();

                    if (packageFiles.Length > 0)
                    {
                        Console.WriteLine($"[VersionLoader] Found package in local folder: {packageFiles[0]}");
                        // Extract the package to a temp location for loading
                        string packageFile = packageFiles[0];
                        string extractPath = Path.Combine(Path.GetTempPath(), "cosmos-compat-tests", Path.GetFileNameWithoutExtension(packageFile));
                        
                        if (!Directory.Exists(extractPath) || !File.Exists(Path.Combine(extractPath, "lib", "netstandard2.0", "Microsoft.Azure.Cosmos.Encryption.Custom.dll")))
                        {
                            Directory.CreateDirectory(extractPath);
                            System.IO.Compression.ZipFile.ExtractToDirectory(packageFile, extractPath, overwriteFiles: true);
                        }

                        return extractPath;
                    }
                    else
                    {
                        Console.WriteLine($"[VersionLoader] Package not found in local folder");
                    }
                }
            }
            else
            {
                Console.WriteLine($"[VersionLoader] Repository root not found, skipping local packages check");
            }

            // Fallback: use global NuGet packages folder
            Console.WriteLine($"[VersionLoader] Falling back to global NuGet cache");
            string globalPackagesPath = Environment.GetEnvironmentVariable("NUGET_PACKAGES");
            
            if (string.IsNullOrWhiteSpace(globalPackagesPath))
            {
                string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                globalPackagesPath = Path.Combine(userProfile, ".nuget", "packages");
            }
            
            Console.WriteLine($"[VersionLoader] Global NuGet path: {globalPackagesPath}");

            return Path.Combine(
                globalPackagesPath,
                "microsoft.azure.cosmos.encryption.custom",
                version.ToLowerInvariant());
        }

        /// <summary>
        /// Crawls up the directory tree to find the repository root.
        /// Looks for .git directory or .sln files as markers.
        /// </summary>
        private static string FindRepositoryRoot(string startPath)
        {
            DirectoryInfo current = new DirectoryInfo(startPath);
            
            while (current != null)
            {
                // Check for .git directory (most reliable indicator)
                if (Directory.Exists(Path.Combine(current.FullName, ".git")))
                {
                    return current.FullName;
                }
                
                // Check for .sln files (backup indicator)
                if (current.GetFiles("*.sln").Length > 0)
                {
                    return current.FullName;
                }
                
                // Move up one level
                current = current.Parent;
            }
            
            return null; // Repository root not found
        }

        private static string FindAssemblyPath(string packagePath)
        {
            // Prefer netstandard2.0
            string libPath = Path.Combine(packagePath, "lib", "netstandard2.0", "Microsoft.Azure.Cosmos.Encryption.Custom.dll");
            if (File.Exists(libPath))
            {
                return libPath;
            }

            // Fallback: search all lib folders
            string libDir = Path.Combine(packagePath, "lib");
            if (Directory.Exists(libDir))
            {
                string dllPath = Directory.GetFiles(libDir, "Microsoft.Azure.Cosmos.Encryption.Custom.dll", SearchOption.AllDirectories)
                    .FirstOrDefault();
                if (dllPath != null)
                {
                    return dllPath;
                }
            }

            throw new FileNotFoundException(
                $"Could not find Microsoft.Azure.Cosmos.Encryption.Custom.dll in package at {packagePath}");
        }

        public void Dispose()
        {
            this.loadContext?.Unload();
        }
    }
}
