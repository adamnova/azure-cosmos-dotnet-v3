//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

#if NET8_0_OR_GREATER
namespace Microsoft.Azure.Cosmos.Encryption.Custom.EmulatorTests
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.Linq;
    using System.Net.Http;
    using System.Security.Cryptography;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;

    internal sealed class CompatibilityMatrixRecord
    {
        public string Kind { get; set; }

        public string Role { get; set; }

        public string ScenarioId { get; set; }

        public string Status { get; set; }

        public string Detail { get; set; }

        public string PackageVersion { get; set; }

        public string InformationalVersion { get; set; }

        public string ProductVersion { get; set; }

        public string AssemblyVersion { get; set; }

        public string AssemblyMvid { get; set; }

        public string AssemblySha256 { get; set; }

        public string AssemblyPath { get; set; }

        public string CosmosVersion { get; set; }

        public string MdeVersion { get; set; }

        public string RequestedProcessor { get; set; }

        public string ActualProcessor { get; set; }

        public IReadOnlyList<string> ObservedScopes { get; set; }

        public string ProviderConstruction { get; set; }

        public string EncryptorKind { get; set; }

        public string DocumentId { get; set; }

        public string FixtureSha256 { get; set; }

        public string InputFixtureSha256 { get; set; }

        public string PlaintextSha256 { get; set; }

        public string RawShape { get; set; }
    }

    internal static class CompatibilityMatrixProtocol
    {
        public static CompatibilityMatrixRecord ParseRecord(string line)
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                throw new InvalidOperationException("Compatibility worker emitted an empty record.");
            }

            CompatibilityMatrixRecord record;
            try
            {
                record = JsonConvert.DeserializeObject<CompatibilityMatrixRecord>(line);
            }
            catch (JsonException exception)
            {
                throw new InvalidOperationException($"Compatibility worker emitted malformed JSON: {line}", exception);
            }

            if (record == null || string.IsNullOrWhiteSpace(record.Kind))
            {
                throw new InvalidOperationException($"Compatibility worker emitted an invalid record: {line}");
            }

            return record;
        }
    }

    internal static class CompatibilityMatrixEndpoint
    {
        private const int EmulatorHttpsPort = 8081;

        public static Uri Validate(string endpoint)
        {
            if (!Uri.TryCreate(endpoint, UriKind.Absolute, out Uri uri) ||
                !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
                !uri.IsLoopback ||
                uri.Port != EmulatorHttpsPort ||
                !string.IsNullOrEmpty(uri.UserInfo))
            {
                throw new InvalidOperationException(
                    "The compatibility matrix only accepts an HTTPS loopback Cosmos emulator endpoint on port 8081.");
            }

            return uri;
        }

        public static HttpClientHandler CreateHttpClientHandler(Uri emulatorEndpoint)
        {
            ArgumentNullException.ThrowIfNull(emulatorEndpoint);
            Validate(emulatorEndpoint.AbsoluteUri);

            return new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (request, _, _, _) =>
                    request?.RequestUri != null &&
                    request.RequestUri.IsLoopback &&
                    string.Equals(
                        request.RequestUri.Scheme,
                        Uri.UriSchemeHttps,
                        StringComparison.OrdinalIgnoreCase) &&
                    request.RequestUri.Port == EmulatorHttpsPort &&
                    string.Equals(
                        request.RequestUri.Host,
                        emulatorEndpoint.Host,
                        StringComparison.OrdinalIgnoreCase),
            };
        }
    }

    internal static class CompatibilityMatrixWorkerProcess
    {
        internal const string AccountKeyEnvironmentVariable = "COSMOS_COMPAT_MATRIX_KEY";

        public static ProcessStartInfo CreateStartInfo(
            string workerPath,
            string accountKey,
            IEnumerable<string> arguments)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(workerPath);
            ArgumentNullException.ThrowIfNull(arguments);

            string[] argumentArray = arguments.ToArray();
            if (argumentArray.Any(argument =>
                argument.StartsWith("--key=", StringComparison.OrdinalIgnoreCase)))
            {
                throw new InvalidOperationException("Compatibility worker secrets must not be passed on the command line.");
            }

            ProcessStartInfo startInfo = new()
            {
                FileName = "dotnet",
                WorkingDirectory = Path.GetDirectoryName(workerPath),
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            startInfo.ArgumentList.Add(workerPath);
            foreach (string argument in argumentArray)
            {
                startInfo.ArgumentList.Add(argument);
            }

            if (!string.IsNullOrWhiteSpace(accountKey))
            {
                startInfo.Environment[AccountKeyEnvironmentVariable] = accountKey;
            }
            else
            {
                startInfo.Environment.Remove(AccountKeyEnvironmentVariable);
            }

            return startInfo;
        }
    }

    internal static class CompatibilityMatrixResultOracle
    {
        public static void Validate(
            IReadOnlyCollection<string> expectedScenarioIds,
            IReadOnlyCollection<CompatibilityMatrixRecord> actualRecords)
        {
            ArgumentNullException.ThrowIfNull(expectedScenarioIds);
            ArgumentNullException.ThrowIfNull(actualRecords);

            HashSet<string> expected = new(expectedScenarioIds, StringComparer.Ordinal);
            if (expected.Count != expectedScenarioIds.Count)
            {
                throw new InvalidOperationException("The expected compatibility scenario set contains duplicates.");
            }

            Dictionary<string, CompatibilityMatrixRecord> actual = new(StringComparer.Ordinal);
            foreach (CompatibilityMatrixRecord record in actualRecords)
            {
                if (record == null ||
                    !string.Equals(record.Kind, "observation", StringComparison.Ordinal) ||
                    string.IsNullOrWhiteSpace(record.ScenarioId))
                {
                    throw new InvalidOperationException("The compatibility result set contains an invalid observation.");
                }

                if (!actual.TryAdd(record.ScenarioId, record))
                {
                    throw new InvalidOperationException($"Duplicate compatibility scenario: {record.ScenarioId}");
                }

                if (string.Equals(record.Status, "pass", StringComparison.Ordinal) &&
                    (string.IsNullOrWhiteSpace(record.RequestedProcessor) ||
                     string.IsNullOrWhiteSpace(record.ActualProcessor) ||
                     string.IsNullOrWhiteSpace(record.ProviderConstruction) ||
                     string.IsNullOrWhiteSpace(record.EncryptorKind)))
                {
                    throw new InvalidOperationException(
                        $"Passing compatibility scenario did not report processor, provider, and encryptor evidence: {record.ScenarioId}");
                }

                if (string.Equals(record.Status, "pass", StringComparison.Ordinal))
                {
                    if (string.IsNullOrWhiteSpace(record.DocumentId) ||
                        string.IsNullOrWhiteSpace(record.FixtureSha256) ||
                        string.IsNullOrWhiteSpace(record.PlaintextSha256) ||
                        string.IsNullOrWhiteSpace(record.RawShape))
                    {
                        throw new InvalidOperationException(
                            $"Passing compatibility scenario did not report fixture and raw-shape evidence: {record.ScenarioId}");
                    }

                    if (record.ScenarioId.StartsWith("rewrite:", StringComparison.Ordinal) &&
                        string.IsNullOrWhiteSpace(record.InputFixtureSha256))
                    {
                        throw new InvalidOperationException(
                            $"Rewrite scenario did not report its hash-pinned input fixture: {record.ScenarioId}");
                    }

                    RequireSha256(record.FixtureSha256, "fixture", record.ScenarioId);
                    RequireSha256(record.PlaintextSha256, "plaintext", record.ScenarioId);
                    if (!string.IsNullOrWhiteSpace(record.InputFixtureSha256))
                    {
                        RequireSha256(record.InputFixtureSha256, "input fixture", record.ScenarioId);
                    }

                    ValidateScenarioEvidence(record);
                }
            }

            string[] missing = expected.Except(actual.Keys, StringComparer.Ordinal).OrderBy(id => id, StringComparer.Ordinal).ToArray();
            string[] unexpected = actual.Keys.Except(expected, StringComparer.Ordinal).OrderBy(id => id, StringComparer.Ordinal).ToArray();
            if (missing.Length != 0 || unexpected.Length != 0)
            {
                throw new InvalidOperationException(
                    $"Compatibility scenario mismatch. Missing=[{string.Join(", ", missing)}] Unexpected=[{string.Join(", ", unexpected)}]");
            }

            CompatibilityMatrixRecord[] failures = actual.Values
                .Where(record => !string.Equals(record.Status, "pass", StringComparison.Ordinal))
                .OrderBy(record => record.ScenarioId, StringComparer.Ordinal)
                .ToArray();
            if (failures.Length != 0)
            {
                throw new InvalidOperationException(
                    "Compatibility failures: " +
                    string.Join(
                        "; ",
                        failures.Select(record => $"{record.ScenarioId}: {record.Detail ?? record.Status}")));
            }

            ValidateRewriteSets(expected, actual);
        }

        private static void ValidateScenarioEvidence(CompatibilityMatrixRecord record)
        {
            bool mde =
                record.ScenarioId.Contains(":MDE:", StringComparison.Ordinal) ||
                record.ScenarioId.StartsWith("reread:", StringComparison.Ordinal);
            if (mde &&
                (!record.RawShape.Contains("_ef:Integer", StringComparison.Ordinal) ||
                 !record.RawShape.Contains("_ea:String", StringComparison.Ordinal) ||
                 !record.RawShape.Contains("_en:String", StringComparison.Ordinal) ||
                 !record.RawShape.Contains("_ed:Null", StringComparison.Ordinal) ||
                 !record.RawShape.Contains("_ep:Array", StringComparison.Ordinal)))
            {
                throw new InvalidOperationException(
                    $"MDE scenario did not report the exact v3 metadata shape: {record.ScenarioId}");
            }

            if (string.Equals(record.Role, "released", StringComparison.Ordinal))
            {
                RequireEvidence(
                    record,
                    "released-dual-provider-constructor",
                    "external-preview07-surface");
                return;
            }

            if (!string.Equals(record.Role, "current", StringComparison.Ordinal))
            {
                return;
            }

            bool streamRequested =
                record.ScenarioId.EndsWith(":Stream", StringComparison.Ordinal) ||
                record.ScenarioId.StartsWith(
                    "boundary:current:MDE:Stream:",
                    StringComparison.Ordinal) ||
                record.ScenarioId.Contains("->StreamRequested:", StringComparison.Ordinal);
            if (mde && streamRequested)
            {
                RequireEvidence(
                    record,
                    "factory-store-provider-cache-options",
                    "built-in-cosmos-encryptor");
                if (!string.Equals(record.ActualProcessor, "Stream", StringComparison.Ordinal) &&
                    !string.Equals(
                        record.ActualProcessor,
                        "typed=Stream,stream=Stream",
                        StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        $"MDE Stream request did not prove Stream execution: {record.ScenarioId}");
                }

                return;
            }

            if (mde)
            {
                RequireEvidence(
                    record,
                    "constructor-store-provider-timespan",
                    "external-preview07-surface");
                return;
            }

            RequireEvidence(
                record,
                "factory-dual-provider-cache-options",
                "external-preview07-surface");
            if (record.ScenarioId.StartsWith(
                    "read:released->current:AEAD:Newtonsoft->StreamRequested:",
                    StringComparison.Ordinal) &&
                !string.Equals(
                    record.ActualProcessor,
                    "typed=NewtonsoftLegacyFallback,stream=NewtonsoftLegacyFallback",
                    StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"Legacy Stream request did not report directly observed Newtonsoft fallback: {record.ScenarioId}");
            }
        }

        private static void ValidateRewriteSets(
            IReadOnlyCollection<string> expected,
            IReadOnlyDictionary<string, CompatibilityMatrixRecord> actual)
        {
            foreach (string rewriteProcessor in new[] { "Newtonsoft", "Stream" })
            {
                IReadOnlyCollection<string> rewriteScenarios =
                    CompatibilityMatrixScenarios.GetRewriteScenarios(rewriteProcessor);
                if (!expected.Any(rewriteScenarios.Contains))
                {
                    continue;
                }

                string[] missing = rewriteScenarios
                    .Where(scenarioId => !actual.ContainsKey(scenarioId))
                    .ToArray();
                if (missing.Length != 0)
                {
                    throw new InvalidOperationException(
                        $"Rewrite evidence set was incomplete. Missing=[{string.Join(", ", missing)}]");
                }

                CompatibilityMatrixRecord rewrite =
                    actual[$"rewrite:released->current:MDE:{rewriteProcessor}"];
                if (string.Equals(
                        rewrite.InputFixtureSha256,
                        rewrite.FixtureSha256,
                        StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException(
                        $"Rewrite did not change ciphertext: {rewrite.ScenarioId}");
                }

                if (!string.Equals(
                        rewrite.RequestedProcessor,
                        rewriteProcessor,
                        StringComparison.Ordinal) ||
                    !string.Equals(
                        rewrite.ActualProcessor,
                        rewriteProcessor,
                        StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        $"Rewrite silently substituted its requested processor: {rewrite.ScenarioId}");
                }

                foreach (string scenarioId in rewriteScenarios.Where(
                    scenarioId => scenarioId.StartsWith("reread:", StringComparison.Ordinal)))
                {
                    CompatibilityMatrixRecord reread = actual[scenarioId];
                    if (!string.Equals(
                            reread.FixtureSha256,
                            rewrite.FixtureSha256,
                            StringComparison.OrdinalIgnoreCase) ||
                        !string.Equals(
                            reread.PlaintextSha256,
                            rewrite.PlaintextSha256,
                            StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidOperationException(
                            $"Rewrite reread did not preserve the output fixture and plaintext hashes: {scenarioId}");
                    }
                }

                RequirePointProcessor(
                    actual[$"reread:released->current:rewrite:{rewriteProcessor}->Newtonsoft:point"],
                    "Newtonsoft");
                RequirePointProcessor(
                    actual[$"reread:released->current:rewrite:{rewriteProcessor}->StreamRequested:point"],
                    "Stream");
            }
        }

        private static void RequirePointProcessor(
            CompatibilityMatrixRecord record,
            string expectedProcessor)
        {
            string expected = $"typed={expectedProcessor},stream={expectedProcessor}";
            if (!string.Equals(record.ActualProcessor, expected, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"Point reread silently substituted processor {expectedProcessor}: {record.ScenarioId}");
            }
        }

        private static void RequireSha256(string value, string description, string scenarioId)
        {
            if (value.Length != 64 || value.Any(character => !Uri.IsHexDigit(character)))
            {
                throw new InvalidOperationException(
                    $"Compatibility scenario reported an invalid {description} SHA-256: {scenarioId}");
            }
        }

        private static void RequireEvidence(
            CompatibilityMatrixRecord record,
            string providerConstruction,
            string encryptorKind)
        {
            if (!string.Equals(
                    record.ProviderConstruction,
                    providerConstruction,
                    StringComparison.Ordinal) ||
                !string.Equals(record.EncryptorKind, encryptorKind, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"Compatibility scenario reported unexpected provider/encryptor evidence: {record.ScenarioId}");
            }
        }
    }

    internal static class CompatibilityMatrixIdentityValidator
    {
        private const string ReleasedVersion = "1.0.0-preview07";

        public static void Validate(
            CompatibilityMatrixRecord released,
            CompatibilityMatrixRecord current,
            CompatibilityMatrixPackageProvenance releasedProvenance,
            CompatibilityMatrixPackageProvenance currentProvenance)
        {
            ValidateIdentity(released, "released");
            ValidateIdentity(current, "current");
            ArgumentNullException.ThrowIfNull(releasedProvenance);
            ArgumentNullException.ThrowIfNull(currentProvenance);

            if (!string.Equals(released.PackageVersion, ReleasedVersion, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"Released worker loaded {released.PackageVersion}, expected {ReleasedVersion}.");
            }

            if (string.Equals(released.AssemblySha256, current.AssemblySha256, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(released.AssemblyMvid, current.AssemblyMvid, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("Released and current workers loaded the same Encryption.Custom binary.");
            }

            ValidatePackageIdentity(released, releasedProvenance, "released");
            ValidatePackageIdentity(current, currentProvenance, "current");

            if (!string.IsNullOrWhiteSpace(currentProvenance.SourceCommit) &&
                !string.Equals(currentProvenance.SourceCommit, "UNSPECIFIED", StringComparison.Ordinal) &&
                (string.IsNullOrWhiteSpace(current.InformationalVersion) ||
                 !current.InformationalVersion.Contains(
                     currentProvenance.SourceCommit,
                     StringComparison.OrdinalIgnoreCase)))
            {
                throw new InvalidOperationException(
                    "Current worker informational version does not contain the configured aggregate source commit.");
            }
        }

        private static void ValidatePackageIdentity(
            CompatibilityMatrixRecord identity,
            CompatibilityMatrixPackageProvenance provenance,
            string expectedRole)
        {
            if (!string.Equals(provenance.Role, expectedRole, StringComparison.Ordinal) ||
                !string.Equals(
                    provenance.PackageId,
                    "Microsoft.Azure.Cosmos.Encryption.Custom",
                    StringComparison.Ordinal) ||
                !string.Equals(identity.PackageVersion, provenance.PackageVersion, StringComparison.Ordinal) ||
                !string.Equals(
                    identity.AssemblySha256,
                    provenance.PackageAssemblySha256,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"{expectedRole} worker identity did not match its sealed package provenance.");
            }

            if (string.IsNullOrWhiteSpace(provenance.NupkgSha256) ||
                provenance.NupkgSha256.Length != 64 ||
                provenance.NupkgSha256.Any(character => !Uri.IsHexDigit(character)))
            {
                throw new InvalidOperationException(
                    $"{expectedRole} worker provenance did not report a valid package archive SHA-256.");
            }

            if (!string.IsNullOrWhiteSpace(provenance.ActualSource) &&
                !string.Equals(
                    NormalizeSource(provenance.ExpectedSource),
                    NormalizeSource(provenance.ActualSource),
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"{expectedRole} worker provenance reported the wrong package source.");
            }

            if (string.Equals(expectedRole, "current", StringComparison.Ordinal) &&
                (!Path.IsPathFullyQualified(provenance.InputNupkgPath) ||
                 !string.Equals(
                     Path.GetDirectoryName(Path.GetFullPath(provenance.InputNupkgPath)),
                     Path.GetFullPath(provenance.ExpectedSource).TrimEnd(Path.DirectorySeparatorChar),
                     StringComparison.OrdinalIgnoreCase)))
            {
                throw new InvalidOperationException(
                    "Current worker provenance did not match the explicit candidate package path.");
            }

            if (!string.IsNullOrWhiteSpace(provenance.WorkerPath))
            {
                string expectedAssemblyPath = Path.Combine(
                    Path.GetDirectoryName(provenance.WorkerPath),
                    "Microsoft.Azure.Cosmos.Encryption.Custom.dll");
                if (!string.Equals(
                        Path.GetFullPath(identity.AssemblyPath),
                        Path.GetFullPath(expectedAssemblyPath),
                        StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException(
                        $"{expectedRole} worker loaded Encryption.Custom outside its isolated output directory.");
                }
            }
        }

        private static string NormalizeSource(string source)
        {
            if (string.IsNullOrWhiteSpace(source))
            {
                return source;
            }

            return Path.IsPathFullyQualified(source)
                ? Path.GetFullPath(source).TrimEnd(Path.DirectorySeparatorChar)
                : source.TrimEnd('/');
        }

        private static void ValidateIdentity(CompatibilityMatrixRecord record, string expectedRole)
        {
            if (record == null ||
                !string.Equals(record.Kind, "identity", StringComparison.Ordinal) ||
                !string.Equals(record.Role, expectedRole, StringComparison.Ordinal) ||
                string.IsNullOrWhiteSpace(record.PackageVersion) ||
                string.IsNullOrWhiteSpace(record.InformationalVersion) ||
                string.IsNullOrWhiteSpace(record.ProductVersion) ||
                string.IsNullOrWhiteSpace(record.AssemblyVersion) ||
                string.IsNullOrWhiteSpace(record.AssemblyMvid) ||
                string.IsNullOrWhiteSpace(record.AssemblySha256) ||
                string.IsNullOrWhiteSpace(record.AssemblyPath))
            {
                throw new InvalidOperationException($"Invalid {expectedRole} worker identity.");
            }
        }
    }

    internal sealed class CompatibilityMatrixPackageProvenance
        {
            private const string PackageIdValue = "Microsoft.Azure.Cosmos.Encryption.Custom";

            public string Role { get; internal set; }

            public string PackageId { get; internal set; }

            public string PackageVersion { get; internal set; }

            public string ExpectedSource { get; internal set; }

            public string ActualSource { get; internal set; }

            public string InputNupkgPath { get; internal set; }

            public string PackageRoot { get; internal set; }

            public string NupkgPath { get; internal set; }

            public string NupkgSha256 { get; internal set; }

            public string PackageAssemblySha256 { get; internal set; }

            public string SourceCommit { get; internal set; }

            public string WorkerPath { get; internal set; }

            public static CompatibilityMatrixPackageProvenance Load(
                string workerPath,
                string expectedRole)
            {
                ArgumentException.ThrowIfNullOrWhiteSpace(workerPath);
                string provenancePath = Path.Combine(
                    Path.GetDirectoryName(workerPath),
                    Path.GetFileNameWithoutExtension(workerPath) + ".package-provenance.txt");
                if (!File.Exists(provenancePath))
                {
                    throw new InvalidOperationException(
                        $"Compatibility worker package provenance was not found: {provenancePath}");
                }

                Dictionary<string, string> values = ParseLines(File.ReadAllLines(provenancePath));
                CompatibilityMatrixPackageProvenance provenance = new()
                {
                    WorkerPath = Path.GetFullPath(workerPath),
                    Role = GetRequired(values, "role"),
                    PackageId = GetRequired(values, "package-id"),
                    PackageVersion = GetRequired(values, "package-version"),
                    ExpectedSource = GetRequired(values, "expected-source"),
                    InputNupkgPath = values.GetValueOrDefault("input-nupkg-path"),
                    PackageRoot = Path.GetFullPath(GetRequired(values, "package-root")),
                    NupkgPath = Path.GetFullPath(GetRequired(values, "nupkg-path")),
                    NupkgSha256 = GetRequired(values, "nupkg-sha256"),
                    SourceCommit = GetRequired(values, "source-commit"),
                };

                if (!string.Equals(provenance.Role, expectedRole, StringComparison.Ordinal) ||
                    !string.Equals(provenance.PackageId, PackageIdValue, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        $"Invalid {expectedRole} compatibility worker package provenance.");
                }

                string isolatedPackagesSegment =
                    $"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}compat-packages{Path.DirectorySeparatorChar}";
                if (!provenance.PackageRoot.Contains(
                        isolatedPackagesSegment,
                        StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException(
                        $"{expectedRole} worker did not restore from its isolated package directory.");
                }

                if (!File.Exists(provenance.NupkgPath) ||
                    !IsWithinDirectory(provenance.NupkgPath, provenance.PackageRoot))
                {
                    throw new InvalidOperationException(
                        $"{expectedRole} worker package archive is missing or outside its package root.");
                }

                string actualNupkgSha256 = HashFile(provenance.NupkgPath);
                if (!string.Equals(
                        actualNupkgSha256,
                        provenance.NupkgSha256,
                        StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException(
                        $"{expectedRole} worker package archive hash did not match its build-time provenance.");
                }

                string metadataPath = Path.Combine(provenance.PackageRoot, ".nupkg.metadata");
                JObject metadata = File.Exists(metadataPath)
                    ? JObject.Parse(File.ReadAllText(metadataPath))
                    : throw new InvalidOperationException(
                        $"{expectedRole} worker package metadata was not found: {metadataPath}");
                provenance.ActualSource = metadata.Value<string>("source");
                if (!SourcesEqual(provenance.ExpectedSource, provenance.ActualSource))
                {
                    throw new InvalidOperationException(
                        $"{expectedRole} worker restored Encryption.Custom from '{provenance.ActualSource}', expected '{provenance.ExpectedSource}'.");
                }

                if (string.Equals(expectedRole, "current", StringComparison.Ordinal) &&
                    !Path.IsPathFullyQualified(provenance.ActualSource))
                {
                    throw new InvalidOperationException(
                        "The current compatibility worker must restore Encryption.Custom from a sealed local feed.");
                }

                if (string.Equals(expectedRole, "current", StringComparison.Ordinal))
                {
                    if (string.IsNullOrWhiteSpace(provenance.InputNupkgPath) ||
                        !Path.IsPathFullyQualified(provenance.InputNupkgPath))
                    {
                        throw new InvalidOperationException(
                            "The current compatibility worker provenance must identify the explicit candidate archive.");
                    }

                    provenance.InputNupkgPath = Path.GetFullPath(provenance.InputNupkgPath);
                    if (!File.Exists(provenance.InputNupkgPath) ||
                        !string.Equals(
                            Path.GetDirectoryName(provenance.InputNupkgPath),
                            Path.GetFullPath(provenance.ExpectedSource).TrimEnd(Path.DirectorySeparatorChar),
                            StringComparison.OrdinalIgnoreCase) ||
                        !string.Equals(
                            HashFile(provenance.InputNupkgPath),
                            provenance.NupkgSha256,
                            StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidOperationException(
                            "The restored current package did not match the explicit candidate archive identity.");
                    }
                }

                if (string.Equals(expectedRole, "current", StringComparison.Ordinal) &&
                    (provenance.SourceCommit.Length != 40 ||
                     provenance.SourceCommit.Any(character => !Uri.IsHexDigit(character))))
                {
                    throw new InvalidOperationException(
                        "The current compatibility worker source commit must be a full 40-character Git SHA.");
                }

                provenance.PackageAssemblySha256 = HashFile(
                    ResolvePackageAssembly(workerPath, provenance));
                return provenance;
            }

            internal static Dictionary<string, string> ParseLines(IEnumerable<string> lines)
            {
                Dictionary<string, string> values = new(StringComparer.Ordinal);
                foreach (string line in lines.Where(line => !string.IsNullOrWhiteSpace(line)))
                {
                    int separator = line.IndexOf('=');
                    if (separator <= 0 ||
                        !values.TryAdd(line.Substring(0, separator), line[(separator + 1)..]))
                    {
                        throw new InvalidOperationException(
                            $"Invalid compatibility package provenance line: {line}");
                    }
                }

                return values;
            }

            private static string ResolvePackageAssembly(
                string workerPath,
                CompatibilityMatrixPackageProvenance provenance)
            {
                string depsPath = Path.ChangeExtension(workerPath, ".deps.json");
                JObject dependencies = JObject.Parse(File.ReadAllText(depsPath));
                JObject targets = dependencies["targets"] as JObject
                    ?? throw new InvalidOperationException(
                        $"Worker dependency graph has no targets section: {depsPath}");
                string libraryName = PackageIdValue + "/" + provenance.PackageVersion;
                JObject targetLibrary = targets.Properties()
                    .Select(property => property.Value[libraryName] as JObject)
                    .SingleOrDefault(library => library != null)
                    ?? throw new InvalidOperationException(
                        $"Worker dependency graph does not contain {libraryName}: {depsPath}");
                JObject runtime = targetLibrary["runtime"] as JObject
                    ?? throw new InvalidOperationException(
                        $"Worker dependency graph has no runtime asset for {libraryName}: {depsPath}");
                string runtimeAsset = runtime.Properties()
                    .Select(property => property.Name)
                    .SingleOrDefault(path => path.EndsWith(
                        "Microsoft.Azure.Cosmos.Encryption.Custom.dll",
                        StringComparison.OrdinalIgnoreCase))
                    ?? throw new InvalidOperationException(
                        $"Worker dependency graph has no Encryption.Custom assembly asset: {depsPath}");
                string assemblyPath = Path.GetFullPath(
                    Path.Combine(
                        provenance.PackageRoot,
                        runtimeAsset.Replace('/', Path.DirectorySeparatorChar)));
                if (!File.Exists(assemblyPath) ||
                    !IsWithinDirectory(assemblyPath, provenance.PackageRoot))
                {
                    throw new InvalidOperationException(
                        $"Worker package assembly was not found inside the package root: {assemblyPath}");
                }

                return assemblyPath;
            }

            private static string GetRequired(
                IReadOnlyDictionary<string, string> values,
                string name)
            {
                if (!values.TryGetValue(name, out string value) ||
                    string.IsNullOrWhiteSpace(value))
                {
                    throw new InvalidOperationException(
                        $"Compatibility package provenance omitted {name}.");
                }

                return value;
            }

            private static bool SourcesEqual(string expected, string actual)
            {
                if (Path.IsPathFullyQualified(expected) && Path.IsPathFullyQualified(actual))
                {
                    return string.Equals(
                        Path.GetFullPath(expected).TrimEnd(Path.DirectorySeparatorChar),
                        Path.GetFullPath(actual).TrimEnd(Path.DirectorySeparatorChar),
                        StringComparison.OrdinalIgnoreCase);
                }

                return string.Equals(
                    expected?.TrimEnd('/'),
                    actual?.TrimEnd('/'),
                    StringComparison.OrdinalIgnoreCase);
            }

            private static bool IsWithinDirectory(string path, string directory)
            {
                string normalizedDirectory =
                    Path.GetFullPath(directory).TrimEnd(Path.DirectorySeparatorChar) +
                    Path.DirectorySeparatorChar;
                return Path.GetFullPath(path).StartsWith(
                    normalizedDirectory,
                    StringComparison.OrdinalIgnoreCase);
            }

            private static string HashFile(string path)
            {
                return Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
            }
        }

    internal static class CompatibilityMatrixScenarios
        {
            public const int ExpectedObservationCount = 60;

            public static IReadOnlyCollection<string> GetWriteScenarios(string writer)
            {
                List<string> scenarios = new()
                {
                    $"write:{writer}:MDE:Newtonsoft",
                    $"write:{writer}:AEAD:Newtonsoft",
                };
                if (string.Equals(writer, "current", StringComparison.Ordinal))
                {
                    scenarios.Insert(1, "write:current:MDE:Stream");
                    scenarios.Add("boundary:current:MDE:Stream:nonzero-input");
                    scenarios.Add("boundary:current:MDE:Stream:readonly-response");
                    scenarios.Add("reject:current:AEAD:Stream:write");
                }
                else
                {
                    scenarios.Add("write:released:PLAINTEXT:None");
                }

                return scenarios;
            }

            public static IReadOnlyCollection<string> GetReadScenarios(
                string writer,
                string reader)
            {
                List<string> scenarios = new();
                IEnumerable<(string Family, string WriteProcessor, string ReadProcessor, string[] Paths)> combinations =
                    string.Equals(writer, "released", StringComparison.Ordinal) &&
                    string.Equals(reader, "current", StringComparison.Ordinal)
                        ? new[]
                        {
                            ("MDE", "Newtonsoft", "Newtonsoft", new[] { "point", "query", "feed", "readmany" }),
                            ("MDE", "Newtonsoft", "Stream", new[] { "point", "query", "feed", "readmany" }),
                            ("AEAD", "Newtonsoft", "Newtonsoft", new[] { "point", "query", "feed", "readmany" }),
                            ("AEAD", "Newtonsoft", "Stream", new[] { "point", "query", "feed", "readmany" }),
                            ("PLAINTEXT", "None", "Newtonsoft", new[] { "point", "query", "feed", "readmany" }),
                            ("PLAINTEXT", "None", "Stream", new[] { "point" }),
                        }
                        : string.Equals(writer, "current", StringComparison.Ordinal) &&
                          string.Equals(reader, "current", StringComparison.Ordinal)
                            ? new[]
                            {
                                ("MDE", "Newtonsoft", "Stream", new[] { "point", "query", "feed", "readmany" }),
                                ("MDE", "Stream", "Newtonsoft", new[] { "point", "query", "feed", "readmany" }),
                            }
                        : new[]
                        {
                            ("MDE", "Newtonsoft", "Newtonsoft", new[] { "point", "query", "feed", "readmany" }),
                            ("MDE", "Stream", "Newtonsoft", new[] { "point", "query", "feed", "readmany" }),
                            ("AEAD", "Newtonsoft", "Newtonsoft", new[] { "point", "query", "feed", "readmany" }),
                        };
                foreach ((string family, string writeProcessor, string readProcessor, string[] paths) in combinations)
                {
                    foreach (string path in paths)
                    {
                        scenarios.Add(
                            $"read:{writer}->{reader}:{family}:{writeProcessor}->{GetRequestedProcessorLabel(readProcessor)}:{path}");
                    }
                }

                return scenarios;
            }

            public static IReadOnlyCollection<string> GetRewriteScenarios(string rewriteProcessor)
            {
                string readProcessorLabel = GetRequestedProcessorLabel(rewriteProcessor);
                string oppositeProcessorLabel = GetRequestedProcessorLabel(
                    string.Equals(rewriteProcessor, "Stream", StringComparison.Ordinal)
                        ? "Newtonsoft"
                        : "Stream");
                return new[]
                {
                    $"rewrite:released->current:MDE:{rewriteProcessor}",
                    $"reread:released->current:rewrite:{rewriteProcessor}->{readProcessorLabel}:point",
                    $"reread:released->current:rewrite:{rewriteProcessor}->{oppositeProcessorLabel}:point",
                    $"reread:released->current:rewrite:{rewriteProcessor}->{readProcessorLabel}:query",
                    $"reread:released->current:rewrite:{rewriteProcessor}->{readProcessorLabel}:feed",
                };
            }

            public static IReadOnlyCollection<string> GetAll()
            {
                string[] scenarios = GetWriteScenarios("released")
                    .Concat(GetWriteScenarios("current"))
                    .Concat(GetReadScenarios("released", "current"))
                    .Concat(GetReadScenarios("current", "current"))
                    .Concat(GetReadScenarios("current", "released"))
                    .Concat(GetRewriteScenarios("Newtonsoft"))
                    .Concat(GetRewriteScenarios("Stream"))
                    .ToArray();
                if (scenarios.Length != ExpectedObservationCount ||
                    scenarios.Distinct(StringComparer.Ordinal).Count() != scenarios.Length)
                {
                    throw new InvalidOperationException(
                        $"The compatibility matrix scenario catalog is not the expected unique {ExpectedObservationCount}-observation set.");
                }

                return scenarios;
            }

            private static string GetRequestedProcessorLabel(string processor)
            {
                return string.Equals(processor, "Stream", StringComparison.Ordinal)
                    ? "StreamRequested"
                    : processor;
            }
    }

    internal static class CompatibilityMatrixWorkerManifest
    {
        public static IReadOnlyDictionary<string, string> Parse(IEnumerable<string> lines)
        {
            ArgumentNullException.ThrowIfNull(lines);

            Dictionary<string, string> workers = new(StringComparer.Ordinal);
            foreach (string line in lines.Where(line => !string.IsNullOrWhiteSpace(line)))
            {
                string[] parts = line.Split('|');
                if (parts.Length != 2)
                {
                    throw new InvalidOperationException($"Invalid compatibility worker manifest line: {line}");
                }

                string role = GetRole(parts[0]);
                if (!workers.TryAdd(role, parts[1]))
                {
                    throw new InvalidOperationException($"Duplicate {role} compatibility worker.");
                }
            }

            if (workers.Count != 2 || !workers.ContainsKey("released") || !workers.ContainsKey("current"))
            {
                throw new InvalidOperationException("Compatibility worker manifest must contain one released and one current worker.");
            }

            return workers;
        }

        private static string GetRole(string projectPath)
        {
            if (projectPath.EndsWith("CompatMatrix.Released.csproj", StringComparison.OrdinalIgnoreCase))
            {
                return "released";
            }

            if (projectPath.EndsWith("CompatMatrix.Current.csproj", StringComparison.OrdinalIgnoreCase))
            {
                return "current";
            }

            throw new InvalidOperationException($"Unknown compatibility worker project: {projectPath}");
        }
    }
}
#endif
