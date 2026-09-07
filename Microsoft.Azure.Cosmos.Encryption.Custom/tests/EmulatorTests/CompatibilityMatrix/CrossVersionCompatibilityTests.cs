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
    using System.Net;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.Azure.Cosmos;
    using Microsoft.Azure.Cosmos.Encryption.Custom.EmulatorTests.Utils;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Newtonsoft.Json.Linq;

    [TestClass]
    public class CrossVersionCompatibilityTests
    {
        private static readonly TimeSpan WorkerTimeout = TimeSpan.FromMinutes(3);
        private static readonly TimeSpan MatrixTimeout = TimeSpan.FromMinutes(12);
        private static readonly TimeSpan ProcessTerminationTimeout = TimeSpan.FromSeconds(10);
        private static readonly TimeSpan CleanupTimeout = TimeSpan.FromMinutes(2);

        [TestMethod]
        [Timeout(15 * 60 * 1000)]
        public async Task ReleasedPreview07AndAggregatePackageRemainCompatible()
        {
#if !COMPAT_MATRIX_ENABLED
            Assert.Inconclusive(
                "The optional compatibility matrix was not enabled. See tests/CompatMatrix/README.md.");
            return;
#else
            using CancellationTokenSource matrixTimeout = new(MatrixTimeout);
            IReadOnlyDictionary<string, string> workers = LoadWorkers();
            CompatibilityMatrixPackageProvenance releasedProvenance =
                CompatibilityMatrixPackageProvenance.Load(workers["released"], "released");
            CompatibilityMatrixPackageProvenance currentProvenance =
                CompatibilityMatrixPackageProvenance.Load(workers["current"], "current");
            ValidateDependencyClosure(workers["released"], releasedProvenance);
            ValidateDependencyClosure(workers["current"], currentProvenance);

            WorkerInvocation releasedIdentityRun = await RunWorkerAsync(
                workers["released"],
                matrixTimeout.Token,
                "--action=identity");
            WorkerInvocation currentIdentityRun = await RunWorkerAsync(
                workers["current"],
                matrixTimeout.Token,
                "--action=identity");
            CompatibilityMatrixRecord releasedIdentity = GetSingleRecord(releasedIdentityRun, "identity");
            CompatibilityMatrixRecord currentIdentity = GetSingleRecord(currentIdentityRun, "identity");
            CompatibilityMatrixIdentityValidator.Validate(
                releasedIdentity,
                currentIdentity,
                releasedProvenance,
                currentProvenance);
            this.RecordIdentityEvidence(releasedIdentity, releasedProvenance);
            this.RecordIdentityEvidence(currentIdentity, currentProvenance);

            string databaseId = "compat-matrix-" + Guid.NewGuid().ToString("N");
            (string endpoint, string key) = TestCommon.GetAccountInfo();
            _ = CompatibilityMatrixEndpoint.Validate(endpoint);
            string[] commonArguments =
            {
                "--endpoint=" + endpoint,
                "--database=" + databaseId,
            };

            Exception primaryFailure = null;
            try
            {
                WorkerInvocation releasedWrite =
                    await RunAuthenticatedWorkerAsync(
                        workers["released"],
                        matrixTimeout.Token,
                        key,
                        commonArguments.Prepend("--action=write").ToArray());
                ValidateObservations(
                    releasedWrite,
                    CompatibilityMatrixScenarios.GetWriteScenarios("released"));
                ValidateFixtureRecords(releasedWrite);
                this.RecordFixtureEvidence(releasedWrite);

                WorkerInvocation currentWrite =
                    await RunAuthenticatedWorkerAsync(
                        workers["current"],
                        matrixTimeout.Token,
                        key,
                        commonArguments.Prepend("--action=write").ToArray());
                ValidateObservations(
                    currentWrite,
                    CompatibilityMatrixScenarios.GetWriteScenarios("current"));
                this.RecordFixtureEvidence(currentWrite);
                ValidateObservations(
                    await RunAuthenticatedWorkerAsync(
                        workers["current"],
                        matrixTimeout.Token,
                        key,
                        commonArguments
                            .Concat(BuildFixtureHashArguments(currentWrite))
                            .Prepend("--writer=current")
                            .Prepend("--action=read")
                            .ToArray()),
                    CompatibilityMatrixScenarios.GetReadScenarios("current", "current"));
                ValidateObservations(
                    await RunAuthenticatedWorkerAsync(
                        workers["current"],
                        matrixTimeout.Token,
                        key,
                        commonArguments
                            .Concat(BuildFixtureHashArguments(releasedWrite))
                            .Prepend("--writer=released")
                            .Prepend("--action=read")
                            .ToArray()),
                    CompatibilityMatrixScenarios.GetReadScenarios("released", "current"));

                foreach (string rewriteProcessor in new[] { "Newtonsoft", "Stream" })
                {
                    WorkerInvocation rewriteInvocation =
                        await RunAuthenticatedWorkerAsync(
                            workers["current"],
                            matrixTimeout.Token,
                            key,
                            commonArguments
                                .Concat(BuildFixtureHashArguments(releasedWrite))
                                .Prepend("--processor=" + rewriteProcessor)
                                .Prepend("--writer=released")
                                .Prepend("--action=rewrite")
                                .ToArray());
                    ValidateObservations(
                        rewriteInvocation,
                        CompatibilityMatrixScenarios.GetRewriteScenarios(rewriteProcessor));
                    this.RecordFixtureEvidence(rewriteInvocation);
                }

                ValidateObservations(
                    await RunAuthenticatedWorkerAsync(
                        workers["released"],
                        matrixTimeout.Token,
                        key,
                        commonArguments
                            .Concat(BuildFixtureHashArguments(currentWrite))
                            .Prepend("--writer=current")
                            .Prepend("--action=read")
                            .ToArray()),
                    CompatibilityMatrixScenarios.GetReadScenarios("current", "released"));
            }
            catch (Exception exception)
            {
                primaryFailure = exception;
                throw;
            }
            finally
            {
                try
                {
                    await DeleteDatabaseAsync(databaseId, endpoint, key);
                }
                catch (Exception cleanupException) when (primaryFailure != null)
                {
                    TestContext.WriteLine($"Compatibility cleanup also failed: {cleanupException}");
                }
            }
#endif
        }

        public TestContext TestContext { get; set; }

        private static IReadOnlyDictionary<string, string> LoadWorkers()
        {
            string manifestPath = Path.Combine(AppContext.BaseDirectory, "CompatMatrix.Workers.txt");
            if (!File.Exists(manifestPath))
            {
                throw new InvalidOperationException($"Compatibility worker manifest was not found: {manifestPath}");
            }

            IReadOnlyDictionary<string, string> workers =
                CompatibilityMatrixWorkerManifest.Parse(File.ReadAllLines(manifestPath));
            foreach (KeyValuePair<string, string> worker in workers)
            {
                if (!File.Exists(worker.Value))
                {
                    throw new InvalidOperationException($"{worker.Key} compatibility worker was not found: {worker.Value}");
                }

                string runtimeConfigPath = Path.ChangeExtension(worker.Value, ".runtimeconfig.json");
                string depsPath = Path.ChangeExtension(worker.Value, ".deps.json");
                if (!File.Exists(runtimeConfigPath) || !File.Exists(depsPath))
                {
                    throw new InvalidOperationException(
                        $"{worker.Key} compatibility worker is missing its runtime configuration or dependency graph.");
                }
            }

            return workers;
        }

        private static void ValidateDependencyClosure(
            string workerPath,
            CompatibilityMatrixPackageProvenance provenance)
        {
            string depsPath = Path.ChangeExtension(workerPath, ".deps.json");
            JObject dependencies = JObject.Parse(File.ReadAllText(depsPath));
            JObject libraries = dependencies["libraries"] as JObject
                ?? throw new InvalidOperationException($"Worker dependency graph has no libraries section: {depsPath}");
            JProperty library = libraries.Properties().SingleOrDefault(
                property => property.Name.StartsWith(
                    "Microsoft.Azure.Cosmos.Encryption.Custom/",
                    StringComparison.Ordinal))
                ?? throw new InvalidOperationException($"Worker dependency graph does not contain Encryption.Custom: {depsPath}");
            string actualType = library.Value.Value<string>("type");
            if (!string.Equals(actualType, "package", StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"Worker dependency graph loaded Encryption.Custom as {actualType}, expected package: {depsPath}");
            }

            if (!string.Equals(
                    library.Name,
                    "Microsoft.Azure.Cosmos.Encryption.Custom/" + provenance.PackageVersion,
                    StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"Worker dependency graph loaded {library.Name}, expected Encryption.Custom/{provenance.PackageVersion}.");
            }
        }

        private static async Task<WorkerInvocation> RunWorkerAsync(
            string workerPath,
            CancellationToken matrixCancellationToken,
            params string[] arguments)
        {
            return await RunWorkerCoreAsync(
                workerPath,
                matrixCancellationToken,
                null,
                arguments);
        }

        private static async Task<WorkerInvocation> RunAuthenticatedWorkerAsync(
            string workerPath,
            CancellationToken matrixCancellationToken,
            string accountKey,
            params string[] arguments)
        {
            return await RunWorkerCoreAsync(
                workerPath,
                matrixCancellationToken,
                accountKey,
                arguments);
        }

        private static async Task<WorkerInvocation> RunWorkerCoreAsync(
            string workerPath,
            CancellationToken matrixCancellationToken,
            string accountKey,
            string[] arguments)
        {
            ProcessStartInfo startInfo = CompatibilityMatrixWorkerProcess.CreateStartInfo(
                workerPath,
                accountKey,
                arguments);

            using Process process = Process.Start(startInfo)
                ?? throw new InvalidOperationException($"Failed to start compatibility worker: {workerPath}");
            Task<string> standardOutputTask = process.StandardOutput.ReadToEndAsync();
            Task<string> standardErrorTask = process.StandardError.ReadToEndAsync();
            using CancellationTokenSource timeout =
                CancellationTokenSource.CreateLinkedTokenSource(matrixCancellationToken);
            timeout.CancelAfter(WorkerTimeout);
            try
            {
                await process.WaitForExitAsync(timeout.Token);
            }
            catch (OperationCanceledException exception)
            {
                await TerminateProcessAsync(process);
                string timedOutStandardOutput = await standardOutputTask;
                string timedOutStandardError = await standardErrorTask;
                string deadline = matrixCancellationToken.IsCancellationRequested
                    ? "matrix"
                    : "worker";

                throw new TimeoutException(
                    $"Compatibility {deadline} deadline expired: {Path.GetFileName(workerPath)} {string.Join(" ", arguments)}" +
                    FormatProcessOutput(timedOutStandardOutput, timedOutStandardError),
                    exception);
            }

            string standardOutput = await standardOutputTask;
            string standardError = await standardErrorTask;
            CompatibilityMatrixRecord[] records = standardOutput
                .Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
                .Select(CompatibilityMatrixProtocol.ParseRecord)
                .ToArray();

            if (!string.IsNullOrWhiteSpace(standardError))
            {
                throw new InvalidOperationException(
                    "Compatibility worker wrote to stderr." +
                    FormatProcessOutput(standardOutput, standardError));
            }

            CompatibilityMatrixRecord[] completions = records
                .Where(record => string.Equals(record.Kind, "completion", StringComparison.Ordinal))
                .ToArray();
            if (completions.Length != 1 ||
                !ReferenceEquals(completions[0], records.LastOrDefault()))
            {
                throw new InvalidOperationException(
                    "Compatibility worker emitted an invalid completion record." +
                    FormatProcessOutput(standardOutput, standardError));
            }

            if (process.ExitCode != 0 ||
                !string.Equals(completions[0].Status, "pass", StringComparison.Ordinal))
            {
                string failureSummary = string.Join(
                    Environment.NewLine,
                    records
                        .Where(record => string.Equals(record.Status, "fail", StringComparison.Ordinal))
                        .Select(record => $"{record.Kind}:{record.ScenarioId}:{record.Detail}"));
                throw new InvalidOperationException(
                    $"Compatibility worker failed with exit code {process.ExitCode}.{Environment.NewLine}" +
                    failureSummary +
                    FormatProcessOutput(standardOutput, standardError));
            }

            return new WorkerInvocation(workerPath, records);
        }

        private static async Task TerminateProcessAsync(Process process)
        {
            if (process.HasExited)
            {
                return;
            }

            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException) when (process.HasExited)
            {
                return;
            }

            using CancellationTokenSource terminationTimeout = new(ProcessTerminationTimeout);
            try
            {
                await process.WaitForExitAsync(terminationTimeout.Token);
            }
            catch (OperationCanceledException exception)
            {
                throw new TimeoutException(
                    $"Compatibility worker did not terminate within {ProcessTerminationTimeout}.",
                    exception);
            }
        }

        private static string FormatProcessOutput(
            string standardOutput,
            string standardError)
        {
            const int maximumCharacters = 4096;
            string combined =
                $"{Environment.NewLine}stdout:{Environment.NewLine}{standardOutput?.Trim()}" +
                $"{Environment.NewLine}stderr:{Environment.NewLine}{standardError?.Trim()}";
            if (combined.Length <= maximumCharacters)
            {
                return combined;
            }

            const int prefixCharacters = 1024;
            int suffixCharacters = maximumCharacters - prefixCharacters;
            return combined.Substring(0, prefixCharacters) +
                Environment.NewLine +
                "<middle truncated>" +
                Environment.NewLine +
                combined.Substring(combined.Length - suffixCharacters);
        }

        private static void ValidateObservations(
            WorkerInvocation invocation,
            IReadOnlyCollection<string> expectedScenarios)
        {
            CompatibilityMatrixRecord[] observations = invocation.Records
                .Where(record => string.Equals(record.Kind, "observation", StringComparison.Ordinal))
                .ToArray();
            CompatibilityMatrixResultOracle.Validate(expectedScenarios, observations);
        }

        private static void ValidateFixtureRecords(WorkerInvocation invocation)
        {
            CompatibilityMatrixRecord[] fixtures = invocation.Records
                .Where(record => string.Equals(record.Kind, "fixture", StringComparison.Ordinal))
                .ToArray();
            if (fixtures.Length != 2 ||
                fixtures.Any(record =>
                    !string.Equals(record.Status, "pass", StringComparison.Ordinal) ||
                    string.IsNullOrWhiteSpace(record.DocumentId) ||
                    string.IsNullOrWhiteSpace(record.FixtureSha256) ||
                    string.IsNullOrWhiteSpace(record.PlaintextSha256) ||
                    string.IsNullOrWhiteSpace(record.RawShape)) ||
                fixtures.Select(record => record.DocumentId).Distinct(StringComparer.Ordinal).Count() != 2)
            {
                throw new InvalidOperationException(
                    "Released worker did not emit two distinct hash-pinned rewrite fixtures.");
            }
        }

        private static IEnumerable<string> BuildFixtureHashArguments(WorkerInvocation invocation)
        {
            CompatibilityMatrixRecord[] records = invocation.Records
                .Where(record =>
                    (string.Equals(record.Kind, "observation", StringComparison.Ordinal) ||
                     string.Equals(record.Kind, "fixture", StringComparison.Ordinal)) &&
                    string.Equals(record.Status, "pass", StringComparison.Ordinal) &&
                    !string.IsNullOrWhiteSpace(record.DocumentId) &&
                    !string.IsNullOrWhiteSpace(record.FixtureSha256))
                .ToArray();
            if (records.Select(record => record.DocumentId).Distinct(StringComparer.Ordinal).Count() != records.Length)
            {
                throw new InvalidOperationException(
                    "Compatibility worker emitted duplicate fixture document ids.");
            }

            return records.Select(
                record => $"--fixture-sha256-{record.DocumentId}={record.FixtureSha256}");
        }

        private void RecordIdentityEvidence(
            CompatibilityMatrixRecord identity,
            CompatibilityMatrixPackageProvenance provenance)
        {
            this.TestContext.WriteLine(
                $"COMPAT_IDENTITY role={identity.Role};package={provenance.PackageId}/{provenance.PackageVersion};" +
                $"inputNupkg={provenance.InputNupkgPath ?? provenance.NupkgPath};" +
                $"source={provenance.ActualSource};sourceCommit={provenance.SourceCommit};" +
                $"nupkgSha256={provenance.NupkgSha256};assemblyPath={identity.AssemblyPath};" +
                $"assemblySha256={identity.AssemblySha256};" +
                $"mvid={identity.AssemblyMvid};assemblyVersion={identity.AssemblyVersion};" +
                $"productVersion={identity.ProductVersion};informationalVersion={identity.InformationalVersion}");
        }

        private void RecordFixtureEvidence(WorkerInvocation invocation)
        {
            foreach (CompatibilityMatrixRecord record in invocation.Records.Where(record =>
                string.Equals(record.Status, "pass", StringComparison.Ordinal) &&
                !string.IsNullOrWhiteSpace(record.FixtureSha256) &&
                (string.Equals(record.Kind, "fixture", StringComparison.Ordinal) ||
                 record.ScenarioId.StartsWith("write:", StringComparison.Ordinal) ||
                 record.ScenarioId.StartsWith("rewrite:", StringComparison.Ordinal))))
            {
                this.TestContext.WriteLine(
                    $"COMPAT_FIXTURE scenario={record.ScenarioId};document={record.DocumentId};" +
                    $"inputSha256={record.InputFixtureSha256 ?? "<created>"};" +
                    $"fixtureSha256={record.FixtureSha256};plaintextSha256={record.PlaintextSha256};" +
                    $"shape={record.RawShape}");
            }
        }

        private static CompatibilityMatrixRecord GetSingleRecord(WorkerInvocation invocation, string kind)
        {
            CompatibilityMatrixRecord[] records = invocation.Records
                .Where(record => string.Equals(record.Kind, kind, StringComparison.Ordinal))
                .ToArray();
            if (records.Length != 1)
            {
                throw new InvalidOperationException(
                    $"{Path.GetFileName(invocation.WorkerPath)} emitted {records.Length} {kind} records.");
            }

            return records[0];
        }

        private static async Task DeleteDatabaseAsync(string databaseId, string endpoint, string key)
        {
            Uri emulatorEndpoint = CompatibilityMatrixEndpoint.Validate(endpoint);
            using CosmosClient client = new(
                emulatorEndpoint.AbsoluteUri,
                key,
                new CosmosClientOptions
                {
                    ConnectionMode = ConnectionMode.Gateway,
                    LimitToEndpoint = true,
                    HttpClientFactory = () => new System.Net.Http.HttpClient(
                        CompatibilityMatrixEndpoint.CreateHttpClientHandler(emulatorEndpoint)),
                });
            using CancellationTokenSource timeout = new(CleanupTimeout);
            try
            {
                using ResponseMessage response = await client
                    .GetDatabase(databaseId)
                    .DeleteStreamAsync(cancellationToken: timeout.Token);
                if (!response.IsSuccessStatusCode && response.StatusCode != HttpStatusCode.NotFound)
                {
                    throw new InvalidOperationException(
                        $"Compatibility database cleanup failed with {response.StatusCode}: {response.ErrorMessage}");
                }
            }
            catch (CosmosException exception) when (exception.StatusCode == HttpStatusCode.NotFound)
            {
            }
        }

        private sealed class WorkerInvocation
        {
            public WorkerInvocation(string workerPath, IReadOnlyList<CompatibilityMatrixRecord> records)
            {
                this.WorkerPath = workerPath;
                this.Records = records;
            }

            public string WorkerPath { get; }

            public IReadOnlyList<CompatibilityMatrixRecord> Records { get; }
        }
    }
}
#endif
