// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// ------------------------------------------------------------
// SPIKE (Option C) as a PROPER dotnet-test harness. Each cross-version compat-matrix cell is its own
// MSTest case via [DynamicData], so `dotnet test` reports per-cell PASS/FAIL. The two version-pinned
// stdio workers are launched ONCE ([ClassInitialize]) and driven via the shared StdioNode +
// MatrixHarness; the sensitive doc is built/encrypted/self-verified inside the workers (only status +
// SHA-256 hashes cross the stdio boundary). If the Cosmos emulator is unreachable the whole class
// self-skips (Assert.Inconclusive), so it is safe in non-emulator CI legs.
namespace CompatMatrix.Server.Tests
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Threading.Tasks;
    using CompatMatrix.Server.Harness;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    [TestClass]
    public sealed class CompatMatrixCellTests
    {
        private const string EmulatorKey = "C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw==";

        private static MatrixHarness? harness;
        private static string status = "not initialized";

        [ClassInitialize]
        public static async Task ClassInitialize(TestContext _)
        {
            (string? oldDll, string? newDll) = ResolveWorkers();
            if (oldDll is null || newDll is null)
            {
                status = "worker DLLs not built (build OldWorker/NewWorker, or set COMPATMATRIX_OLD_WORKER/NEW_WORKER)";
                return;
            }

            List<INode> nodes = new()
            {
                new StdioNode("old", oldDll, "1.0.0-preview07"),
                new StdioNode("new", newDll, "1.1.0-preview01"),
            };
            harness = new MatrixHarness(nodes);

            string endpoint = Environment.GetEnvironmentVariable("COSMOS_ENDPOINT") ?? "http://127.0.0.1:8081/";
            string key = Environment.GetEnvironmentVariable("COSMOS_KEY") ?? EmulatorKey;
            string db = "compat-matrix-test-" + Guid.NewGuid().ToString("N")[..8];

            await harness.StartAsync(endpoint, key, db, "both");
            status = harness.FatalError is not null ? "FATAL: " + harness.FatalError
                : harness.SkipReason is not null ? "SKIP: " + harness.SkipReason
                : string.Empty; // ready
        }

        [ClassCleanup]
        public static void ClassCleanup() => harness?.Dispose();

        [TestMethod]
        public void Versions_AreExpected_AndDistinct()
        {
            Gate();
            Assert.AreEqual("1.0.0-preview07", harness!.VersionOf("old")!.Informational, "OLD must load preview07");
            Assert.AreEqual("1.1.0-preview01", harness.VersionOf("new")!.Informational, "NEW must load preview01");
            Assert.AreNotEqual(harness.VersionOf("old")!.Informational, harness.VersionOf("new")!.Informational, "workers must load different versions");
        }

        // One test case per SUPPORTED read cell (writer x reader x algo x wproc->rproc x path) = 39 cases.
        [DataTestMethod]
        [DynamicData(nameof(MatrixHarness.ReadCells), typeof(MatrixHarness), DynamicDataSourceType.Method)]
        public async Task Cell_RoundTrips(string writer, string reader, string family, string wproc, string rproc, string path)
        {
            Gate();
            (bool pass, string detail) = await harness!.ReadCellAsync(writer, reader, family, wproc, rproc, path);
            Assert.IsTrue(pass, $"{writer}-write {reader}-read {family} {wproc}->{rproc}/{path}: {detail}");
        }

        // One test case per cross-processor A/B equivalence cell = 3 cases.
        [DataTestMethod]
        [DynamicData(nameof(MatrixHarness.EquivCells), typeof(MatrixHarness), DynamicDataSourceType.Method)]
        public async Task Cell_CrossProcessorEquivalence(string writer, string reader, string family, string wproc)
        {
            Gate();
            (bool pass, string detail) = await harness!.EquivalenceAsync(writer, reader, family, wproc);
            Assert.IsTrue(pass, $"{writer}-write {reader}-read {family} {wproc} A/B: {detail}");
        }

        // Anti-fake-green: a plaintext doc must be REJECTED by the raw assertion on each version.
        [DataTestMethod]
        [DynamicData(nameof(TamperNodes), DynamicDataSourceType.Method)]
        public async Task Tamper_PlaintextRejected(string name)
        {
            Gate();
            (bool pass, string detail) = await harness!.TamperAsync(name);
            Assert.IsTrue(pass, $"tamper {name}: {detail}");
        }

        private static IEnumerable<object[]> TamperNodes()
        {
            yield return new object[] { "old" };
            yield return new object[] { "new" };
        }

        // A version/write break fails every case; an unreachable emulator (or unbuilt workers) skips.
        private static void Gate()
        {
            if (status.StartsWith("FATAL", StringComparison.Ordinal)) { Assert.Fail(status); }
            if (status.Length > 0) { Assert.Inconclusive(status); }
            Assert.IsNotNull(harness);
        }

        // Locate the two worker DLLs built alongside this test (via ProjectReference), honoring an env override.
        private static (string? oldDll, string? newDll) ResolveWorkers()
        {
            string? envOld = Environment.GetEnvironmentVariable("COMPATMATRIX_OLD_WORKER");
            string? envNew = Environment.GetEnvironmentVariable("COMPATMATRIX_NEW_WORKER");
            if (File.Exists(envOld) && File.Exists(envNew)) { return (envOld, envNew); }

            // BaseDirectory = ...\Tests\bin\<config>\net8.0\  ->  csRoot = tests\CompatMatrix.Server
            DirectoryInfo tfm = new(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar));
            string config = tfm.Parent?.Name ?? "Release";
            DirectoryInfo? csRoot = tfm.Parent?.Parent?.Parent?.Parent;
            if (csRoot is null) { return (null, null); }

            string Find(string workerDir, string dll)
            {
                foreach (string cfg in new[] { config, "Release", "Debug" })
                {
                    string p = Path.Combine(csRoot.FullName, workerDir, "bin", cfg, "net8.0", dll);
                    if (File.Exists(p)) { return p; }
                }
                return string.Empty;
            }

            string o = Find("OldWorker", "CompatMatrix.Worker.Old.dll");
            string n = Find("NewWorker", "CompatMatrix.Worker.New.dll");
            return (o.Length == 0 ? null : o, n.Length == 0 ? null : n);
        }
    }
}
