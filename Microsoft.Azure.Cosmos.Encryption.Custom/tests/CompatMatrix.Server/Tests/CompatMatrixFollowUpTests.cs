// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// ------------------------------------------------------------
namespace CompatMatrix.Server.Tests;

using System.Reflection;
using System.Xml.Linq;
using CompatMatrix.Server.Harness;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
[DoNotParallelize]
public sealed class CompatMatrixFollowUpTests
{
    private const string OldVersion = "1.0.0-preview07";
    private const string FixedNewVersion = "1.1.0-preview01";
    private const string CommitQualifiedNewVersion = "1.1.0-preview01.ga15fefb3";
    private const string WrongCommitQualifiedNewVersion = "1.1.0-preview01.gdeadbee";

    [TestMethod]
    public async Task RequiredEmulator_InitializationFailure_IsReportedAsFailure()
    {
        using EnvironmentVariableScope scope = new("COMPATMATRIX_REQUIRE_EMULATOR", "true");
        using MatrixHarness matrix = await StartMatrixAsync(new FakeNode(
            "new",
            CommitQualifiedNewVersion,
            CommitQualifiedNewVersion,
            CommitQualifiedNewVersion,
            initOk: false));

        Exception gateException = InvokeCellGate(matrix);

        Assert.IsInstanceOfType(gateException, typeof(AssertFailedException));
    }

    [TestMethod]
    public async Task LocalRun_InitializationFailure_RemainsInconclusive()
    {
        using EnvironmentVariableScope scope = new("COMPATMATRIX_REQUIRE_EMULATOR", null);
        using MatrixHarness matrix = await StartMatrixAsync(new FakeNode(
            "new",
            CommitQualifiedNewVersion,
            CommitQualifiedNewVersion,
            CommitQualifiedNewVersion,
            initOk: false));

        Exception gateException = InvokeCellGate(matrix);

        Assert.IsInstanceOfType(gateException, typeof(AssertInconclusiveException));
    }

    [TestMethod]
    public async Task RequiredEmulator_Matching_IsCaseInsensitive()
    {
        foreach (string value in new[] { "TRUE", "True", "tRuE" })
        {
            using EnvironmentVariableScope scope = new("COMPATMATRIX_REQUIRE_EMULATOR", value);
            using MatrixHarness matrix = await StartMatrixAsync(new FakeNode(
                "new",
                CommitQualifiedNewVersion,
                CommitQualifiedNewVersion,
                CommitQualifiedNewVersion,
                initOk: false));

            Assert.IsInstanceOfType(
                InvokeCellGate(matrix),
                typeof(AssertFailedException),
                $"'{value}' must require the emulator.");
        }
    }

    [TestMethod]
    public async Task ExplicitFalseEmulatorRequirement_RemainsInconclusive()
    {
        using EnvironmentVariableScope scope = new("COMPATMATRIX_REQUIRE_EMULATOR", "false");
        using MatrixHarness matrix = await StartMatrixAsync(new FakeNode(
            "new",
            CommitQualifiedNewVersion,
            CommitQualifiedNewVersion,
            CommitQualifiedNewVersion,
            initOk: false));

        Assert.IsInstanceOfType(InvokeCellGate(matrix), typeof(AssertInconclusiveException));
    }

    [TestMethod]
    public async Task NewPackageIdentity_CommitQualifiedVersion_IsAcceptedWhenExact()
    {
        using MatrixHarness matrix = await StartMatrixAsync(new FakeNode(
            "new",
            CommitQualifiedNewVersion,
            CommitQualifiedNewVersion,
            CommitQualifiedNewVersion,
            initOk: true));

        Assert.IsTrue(matrix.Ready, matrix.FatalError ?? matrix.SkipReason);
        Assert.AreEqual(CommitQualifiedNewVersion, matrix.VersionOf("new")!.Informational);
    }

    [TestMethod]
    public async Task VersionGuard_RejectsStaleFixedWorkerExpectation()
    {
        using MatrixHarness matrix = await StartMatrixAsync(new FakeNode(
            "new",
            CommitQualifiedNewVersion,
            FixedNewVersion,
            CommitQualifiedNewVersion,
            initOk: true));

        Assert.IsNotNull(
            matrix.FatalError,
            "The version guard must reject a worker still compiled for the reusable fixed NEW version.");
    }

    [TestMethod]
    public async Task VersionGuard_RejectsWrongCommitQualifier()
    {
        using MatrixHarness matrix = await StartMatrixAsync(new FakeNode(
            "new",
            CommitQualifiedNewVersion,
            CommitQualifiedNewVersion,
            WrongCommitQualifiedNewVersion,
            initOk: true));

        StringAssert.Contains(matrix.FatalError, WrongCommitQualifiedNewVersion);
        StringAssert.Contains(matrix.FatalError, CommitQualifiedNewVersion);
    }

    [TestMethod]
    public async Task VersionGuard_RejectsMissingOrMalformedWorkerMetadataClearly()
    {
        foreach (string? reportedExpected in new string?[] { null, string.Empty, " " })
        {
            using MatrixHarness matrix = await StartMatrixAsync(new FakeNode(
                "new",
                CommitQualifiedNewVersion,
                reportedExpected,
                CommitQualifiedNewVersion,
                initOk: true));

            StringAssert.Contains(matrix.FatalError, "assembly metadata");
            StringAssert.Contains(matrix.FatalError, "new worker");
        }
    }

    [TestMethod]
    public void ConfiguredVersionMetadata_MissingOrMalformed_FailsClearly()
    {
        InvalidOperationException missing = Assert.ThrowsException<InvalidOperationException>(
            () => ConfiguredVersions.ReadRequired(Array.Empty<AssemblyMetadataAttribute>(), "CompatMatrixNewVersion"));
        StringAssert.Contains(missing.Message, "must appear exactly once");
        StringAssert.Contains(missing.Message, "found 0 entries");

        InvalidOperationException empty = Assert.ThrowsException<InvalidOperationException>(
            () => ConfiguredVersions.ReadRequired(
                new[] { new AssemblyMetadataAttribute("CompatMatrixNewVersion", " ") },
                "CompatMatrixNewVersion"));
        StringAssert.Contains(empty.Message, "non-empty package version");

        InvalidOperationException duplicate = Assert.ThrowsException<InvalidOperationException>(
            () => ConfiguredVersions.ReadRequired(
                new[]
                {
                    new AssemblyMetadataAttribute("CompatMatrixNewVersion", CommitQualifiedNewVersion),
                    new AssemblyMetadataAttribute("CompatMatrixNewVersion", WrongCommitQualifiedNewVersion),
                },
                "CompatMatrixNewVersion"));
        StringAssert.Contains(duplicate.Message, "must appear exactly once");
        StringAssert.Contains(duplicate.Message, "found 2 entries");
    }

    [TestMethod]
    public async Task VersionProbe_MetadataFailure_IsReportedClearly()
    {
        const string metadataError =
            "Configured assembly metadata 'CompatMatrixNewVersion' must contain a non-empty package version.";
        using MatrixHarness matrix = await StartMatrixAsync(new FakeNode(
            "new",
            CommitQualifiedNewVersion,
            CommitQualifiedNewVersion,
            CommitQualifiedNewVersion,
            initOk: true,
            versionFailure: new InvalidOperationException(metadataError)));

        StringAssert.Contains(matrix.FatalError, "version probe failed");
        StringAssert.Contains(matrix.FatalError, metadataError);
    }

    [TestMethod]
    public void CiDefinition_DerivesAndPassesCommitQualifiedNewPackageVersion()
    {
        string yaml = File.ReadAllText(Path.Combine(CompatMatrixRoot(), "azure-pipelines-compat-matrix.yml"));
        string newWorkerProject = File.ReadAllText(Path.Combine(
            CompatMatrixRoot(),
            "NewWorker",
            "CompatMatrix.Worker.New.csproj"));

        StringAssert.Contains(yaml, "$sourceVersion = '$(Build.SourceVersion)'");
        StringAssert.Contains(yaml, "$shortCommit = $sourceVersion.Substring(0, 8).ToLowerInvariant()");
        StringAssert.Contains(yaml, "$newVersion = \"1.1.0-preview01.g$shortCommit\"");
        StringAssert.Contains(yaml, "##vso[task.setvariable variable=CompatMatrixNewVersion]$newVersion");
        StringAssert.Contains(yaml, "/p:CustomEncryptionVersion=$(CompatMatrixNewVersion)");
        StringAssert.Contains(
            yaml,
            "/p:RestoreConfigFile=$(Build.SourcesDirectory)/$(CompatMatrixDir)/nuget.ci.config /p:CompatMatrixNewVersion=$(CompatMatrixNewVersion)");
        StringAssert.Contains(newWorkerProject, "Version=\"[$(CompatMatrixNewVersion)]\"");
        StringAssert.Contains(yaml, "COMPATMATRIX_REQUIRE_EMULATOR: 'true'");
    }

    [TestMethod]
    public void LocalConfiguration_DefaultsNewVersionToPreview01()
    {
        XDocument properties = XDocument.Load(Path.Combine(CompatMatrixRoot(), "Directory.Build.props"));
        XElement version = properties
            .Descendants("CompatMatrixNewVersion")
            .Single();

        Assert.AreEqual(FixedNewVersion, version.Value.Trim());
        Assert.AreEqual(
            "'$(CompatMatrixNewVersion)' == ''",
            version.Attribute("Condition")?.Value.Trim());
    }

    private static async Task<MatrixHarness> StartMatrixAsync(FakeNode newNode)
    {
        MatrixHarness matrix = new(new INode[]
        {
            new FakeNode("old", OldVersion, OldVersion, OldVersion, initOk: true),
            newNode,
        });

        await matrix.StartAsync("https://unused.invalid/", "unused", "unused", "both");
        return matrix;
    }

    private static Exception InvokeCellGate(MatrixHarness matrix)
    {
        Type testType = typeof(CompatMatrixCellTests);
        FieldInfo harnessField = testType.GetField("harness", BindingFlags.NonPublic | BindingFlags.Static)!;
        FieldInfo statusField = testType.GetField("status", BindingFlags.NonPublic | BindingFlags.Static)!;
        MethodInfo gate = testType.GetMethod("Gate", BindingFlags.NonPublic | BindingFlags.Static)!;
        object? previousHarness = harnessField.GetValue(null);
        object? previousStatus = statusField.GetValue(null);

        try
        {
            harnessField.SetValue(null, matrix);
            statusField.SetValue(
                null,
                matrix.FatalError is not null ? "FATAL: " + matrix.FatalError
                    : matrix.SkipReason is not null ? "SKIP: " + matrix.SkipReason
                    : string.Empty);

            try
            {
                gate.Invoke(null, null);
                return new InvalidOperationException("Gate unexpectedly returned.");
            }
            catch (TargetInvocationException exception) when (exception.InnerException is not null)
            {
                return exception.InnerException;
            }
        }
        finally
        {
            harnessField.SetValue(null, previousHarness);
            statusField.SetValue(null, previousStatus);
        }
    }

    private static string CompatMatrixRoot()
        => Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));

    private sealed class EnvironmentVariableScope : IDisposable
    {
        private readonly string name;
        private readonly string? originalValue;

        public EnvironmentVariableScope(string name, string? value)
        {
            this.name = name;
            this.originalValue = Environment.GetEnvironmentVariable(name);
            Environment.SetEnvironmentVariable(name, value);
        }

        public void Dispose() => Environment.SetEnvironmentVariable(this.name, this.originalValue);
    }

    private sealed class FakeNode : INode
    {
        private readonly string? reportedExpected;
        private readonly string informational;
        private readonly bool initOk;
        private readonly Exception? versionFailure;

        public FakeNode(
            string name,
            string expected,
            string? reportedExpected,
            string informational,
            bool initOk,
            Exception? versionFailure = null)
        {
            this.Name = name;
            this.Expected = expected;
            this.reportedExpected = reportedExpected;
            this.informational = informational;
            this.initOk = initOk;
            this.versionFailure = versionFailure;
        }

        public string Name { get; }

        public string Expected { get; }

        public VersionInfo? Version { get; set; }

        public void Launch(string endpoint, string key, string db)
        {
        }

        public Task<VersionInfo?> WaitVersionAsync(TimeSpan timeout)
            => this.versionFailure is null
                ? Task.FromResult<VersionInfo?>(new VersionInfo(
                    this.Name,
                    this.reportedExpected!,
                    this.informational,
                    "1.0.0.0"))
                : Task.FromException<VersionInfo?>(this.versionFailure);

        public Task<(bool ok, string detail)> InitAsync()
            => Task.FromResult((this.initOk, this.initOk ? "ready" : "fake initialization failure"));

        public Task<WriteInfo> WriteAsync(string family, string wproc, string id)
            => Task.FromResult(new WriteInfo(
                family == "AEAD" && wproc == "Stream" ? "EXPECTED-UNSUPPORTED" : "OK",
                "fake",
                "hash-" + id));

        public Task<ReadInfo> ReadAsync(string family, string rproc, string path, string id)
            => Task.FromResult(new ReadInfo(true, "fake", true, "fake", "hash-" + id));

        public Task<TamperInfo> TamperAsync(string id)
            => Task.FromResult(new TamperInfo(true, "fake"));

        public void Dispose()
        {
        }
    }
}
