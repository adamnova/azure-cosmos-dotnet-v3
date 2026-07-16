// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// ------------------------------------------------------------
namespace CompatMatrix.Server.Tests;

using System.Reflection;
using System.Text.RegularExpressions;
using CompatMatrix.Server.Harness;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
[DoNotParallelize]
public sealed class CompatMatrixAdversarialTests
{
    private const string OldVersion = "1.0.0-preview07";
    private const string NewVersion = "1.1.0-preview01.ga15fefb3";

    [TestMethod]
    public void RequiredMode_MissingWorkerDlls_FailsClassInitialization()
    {
        string source = File.ReadAllText(Path.Combine(CompatMatrixRoot(), "Tests", "CompatMatrixCellTests.cs"));
        int missingWorkerBlockStart = RequiredIndexOf(source, "if (oldDll is null || newDll is null)");
        int nodeConstructionStart = RequiredIndexOf(source, "List<INode> nodes");
        string missingWorkerBlock = source[missingWorkerBlockStart..nodeConstructionStart];

        StringAssert.Contains(
            missingWorkerBlock,
            "Assert.Fail",
            "Required-mode missing workers must fail directly from ClassInitialize, not defer to Gate as inconclusive.");
    }

    [TestMethod]
    public async Task RequiredMode_WhitespaceAroundTrue_IsRequired()
    {
        using EnvironmentVariableScope scope = new("COMPATMATRIX_REQUIRE_EMULATOR", " true ");
        using MatrixHarness matrix = await StartMatrixAsync(initOk: false);

        Assert.IsNotNull(matrix.FatalError, "Whitespace must be trimmed before required-mode parsing.");
        Assert.IsNull(matrix.SkipReason, "Required mode must not fail open to a local inconclusive result.");
    }

    [TestMethod]
    public async Task RequiredMode_InvalidNonEmptyValue_FailsConfigurationExplicitly()
    {
        foreach (string value in new[] { "yes", "1", "required" })
        {
            using EnvironmentVariableScope scope = new("COMPATMATRIX_REQUIRE_EMULATOR", value);
            using MatrixHarness matrix = await StartMatrixAsync(initOk: false);

            Assert.IsNotNull(matrix.FatalError, $"Invalid value '{value}' must fail configuration.");
            Assert.IsNull(matrix.SkipReason, $"Invalid value '{value}' must not fail open to inconclusive.");
            StringAssert.Contains(matrix.FatalError, "COMPATMATRIX_REQUIRE_EMULATOR");
            StringAssert.Contains(matrix.FatalError, value);
        }
    }

    [TestMethod]
    public async Task AeadStreamWrite_UnexpectedFailure_FailsHarness()
    {
        using MatrixHarness matrix = await StartMatrixAsync(
            initOk: true,
            newAeadStreamStatus: "FAIL");

        Assert.IsNotNull(matrix.FatalError, "A skipped AEAD+Stream read cell must not hide a failed write.");
        StringAssert.Contains(matrix.FatalError, "AEAD+Stream");
        StringAssert.Contains(matrix.FatalError, "FAIL");
    }

    [TestMethod]
    public async Task AeadStreamWrite_OldUnexpectedFailure_FailsHarness()
    {
        using MatrixHarness matrix = await StartMatrixAsync(
            initOk: true,
            oldAeadStreamStatus: "FAIL");

        Assert.IsNotNull(matrix.FatalError, "A skipped old-worker AEAD+Stream cell must not hide a failed write.");
        StringAssert.Contains(matrix.FatalError, "AEAD+Stream");
        StringAssert.Contains(matrix.FatalError, "FAIL");
    }

    [TestMethod]
    public void CiDefinition_UsesFreshBuildUniqueNuGetPackagesForPackAndTest()
    {
        string yaml = File.ReadAllText(Path.Combine(CompatMatrixRoot(), "azure-pipelines-compat-matrix.yml"));
        Match packagesVariable = Regex.Match(
            yaml,
            @"(?m)^\s*CompatNuGetPackages:\s*(?<value>.+)$",
            RegexOptions.CultureInvariant);

        Assert.IsTrue(packagesVariable.Success, "CI must define an isolated CompatNuGetPackages path.");
        StringAssert.Contains(packagesVariable.Groups["value"].Value, "$(Build.BuildId)");

        int packStart = RequiredIndexOf(yaml, "displayName: Pack Encryption.Custom source");
        int testStart = RequiredIndexOf(yaml, "displayName: CompatMatrix.Server per-cell harness");
        int prepareStart = yaml.LastIndexOf("- powershell:", packStart, StringComparison.Ordinal);
        Assert.IsTrue(prepareStart >= 0, "CI must prepare the isolated package directory before pack restore.");

        string prepareSection = yaml[prepareStart..packStart];
        StringAssert.Contains(prepareSection, "$(CompatNuGetPackages)");
        int removeIndex = RequiredIndexOf(prepareSection, "Remove-Item");
        int createIndex = RequiredIndexOf(prepareSection, "New-Item");
        Assert.IsTrue(removeIndex < createIndex, "The isolated package directory must be cleared before it is created.");

        string packSection = yaml[packStart..testStart];
        string testSection = yaml[testStart..];
        StringAssert.Contains(packSection, "NUGET_PACKAGES: $(CompatNuGetPackages)");
        StringAssert.Contains(testSection, "NUGET_PACKAGES: $(CompatNuGetPackages)");
    }

    [TestMethod]
    public void CiDefinition_EnforcesReleaseForCommitQualifiedPackAndTest()
    {
        string yaml = File.ReadAllText(Path.Combine(CompatMatrixRoot(), "azure-pipelines-compat-matrix.yml"));
        int packStart = RequiredIndexOf(yaml, "displayName: Pack Encryption.Custom source");
        int testStart = RequiredIndexOf(yaml, "displayName: CompatMatrix.Server per-cell harness");
        string packSection = yaml[packStart..testStart];
        string testSection = yaml[testStart..];

        StringAssert.Contains(packSection, "-c Release");
        StringAssert.Contains(testSection, "-c Release");
        Assert.IsFalse(
            packSection.Contains("parameters.BuildConfiguration", StringComparison.Ordinal),
            "The package identity must not be reusable for a caller-selected pack configuration.");
        Assert.IsFalse(
            testSection.Contains("parameters.BuildConfiguration", StringComparison.Ordinal),
            "The package-under-test configuration must be Release.");
    }

    [TestMethod]
    public void Documentation_ExactMstestTotals_IncludeFollowUpTests()
    {
        int matrixCount = 1
            + MatrixHarness.ReadCells().Count()
            + MatrixHarness.EquivCells().Count()
            + 2;
        int followUpCount = typeof(CompatMatrixAdversarialTests).Assembly
            .GetTypes()
            .Where(type => type != typeof(CompatMatrixCellTests)
                && type.GetCustomAttribute<TestClassAttribute>() is not null)
            .SelectMany(type => type.GetMethods(BindingFlags.Instance | BindingFlags.Public))
            .Count(method => method.GetCustomAttributes(inherit: true)
                .Any(attribute => attribute is TestMethodAttribute || attribute is DataTestMethodAttribute));
        int totalCount = matrixCount + followUpCount;

        AssertDocumentationCounts(
            File.ReadAllText(Path.Combine(CompatMatrixRoot(), "README.md")),
            matrixCount,
            followUpCount,
            totalCount,
            "README.md");
        AssertDocumentationCounts(
            File.ReadAllText(Path.Combine(CompatMatrixRoot(), "EXPLORATION.md")),
            matrixCount,
            followUpCount,
            totalCount,
            "EXPLORATION.md");
    }

    private static async Task<MatrixHarness> StartMatrixAsync(
        bool initOk,
        string oldAeadStreamStatus = "OLD-NO-STREAM-EXPECTED",
        string newAeadStreamStatus = "EXPECTED-UNSUPPORTED")
    {
        MatrixHarness matrix = new(new INode[]
        {
            new FakeNode("old", OldVersion, initOk: true, oldAeadStreamStatus),
            new FakeNode("new", NewVersion, initOk, newAeadStreamStatus),
        });
        await matrix.StartAsync("https://unused.invalid/", "unused", "unused", "both");
        return matrix;
    }

    private static void AssertDocumentationCounts(
        string documentation,
        int matrixCount,
        int followUpCount,
        int totalCount,
        string documentName)
    {
        StringAssert.Contains(documentation, $"Passed: {totalCount}", documentName);
        StringAssert.Contains(documentation, $"{matrixCount} matrix", documentName);
        StringAssert.Contains(documentation, $"{followUpCount} follow-up", documentName);
        StringAssert.Contains(documentation, $"Skipped: {matrixCount}", documentName);
        StringAssert.Contains(documentation, $"Passed: {followUpCount}", documentName);
    }

    private static int RequiredIndexOf(string text, string value)
    {
        int index = text.IndexOf(value, StringComparison.Ordinal);
        Assert.IsTrue(index >= 0, $"Expected to find '{value}'.");
        return index;
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
        private readonly bool initOk;
        private readonly string aeadStreamStatus;

        public FakeNode(string name, string expected, bool initOk, string aeadStreamStatus)
        {
            this.Name = name;
            this.Expected = expected;
            this.initOk = initOk;
            this.aeadStreamStatus = aeadStreamStatus;
        }

        public string Name { get; }

        public string Expected { get; }

        public VersionInfo? Version { get; set; }

        public void Launch(string endpoint, string key, string db)
        {
        }

        public Task<VersionInfo?> WaitVersionAsync(TimeSpan timeout)
            => Task.FromResult<VersionInfo?>(new VersionInfo(
                this.Name,
                this.Expected,
                this.Expected,
                "1.0.0.0"));

        public Task<(bool ok, string detail)> InitAsync()
            => Task.FromResult((this.initOk, this.initOk ? "ready" : "fake initialization failure"));

        public Task<WriteInfo> WriteAsync(string family, string wproc, string id)
            => Task.FromResult(new WriteInfo(
                family == "AEAD" && wproc == "Stream" ? this.aeadStreamStatus : "OK",
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
