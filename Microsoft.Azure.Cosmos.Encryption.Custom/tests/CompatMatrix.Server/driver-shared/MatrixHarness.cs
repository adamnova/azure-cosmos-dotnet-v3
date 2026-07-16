// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// ------------------------------------------------------------
// SPIKE (Option C) test harness core. Wraps the long-lived-worker lifecycle and exposes the matrix
// as PER-CELL operations so an MSTest class can turn each cell into its own [DataTestMethod] via
// [DynamicData] — the "proper dotnet-test-hosted harness". The static Read/EquivCells enumerations
// are pure (no live node), so MSTest can enumerate cases at discovery time; the live nodes are
// launched once in [ClassInitialize]. SkipReason => optional emulator down (Assert.Inconclusive);
// FatalError => required emulator/configuration/version/write break (fail).
namespace CompatMatrix.Server.Harness;

public sealed class MatrixHarness : IDisposable
{
    private const string RequireEmulatorVariable = "COMPATMATRIX_REQUIRE_EMULATOR";
    private readonly IReadOnlyList<INode> nodes;
    private readonly Dictionary<string, string> expectedHash = new();
    private readonly Dictionary<string, WriteInfo> writeById = new();
    private readonly List<(string writer, string family, string wproc, WriteInfo info)> writes = new();

    public MatrixHarness(IReadOnlyList<INode> nodes) => this.nodes = nodes;

    public string? SkipReason { get; private set; }

    public string? FatalError { get; private set; }

    public bool Ready => this.SkipReason is null && this.FatalError is null;

    // The write-phase results (for the console WROTE| output and root-cause attribution on read failures).
    public IReadOnlyList<(string writer, string family, string wproc, WriteInfo info)> Writes => this.writes;

    // Launch all workers at once, version-guard, init (emulator gate), then write every cell once.
    public async Task StartAsync(string endpoint, string key, string db, string toggle)
    {
        bool emulatorRequired;
        try
        {
            emulatorRequired = EmulatorIsRequired();
        }
        catch (InvalidOperationException exception)
        {
            this.FatalError = $"CONFIGURATION BREAK: {exception.Message}";
            return;
        }

        foreach (INode n in this.nodes) { n.Launch(endpoint, key, db); }
        foreach (INode n in this.nodes)
        {
            VersionInfo? v;
            try
            {
                v = await n.WaitVersionAsync(TimeSpan.FromSeconds(40));
            }
            catch (Exception exception)
            {
                this.FatalError = $"VERSION BREAK: {n.Name} worker version probe failed: {exception.Message}";
                return;
            }

            if (v is null) { this.FatalError = $"{n.Name}: worker did not answer version."; return; }
            n.Version = v;
        }
        foreach (INode n in this.nodes)
        {
            if (string.IsNullOrWhiteSpace(n.Version!.Expected))
            {
                this.FatalError = $"VERSION BREAK: {n.Name} worker returned missing or malformed configured-version assembly metadata.";
                return;
            }
            if (string.IsNullOrWhiteSpace(n.Version.Informational) || n.Version.Informational == "<missing>")
            {
                this.FatalError = $"VERSION BREAK: {n.Name} worker returned a missing or malformed loaded package version.";
                return;
            }
            if (!string.Equals(n.Version.Expected, n.Expected, StringComparison.Ordinal))
            {
                this.FatalError = $"VERSION BREAK: {n.Name} worker expects '{n.Version.Expected}', configured '{n.Expected}'.";
                return;
            }
            if (!string.Equals(n.Version.Informational, n.Expected, StringComparison.Ordinal))
            {
                this.FatalError = $"VERSION BREAK: {n.Name} loaded '{n.Version.Informational}', expected '{n.Expected}'.";
                return;
            }
        }
        if (this.nodes.Select(n => n.Version!.Informational).Distinct().Count() != this.nodes.Count)
        {
            this.FatalError = "VERSION BREAK: the workers must load DIFFERENT Encryption.Custom versions.";
            return;
        }

        foreach (INode n in this.nodes)
        {
            (bool ok, string detail) = await n.InitAsync();
            if (!ok)
            {
                string reason = $"Cosmos emulator not reachable for {n.Name} ({detail}).";
                if (emulatorRequired)
                {
                    this.FatalError = reason;
                }
                else
                {
                    this.SkipReason = reason;
                }
                return;
            }
        }

        foreach (INode writer in this.nodes)
        {
            foreach ((string family, string wproc) in Cells())
            {
                string id = $"cell-{family}-{wproc}-by-{writer.Name}";
                WriteInfo w = await writer.WriteAsync(family, wproc, id);
                this.expectedHash[id] = w.ExpectedSignatureHash;
                this.writeById[id] = w;
                this.writes.Add((writer.Name, family, wproc, w));
                if (family == "AEAD"
                    && wproc == "Stream"
                    && writer.Name != "old"
                    && !string.Equals(w.Status, "EXPECTED-UNSUPPORTED", StringComparison.Ordinal))
                {
                    this.FatalError = $"WRITE BREAK: AEAD+Stream on a Stream-capable version must return EXPECTED-UNSUPPORTED; got '{w.Status}' ({w.Detail}) for {id}.";
                    return;
                }
            }
        }
    }

    // One read cell: raw-ciphertext verdict AND decrypted self-verify (server-side VerifyDoc + number-integrity).
    public async Task<(bool pass, string detail)> ReadCellAsync(string writer, string reader, string family, string wproc, string rproc, string path)
    {
        string id = $"cell-{family}-{wproc}-by-{writer}";
        ReadInfo r = await this.Node(reader).ReadAsync(family, rproc, path, id);
        bool pass = r.RawOk && r.DecOk;
        string detail = pass ? r.RawDetail : (!r.RawOk ? $"raw:{r.RawDetail}" : r.Detail);
        // Root-cause attribution: if this id's WRITE failed, a broken write otherwise surfaces misleadingly
        // as raw-not-found on the read path — so prefix the writer's failure (see review finding #3).
        if (!pass && this.writeById.TryGetValue(id, out WriteInfo? w) && w.Status == "FAIL")
        {
            detail = $"WRITE-FAILED[{w.Detail}] -> {detail}";
        }
        return (pass, detail);
    }

    // Cross-processor A/B equivalence: the SAME _ei doc must decrypt IDENTICALLY under Newtonsoft AND
    // Stream, and match the writer's intended content (all compared as SHA-256 hashes).
    public async Task<(bool pass, string detail)> EquivalenceAsync(string writer, string reader, string family, string wproc)
    {
        string id = $"cell-{family}-{wproc}-by-{writer}";
        ReadInfo rN = await this.Node(reader).ReadAsync(family, "Newtonsoft", "point", id);
        ReadInfo rS = await this.Node(reader).ReadAsync(family, "Stream", "point", id);
        string? hN = rN.RawOk && rN.DecOk ? rN.SignatureHash : null;
        string? hS = rS.RawOk && rS.DecOk ? rS.SignatureHash : null;
        string exp = this.expectedHash.GetValueOrDefault(id, "<no-writer-hash>");
        bool pass = hN is not null && hN == hS && hN == exp;
        return (pass, pass ? "N==S==writer (full doc interchangeable)" : $"mismatch hN={hN ?? "<fail>"} hS={hS ?? "<fail>"} exp={exp}");
    }

    public async Task<(bool pass, string detail)> TamperAsync(string name)
    {
        TamperInfo t = await this.Node(name).TamperAsync($"cell-MDE-Newtonsoft-tamper-by-{name}");
        return (t.Pass, t.Detail);
    }

    public VersionInfo? VersionOf(string name) => this.Node(name).Version;

    public static bool EmulatorIsRequired()
    {
        string value = (Environment.GetEnvironmentVariable(RequireEmulatorVariable) ?? string.Empty).Trim();
        if (value.Length == 0 || string.Equals(value, "false", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (string.Equals(value, "true", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        throw new InvalidOperationException(
            $"{RequireEmulatorVariable} must be empty, 'false', or 'true'; received '{value}'.");
    }

    public void Dispose()
    {
        foreach (INode n in this.nodes) { n.Dispose(); }
    }

    private INode Node(string name) => this.nodes.First(n => n.Name == name);

    // ---- pure static enumerations (no live node) for MSTest [DynamicData] discovery ----
    public static readonly string[] Versions = { "old", "new" };

    public static IEnumerable<(string family, string wproc)> Cells()
    {
        yield return ("MDE", "Newtonsoft");
        yield return ("MDE", "Stream");
        yield return ("AEAD", "Newtonsoft");
        yield return ("AEAD", "Stream"); // unsupported-by-design (asserted to throw on write)
    }

    public static IEnumerable<string> ReadProcessors(string family, string readerName, string toggle)
    {
        if (family == "AEAD") { yield return "Newtonsoft"; yield break; }
        bool readerSupportsStream = readerName != "old";
        switch (toggle)
        {
            case "newtonsoft": yield return "Newtonsoft"; break;
            case "stream": yield return readerSupportsStream ? "Stream" : "Newtonsoft"; break;
            default: yield return "Newtonsoft"; if (readerSupportsStream) { yield return "Stream"; } break;
        }
    }

    // The 39 supported read cells at -Processor both (parameterless form is the MSTest [DynamicData] source).
    public static IEnumerable<object[]> ReadCells() => ReadCellsFor("both");

    // Toggle-aware read-cell enumeration, shared with the console MatrixRunner (single source of the grid).
    public static IEnumerable<object[]> ReadCellsFor(string toggle)
    {
        foreach (string reader in Versions)
        {
            foreach (string writer in Versions)
            {
                foreach ((string family, string wproc) in Cells())
                {
                    if (family == "AEAD" && wproc == "Stream") { continue; }
                    if (wproc == "Stream" && writer == "old") { continue; }
                    foreach (string rproc in ReadProcessors(family, reader, toggle))
                    {
                        foreach (string path in new[] { "point", "query", "feed" })
                        {
                            yield return new object[] { writer, reader, family, wproc, rproc, path };
                        }
                    }
                }
            }
        }
    }

    // The 3 cross-processor equivalence cells at -Processor both (parameterless form is the [DynamicData] source).
    public static IEnumerable<object[]> EquivCells() => EquivCellsFor("both");

    // reader reads BOTH N and S — so only present at -Processor both (single-processor toggles have no equivalence).
    public static IEnumerable<object[]> EquivCellsFor(string toggle)
    {
        foreach (string reader in Versions)
        {
            foreach (string writer in Versions)
            {
                foreach ((string family, string wproc) in Cells())
                {
                    if (family != "MDE") { continue; }
                    if (wproc == "Stream" && writer == "old") { continue; }
                    List<string> procs = ReadProcessors(family, reader, toggle).ToList();
                    if (procs.Contains("Newtonsoft") && procs.Contains("Stream"))
                    {
                        yield return new object[] { writer, reader, family, wproc };
                    }
                }
            }
        }
    }
}
