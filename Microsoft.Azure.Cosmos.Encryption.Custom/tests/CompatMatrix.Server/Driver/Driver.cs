// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// ------------------------------------------------------------
// SPIKE (Option B) driver: the typed orchestrator for the "thin server" compat-matrix. It is a
// direct, apples-to-apples re-expression of tests/CompatMatrix/run-matrix.ps1 -- same versions,
// same cells, same hardened doc, same exit codes -- but the transport is HTTP to two long-lived
// servers that run AT ONCE and share ONE Cosmos DB, instead of stdout parsing of one-shot procs.
//
//   0 = every cross-version/cross-processor cell PASS (and exact cell count)
//   1 = data break / version break / wrong cell count / tamper guard failed
//   3 = emulator unreachable (skip; servers still built + version-guarded)
namespace CompatMatrix.Server.Driver;

using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text.Json;

internal static class Program
{
    private const string EmulatorKey = "C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw==";
    private static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true };

    private static async Task<int> Main(string[] args)
    {
        Dictionary<string, string> a = Parse(args);
        string here = AppContext.BaseDirectory;
        string root = Path.GetFullPath(Path.Combine(here, "..", "..", "..", ".."));   // -> tests/CompatMatrix.Server
        string endpoint = a.GetValueOrDefault("endpoint", Environment.GetEnvironmentVariable("COSMOS_ENDPOINT") ?? "http://127.0.0.1:8081/");
        string key = a.GetValueOrDefault("key", Environment.GetEnvironmentVariable("COSMOS_KEY") ?? EmulatorKey);
        string db = a.GetValueOrDefault("db", "compat-matrix-srv-" + Guid.NewGuid().ToString("N")[..8]);
        string toggle = a.GetValueOrDefault("processor", "both").Trim().ToLowerInvariant();
        if (toggle is not ("newtonsoft" or "stream" or "both")) { toggle = "both"; }
        string oldDll = a.GetValueOrDefault("old", Path.Combine(root, "Old", "bin", "Release", "net8.0", "CompatMatrix.Server.Old.dll"));
        string newDll = a.GetValueOrDefault("new", Path.Combine(root, "New", "bin", "Release", "net8.0", "CompatMatrix.Server.New.dll"));

        if (!File.Exists(oldDll) || !File.Exists(newDll))
        {
            Console.Error.WriteLine($"Build the shims first. Missing:\n  {(File.Exists(oldDll) ? "" : oldDll)}\n  {(File.Exists(newDll) ? "" : newDll)}");
            return 1;
        }

        List<Node> nodes = new()
        {
            new Node("old", oldDll, "1.0.0-preview07"),
            new Node("new", newDll, "1.1.0-preview01"),
        };

        try
        {
            // ---- Launch both shims AT ONCE and health-check /version (works even if the emulator is down) ----
            foreach (Node n in nodes) { n.Launch(endpoint, key, db); }
            foreach (Node n in nodes)
            {
                VersionInfo? v = await n.WaitVersionAsync(TimeSpan.FromSeconds(40));
                if (v is null) { Console.Error.WriteLine($"{n.Name}: server did not answer /version."); return 1; }
                n.Version = v;
            }

            // ---- Version guard: exact expected versions AND the two must differ (anti-fake-green) ----
            foreach (Node n in nodes)
            {
                if (n.Version!.Informational != n.Expected)
                {
                    Console.Error.WriteLine($"VERSION BREAK: {n.Name} loaded '{n.Version.Informational}', expected '{n.Expected}'.");
                    return 1;
                }
            }
            if (nodes.Select(n => n.Version!.Informational).Distinct().Count() != nodes.Count)
            {
                Console.Error.WriteLine("VERSION BREAK: the shims must load DIFFERENT Encryption.Custom versions.");
                return 1;
            }
            Console.WriteLine("Versions: " + string.Join(" ", nodes.Select(n => $"{n.Name.ToUpperInvariant()}={n.Version!.Informational}")));

            // ---- Emulator gate: POST /init connects to Cosmos + creates the DEKs. Unreachable => skip (exit 3) ----
            foreach (Node n in nodes)
            {
                (bool ok, string detail) = await n.InitAsync();
                if (!ok)
                {
                    Console.WriteLine($"SKIP: Cosmos emulator not reachable for {n.Name} ({detail}). Start it, e.g.:");
                    Console.WriteLine("  docker run -d --name cosmos-emu -p 8081:8081 mcr.microsoft.com/cosmosdb/linux/azure-cosmos-emulator:vnext-preview");
                    return 3;
                }
            }
            Console.WriteLine($"Emulator: {endpoint}  DB: {db}  Processor: {toggle}");

            // ---- Write phase: every node writes every cell into the shared DB (state shared via Cosmos) ----
            Dictionary<string, string> expectedHash = new();
            List<string> didNotThrow = new();
            foreach (Node writer in nodes)
            {
                foreach ((string family, string wproc) in Cells())
                {
                    string id = $"cell-{family}-{wproc}-by-{writer.Name}";
                    WriteInfo w = await writer.PostAsync<WriteInfo>($"/write?family={family}&wproc={wproc}&id={Uri.EscapeDataString(id)}");
                    expectedHash[id] = w.ExpectedSignatureHash;
                    Console.WriteLine($"WROTE|{writer.Name}|{family}|{wproc}|{w.Status}|{w.Detail}");
                    if (w.Status == "UNSUPPORTED-DID-NOT-THROW") { didNotThrow.Add(id); }
                }
            }
            if (didNotThrow.Count > 0)
            {
                Console.Error.WriteLine("WRITE BREAK: AEAD+Stream did not throw on a Stream-capable version: " + string.Join(", ", didNotThrow));
                return 1;
            }

            // ---- Read phase: cross every reader x writer, honoring the read-proc override (real Stream DECRYPT),
            //      across point/query/feed, then a cross-processor A/B equivalence meta-cell. Same shape as
            //      Program.Read, but each cell is one HTTP round-trip to the reader's live server. ----
            List<GridRow> grid = new();
            foreach (Node reader in nodes)
            {
                foreach (Node writer in nodes)
                {
                    foreach ((string family, string wproc) in Cells())
                    {
                        if (family == "AEAD" && wproc == "Stream") { continue; }   // unsupported-by-design
                        if (wproc == "Stream" && writer.Name == "old") { continue; } // preview07 never produced a stream-written doc
                        string id = $"cell-{family}-{wproc}-by-{writer.Name}";
                        Dictionary<string, string> hashByProc = new();

                        foreach (string rproc in ReadProcessors(family, reader.Name, toggle))
                        {
                            foreach (string path in new[] { "point", "query", "feed" })
                            {
                                ReadInfo r = await reader.PostAsync<ReadInfo>(
                                    $"/read?family={family}&rproc={rproc}&path={path}&id={Uri.EscapeDataString(id)}");
                                bool cellPass = r.RawOk && r.DecOk;
                                string msg = cellPass ? r.RawDetail : (!r.RawOk ? $"raw:{r.RawDetail}" : r.Detail);
                                grid.Add(new GridRow($"{writer.Name}-write", $"{reader.Name}-read", family, $"{wproc}->{rproc}", path, cellPass ? "PASS" : "FAIL", msg));
                                if (cellPass) { hashByProc[rproc] = r.SignatureHash; }
                            }
                        }

                        // A/B equivalence: the SAME _ei doc must decrypt IDENTICALLY under Newtonsoft AND Stream,
                        // and match the writer's intended content (all compared as SHA-256 hashes over HTTP).
                        if (hashByProc.TryGetValue("Newtonsoft", out string? hN) && hashByProc.TryGetValue("Stream", out string? hS))
                        {
                            bool eq = hN == hS && hN == expectedHash.GetValueOrDefault(id);
                            grid.Add(new GridRow($"{writer.Name}-write", $"{reader.Name}-read", family, $"{wproc}->A/B", "equiv", eq ? "PASS" : "FAIL", eq ? "N==S (full doc interchangeable)" : "N/S/expected hash mismatch"));
                        }
                    }
                }
            }

            PrintGrid(grid);
            int pass = grid.Count(g => g.Status == "PASS");
            List<GridRow> fails = grid.Where(g => g.Status != "PASS").ToList();
            Console.WriteLine($"PASS={pass} FAIL={fails.Count}");
            if (fails.Count > 0)
            {
                Console.Error.WriteLine("DATA BREAK:");
                foreach (GridRow f in fails) { Console.Error.WriteLine($"  {f.Write} {f.Read} {f.Family} {f.Wproc}/{f.Path}: {f.Msg}"); }
                return 1;
            }

            // ---- Exact-tuple enforcement (mirrors run-matrix.ps1): a silently dropped/duplicated cell fails. ----
            int expected = toggle == "both" ? 42 : 30;
            if (grid.Count != expected)
            {
                Console.Error.WriteLine($"CELL COUNT BREAK: expected {expected} cells for -Processor {toggle}, got {grid.Count}.");
                return 1;
            }

            // ---- Anti-fake-green: a plaintext doc must be REJECTED by the raw assertion on each node. ----
            foreach (Node n in nodes)
            {
                TamperInfo t = await n.PostAsync<TamperInfo>($"/tamper?id={Uri.EscapeDataString($"cell-MDE-Newtonsoft-tamper-by-{n.Name}")}");
                Console.WriteLine($"TAMPER|{n.Name}|{(t.Pass ? "PASS" : "FAIL")}|{t.Detail}");
                if (!t.Pass) { Console.Error.WriteLine("GUARD BREAK: plaintext doc accepted as encrypted."); return 1; }
            }

            Console.WriteLine("All cross-version cells PASS (no data break); plaintext rejected.");
            return 0;
        }
        finally
        {
            foreach (Node n in nodes) { n.Dispose(); }
        }
    }

    private static IEnumerable<(string family, string wproc)> Cells()
    {
        yield return ("MDE", "Newtonsoft");
        yield return ("MDE", "Stream");
        yield return ("AEAD", "Newtonsoft");
        yield return ("AEAD", "Stream"); // unsupported-by-design: asserted to throw on write
    }

    // Read processors applied to a stored cell. AEAD is Newtonsoft-only; MDE honors the toggle. Stream
    // DECRYPT only exists in preview01, so an OLD reader stays Newtonsoft (MDE is interchangeable).
    private static IEnumerable<string> ReadProcessors(string family, string readerName, string toggle)
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

    private static void PrintGrid(List<GridRow> grid)
    {
        Console.WriteLine("\n===== COMPAT MATRIX GRID (thin-server / HTTP) =====");
        var rows = grid.OrderBy(g => g.Write).ThenBy(g => g.Read).ThenBy(g => g.Family).ThenBy(g => g.Wproc).ThenBy(g => g.Path).ToList();
        string[] headers = { "Write", "Read", "Algo", "wproc->rproc", "Path", "Status" };
        Func<GridRow, string>[] cols = { g => g.Write, g => g.Read, g => g.Family, g => g.Wproc, g => g.Path, g => g.Status };
        int[] w = headers.Select((h, i) => Math.Max(h.Length, rows.Count == 0 ? 0 : rows.Max(r => cols[i](r).Length))).ToArray();
        Console.WriteLine(string.Join("  ", headers.Select((h, i) => h.PadRight(w[i]))));
        foreach (GridRow r in rows) { Console.WriteLine(string.Join("  ", cols.Select((c, i) => c(r).PadRight(w[i])))); }
    }

    private static Dictionary<string, string> Parse(string[] args)
    {
        Dictionary<string, string> d = new();
        foreach (string s in args)
        {
            int i = s.IndexOf('=');
            if (s.StartsWith("--") && i > 0) { d[s[2..i]] = s[(i + 1)..]; }
        }
        return d;
    }

    private sealed class Node : IDisposable
    {
        public string Name { get; }
        public string Dll { get; }
        public string Expected { get; }
        public int Port { get; }
        public VersionInfo? Version { get; set; }
        private readonly HttpClient http;
        private Process? proc;

        public Node(string name, string dll, string expected)
        {
            this.Name = name;
            this.Dll = dll;
            this.Expected = expected;
            this.Port = FreePort();
            this.http = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{this.Port}"), Timeout = TimeSpan.FromSeconds(120) };
        }

        public void Launch(string endpoint, string key, string db)
        {
            ProcessStartInfo psi = new() { FileName = "dotnet", UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (string arg in new[] { this.Dll, "--urls", $"http://127.0.0.1:{this.Port}", "--endpoint", endpoint, "--key", key, "--db", db })
            {
                psi.ArgumentList.Add(arg);
            }
            this.proc = Process.Start(psi)!;
            this.proc.OutputDataReceived += (_, _) => { };
            this.proc.ErrorDataReceived += (_, e) => { if (!string.IsNullOrWhiteSpace(e.Data)) { Console.Error.WriteLine($"[{this.Name}] {e.Data}"); } };
            this.proc.BeginOutputReadLine();
            this.proc.BeginErrorReadLine();
        }

        public async Task<VersionInfo?> WaitVersionAsync(TimeSpan timeout)
        {
            Stopwatch sw = Stopwatch.StartNew();
            while (sw.Elapsed < timeout)
            {
                try
                {
                    HttpResponseMessage r = await this.http.GetAsync("/version");
                    if (r.IsSuccessStatusCode) { return await r.Content.ReadFromJsonAsync<VersionInfo>(Json); }
                }
                catch { /* not up yet */ }
                await Task.Delay(250);
            }
            return null;
        }

        public async Task<(bool ok, string detail)> InitAsync()
        {
            try
            {
                HttpResponseMessage r = await this.http.PostAsync("/init", null);
                if (r.IsSuccessStatusCode) { return (true, "ok"); }
                return (false, await r.Content.ReadAsStringAsync());
            }
            catch (Exception ex) { return (false, $"{ex.GetType().Name}: {ex.Message.Split('\n')[0]}"); }
        }

        public async Task<T> PostAsync<T>(string url)
        {
            HttpResponseMessage r = await this.http.PostAsync(url, null);
            r.EnsureSuccessStatusCode();
            return (await r.Content.ReadFromJsonAsync<T>(Json))!;
        }

        public void Dispose()
        {
            try { if (this.proc is { HasExited: false }) { this.proc.Kill(entireProcessTree: true); } } catch { }
            this.http.Dispose();
            this.proc?.Dispose();
        }

        private static int FreePort()
        {
            TcpListener l = new(IPAddress.Loopback, 0);
            l.Start();
            int port = ((IPEndPoint)l.LocalEndpoint).Port;
            l.Stop();
            return port;
        }
    }

    private sealed record VersionInfo(string Version, string Expected, string Informational, string AssemblyVersion);

    private sealed record WriteInfo(string Status, string Detail, string ExpectedSignatureHash);

    private sealed record ReadInfo(bool RawOk, string RawDetail, bool DecOk, string Detail, string SignatureHash);

    private sealed record TamperInfo(bool Pass, string Detail);

    private sealed record GridRow(string Write, string Read, string Family, string Wproc, string Path, string Status, string Msg);
}
