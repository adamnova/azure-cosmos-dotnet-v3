// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// ------------------------------------------------------------
// SPIKE shared orchestration: identical to run-matrix.ps1's flow (version-guard -> emulator gate ->
// write -> cross read grid -> count -> tamper), but expressed once and reused by BOTH the HTTP
// (Option B) and stdio (Option C) drivers through INode. Exit codes: 0 pass / 1 break / 3 skip.
namespace CompatMatrix.Server.Harness;

public static class MatrixRunner
{
    public static async Task<int> RunAsync(IReadOnlyList<INode> nodes, string endpoint, string key, string db, string toggle, string transportLabel)
    {
        try
        {
            // ---- Launch all version workers AT ONCE and health-check (works even if the emulator is down) ----
            foreach (INode n in nodes) { n.Launch(endpoint, key, db); }
            foreach (INode n in nodes)
            {
                VersionInfo? v = await n.WaitVersionAsync(TimeSpan.FromSeconds(40));
                if (v is null) { Console.Error.WriteLine($"{n.Name}: worker did not answer version."); return 1; }
                n.Version = v;
            }

            // ---- Version guard: exact expected versions AND the two must differ (anti-fake-green) ----
            foreach (INode n in nodes)
            {
                if (n.Version!.Informational != n.Expected)
                {
                    Console.Error.WriteLine($"VERSION BREAK: {n.Name} loaded '{n.Version.Informational}', expected '{n.Expected}'.");
                    return 1;
                }
            }
            if (nodes.Select(n => n.Version!.Informational).Distinct().Count() != nodes.Count)
            {
                Console.Error.WriteLine("VERSION BREAK: the workers must load DIFFERENT Encryption.Custom versions.");
                return 1;
            }
            Console.WriteLine($"[{transportLabel}] Versions: " + string.Join(" ", nodes.Select(n => $"{n.Name.ToUpperInvariant()}={n.Version!.Informational}")));

            // ---- Emulator gate: init connects to Cosmos + creates the DEKs. Unreachable => skip (exit 3) ----
            foreach (INode n in nodes)
            {
                (bool ok, string detail) = await n.InitAsync();
                if (!ok)
                {
                    Console.WriteLine($"SKIP: Cosmos emulator not reachable for {n.Name} ({detail}). Start it, e.g.:");
                    Console.WriteLine("  docker run -d --name cosmos-emu -p 8081:8081 mcr.microsoft.com/cosmosdb/linux/azure-cosmos-emulator:vnext-preview");
                    return 3;
                }
            }
            Console.WriteLine($"[{transportLabel}] Emulator: {endpoint}  DB: {db}  Processor: {toggle}");

            // ---- Write phase: every node writes every cell into the shared DB (state shared via Cosmos) ----
            Dictionary<string, string> expectedHash = new();
            List<string> didNotThrow = new();
            foreach (INode writer in nodes)
            {
                foreach ((string family, string wproc) in Cells())
                {
                    string id = $"cell-{family}-{wproc}-by-{writer.Name}";
                    WriteInfo w = await writer.WriteAsync(family, wproc, id);
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
            //      across point/query/feed, then a cross-processor A/B equivalence meta-cell. ----
            List<GridRow> grid = new();
            foreach (INode reader in nodes)
            {
                foreach (INode writer in nodes)
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
                                ReadInfo r = await reader.ReadAsync(family, rproc, path, id);
                                bool cellPass = r.RawOk && r.DecOk;
                                string msg = cellPass ? r.RawDetail : (!r.RawOk ? $"raw:{r.RawDetail}" : r.Detail);
                                grid.Add(new GridRow($"{writer.Name}-write", $"{reader.Name}-read", family, $"{wproc}->{rproc}", path, cellPass ? "PASS" : "FAIL", msg));
                                if (cellPass) { hashByProc[rproc] = r.SignatureHash; }
                            }
                        }

                        if (hashByProc.TryGetValue("Newtonsoft", out string? hN) && hashByProc.TryGetValue("Stream", out string? hS))
                        {
                            bool eq = hN == hS && hN == expectedHash.GetValueOrDefault(id);
                            grid.Add(new GridRow($"{writer.Name}-write", $"{reader.Name}-read", family, $"{wproc}->A/B", "equiv", eq ? "PASS" : "FAIL", eq ? "N==S (full doc interchangeable)" : "N/S/expected hash mismatch"));
                        }
                    }
                }
            }

            PrintGrid(grid, transportLabel);
            int pass = grid.Count(g => g.Status == "PASS");
            List<GridRow> fails = grid.Where(g => g.Status != "PASS").ToList();
            Console.WriteLine($"PASS={pass} FAIL={fails.Count}");
            if (fails.Count > 0)
            {
                Console.Error.WriteLine("DATA BREAK:");
                foreach (GridRow f in fails) { Console.Error.WriteLine($"  {f.Write} {f.Read} {f.Family} {f.Wproc}/{f.Path}: {f.Msg}"); }
                return 1;
            }

            int expected = toggle == "both" ? 42 : 30;
            if (grid.Count != expected)
            {
                Console.Error.WriteLine($"CELL COUNT BREAK: expected {expected} cells for -Processor {toggle}, got {grid.Count}.");
                return 1;
            }

            foreach (INode n in nodes)
            {
                TamperInfo t = await n.TamperAsync($"cell-MDE-Newtonsoft-tamper-by-{n.Name}");
                Console.WriteLine($"TAMPER|{n.Name}|{(t.Pass ? "PASS" : "FAIL")}|{t.Detail}");
                if (!t.Pass) { Console.Error.WriteLine("GUARD BREAK: plaintext doc accepted as encrypted."); return 1; }
            }

            Console.WriteLine($"[{transportLabel}] All cross-version cells PASS (no data break); plaintext rejected.");
            return 0;
        }
        finally
        {
            foreach (INode n in nodes) { n.Dispose(); }
        }
    }

    private static IEnumerable<(string family, string wproc)> Cells()
    {
        yield return ("MDE", "Newtonsoft");
        yield return ("MDE", "Stream");
        yield return ("AEAD", "Newtonsoft");
        yield return ("AEAD", "Stream"); // unsupported-by-design: asserted to throw on write
    }

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

    private static void PrintGrid(List<GridRow> grid, string transportLabel)
    {
        Console.WriteLine($"\n===== COMPAT MATRIX GRID ({transportLabel}) =====");
        var rows = grid.OrderBy(g => g.Write).ThenBy(g => g.Read).ThenBy(g => g.Family).ThenBy(g => g.Wproc).ThenBy(g => g.Path).ToList();
        string[] headers = { "Write", "Read", "Algo", "wproc->rproc", "Path", "Status" };
        Func<GridRow, string>[] cols = { g => g.Write, g => g.Read, g => g.Family, g => g.Wproc, g => g.Path, g => g.Status };
        int[] w = headers.Select((h, i) => Math.Max(h.Length, rows.Count == 0 ? 0 : rows.Max(r => cols[i](r).Length))).ToArray();
        Console.WriteLine(string.Join("  ", headers.Select((h, i) => h.PadRight(w[i]))));
        foreach (GridRow r in rows) { Console.WriteLine(string.Join("  ", cols.Select((c, i) => c(r).PadRight(w[i])))); }
    }

    public static Dictionary<string, string> ParseArgs(string[] args)
    {
        Dictionary<string, string> d = new();
        foreach (string s in args)
        {
            int i = s.IndexOf('=');
            if (s.StartsWith("--") && i > 0) { d[s[2..i]] = s[(i + 1)..]; }
        }
        return d;
    }

    private sealed record GridRow(string Write, string Read, string Family, string Wproc, string Path, string Status, string Msg);
}
