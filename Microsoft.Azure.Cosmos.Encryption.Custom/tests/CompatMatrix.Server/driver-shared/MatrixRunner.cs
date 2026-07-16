// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// ------------------------------------------------------------
// SPIKE shared console orchestration for BOTH the HTTP (Option B) and stdio (Option C) drivers.
// It is a THIN wrapper over MatrixHarness: the harness owns the version-guard, emulator gate, write
// phase, the cell enumerations (Cells/ReadProcessors/Read+EquivCells) and the per-cell operations —
// so the console grid and the `dotnet test` harness test the EXACT SAME matrix (no duplicated grid
// definition that could silently diverge). This runner only formats the grid and maps to exit codes:
//   0 = all PASS · 1 = data/version/count/tamper break · 3 = emulator unreachable (skip).
namespace CompatMatrix.Server.Harness;

public static class MatrixRunner
{
    public static async Task<int> RunAsync(IReadOnlyList<INode> nodes, string endpoint, string key, string db, string toggle, string transportLabel)
    {
        MatrixHarness harness = new(nodes);
        try
        {
            // Launch all workers at once, version-guard, emulator gate, write every cell (all in the harness).
            await harness.StartAsync(endpoint, key, db, toggle);

            if (harness.SkipReason is not null)
            {
                Console.WriteLine($"SKIP: {harness.SkipReason} Start the emulator, e.g.:");
                Console.WriteLine("  docker run -d --name cosmos-emu -p 8081:8081 mcr.microsoft.com/cosmosdb/linux/azure-cosmos-emulator:vnext-preview");
                return 3;
            }
            if (harness.FatalError is not null)
            {
                Console.Error.WriteLine(harness.FatalError);
                return 1;
            }

            Console.WriteLine($"[{transportLabel}] Versions: " + string.Join(" ", nodes.Select(n => $"{n.Name.ToUpperInvariant()}={n.Version!.Informational}")));
            Console.WriteLine($"[{transportLabel}] Emulator: {endpoint}  DB: {db}  Processor: {toggle}");
            foreach ((string writer, string family, string wproc, WriteInfo info) in harness.Writes)
            {
                Console.WriteLine($"WROTE|{writer}|{family}|{wproc}|{info.Status}|{info.Detail}");
            }

            // Read grid — driven by the SAME enumerations + per-cell ops the dotnet-test harness uses.
            List<GridRow> grid = new();
            foreach (object[] c in MatrixHarness.ReadCellsFor(toggle))
            {
                string writer = (string)c[0], reader = (string)c[1], family = (string)c[2], wproc = (string)c[3], rproc = (string)c[4], path = (string)c[5];
                (bool pass, string detail) = await harness.ReadCellAsync(writer, reader, family, wproc, rproc, path);
                grid.Add(new GridRow($"{writer}-write", $"{reader}-read", family, $"{wproc}->{rproc}", path, pass ? "PASS" : "FAIL", detail));
            }
            foreach (object[] c in MatrixHarness.EquivCellsFor(toggle))
            {
                string writer = (string)c[0], reader = (string)c[1], family = (string)c[2], wproc = (string)c[3];
                (bool pass, string detail) = await harness.EquivalenceAsync(writer, reader, family, wproc);
                grid.Add(new GridRow($"{writer}-write", $"{reader}-read", family, $"{wproc}->A/B", "equiv", pass ? "PASS" : "FAIL", detail));
            }

            PrintGrid(grid, transportLabel);
            int passCount = grid.Count(g => g.Status == "PASS");
            List<GridRow> fails = grid.Where(g => g.Status != "PASS").ToList();
            Console.WriteLine($"PASS={passCount} FAIL={fails.Count}");
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
                (bool pass, string detail) = await harness.TamperAsync(n.Name);
                Console.WriteLine($"TAMPER|{n.Name}|{(pass ? "PASS" : "FAIL")}|{detail}");
                if (!pass) { Console.Error.WriteLine("GUARD BREAK: plaintext doc accepted as encrypted."); return 1; }
            }

            Console.WriteLine($"[{transportLabel}] All cross-version cells PASS (no data break); plaintext rejected.");
            return 0;
        }
        finally
        {
            harness.Dispose();
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
