// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// ------------------------------------------------------------
// SPIKE (Option C) console driver: stdio/NDJSON transport. Launches the two long-lived stdio
// workers (shared StdioNode) and hands them to the shared, transport-agnostic MatrixRunner — the
// SAME runner the HTTP driver uses. The dotnet-test harness (Tests/) drives the same StdioNode +
// MatrixHarness with one test case per cell; this console driver is the scriptable equivalent.
namespace CompatMatrix.Server.StdioDriver;

using CompatMatrix.Server.Harness;

internal static class Program
{
    private const string EmulatorKey = "C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw==";

    private static async Task<int> Main(string[] args)
    {
        Dictionary<string, string> a = MatrixRunner.ParseArgs(args);
        string root = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));   // -> tests/CompatMatrix.Server
        string endpoint = a.GetValueOrDefault("endpoint", Environment.GetEnvironmentVariable("COSMOS_ENDPOINT") ?? "http://127.0.0.1:8081/");
        string key = a.GetValueOrDefault("key", Environment.GetEnvironmentVariable("COSMOS_KEY") ?? EmulatorKey);
        string db = a.GetValueOrDefault("db", "compat-matrix-stdio-" + Guid.NewGuid().ToString("N")[..8]);
        string toggle = a.GetValueOrDefault("processor", "both").Trim().ToLowerInvariant();
        if (toggle is not ("newtonsoft" or "stream" or "both")) { toggle = "both"; }
        string oldDll = a.GetValueOrDefault("old", Path.Combine(root, "OldWorker", "bin", "Release", "net8.0", "CompatMatrix.Worker.Old.dll"));
        string newDll = a.GetValueOrDefault("new", Path.Combine(root, "NewWorker", "bin", "Release", "net8.0", "CompatMatrix.Worker.New.dll"));

        if (!File.Exists(oldDll) || !File.Exists(newDll))
        {
            Console.Error.WriteLine($"Build the workers first. Missing:\n  {(File.Exists(oldDll) ? "" : oldDll)}\n  {(File.Exists(newDll) ? "" : newDll)}");
            return 1;
        }

        List<INode> nodes = new()
        {
            new StdioNode("old", oldDll, "1.0.0-preview07"),
            new StdioNode("new", newDll, "1.1.0-preview01"),
        };
        return await MatrixRunner.RunAsync(nodes, endpoint, key, db, toggle, "stdio worker / NDJSON");
    }
}
