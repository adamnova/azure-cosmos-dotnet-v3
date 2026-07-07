// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// ------------------------------------------------------------
// SPIKE (Option C) driver: stdio/NDJSON transport. Launches the two long-lived stdio workers, then
// hands them to the SAME shared MatrixRunner the HTTP driver uses. The ONLY difference from the
// HTTP driver (Option B) is this INode implementation: request/response is a JSON line over the
// worker's stdin/stdout instead of an HTTP call — no Kestrel, no ports, no health-check polling.
namespace CompatMatrix.Server.StdioDriver;

using System.Diagnostics;
using System.Text.Json;
using CompatMatrix.Server.Harness;

internal static class Program
{
    private const string EmulatorKey = "C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw==";
    private static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true };

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

    // INode over stdio: one long-lived worker process per version; request/response is one JSON line.
    private sealed class StdioNode : INode
    {
        public string Name { get; }
        public string Expected { get; }
        public VersionInfo? Version { get; set; }
        private readonly string dll;
        private readonly SemaphoreSlim gate = new(1, 1);
        private string endpoint = "";
        private string key = "";
        private string db = "";
        private Process? proc;
        private StreamWriter? toWorker;
        private StreamReader? fromWorker;

        public StdioNode(string name, string dll, string expected)
        {
            this.Name = name;
            this.dll = dll;
            this.Expected = expected;
        }

        public void Launch(string endpoint, string key, string db)
        {
            this.endpoint = endpoint;
            this.key = key;
            this.db = db;
            ProcessStartInfo psi = new()
            {
                FileName = "dotnet",
                UseShellExecute = false,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            psi.ArgumentList.Add(this.dll);
            this.proc = Process.Start(psi)!;
            this.toWorker = this.proc.StandardInput;
            this.fromWorker = this.proc.StandardOutput;
            this.proc.ErrorDataReceived += (_, e) => { if (!string.IsNullOrWhiteSpace(e.Data)) { Console.Error.WriteLine($"[{this.Name}] {e.Data}"); } };
            this.proc.BeginErrorReadLine();
        }

        public async Task<VersionInfo?> WaitVersionAsync(TimeSpan timeout)
        {
            Task<VersionInfo> t = this.RpcAsync<VersionInfo>(new { op = "version" });
            Task done = await Task.WhenAny(t, Task.Delay(timeout));
            if (done != t) { return null; }
            try { return await t; } catch { return null; }
        }

        public async Task<(bool ok, string detail)> InitAsync()
        {
            try
            {
                InitReply r = await this.RpcAsync<InitReply>(new { op = "init", endpoint = this.endpoint, key = this.key, db = this.db });
                return (r.Ok, r.Error ?? "ok");
            }
            catch (Exception ex) { return (false, $"{ex.GetType().Name}: {ex.Message.Split('\n')[0]}"); }
        }

        public Task<WriteInfo> WriteAsync(string family, string wproc, string id)
            => this.RpcAsync<WriteInfo>(new { op = "write", family, wproc, id });

        public Task<ReadInfo> ReadAsync(string family, string rproc, string path, string id)
            => this.RpcAsync<ReadInfo>(new { op = "read", family, rproc, path, id });

        public Task<TamperInfo> TamperAsync(string id)
            => this.RpcAsync<TamperInfo>(new { op = "tamper", id });

        private async Task<T> RpcAsync<T>(object request)
        {
            await this.gate.WaitAsync();
            try
            {
                await this.toWorker!.WriteLineAsync(JsonSerializer.Serialize(request, Json));
                await this.toWorker.FlushAsync();
                string line = await this.ReadJsonLineAsync();
                return JsonSerializer.Deserialize<T>(line, Json)!;
            }
            finally { this.gate.Release(); }
        }

        // Read the next JSON-object line, skipping any stray non-JSON output (defensive against a
        // dependency accidentally writing to stdout — keeps the NDJSON framing robust).
        private async Task<string> ReadJsonLineAsync()
        {
            string? line;
            while ((line = await this.fromWorker!.ReadLineAsync()) != null)
            {
                line = line.Trim();
                if (line.StartsWith('{')) { return line; }
            }
            throw new IOException($"{this.Name}: worker stdout closed");
        }

        public void Dispose()
        {
            try { this.toWorker?.WriteLine(JsonSerializer.Serialize(new { op = "shutdown" }, Json)); this.toWorker?.Flush(); } catch { }
            try { if (this.proc is { HasExited: false }) { this.proc.Kill(entireProcessTree: true); } } catch { }
            this.proc?.Dispose();
            this.gate.Dispose();
        }

        private sealed record InitReply(bool Ok, string? Error);
    }
}
