// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// ------------------------------------------------------------
// SPIKE (Option B) driver: HTTP transport. Launches the two ASP.NET shims, then hands them to the
// shared, transport-agnostic MatrixRunner. Compare with DriverStdio (Option C): the ONLY difference
// between the two drivers is this INode implementation — the orchestration/matrix/grid is identical.
namespace CompatMatrix.Server.Driver;

using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
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
        string db = a.GetValueOrDefault("db", "compat-matrix-http-" + Guid.NewGuid().ToString("N")[..8]);
        string toggle = a.GetValueOrDefault("processor", "both").Trim().ToLowerInvariant();
        if (toggle is not ("newtonsoft" or "stream" or "both")) { toggle = "both"; }
        string oldDll = a.GetValueOrDefault("old", Path.Combine(root, "Old", "bin", "Release", "net8.0", "CompatMatrix.Server.Old.dll"));
        string newDll = a.GetValueOrDefault("new", Path.Combine(root, "New", "bin", "Release", "net8.0", "CompatMatrix.Server.New.dll"));

        if (!File.Exists(oldDll) || !File.Exists(newDll))
        {
            Console.Error.WriteLine($"Build the shims first. Missing:\n  {(File.Exists(oldDll) ? "" : oldDll)}\n  {(File.Exists(newDll) ? "" : newDll)}");
            return 1;
        }

        List<INode> nodes = new()
        {
            new HttpNode("old", oldDll, "1.0.0-preview07"),
            new HttpNode("new", newDll, "1.1.0-preview01"),
        };
        return await MatrixRunner.RunAsync(nodes, endpoint, key, db, toggle, "thin-server / HTTP");
    }

    // INode over HTTP: one long-lived ASP.NET shim per version on its own loopback port.
    private sealed class HttpNode : INode
    {
        public string Name { get; }
        public string Expected { get; }
        public VersionInfo? Version { get; set; }
        private readonly string dll;
        private readonly int port;
        private readonly HttpClient http;
        private Process? proc;

        public HttpNode(string name, string dll, string expected)
        {
            this.Name = name;
            this.dll = dll;
            this.Expected = expected;
            this.port = FreePort();
            this.http = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{this.port}"), Timeout = TimeSpan.FromSeconds(120) };
        }

        public void Launch(string endpoint, string key, string db)
        {
            ProcessStartInfo psi = new() { FileName = "dotnet", UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (string arg in new[] { this.dll, "--urls", $"http://127.0.0.1:{this.port}", "--endpoint", endpoint, "--key", key, "--db", db })
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
                return r.IsSuccessStatusCode ? (true, "ok") : (false, await r.Content.ReadAsStringAsync());
            }
            catch (Exception ex) { return (false, $"{ex.GetType().Name}: {ex.Message.Split('\n')[0]}"); }
        }

        public Task<WriteInfo> WriteAsync(string family, string wproc, string id)
            => this.PostAsync<WriteInfo>($"/write?family={family}&wproc={wproc}&id={Uri.EscapeDataString(id)}");

        public Task<ReadInfo> ReadAsync(string family, string rproc, string path, string id)
            => this.PostAsync<ReadInfo>($"/read?family={family}&rproc={rproc}&path={path}&id={Uri.EscapeDataString(id)}");

        public Task<TamperInfo> TamperAsync(string id)
            => this.PostAsync<TamperInfo>($"/tamper?id={Uri.EscapeDataString(id)}");

        private async Task<T> PostAsync<T>(string url)
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
}
