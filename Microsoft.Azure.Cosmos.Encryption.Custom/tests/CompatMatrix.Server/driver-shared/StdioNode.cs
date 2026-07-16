// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// ------------------------------------------------------------
// SPIKE (Option C) transport: INode over stdio. One long-lived worker process per version;
// request/response is one NDJSON line over the worker's stdin/stdout. Extracted to driver-shared so
// BOTH the console stdio driver (DriverStdio) and the dotnet-test harness (Tests) construct the same
// node. No ASP.NET, no ports, no health-check polling — the first response IS readiness.
namespace CompatMatrix.Server.Harness;

using System.Diagnostics;
using System.Text.Json;

public sealed class StdioNode : INode
{
    private static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true };
    private static readonly TimeSpan DefaultRpcTimeout = TimeSpan.FromSeconds(120);

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
    private bool faulted;

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
        => await this.RpcAsync<VersionInfo>(new { op = "version" }, timeout);

    public async Task<(bool ok, string detail)> InitAsync()
    {
        try
        {
            // init replies with {Ok, Error}, which legitimately carries an "Error" field — so the
            // error-envelope check is disabled here (see RpcAsync) to avoid misreading a normal reply.
            InitReply r = await this.RpcAsync<InitReply>(new { op = "init", endpoint = this.endpoint, key = this.key, db = this.db }, checkErrorEnvelope: false);
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

    // Every RPC is bounded by a timeout (default 120s), so a hung worker fails THIS cell with a clear
    // TimeoutException instead of hanging the whole run until the CI job timeout. On timeout the gate
    // is released by the finally (the read is cancelled first), so no semaphore leak.
    private async Task<T> RpcAsync<T>(object request, TimeSpan? timeout = null, bool checkErrorEnvelope = true)
    {
        // After a timeout the abandoned ReadLineAsync may still consume the worker's late line out of band,
        // so the stdout stream is no longer safe to reuse — fail fast on any further RPC to this node rather
        // than risk a desynced (mismatched) response. (A "promote to real harness" step could relaunch instead.)
        if (this.faulted) { throw new InvalidOperationException($"{this.Name} worker is faulted (a prior RPC timed out; its stdio stream is no longer safe to reuse)."); }
        await this.gate.WaitAsync();
        using CancellationTokenSource cts = new(timeout ?? DefaultRpcTimeout);
        try
        {
            await this.toWorker!.WriteLineAsync(JsonSerializer.Serialize(request, Json));
            await this.toWorker.FlushAsync();
            string line = await this.ReadJsonLineAsync(cts.Token);

            // #2: a worker-side failure comes back as the {Error:...} envelope. Deserializing that into a
            // typed result record would silently default-fill it (RawOk=false, Status=null, ...) and drop
            // the root cause. Detect it and surface the worker's message instead.
            if (checkErrorEnvelope)
            {
                using JsonDocument probe = JsonDocument.Parse(line);
                if (probe.RootElement.ValueKind == JsonValueKind.Object &&
                    (probe.RootElement.TryGetProperty("Error", out JsonElement e) || probe.RootElement.TryGetProperty("error", out e)))
                {
                    throw new InvalidOperationException($"{this.Name} worker error: {e.GetString()}");
                }
            }

            return JsonSerializer.Deserialize<T>(line, Json)!;
        }
        catch (OperationCanceledException)
        {
            this.faulted = true;
            throw new TimeoutException($"{this.Name} worker did not respond within {(timeout ?? DefaultRpcTimeout).TotalSeconds:0}s.");
        }
        finally { this.gate.Release(); }
    }

    // Read the next JSON-object line, skipping any stray non-JSON output (defensive against a
    // dependency accidentally writing to stdout — keeps the NDJSON framing robust).
    private async Task<string> ReadJsonLineAsync(CancellationToken ct)
    {
        string? line;
        while ((line = await this.fromWorker!.ReadLineAsync(ct)) != null)
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
