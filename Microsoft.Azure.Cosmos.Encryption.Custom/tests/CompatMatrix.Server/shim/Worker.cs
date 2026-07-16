// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// ------------------------------------------------------------
// SPIKE (Option C): the stdio worker host. Same version-owning MatrixCore + KeyProviders as the
// ASP.NET shim (Shim.cs) -- ONLY the transport differs: instead of Kestrel + HTTP + a port, this
// reads newline-delimited JSON (NDJSON) requests from stdin and writes one JSON response per line
// to stdout, staying alive in a loop. No ASP.NET, no ports, no health-check polling.
//
// Requests (one JSON object per line):
//   {"op":"version"}
//   {"op":"init","endpoint":..,"key":..,"db":..}
//   {"op":"write","family":..,"wproc":..,"id":..}
//   {"op":"read","family":..,"rproc":..,"path":..,"id":..}
//   {"op":"tamper","id":..}
//   {"op":"shutdown"}
// Responses mirror MatrixCore's records (version/write/read/tamper) or {"ok":..,"error":..} for init.
namespace CompatMatrix.Server
{
    using System;
    using System.IO;
    using System.Text.Json;
    using System.Threading.Tasks;

    public static class Worker
    {
        private static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true };

        public static async Task Main()
        {
            TextReader stdin = Console.In;
            TextWriter stdout = Console.Out;
            string line;
            while ((line = await stdin.ReadLineAsync()) != null)
            {
                if (string.IsNullOrWhiteSpace(line)) { continue; }
                Req req;
                try { req = JsonSerializer.Deserialize<Req>(line, Json); }
                catch (Exception ex) { WriteLine(stdout, new ErrorResult($"bad-request: {ex.Message}")); continue; }

                try
                {
                    switch (req.Op)
                    {
                        case "version": WriteLine(stdout, MatrixCore.VersionInfo()); break;
                        case "init":
                            await MatrixCore.InitAsync(req.Endpoint, req.Key, req.Db);
                            WriteLine(stdout, new InitResult(true, null));
                            break;
                        case "write": WriteLine(stdout, await MatrixCore.WriteAsync(req.Family, req.Wproc, req.Id)); break;
                        case "read": WriteLine(stdout, await MatrixCore.ReadAsync(req.Family, req.Rproc, req.Path, req.Id)); break;
                        case "tamper": WriteLine(stdout, await MatrixCore.TamperAsync(req.Id)); break;
                        case "shutdown": return;
                        default: WriteLine(stdout, new ErrorResult($"unknown-op:{req.Op}")); break;
                    }
                }
                catch (Exception ex)
                {
                    // init failure (emulator down) is expected/handled by the driver; keep the loop alive on anything else.
                    if (req.Op == "init") { WriteLine(stdout, new InitResult(false, $"{ex.GetType().Name}: {ex.Message.Split('\n')[0]}")); }
                    else { WriteLine(stdout, new ErrorResult($"{ex.GetType().Name}: {ex.Message.Split('\n')[0]}")); }
                }
            }
        }

        private static void WriteLine(TextWriter w, object o)
        {
            w.WriteLine(JsonSerializer.Serialize(o, Json));
            w.Flush();
        }

        private sealed class Req
        {
            public string Op { get; set; }
            public string Endpoint { get; set; }
            public string Key { get; set; }
            public string Db { get; set; }
            public string Family { get; set; }
            public string Wproc { get; set; }
            public string Rproc { get; set; }
            public string Path { get; set; }
            public string Id { get; set; }
        }

        private sealed record InitResult(bool Ok, string Error);

        private sealed record ErrorResult(string Error);
    }
}
