// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// ------------------------------------------------------------
// SPIKE (Option B): the "thin server" — a minimal ASP.NET Core shim that exposes ONE package
// version's encrypt/decrypt over HTTP. The driver launches one of these per version (Old/New),
// they share ONE Cosmos DB, and cross-read every write/read combination. This replaces the
// subprocess "--role + stdout text protocol" of tests/CompatMatrix with an HTTP contract while
// keeping the crypto/document/verify logic (MatrixCore) inside the version-owning process.
//
// Launch (the driver does this):
//   dotnet CompatMatrix.Server.<Old|New>.dll --urls http://127.0.0.1:<port> \
//       --endpoint <cosmos> --key <key> --db <shared-db>
//
// Endpoints (all payloads are selectors/status only — the sensitive doc never crosses HTTP):
//   GET  /version                                  -> VersionResult   (no Cosmos; safe when emulator down)
//   POST /init                                     -> 200 | 503       (connects to Cosmos, creates DEKs)
//   POST /write?family=&wproc=&id=                 -> WriteResult
//   POST /read?family=&rproc=&path=&id=            -> ReadResult
//   POST /tamper?id=                               -> TamperResult
namespace CompatMatrix.Server
{
    using System;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Builder;
    using Microsoft.AspNetCore.Http;
    using Microsoft.Extensions.Configuration;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.Logging;

    public static class Shim
    {
        private const string EmulatorKey = "C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw==";
        private static volatile bool initialized;

        public static async Task Main(string[] args)
        {
            WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
            builder.Logging.ClearProviders();
            builder.Logging.SetMinimumLevel(LogLevel.Warning);
            WebApplication app = builder.Build();

            IConfiguration cfg = app.Configuration;
            string endpoint = cfg["endpoint"] ?? Environment.GetEnvironmentVariable("COSMOS_ENDPOINT") ?? "https://127.0.0.1:8081/";
            string key = cfg["key"] ?? Environment.GetEnvironmentVariable("COSMOS_KEY") ?? EmulatorKey;
            string db = cfg["db"] ?? "compat-matrix";

            // /version answers via reflection only, so the driver can build+version-guard even with no emulator.
            app.MapGet("/version", () => Results.Json(MatrixCore.VersionInfo()));

            app.MapPost("/init", async () =>
            {
                try
                {
                    await MatrixCore.InitAsync(endpoint, key, db);
                    initialized = true;
                    return Results.Ok(new { ok = true, db });
                }
                catch (Exception ex)
                {
                    return Results.Json(new { ok = false, error = $"{ex.GetType().Name}: {ex.Message.Split('\n')[0]}" }, statusCode: 503);
                }
            });

            app.MapPost("/write", async (string family, string wproc, string id) =>
                initialized ? Results.Json(await MatrixCore.WriteAsync(family, wproc, id)) : NotReady());

            app.MapPost("/read", async (string family, string rproc, string path, string id) =>
                initialized ? Results.Json(await MatrixCore.ReadAsync(family, rproc, path, id)) : NotReady());

            app.MapPost("/tamper", async (string id) =>
                initialized ? Results.Json(await MatrixCore.TamperAsync(id)) : NotReady());

            await app.RunAsync();
        }

        private static IResult NotReady() => Results.Json(new { ok = false, error = "not-initialized; POST /init first" }, statusCode: 409);
    }
}
