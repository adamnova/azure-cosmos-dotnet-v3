# CompatMatrix.Server — long-lived-worker compat-matrix spike (Options B & C)

> **This is a design SPIKE** for PR #5986, not a shipping change. It explores running the
> Encryption.Custom cross-version compat matrix as **one long-lived process per package version**,
> driven by a **typed C# driver**, instead of the short-lived subprocess + PowerShell-stdout harness
> in `tests/CompatMatrix/`. Two transports are prototyped and both run GREEN:
> - **Option B — thin ASP.NET Core server** per version, driven over **HTTP**.
> - **Option C — stdio NDJSON worker** per version, driven over **stdin/stdout** (no ASP.NET/ports).
>
> The matrix-driving logic is **transport-agnostic** (`driver-shared/MatrixRunner` + `INode`), so the
> two drivers differ ONLY in a ~90-line node implementation. See **`EXPLORATION.md`** for the full
> comparison of A/B/C/D/E and the recommendation.

Both transports share **one Cosmos DB** and cross-read every write/read combination — same versions,
same hardened document, same 42-cell grid, same exit codes as `tests/CompatMatrix/run-matrix.ps1`.
Proven **PASS=42, exit 0** against the Docker Linux emulator (each transport).

## Why a long-lived worker (vs the subprocess harness)
- The matrix + assertions become **typed C# in `MatrixRunner`**, not an ad-hoc `CELL|…|PASS` stdout
  parser in PowerShell.
- Both versions run **at once** (no per-role process respawn); a cell is one round-trip.
- The transport is swappable behind `INode` (HTTP for a curl-able contract, stdio for zero ceremony).

## Fidelity invariant (why this is still a valid corruption test)
The hardened doc is built, encrypted and **self-verified inside the version-owning process**. Only
ids, selectors, status strings and a **SHA-256 signature hash** cross the wire — never a decrypted
field — so the transport's serializer can neither sit in the fidelity path nor leak plaintext.
`MatrixCore.DecOk` (server-side `VerifyDoc`) is the per-cell PASS authority; the driver compares
hashes only. (Bonus: because only hashes cross the wire, the astral/surrogate payloads never hit the
transport encoder.)

## Layout
Shared version-owning core (compiled into every per-version binary):
- `shim/MatrixCore.cs` — per-cell encrypt/decrypt/verify; hardened doc + coverage identical to
  `tests/CompatMatrix/src/Program.cs`; returns signature **hashes** only.
- `shim/KeyProviders.cs` — reused verbatim (deterministic keys so DEKs interop across versions).

Option B (HTTP):
- `shim/Shim.cs` — minimal ASP.NET Core host: `GET /version`, `POST /init|/write|/read|/tamper`.
- `Old/`, `New/` — `Sdk.Web` binaries pinning preview07 / preview01.
- `Driver/Driver.cs` — `HttpNode : INode` + thin `Main`.

Option C (stdio):
- `shim/Worker.cs` — NDJSON stdio host (one JSON request/response per line).
- `OldWorker/`, `NewWorker/` — console binaries pinning preview07 / preview01.
- `driver-shared/StdioNode.cs` — `StdioNode : INode` (shared by the console driver and the test harness).
- `DriverStdio/DriverStdio.cs` — console driver (`MatrixRunner`: grid + exit codes).
- `Tests/` — **MSTest per-cell harness**: one `dotnet test` case per cell (`CompatMatrixCellTests` +
  `driver-shared/MatrixHarness`). 63 cases: 45 matrix cases (39 cells + 3 equivalence + 2 tamper +
  1 version guard) plus 18 follow-up contract tests. Optional local runs skip the 45 matrix cases
  when the emulator or workers are unavailable; required CI runs fail, with missing workers reported
  directly from class initialization.

Shared + support:
- `driver-shared/INode.cs`, `driver-shared/MatrixRunner.cs`, `driver-shared/MatrixHarness.cs` — the
  transport-agnostic orchestrator (console grid + per-cell test primitives) used by BOTH drivers and
  the `dotnet test` harness.
- `AlcProbe/` — evidence for the single-process (Option D) analysis in `EXPLORATION.md`.
- `nuget.config` — nuget.org + local-feed mapping (dev). `nuget.ci.config` — CI variant that resolves
  NEW from `%COMPATMATRIX_FEED%` (a pack-from-source feed) instead of the local feed.
- `run-server-matrix.ps1` — build + run either/both transports.
- `CompatMatrix.Server.sln` — standalone solution grouping all 8 projects (not in the main solution).
- `azure-pipelines-compat-matrix.yml` — **opt-in** (`trigger: none`) CI leg: packs the in-repo source
  as preview01 and runs the per-cell harness on the Windows emulator. See EXPLORATION.md §8 for why it
  is opt-in and when it goes green.

## Run
```powershell
docker run -d --name cosmos-emu -p 8081:8081 `
  mcr.microsoft.com/cosmosdb/linux/azure-cosmos-emulator:vnext-preview
cd Microsoft.Azure.Cosmos.Encryption.Custom/tests/CompatMatrix.Server
./run-server-matrix.ps1 -Transport http    # Option B -> PASS=42, exit 0
./run-server-matrix.ps1 -Transport stdio   # Option C -> PASS=42, exit 0
./run-server-matrix.ps1 -Transport both    # both, back to back
./run-server-matrix.ps1 -Transport stdio -Processor Stream   # force a single read processor (30 cells)

# Option C as a PROPER dotnet-test harness — one MSTest case per cell; skips cleanly with no emulator:
dotnet test ./Tests/CompatMatrix.Server.Tests.csproj -c Release
#   emulator up             -> Passed: 63 (45 matrix + 18 follow-up), Failed: 0
#   emulator down, optional -> Skipped: 45, Passed: 18 follow-up, Failed: 0
#   required mode           -> failures are fatal; missing workers fail class initialization
```
Exit: `0` all PASS · `1` data/version/count/tamper break · `3` emulator unreachable (skip, no hang).

## Contracts
**Option B — HTTP (per shim):**
| Method | Route | Query | Returns |
|---|---|---|---|
| GET | `/version` | — | `{version, expected, informational, assemblyVersion}` (no Cosmos) |
| POST | `/init` | — | `200` (Cosmos + DEKs) or `503` |
| POST | `/write` | `?family=&wproc=&id=` | `{status, detail, expectedSignatureHash}` |
| POST | `/read` | `?family=&rproc=&path=&id=` | `{rawOk, rawDetail, decOk, detail, signatureHash}` |
| POST | `/tamper` | `?id=` | `{pass, detail}` |

**Option C — stdio NDJSON (per worker):** one JSON request object per line on stdin, one JSON
response per line on stdout. Ops: `version` · `init {endpoint,key,db}` · `write {family,wproc,id}` ·
`read {family,rproc,path,id}` · `tamper {id}` · `shutdown`. Responses mirror the HTTP DTOs.

## Version pin & retarget
`CompatMatrixOldVersion` stays pinned to `1.0.0-preview07`. `CompatMatrixNewVersion` defaults to
`1.1.0-preview01` for local development, and flows into all NEW package references plus assembly
metadata consumed by the workers, drivers, and test version guards.

CI derives `1.1.0-preview01.g<short-commit>` from `Build.SourceVersion`, passes it as
`CustomEncryptionVersion` when packing, and passes the same value as `CompatMatrixNewVersion` when
restoring and testing. Pack and test/build both use Release plus a clean, build-unique NuGet packages
directory. This avoids reusing a fixed NEW package identity or cached package contents while keeping
local commands unchanged.

## Notes
- Each run uses a fresh GUID database (`compat-matrix-*`); repeated local runs accumulate DBs on the
  emulator (2 containers × 400 RU each). The emulator is ephemeral, so this is only a local-tidiness
  note; a future best-effort drop-database on dispose would require a new worker op.
