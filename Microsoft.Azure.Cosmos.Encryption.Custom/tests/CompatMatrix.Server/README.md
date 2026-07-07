# CompatMatrix.Server — "thin server per version" spike (Option B)

> **This is a design SPIKE** for PR #5986, not a shipping change. It explores running the
> Encryption.Custom cross-version compat matrix as **one long-lived ASP.NET Core shim per package
> version**, driven by a **typed C# driver** over HTTP, instead of the short-lived subprocess +
> PowerShell-stdout harness in `tests/CompatMatrix/`. See **`EXPLORATION.md`** for the full
> comparison of alternatives and the recommendation.

Both shims share **one Cosmos DB** and cross-read every write/read combination — same versions,
same hardened document, same 42-cell grid, same exit codes as `tests/CompatMatrix/run-matrix.ps1`.
Proven **PASS=42, exit 0** against the Docker Linux emulator.

## Why a server (vs the subprocess harness)
- The matrix + assertions become **typed C# in the driver**, not an ad-hoc `CELL|…|PASS` stdout
  parser in PowerShell.
- Both versions run **at once** (no per-role process respawn); a cell is one HTTP round-trip.
- The HTTP contract is a stable, **curl-debuggable** interop boundary and scales to N versions.

## Fidelity invariant (why this is still a valid corruption test)
The hardened doc is built, encrypted and **self-verified inside the version-owning process**. Only
ids, selectors, status strings and a **SHA-256 signature hash** cross HTTP — never a decrypted field
— so ASP.NET's serializer can neither sit in the fidelity path nor leak plaintext. `MatrixCore`'s
`DecOk` (server-side `VerifyDoc`) is the per-cell PASS authority; the driver only compares hashes.

## Layout
- `shim/MatrixCore.cs` — per-cell encrypt/decrypt/verify; hardened doc + coverage identical to
  `tests/CompatMatrix/src/Program.cs`; returns signature **hashes** only.
- `shim/Shim.cs` — minimal ASP.NET Core host: `GET /version`, `POST /init|/write|/read|/tamper`.
- `shim/KeyProviders.cs` — reused verbatim (deterministic keys so DEKs interop across versions).
- `Old/` — pins `1.0.0-preview07` (nuget.org) → `CompatMatrix.Server.Old.dll`.
- `New/` — pins `1.1.0-preview01` (local-feed) → `CompatMatrix.Server.New.dll`.
- `Driver/Driver.cs` — typed orchestrator (ports, launch, version-guard, matrix, grid, exit codes).
- `AlcProbe/` — evidence for the single-process (Option D) analysis in `EXPLORATION.md`.
- `nuget.config` — nuget.org + local-feed mapping (same as `tests/CompatMatrix/nuget.config`).
- `run-server-matrix.ps1` — build the two shims + driver, run the matrix.

## Run
```powershell
docker run -d --name cosmos-emu -p 8081:8081 `
  mcr.microsoft.com/cosmosdb/linux/azure-cosmos-emulator:vnext-preview
cd Microsoft.Azure.Cosmos.Encryption.Custom/tests/CompatMatrix.Server
./run-server-matrix.ps1                     # -> PASS=42, exit 0
./run-server-matrix.ps1 -Processor Stream   # force a single read processor (30 cells)
```
Exit: `0` all PASS · `1` data/version/count/tamper break · `3` emulator unreachable (skip, no hang).

## HTTP contract (per shim)
| Method | Route | Body/query | Returns |
|---|---|---|---|
| GET | `/version` | — | `{version, expected, informational, assemblyVersion}` (no Cosmos) |
| POST | `/init` | — | `200` (Cosmos connected + DEKs created) or `503` |
| POST | `/write` | `?family=&wproc=&id=` | `{status, detail, expectedSignatureHash}` |
| POST | `/read` | `?family=&rproc=&path=&id=` | `{rawOk, rawDetail, decOk, detail, signatureHash}` |
| POST | `/tamper` | `?id=` | `{pass, detail}` |
