# EXPLORATION — cross-version Encryption.Custom compat matrix: "thin server" vs alternatives

Spike branch: `users/adamnova/enccustom-compat-matrix-server-spike` (based on PR #5986).
PR under discussion: https://github.com/Azure/azure-cosmos-dotnet-v3/pull/5986

This is a **design spike**, not a shipping change. It answers: *is the "thin server per version"
idea a good way to run the Encryption.Custom cross-version compat matrix, and how does it compare
to the subprocess harness already in PR #5986?* Everything here is test-only.

---

## 1. The problem, precisely

Prove a document written by one version of `Microsoft.Azure.Cosmos.Encryption.Custom` is
readable/decryptable by another, across **algorithm** (MDE / AEAD) × **JSON processor**
(Newtonsoft / System.Text.Json "Stream") × **read path** (point / query / feed), all over **one
shared Cosmos DB** (emulator). The two versions **cannot** be referenced by one project:

| Version | `Microsoft.Azure.Cosmos` | `Microsoft.Data.Encryption.Cryptography` |
|---|---|---|
| OLD `1.0.0-preview07` (nuget.org) | `3.41.0-preview.0` | **`0.2.0-pre`** |
| NEW `1.1.0-preview01` (local-feed) | `3.41.0-preview.0` | **`2.0.0-pre015`** |

Cosmos itself is the **same** version in both; only the MDE crypto dep (and the Encryption.Custom
assembly) differ. So the interop question is really about the Encryption.Custom layer + its crypto.

## 2. The one design constraint that governs every option — FIDELITY

The entire value of this harness is catching **Stream-processor data corruption** (string /
property-name double-escape, null-inside-encrypted-container, large-integer/double precision). Those
bugs live in the library's own JSON serialize/deserialize during encrypt/decrypt. Therefore:

> The hardened document must be **built, encrypted and self-verified inside the process that owns a
> specific Encryption.Custom version**. No transport (stdout, HTTP, IPC) may sit in the fidelity
> path, or it could mask (or fake) a corruption. Only ids, cell selectors, status strings, and a
> content **hash** may cross the wire.

Any option that ships the tricky doc *through* its transport's serializer to decide pass/fail is
**invalid**, regardless of how elegant it looks.

## 3. Solution space

| # | Approach | Isolation | Orchestration | Transport | Ceremony |
|---|---|---|---|---|---|
| **A** | Short-lived subprocess per version + PowerShell | process (per-role respawn) | PowerShell script | stdout text protocol | low |
| **B** | **Thin ASP.NET Core server per version + typed driver** | process (long-lived) | typed C# driver | HTTP/JSON | medium |
| **C** | Long-lived worker per version + stdio/named-pipe JSON-RPC | process (long-lived) | typed C# driver | stdin/stdout or pipe | low–medium |
| **D** | Single process, two `AssemblyLoadContext` | none (shared process) | in-proc | reflection across ALC | high |
| **E** | Docker-composed image per version | container | compose + driver | HTTP over docker net | high |

- **A** is the current PR. Its only real warts: matrix/orchestration logic lives in PowerShell and
  parses an ad-hoc `CELL|...|PASS` stdout protocol, and each role re-spawns the process.
- **B** is the user's idea and the focus of this spike.
- **C** is B's insight (long-lived versions + typed driver) minus the ASP.NET/Kestrel/port weight.
- **D** trades all process isolation for a single process; see the probe below.
- **E** is B taken to full container isolation — hermetic but heavy; noted for completeness.

## 4. What was actually built + proven (empirical)

### Option B — built and RUN GREEN against the live emulator
`tests/CompatMatrix.Server/`:
- `shim/MatrixCore.cs` — per-cell encrypt/decrypt/verify, **identical hardened doc + coverage** to
  PR #5986's `Program.cs`. Self-verifies (`VerifyDoc`) and returns only a **SHA-256 hash** of the
  canonical signature — no decrypted field ever crosses HTTP (fidelity invariant honored).
- `shim/Shim.cs` — minimal ASP.NET Core host: `GET /version`, `POST /init`, `POST /write`,
  `POST /read`, `POST /tamper`. `/version` answers via reflection so the version-guard works even
  with the emulator down.
- `shim/KeyProviders.cs` — reused verbatim (deterministic keys → a DEK made by one version yields
  identical key material to the other).
- `Old/` (`Sdk.Web`, pins preview07), `New/` (pins preview01) — one binary per version.
- `Driver/Driver.cs` — typed orchestrator: picks free ports, launches **both** servers at once,
  health-checks + version-guards them, drives the full matrix over HTTP, prints the grid, returns
  `0/1/3` exit codes. It is a direct re-expression of `run-matrix.ps1`.

**Result (Docker Linux emulator `http://127.0.0.1:8081`):**
```
Versions: OLD=1.0.0-preview07 NEW=1.1.0-preview01
PASS=42 FAIL=0
TAMPER|old|PASS|plaintext-rejected  TAMPER|new|PASS|plaintext-rejected
exit 0
```
Same **42 cells** as PR #5986's default `-Processor both`, same PASS, including cross-version
(old↔new both directions), **real Stream DECRYPT** honored on reads, and the cross-processor A/B
equivalence meta-cells (N-hash == S-hash == writer-hash). **B is functionally equivalent to A.**

### Option D — coexistence probe (`AlcProbe/`, evidence only)
Loaded both crypto DLLs into two `AssemblyLoadContext`s in one process:
```
OLD  ctx=old-crypto  Microsoft.Data.Encryption.Cryptography v0.2.0.0
NEW  ctx=new-crypto  Microsoft.Data.Encryption.Cryptography v2.0.0.0
Same full name, same runtime Type? False   (0.2.0.0 vs 2.0.0.0)
COEXIST=OK (both versions loaded live in ONE process)
```
**Verdict:** single-process is *technically possible* (ALC coexistence works). But the same type
name yields **two distinct runtime types**, so every version-specific value (`EncryptionOptions`,
`EncryptionItemRequestOptions`, the encryptor) must cross the boundary via **reflection** or as
primitives — i.e. you re-implement the per-version shim anyway, but behind a messier boundary,
with ALC lifetime hazards, and you **lose process isolation** (a native-crypto crash kills the whole
run). For a test harness, isolation is a feature. **Not worth it.**

## 5. Head-to-head

| Criterion | A (subprocess/PS) | **B (ASP.NET server)** | C (stdio worker) | D (ALC) |
|---|---|---|---|---|
| Proven green here | (PR: PASS=42) | **yes, PASS=42** | design only | coexist-only |
| Fidelity preserved | yes (stdout = status only) | **yes (hash only)** | yes (hash only) | yes (in-proc) |
| Versions run at once | no (per-role respawn) | **yes** | yes | yes |
| Matrix logic location | PowerShell | **typed C# driver** | typed C# driver | typed C#, +reflection |
| Transport | ad-hoc stdout text | **HTTP/JSON (curl-able)** | JSON lines | none |
| Process isolation | yes | **yes** | yes | **no** |
| Extra runtime dep | none | **ASP.NET Core** | none | none |
| Ports / lifecycle mgmt | none | **yes (2 servers)** | pipes only | none |
| Scales to N versions | ok | **clean** | clean | painful |
| Could be a `dotnet test` citizen | awkward | **natural** | natural | natural |
| Ceremony / new code | lowest | medium (3 projects) | low–medium | high |

## 6. Recommendation

1. **If the goal is to ship the matrix with least risk:** keep **A** (PR #5986). It already passes,
   is merge-ready, and the server model is a *nice-to-have*, not a correctness requirement.

2. **If the harness is expected to grow** (more versions, more cells, run under `dotnet test`,
   better CI per-cell reporting) — which is the likely trajectory — then the **long-lived-version +
   typed-driver** shape is the better foundation, because it moves the matrix and its assertions out
   of a stdout-parsing PowerShell script into typed, debuggable code, and it lets versions run at
   once. Two ways to get there:
   - **B (thin ASP.NET server)** — validated here, standard + curl-debuggable HTTP contract, the
     most natural path to a `dotnet test`-hosted harness (spin servers up in a fixture). Cost: an
     ASP.NET dependency and 2 server lifecycles/ports to manage. **Recommended if we adopt the
     server model.**
   - **C (stdio/named-pipe worker)** — the same wins with less ceremony (no Kestrel/ports). Best if
     we want the lightest possible long-lived-version harness and don't value HTTP's curl-ability.

3. **Avoid D and E** for this harness: D sacrifices the process isolation that makes the test
   trustworthy; E's container overhead isn't justified when process isolation already suffices.

**My call:** the server model is a genuine, proven improvement in *maintainability and
extensibility*, not correctness. If we're evolving the harness, go **B** (what was spiked) — or
**C** if we want to shed the ASP.NET/port overhead. If we're not evolving it soon, **A stays**.

## 7. How to reproduce
```powershell
# emulator (Docker Linux vnext-preview) on http://127.0.0.1:8081
docker run -d --name cosmos-emu -p 8081:8081 mcr.microsoft.com/cosmosdb/linux/azure-cosmos-emulator:vnext-preview
cd Microsoft.Azure.Cosmos.Encryption.Custom/tests/CompatMatrix.Server
./run-server-matrix.ps1                 # build 2 shims + driver, run full matrix -> PASS=42, exit 0
./run-server-matrix.ps1 -Processor Stream   # force single read processor (30 cells)
```
