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

Both long-lived-worker options (B and C) were built and share ONE **transport-agnostic** orchestrator
(`driver-shared/MatrixRunner.cs` + `INode`): version-guard → emulator gate → write → cross-read grid
→ exact-count → tamper. The two drivers differ ONLY in a ~90-line `INode` implementation
(`HttpNode` vs `StdioNode`). This is the core finding: the matrix/assertions are independent of the
transport, so choosing B vs C is purely a transport/ergonomics decision.

### Option B — built and RUN GREEN against the live emulator (HTTP)
`tests/CompatMatrix.Server/`:
- `shim/MatrixCore.cs` — per-cell encrypt/decrypt/verify, **identical hardened doc + coverage** to
  PR #5986's `Program.cs`. Self-verifies (`VerifyDoc`) and returns only a **SHA-256 hash** of the
  canonical signature — no decrypted field ever crosses the wire (fidelity invariant honored).
- `shim/Shim.cs` — minimal ASP.NET Core host: `GET /version`, `POST /init|/write|/read|/tamper`.
- `shim/KeyProviders.cs` — reused verbatim (deterministic keys → a DEK made by one version yields
  identical key material to the other).
- `Old/` (`Sdk.Web`, pins preview07), `New/` (pins preview01) — one binary per version.
- `Driver/Driver.cs` — `HttpNode : INode` + a thin `Main` that hands nodes to `MatrixRunner`.

**Result (Docker Linux emulator `http://127.0.0.1:8081`):**
```
[thin-server / HTTP] Versions: OLD=1.0.0-preview07 NEW=1.1.0-preview01
PASS=42 FAIL=0   TAMPER|old|PASS  TAMPER|new|PASS   exit 0
```
Same **42 cells** as PR #5986's default `-Processor both`, same PASS, including cross-version
(old↔new both directions), **real Stream DECRYPT** honored on reads, and the cross-processor A/B
equivalence meta-cells (N-hash == S-hash == writer-hash). **B is functionally equivalent to A.**

### Option C — built and RUN GREEN against the live emulator (stdio)
Same `MatrixCore` + `KeyProviders` + `MatrixRunner`; the only new code is the host and the node:
- `shim/Worker.cs` — an NDJSON stdio host (reads one JSON request per line from stdin, writes one
  JSON response per line to stdout). No ASP.NET, no Kestrel, no port.
- `OldWorker/`, `NewWorker/` — plain console (`Microsoft.NET.Sdk`) workers, one per version.
- `DriverStdio/DriverStdio.cs` — `StdioNode : INode` (request/response over the worker's
  stdin/stdout) + a thin `Main` that hands nodes to the SAME `MatrixRunner`.

**Result (same emulator):**
```
[stdio worker / NDJSON] Versions: OLD=1.0.0-preview07 NEW=1.1.0-preview01
PASS=42 FAIL=0   TAMPER|old|PASS  TAMPER|new|PASS   exit 0
```
Identical 42-cell PASS to A and B, with **less machinery** (no HTTP stack, no ports, no health-check
polling — the first response IS readiness). NDJSON framing is trivial and the driver defensively
skips any stray non-`{` stdout line. Because responses are hashes/status only, there are also **no
encoding pitfalls** for the astral/surrogate payloads (they never enter the transport).

**Wired as a `dotnet test` harness** (`Tests/CompatMatrixCellTests.cs` + `driver-shared/MatrixHarness`):
each matrix cell is its own MSTest case via `[DynamicData]`, so `dotnet test` gives **per-cell**
PASS/FAIL reporting (e.g. `Cell_RoundTrips ("new","old","MDE","Stream","Newtonsoft","point")`).
`[ClassInitialize]` launches the two stdio workers once; `[ClassCleanup]` disposes them; the workers
are built via `ProjectReference ReferenceOutputAssembly="false"`. Result:
- **emulator up → `Passed: 45`** (39 cells + 3 equivalence + 2 tamper + 1 version guard),
- **emulator down → `Skipped: 45, Failed: 0`** (`Assert.Inconclusive`) — safe in non-emulator CI legs.

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
| Proven green here | (PR: PASS=42) | **yes, PASS=42** | **yes, PASS=42** | coexist-only |
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
   once. Both proven-green options share the exact same `MatrixRunner`; pick a transport:
   - **C (stdio/NDJSON worker)** — **my pick if we adopt the worker model.** Same 42-cell PASS as B
     with the least machinery: no ASP.NET dependency, no Kestrel, no ports, no health-check polling.
     The `INode` implementation is ~90 lines. It is the natural "spawn a process, talk to it" model.
   - **B (thin ASP.NET server)** — choose over C only if you specifically want a standard,
     curl-debuggable HTTP contract (e.g. to poke a version by hand, or reuse the shim outside the
     harness). Costs an ASP.NET dependency and 2 server lifecycles/ports to manage.

3. **Avoid D and E** for this harness: D sacrifices the process isolation that makes the test
   trustworthy (probe: coexistence works, but every version-specific value must cross a reflection
   boundary); E's container overhead isn't justified when process isolation already suffices.

**My call:** the worker model is a genuine, proven improvement in *maintainability and
extensibility*, not correctness. If we're evolving the harness, go **C** (stdio) for the lightest
footprint, or **B** (HTTP) if a curl-able contract earns its keep. If we're not evolving it soon,
**A (PR #5986) stays** — it already passes and ships.

**Decision taken in this spike:** **C** was adopted and wired as a proper `dotnet test` harness
(`Tests/`), turning each matrix cell into its own MSTest case with clean emulator-skip semantics. The
console drivers (both transports) and the `AlcProbe` remain as comparison artifacts.

## 7. How to reproduce
```powershell
# emulator (Docker Linux vnext-preview) on http://127.0.0.1:8081
docker run -d --name cosmos-emu -p 8081:8081 mcr.microsoft.com/cosmosdb/linux/azure-cosmos-emulator:vnext-preview
cd Microsoft.Azure.Cosmos.Encryption.Custom/tests/CompatMatrix.Server
./run-server-matrix.ps1 -Transport http    # Option B: ASP.NET shims + HTTP driver -> PASS=42
./run-server-matrix.ps1 -Transport stdio   # Option C: stdio NDJSON workers        -> PASS=42
./run-server-matrix.ps1 -Transport both    # run both back to back
./run-server-matrix.ps1 -Transport stdio -Processor Stream   # force single read processor (30 cells)
cd AlcProbe; dotnet run                     # Option D coexistence evidence
```

## 8. CI integration — what's feasible, and the pack-from-source finding
The matrix needs TWO packages: OLD = `1.0.0-preview07` (nuget.org) and NEW = `1.1.0-preview01`. The
**fixed** preview01 exists only in the developer `local-feed` (built from the Stream-corruption-fixes
branch); it is **not on any CI-accessible feed**. That is exactly why the sibling subprocess harness
(`tests/CompatMatrix`) is a MANUAL script excluded from the solution — the standard CI restore
(repo-root `NuGet.config`, no local-feed) can't get preview01. Two CI paths:

- **Publish-then-restore (truthful, future):** once `1.1.0-preview01` is published to nuget.org or an
  ADO artifact feed, a leg just restores it (drop the pack step; point `COMPATMATRIX_FEED` at that
  feed). Tests the SHIPPED package; can auto-run and stay green.
- **Pack-from-source (regression, now):** `azure-pipelines-compat-matrix.yml` (opt-in, `trigger: none`)
  packs the in-repo source — which versions to `1.1.0-preview01` — into a temp feed and resolves NEW
  from `%COMPATMATRIX_FEED%` via `nuget.ci.config`. No checked-in feed needed. This tests CURRENT
  (HEAD source) ↔ OLD — a HEAD regression leg.

**Validated locally (the plumbing):** `dotnet pack` → NEW restores `1.1.0-preview01` from the packed
feed into a CLEAN packages dir (no local-feed, no cache) → the harness runs. **Finding:** packing
*this* branch's source yields an **unfixed** preview01, so the hardened **Stream** cells FAIL with the
exact RUN-REPORT §8 signature — `PlainEscaped got 'p_q=\" p_b=\\ …' want 'p_q=" p_b=\ …'` (Stream
plaintext double-escape) — while Newtonsoft/AEAD cells pass (**24 fail / 21 pass**). That is the
anti-fake-green control working, and a demonstration that the per-cell harness **pinpoints the exact
failing field and cell**. The leg turns fully green once the Stream fixes are in the source under test
(e.g. after they merge to main). The dev run is green because there NEW = the *fixed* local-feed
preview01.

## 9. Build/run as a unit
`CompatMatrix.Server.sln` groups all 8 projects (shims, workers, drivers, test, probe) so
`dotnet build CompatMatrix.Server.sln` / `dotnet test` work as one unit. It is a standalone solution
(not added to `Microsoft.Azure.Cosmos.sln`, matching the isolated `tests/CompatMatrix` pattern),
because the preview01 dependency is not restorable from the repo-root feed.
