# Encryption.Custom compatibility evidence matrix

This optional `net8.0` emulator harness validates one explicitly selected
Encryption.Custom candidate against the exact released
`Microsoft.Azure.Cosmos.Encryption.Custom` `1.0.0-preview07` package. The
released and candidate workers run in separate processes and both consume
packages; the candidate worker never uses a project reference.

The harness is test-only. It does not implement transport fallback or rewind
policy. It records the behavior of the selected package at actual item,
query/feed, and read-many SDK boundaries.

## Sealed package identity

The candidate is identified by all of:

- an absolute `.nupkg` path;
- its exact package version and independently supplied archive SHA-256;
- the full source commit expected in assembly informational version;
- the local directory containing that exact archive.

Each worker restores into a SHA-scoped isolated package directory. Build and
runtime evidence records the package archive path/hash/source, selected package
assembly hash, loaded assembly path/hash/MVID/version, Cosmos dependency
closure, and distinct released/current binaries. A missing archive, wrong
source, wrong hash, global-cache substitution, or package/project dependency
fails the build or matrix.

## Payload and fixture oracle

Every typed and raw-stream success must return the complete expected payload:
identity and partition key plus protected and unprotected strings, arrays,
objects, nulls, long values, and ISO date strings. The payload also exercises
escaped/astral strings and integral/non-integral doubles.

- Decrypted output must contain every expected value and JSON token type and
  must not retain `_ei`.
- Newtonsoft comparisons require semantic preservation, not formatting.
- Stream comparisons additionally pin numeric lexical form where the Stream
  contract applies.
- MDE-v3 at-rest properties must be opaque ciphertext with exact `_ei`
  metadata (`_ef`, `_en`, `_ea`, `_ed: null`, ordered `_ep`).
- AEAD-v2 at-rest documents must not retain protected plaintext.
- Non-sensitive fields must remain exact across rewrites.

The released worker creates the authentic preview07 fixtures. Their ciphertext
and package identities are hash-pinned at the process boundary before current
code can read or rewrite them. Fixture hashing canonicalizes JSON whitespace,
so LF/CRLF transport differences do not alter identity; ciphertext values,
token types, metadata, and package hashes remain exact.

## Coverage

The 60-observation catalog includes:

- released MDE/AEAD writes and a released plaintext fixture;
- candidate MDE Newtonsoft/Stream and AEAD Newtonsoft writes;
- released-to-candidate point, query, feed, and read-many reads;
- candidate MDE Newtonsoft/Stream cross-reads;
- candidate-to-released rollback reads for common wire formats;
- representative released-MDE read/modify/write transitions through both
  candidate processors and both candidate point readers;
- actual nonzero-position Stream input and read-only SDK response probes;
- explicit legacy AEAD Stream-write rejection with no stored item.

A Stream request for MDE is not accepted as Newtonsoft success. Legacy AEAD
fallback remains algorithm-specific and requires direct external decryptor
evidence. Old packages are not required to read an unknown future wire format.

`CompatibilityMatrixInfrastructureTests` run without the emulator and prove the
oracle rejects missing/duplicate cells, payload deletion, string/date mutation,
wrong package/source/hash identity, processor substitution, malformed hashes,
and incomplete MDE metadata.

## Final integrated run

Run this once after the integrated candidate package exists:

```powershell
$candidate = "C:\absolute\sealed-feed\Microsoft.Azure.Cosmos.Encryption.Custom.<exact-version>.nupkg"
$candidateVersion = "<exact-version>"
$candidateSha256 = "<independently-recorded-64-character-SHA256>"
$candidateCommit = "<full-40-character-integrated-source-SHA>"
$transitiveSource = "<sealed-transitive-package-source>"

dotnet test ..\EmulatorTests\Microsoft.Azure.Cosmos.Encryption.Custom.EmulatorTests.csproj `
  -f net8.0 `
  -c Release `
  --filter "FullyQualifiedName~CrossVersionCompatibilityTests" `
  -p:RunEncryptionCustomCompatibilityMatrix=true `
  -p:CompatMatrixReleasedPackageSource="https://api.nuget.org/v3/index.json" `
  -p:CompatMatrixCurrentPackagePath="$candidate" `
  -p:CompatMatrixCurrentPackageVersion="$candidateVersion" `
  -p:CompatMatrixCurrentPackageSha256="$candidateSha256" `
  -p:CompatMatrixCurrentSourceCommit="$candidateCommit" `
  -p:CompatMatrixTransitivePackageSource="$transitiveSource"
```

The endpoint must be HTTPS loopback on port 8081 and uses Gateway mode.
Certificate bypass is limited to that endpoint. The account key is passed to
workers only through `COSMOS_COMPAT_MATRIX_KEY`.
