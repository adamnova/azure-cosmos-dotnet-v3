// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// ------------------------------------------------------------
// SPIKE shared harness contract. The matrix-driving logic (MatrixRunner) is TRANSPORT-AGNOSTIC:
// it talks to nodes through INode, so the exact same orchestration runs over HTTP (Option B,
// HttpNode) or over stdio JSON-lines (Option C, StdioNode). This file is compiled into BOTH driver
// projects, which is the point of the comparison: only the transport differs.
namespace CompatMatrix.Server.Harness;

// A version-owning worker (one Encryption.Custom version), however it is reached.
public interface INode : IDisposable
{
    string Name { get; }             // "old" | "new"
    string Expected { get; }         // expected informational package version
    VersionInfo? Version { get; set; }

    void Launch(string endpoint, string key, string db);
    Task<VersionInfo?> WaitVersionAsync(TimeSpan timeout);
    Task<(bool ok, string detail)> InitAsync();
    Task<WriteInfo> WriteAsync(string family, string wproc, string id);
    Task<ReadInfo> ReadAsync(string family, string rproc, string path, string id);
    Task<TamperInfo> TamperAsync(string id);
}

// DTOs shared by both transports (mirror MatrixCore's records). Only ids/selectors/status + a
// SHA-256 signature hash ever cross the wire — never a decrypted field.
public sealed record VersionInfo(string Version, string Expected, string Informational, string AssemblyVersion);

public sealed record WriteInfo(string Status, string Detail, string ExpectedSignatureHash);

public sealed record ReadInfo(bool RawOk, string RawDetail, bool DecOk, string Detail, string SignatureHash);

public sealed record TamperInfo(bool Pass, string Detail);
