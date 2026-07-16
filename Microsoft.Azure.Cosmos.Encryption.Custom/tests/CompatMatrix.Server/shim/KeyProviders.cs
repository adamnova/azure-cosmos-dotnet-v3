// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// ------------------------------------------------------------
// Shared test key providers for the compat-matrix SERVER shims (spike Option B).
// Byte-for-byte identical semantics to tests/CompatMatrix/src/KeyProviders.cs; only the namespace
// differs (CompatMatrix.Server). Compiled into BOTH the OLD (preview07) and NEW (preview01) shims,
// against whichever Microsoft.Data.Encryption.Cryptography each package pins. The providers are
// DETERMINISTIC (fixed derived key), so a DEK created by one version yields identical key material
// to the other -> a doc encrypted by OLD is decryptable by NEW over the shared DB, and vice-versa.
namespace CompatMatrix.Server
{
    using System;
    using System.Linq;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.Azure.Cosmos.Encryption.Custom;
    using Microsoft.Data.Encryption.Cryptography;

    internal sealed class MatrixKeyStoreProvider : EncryptionKeyStoreProvider
    {
        private readonly byte[] derived = Enumerable.Range(0, 32).Select(i => (byte)(255 - i)).ToArray();

        public override string ProviderName => "matrix-store";

        public override byte[] UnwrapKey(string id, KeyEncryptionKeyAlgorithm a, byte[] enc) => this.derived;

        public override byte[] WrapKey(string id, KeyEncryptionKeyAlgorithm a, byte[] key) => key;

        public override byte[] Sign(string id, bool enclave) => new byte[] { 0x01 };

        public override bool Verify(string id, bool enclave, byte[] sig) => sig?.Length == 1 && sig[0] == 0x01;
    }

    internal sealed class MatrixWrapProvider : EncryptionKeyWrapProvider
    {
        public override Task<EncryptionKeyUnwrapResult> UnwrapKeyAsync(byte[] wrapped, EncryptionKeyWrapMetadata md, CancellationToken ct)
            => Task.FromResult(new EncryptionKeyUnwrapResult(wrapped.Select(b => (byte)(b - 2)).ToArray(), TimeSpan.FromDays(1)));

        public override Task<EncryptionKeyWrapResult> WrapKeyAsync(byte[] key, EncryptionKeyWrapMetadata md, CancellationToken ct)
            => Task.FromResult(new EncryptionKeyWrapResult(key.Select(b => (byte)(b + 2)).ToArray(), md));
    }

    internal sealed class MatrixEncryptor : Encryptor
    {
        private readonly CosmosEncryptor inner;

        public MatrixEncryptor(DataEncryptionKeyProvider provider) => this.inner = new CosmosEncryptor(provider);

        public override Task<byte[]> DecryptAsync(byte[] cipherText, string dekId, string algo, CancellationToken ct = default)
            => this.inner.DecryptAsync(cipherText, dekId, algo, ct);

        public override Task<byte[]> EncryptAsync(byte[] plainText, string dekId, string algo, CancellationToken ct = default)
            => this.inner.EncryptAsync(plainText, dekId, algo, ct);
#if CEC_NEW
        public override Task<Microsoft.Azure.Cosmos.Encryption.Custom.DataEncryptionKey> GetEncryptionKeyAsync(string dekId, string algo, CancellationToken ct = default)
            => this.inner.GetEncryptionKeyAsync(dekId, algo, ct);
#endif
    }
}
