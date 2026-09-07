//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

namespace CompatMatrix
{
    using System;
    using System.Linq;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.Azure.Cosmos.Encryption.Custom;
    using Microsoft.Data.Encryption.Cryptography;
    using CustomDataEncryptionKey = Microsoft.Azure.Cosmos.Encryption.Custom.DataEncryptionKey;

    internal sealed class MatrixKeyStoreProvider : EncryptionKeyStoreProvider
    {
        public override string ProviderName => "compat-matrix-store";

        public override byte[] UnwrapKey(
            string encryptionKeyId,
            KeyEncryptionKeyAlgorithm algorithm,
            byte[] encryptedKey)
        {
            int shift = GetShift(encryptionKeyId);
            return encryptedKey.Select(value => unchecked((byte)(value - shift))).ToArray();
        }

        public override byte[] WrapKey(
            string encryptionKeyId,
            KeyEncryptionKeyAlgorithm algorithm,
            byte[] key)
        {
            int shift = GetShift(encryptionKeyId);
            return key.Select(value => unchecked((byte)(value + shift))).ToArray();
        }

        public override byte[] Sign(string encryptionKeyId, bool allowEnclaveComputations)
        {
            return new[] { (byte)GetShift(encryptionKeyId) };
        }

        public override bool Verify(string encryptionKeyId, bool allowEnclaveComputations, byte[] signature)
        {
            return signature?.Length == 1 && signature[0] == GetShift(encryptionKeyId);
        }

        private static int GetShift(string value)
        {
            return (value?.Sum(character => (int)character) ?? 0) % 31 + 1;
        }
    }

#pragma warning disable CS0618
    internal sealed class MatrixKeyWrapProvider : EncryptionKeyWrapProvider
    {
        public override Task<EncryptionKeyUnwrapResult> UnwrapKeyAsync(
            byte[] wrappedKey,
            EncryptionKeyWrapMetadata metadata,
            CancellationToken cancellationToken)
        {
            int shift = GetShift(metadata?.Value);
            byte[] key = wrappedKey.Select(value => unchecked((byte)(value - shift))).ToArray();
            return Task.FromResult(new EncryptionKeyUnwrapResult(key, TimeSpan.FromMinutes(5)));
        }

        public override Task<EncryptionKeyWrapResult> WrapKeyAsync(
            byte[] key,
            EncryptionKeyWrapMetadata metadata,
            CancellationToken cancellationToken)
        {
            int shift = GetShift(metadata?.Value);
            byte[] wrappedKey = key.Select(value => unchecked((byte)(value + shift))).ToArray();
            return Task.FromResult(new EncryptionKeyWrapResult(wrappedKey, metadata));
        }

        private static int GetShift(string value)
        {
            return (value?.Sum(character => (int)character) ?? 0) % 31 + 1;
        }
    }
#pragma warning restore CS0618

    internal sealed class MatrixEncryptor : Encryptor
    {
        private readonly DataEncryptionKeyProvider provider;
        private int decryptCallCount;

        public MatrixEncryptor(DataEncryptionKeyProvider provider)
        {
            this.provider = provider ?? throw new ArgumentNullException(nameof(provider));
        }

        public override async Task<byte[]> DecryptAsync(
            byte[] cipherText,
            string dataEncryptionKeyId,
            string encryptionAlgorithm,
            CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref this.decryptCallCount);
            MatrixDataEncryptionKey key = await this.GetKeyAsync(
                dataEncryptionKeyId,
                encryptionAlgorithm,
                cancellationToken);
            return key.DecryptData(cipherText);
        }

        public int DecryptCallCount => Volatile.Read(ref this.decryptCallCount);

        public override async Task<byte[]> EncryptAsync(
            byte[] plainText,
            string dataEncryptionKeyId,
            string encryptionAlgorithm,
            CancellationToken cancellationToken = default)
        {
            MatrixDataEncryptionKey key = await this.GetKeyAsync(
                dataEncryptionKeyId,
                encryptionAlgorithm,
                cancellationToken);
            return key.EncryptData(plainText);
        }

        private async Task<MatrixDataEncryptionKey> GetKeyAsync(
            string dataEncryptionKeyId,
            string encryptionAlgorithm,
            CancellationToken cancellationToken)
        {
            CustomDataEncryptionKey key = await this.provider.FetchDataEncryptionKeyWithoutRawKeyAsync(
                dataEncryptionKeyId,
                encryptionAlgorithm,
                cancellationToken);
            return new MatrixDataEncryptionKey(
                key ?? throw new InvalidOperationException("The data encryption key provider returned null."));
        }
    }

    internal sealed class MatrixDataEncryptionKey : CustomDataEncryptionKey
    {
        private readonly CustomDataEncryptionKey inner;

        public MatrixDataEncryptionKey(CustomDataEncryptionKey inner)
        {
            this.inner = inner ?? throw new ArgumentNullException(nameof(inner));
        }

        public override byte[] RawKey => this.inner.RawKey;

        public override string EncryptionAlgorithm => this.inner.EncryptionAlgorithm;

        public override byte[] EncryptData(byte[] plainText)
        {
            return this.inner.EncryptData(plainText);
        }

        public override byte[] DecryptData(byte[] cipherText)
        {
            return this.inner.DecryptData(cipherText);
        }
    }
}
