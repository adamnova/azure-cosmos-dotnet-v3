//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------
namespace Microsoft.Azure.Cosmos.Encryption.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Linq.Expressions;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.Azure.Cosmos.Encryption.Custom;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Moq;

    /// <summary>
    /// Shared helper for creating Encryptor instances used in tests.
    /// </summary>
    internal static class TestEncryptorFactory
    {
        /// <summary>
        /// Concrete Encryptor that also implements IDataEncryptionKeyAccessor so it works
        /// with the Stream processor without needing Moq interface projections on an internal type.
        /// </summary>
        internal sealed class MdeConcreteEncryptor : Encryptor, IDataEncryptionKeyAccessor
        {
            private readonly string dekId;
            private readonly DataEncryptionKey dek;
            private readonly List<string> keyAccessAlgorithms = new ();

            public MdeConcreteEncryptor(string dekId, DataEncryptionKey dek)
            {
                this.dekId = dekId;
                this.dek = dek;
            }

            public Encryptor Object => this;

            public Task<DataEncryptionKey> GetEncryptionKeyAsync(
                string dataEncryptionKeyId,
                string encryptionAlgorithm,
                CancellationToken cancellationToken = default)
            {
                this.keyAccessAlgorithms.Add(encryptionAlgorithm);
                return dataEncryptionKeyId == this.dekId
                    ? Task.FromResult(this.dek)
                    : throw new InvalidOperationException("DEK not found");
            }

            public int GetKeyAccessCount(string encryptionAlgorithm)
            {
                return this.keyAccessAlgorithms.Count(
                    candidate => string.Equals(candidate, encryptionAlgorithm, StringComparison.Ordinal));
            }

            public void Verify(
                Expression<Func<IDataEncryptionKeyAccessor, Task<DataEncryptionKey>>> expression,
                Times times)
            {
                if (!times.Equals(Times.Never()))
                {
                    throw new NotSupportedException("Only Times.Never is required by the compatibility adapter.");
                }

                MethodCallExpression call = (MethodCallExpression)expression.Body;
                string encryptionAlgorithm = (call.Arguments[1] as ConstantExpression)?.Value as string;
                int callCount = encryptionAlgorithm == null
                    ? this.keyAccessAlgorithms.Count
                    : this.GetKeyAccessCount(encryptionAlgorithm);
                if (callCount != 0)
                {
                    throw new AssertFailedException(
                        $"Expected no key-access calls, but observed {callCount}.");
                }
            }

            public void Verify(
                Expression<Func<IDataEncryptionKeyAccessor, Task<DataEncryptionKey>>> expression,
                Func<Times> times)
            {
                this.Verify(expression, times());
            }

            public override Task<byte[]> EncryptAsync(
                byte[] plainText,
                string dataEncryptionKeyId,
                string encryptionAlgorithm,
                CancellationToken cancellationToken = default)
            {
                return dataEncryptionKeyId == this.dekId
                    ? Task.FromResult(TestCommon.EncryptData(plainText))
                    : throw new InvalidOperationException("DEK not found");
            }

            public override Task<byte[]> DecryptAsync(
                byte[] cipherText,
                string dataEncryptionKeyId,
                string encryptionAlgorithm,
                CancellationToken cancellationToken = default)
            {
                return dataEncryptionKeyId == this.dekId
                    ? Task.FromResult(TestCommon.DecryptData(cipherText))
                    : throw new InvalidOperationException("DEK not found");
            }
        }

        private sealed class MdeConcreteDataEncryptionKey : DataEncryptionKey, IDataEncryptionKeyBuffer
        {
            public override byte[] RawKey => null;

            public override string EncryptionAlgorithm => CosmosEncryptionAlgorithm.MdeAeadAes256CbcHmac256Randomized;

            public override byte[] EncryptData(byte[] plainText)
            {
                return TestCommon.EncryptData(plainText);
            }

            public int EncryptData(
                byte[] plainText,
                int plainTextOffset,
                int plainTextLength,
                byte[] output,
                int outputOffset)
            {
                return TestCommon.EncryptData(plainText, plainTextOffset, plainTextLength, output, outputOffset);
            }

            public int GetEncryptByteCount(int plainTextLength)
            {
                return plainTextLength;
            }

            public override byte[] DecryptData(byte[] cipherText)
            {
                return TestCommon.DecryptData(cipherText);
            }

            public int DecryptData(
                byte[] cipherText,
                int cipherTextOffset,
                int cipherTextLength,
                byte[] output,
                int outputOffset)
            {
                return TestCommon.DecryptData(cipherText, cipherTextOffset, cipherTextLength, output, outputOffset);
            }

            public int GetDecryptByteCount(int cipherTextLength)
            {
                return cipherTextLength;
            }
        }

        public static MdeConcreteEncryptor CreateMde(string dekId)
        {
            return CreateMde(dekId, out _);
        }

        public static MdeConcreteEncryptor CreateMde(string dekId, out DataEncryptionKey dataEncryptionKey)
        {
            MdeConcreteDataEncryptionKey dek = new ();
            dataEncryptionKey = dek;
            return new MdeConcreteEncryptor(dekId, dek);
        }

        public static Mock<Encryptor> CreateLegacy(string dekId)
        {
            Mock<Encryptor> encryptor = new Mock<Encryptor>();
            encryptor.Setup(e => e.EncryptAsync(It.IsAny<byte[]>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync((byte[] plain, string id, string algo, CancellationToken t) => id == dekId ? TestCommon.EncryptData(plain) : throw new InvalidOperationException("DEK not found"));
            encryptor.Setup(e => e.DecryptAsync(It.IsAny<byte[]>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync((byte[] cipher, string id, string algo, CancellationToken t) => id == dekId ? TestCommon.DecryptData(cipher) : throw new InvalidOperationException("Null DEK was returned."));
            return encryptor;
        }
    }
}
