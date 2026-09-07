//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

namespace Microsoft.Azure.Cosmos.Encryption.Tests
{
    using Microsoft.Azure.Cosmos.Encryption.Custom;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using System;
    using System.Linq;

    [TestClass]
    public class AeadAes256CbcHmac256AlgorithmTests
    {
        private static readonly byte[] RootKey = new byte[32];

        private static AeadAes256CbcHmac256EncryptionKey key;
        private static AeadAes256CbcHmac256Algorithm algorithm;

        [ClassInitialize]
        public static void ClassInitialize(TestContext testContext)
        {
            _ = testContext;

            AeadAes256CbcHmac256AlgorithmTests.key = new AeadAes256CbcHmac256EncryptionKey(RootKey, "AEAes256CbcHmacSha256Randomized");
            AeadAes256CbcHmac256AlgorithmTests.algorithm = new AeadAes256CbcHmac256Algorithm(AeadAes256CbcHmac256AlgorithmTests.key, EncryptionType.Randomized, algorithmVersion: 1);
        }

        [TestMethod]
        public void DecryptDataTamperedAuthenticationTagIsRejectedAtEveryPosition()
        {
            byte[] plainText = Enumerable.Range(0, 16).Select(value => (byte)value).ToArray();
            byte[] cipherText = algorithm.EncryptData(plainText);
            const int AuthenticationTagOffset = 1;
            const int AuthenticationTagLength = 32;

            for (int index = 0; index < AuthenticationTagLength; index++)
            {
                byte[] tamperedCipherText = (byte[])cipherText.Clone();
                tamperedCipherText[AuthenticationTagOffset + index] ^= 0xFF;

                ArgumentException exception = Assert.ThrowsException<ArgumentException>(
                    () => algorithm.DecryptData(tamperedCipherText),
                    $"A modified authentication tag byte at position {index} must be rejected.");

                Assert.AreEqual("cipherText", exception.ParamName);
                StringAssert.Contains(exception.Message, "Invalid authentication tag in cipher text.");
            }
        }

        [TestMethod]
        public void DecryptDataTamperedCipherTextIsRejected()
        {
            byte[] plainText = Enumerable.Range(0, 16).Select(value => (byte)value).ToArray();
            byte[] tamperedCipherText = algorithm.EncryptData(plainText);
            tamperedCipherText[tamperedCipherText.Length - 1] ^= 0xFF;

            ArgumentException exception = Assert.ThrowsException<ArgumentException>(
                () => algorithm.DecryptData(tamperedCipherText));

            Assert.AreEqual("cipherText", exception.ParamName);
            StringAssert.Contains(exception.Message, "Invalid authentication tag in cipher text.");
        }
    }
}
