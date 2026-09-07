//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

namespace Microsoft.Azure.Cosmos.Encryption.Tests
{
    using System.Linq;
    using Microsoft.Azure.Cosmos.Encryption.Custom;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    [TestClass]
    public class SecurityUtilityTests
    {
        [TestMethod]
        public void CompareBytesEqualRequestedRangeReturnsTrue()
        {
            byte[] expected = new byte[] { 10, 20, 30, 40 };
            byte[] actual = new byte[] { 99, 10, 20, 30, 40, 98 };

            Assert.IsTrue(SecurityUtility.CompareBytes(expected, actual, 1, expected.Length));
        }

        [TestMethod]
        public void CompareBytesDifferenceAtEveryRequestedPositionReturnsFalse()
        {
            byte[] expected = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();

            for (int index = 0; index < expected.Length; index++)
            {
                byte[] actual = (byte[])expected.Clone();
                actual[index] ^= 0xFF;

                Assert.IsFalse(
                    SecurityUtility.CompareBytes(expected, actual, 0, expected.Length),
                    $"A difference at position {index} must be rejected.");
            }
        }

        [TestMethod]
        public void CompareBytesShortFirstBufferRejectsMatchingPrefix()
        {
            byte[] expected = new byte[] { 1, 2, 3 };
            byte[] actual = new byte[] { 1, 2, 3, 4 };

            Assert.IsFalse(SecurityUtility.CompareBytes(expected, actual, 0, actual.Length));
        }

        [TestMethod]
        public void CompareBytesIgnoresBytesOutsideRequestedRange()
        {
            byte[] expected = new byte[] { 1, 2, 3, 4, 5 };
            byte[] actual = new byte[] { 99, 1, 2, 3, 4, 98 };

            Assert.IsTrue(SecurityUtility.CompareBytes(expected, actual, 1, 4));
            Assert.IsFalse(SecurityUtility.CompareBytes(expected, actual, 0, 4));
        }

        [TestMethod]
        public void CompareBytesInsufficientSecondRangeReturnsFalse()
        {
            byte[] expected = new byte[] { 1, 2, 3, 4 };
            byte[] actual = new byte[] { 99, 1, 2, 3 };

            Assert.IsFalse(SecurityUtility.CompareBytes(expected, actual, 1, expected.Length));
        }

        [TestMethod]
        public void CompareBytesNullBufferReturnsFalse()
        {
            Assert.IsFalse(SecurityUtility.CompareBytes(null, new byte[1], 0, 1));
            Assert.IsFalse(SecurityUtility.CompareBytes(new byte[1], null, 0, 1));
        }

        [TestMethod]
        public void CompareBytesZeroLengthReturnsTrue()
        {
            Assert.IsTrue(SecurityUtility.CompareBytes(new byte[1], new byte[1], 0, 0));
        }
    }
}
