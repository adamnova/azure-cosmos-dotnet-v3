//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

namespace Microsoft.Azure.Cosmos.Encryption.Custom.EmulatorTests
{
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Newtonsoft.Json.Linq;

    [TestClass]
    public sealed class LegacyPreview07FixturePortabilityTests
    {
        private const string CrlfFixtureSha256 = "FE4196FFD23DF3192A9369EF634CAED32CE3624F9ECA129255A008BA73CAE699";
        private const string LfFixtureSha256 = "62B7F88E998A77A19D2A9F86094376D0BBA059DAB27C511659CA437B91B50E14";

        [DataTestMethod]
        [DataRow(false, LfFixtureSha256)]
        [DataRow(true, CrlfFixtureSha256)]
        public void ReleasedFixtureHash_AcceptsExactLfAndCrlfCheckoutRepresentations(
            bool useCrlf,
            string expectedRawHash)
        {
            string fixturePath = Path.Combine(
                AppContext.BaseDirectory,
                "Fixtures",
                "LegacyPreview07PointOperationFixture.json");
            byte[] sourceBytes = File.ReadAllBytes(fixturePath);
            string sourceHash = ComputeHash(sourceBytes);
            Assert.IsTrue(
                sourceHash == LfFixtureSha256 || sourceHash == CrlfFixtureSha256,
                $"Fixture source bytes are not an authentic pinned representation: {sourceHash}.");

            string lfText = Encoding.UTF8.GetString(sourceBytes).Replace("\r\n", "\n");
            Assert.IsFalse(lfText.Contains("\r"));
            string checkoutText = useCrlf
                ? lfText.Replace("\n", "\r\n")
                : lfText;
            byte[] checkoutBytes = Encoding.UTF8.GetBytes(checkoutText);
            Assert.AreEqual(expectedRawHash, ComputeHash(checkoutBytes));

            string scratchDirectory = Path.Combine(
                AppContext.BaseDirectory,
                nameof(LegacyPreview07FixturePortabilityTests) + "-" + Guid.NewGuid().ToString("N"));
            string checkoutPath = Path.Combine(
                scratchDirectory,
                "LegacyPreview07PointOperationFixture.json");
            Directory.CreateDirectory(scratchDirectory);
            try
            {
                File.WriteAllBytes(checkoutPath, checkoutBytes);
                MdeCustomEncryptionTests.VerifyLegacyPreview07FixtureHash(checkoutPath);
                JObject fixture = JObject.Parse(File.ReadAllText(checkoutPath));
                Assert.AreEqual(
                    "AEAes256CbcHmacSha256Randomized",
                    fixture["legacyItem"]["_ei"]["_ea"].Value<string>());
                Assert.IsTrue(
                    Convert.FromBase64String(
                        fixture["legacyItem"]["_ei"]["_ed"].Value<string>()).Length > 0);
            }
            finally
            {
                Directory.Delete(scratchDirectory, recursive: true);
            }
        }

        private static string ComputeHash(byte[] bytes)
        {
            using SHA256 sha256 = SHA256.Create();
            return Convert.ToHexString(sha256.ComputeHash(bytes));
        }
    }
}
