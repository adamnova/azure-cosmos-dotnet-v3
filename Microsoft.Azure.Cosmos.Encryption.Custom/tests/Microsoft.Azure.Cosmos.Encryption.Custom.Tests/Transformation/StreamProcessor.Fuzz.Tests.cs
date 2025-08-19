//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

#if ENCRYPTION_CUSTOM_PREVIEW && NET8_0_OR_GREATER
namespace Microsoft.Azure.Cosmos.Encryption.Tests.Transformation
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.IO.Compression;
    using System.Linq;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.Azure.Cosmos.Encryption.Custom;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Newtonsoft.Json.Linq;

    public partial class StreamProcessorTests
    {
        [TestMethod]
        [TestCategory("Fuzz")]
        public async Task Fuzz_RoundTrip_Metadata_Context_Seekability()
        {
            // Gate via env var to avoid running by default in CI
            if (!string.Equals(Environment.GetEnvironmentVariable("COSMOS_ENC_FUZZ"), "1", StringComparison.Ordinal))
            {
                Assert.Inconclusive("Fuzz disabled. Set COSMOS_ENC_FUZZ=1 to enable.");
            }

            int iterations = TryParseOrDefault(Environment.GetEnvironmentVariable("COSMOS_ENC_FUZZ_ITERS"), 25);
            int seed = TryParseOrDefault(Environment.GetEnvironmentVariable("COSMOS_ENC_FUZZ_SEED"), 12345);

            for (int i = 0; i < iterations; i++)
            {
                int caseSeed = unchecked(seed + i);
                Random rng = new(caseSeed);

                // Generate a bounded top-level JSON object
                JObject doc = BuildRandomTopLevelObject(rng, maxProps: 8, maxArrayLen: 8, maxStringLen: 256, maxInnerProps: 6);
                string[] presentKeys = doc.Properties().Select(p => p.Name).ToArray();

                // Choose a random subset of top-level paths to encrypt; include a couple of missing ones
                List<string> pathsToEncrypt = ChoosePathsToEncrypt(rng, presentKeys, extraMissing: 2);

                // Compression options: None or Brotli with thresholds around 64/128
                CompressionOptions compression = ChooseCompression(rng);

                var options = new EncryptionOptions
                {
                    DataEncryptionKeyId = DekId,
                    EncryptionAlgorithm = CosmosEncryptionAlgorithm.MdeAeadAes256CbcHmac256Randomized,
                    PathsToEncrypt = pathsToEncrypt,
                    JsonProcessor = JsonProcessor.Stream,
                    CompressionOptions = compression,
                };

                // Serialize input
                using Stream input = EncryptionProcessor.BaseSerializer.ToStream(doc);
                using Stream maybeChunkedInput = (rng.Next(2) == 0) ? new ChunkedReadStream(input, 16) : input;
                using MemoryStream encrypted = new();

                try
                {
                    await EncryptionProcessor.EncryptAsync(maybeChunkedInput, encrypted, mockEncryptor.Object, options, new CosmosDiagnosticsContext(), CancellationToken.None);
                }
                catch (Exception ex)
                {
                    Assert.Fail($"Encrypt failed seed={seed} iter={i} caseSeed={caseSeed}: {ex}");
                }

                // Inspect metadata minimally
                encrypted.Position = 0;
                JObject encryptedDoc = EncryptionProcessor.BaseSerializer.FromStream<JObject>(encrypted);
                Assert.IsTrue(encryptedDoc.ContainsKey(Constants.EncryptedInfo), $"_ei missing seed={seed} iter={i} caseSeed={caseSeed}");

                // Decrypt (maybe with chunked reads)
                encrypted.Position = 0;
                using Stream maybeChunkedEncrypted = (rng.Next(2) == 0) ? new ChunkedReadStream(encrypted, 16) : encrypted;
                using MemoryStream decrypted = new();

                DecryptionContext ctx;
                try
                {
                    ctx = await EncryptionProcessor.DecryptAsync(maybeChunkedEncrypted, decrypted, mockEncryptor.Object, new CosmosDiagnosticsContext(), JsonProcessor.Stream, CancellationToken.None);
                }
                catch (Exception ex)
                {
                    Assert.Fail($"Decrypt failed seed={seed} iter={i} caseSeed={caseSeed}: {ex}");
                    return; // unreachable
                }

                // Validate stream invariants
                Assert.IsTrue(decrypted.CanSeek, "Decrypted stream must be seekable");
                Assert.AreEqual(0, decrypted.Position, "Decrypted stream position should be 0");

                // Validate round-trip equality
                JObject roundTripped = EncryptionProcessor.BaseSerializer.FromStream<JObject>(decrypted);
                Assert.IsNull(roundTripped[Constants.EncryptedInfo], "_ei should be removed after decrypt");
                AssertJsonTopLevelEqual(doc, roundTripped, $"seed={seed} iter={i} caseSeed={caseSeed}");

                // Validate decryption context paths: exactly those encrypted paths that existed and were non-null
                var expectedDecrypted = pathsToEncrypt
                    .Where(p => p.StartsWith("/", StringComparison.Ordinal))
                    .Where(p => roundTripped.ContainsKey(p.Substring(1)))
                    .Where(p => roundTripped[p.Substring(1)]?.Type != JTokenType.Null)
                    .ToHashSet(StringComparer.Ordinal);

                var actual = ctx?.DecryptionInfoList?.FirstOrDefault()?.PathsDecrypted ?? new List<string>();
                CollectionAssert.AreEquivalent(expectedDecrypted.ToList(), actual.ToList(), $"PathsDecrypted mismatch seed={seed} iter={i} caseSeed={caseSeed}");
            }
        }

        private static int TryParseOrDefault(string value, int fallback)
        {
            return int.TryParse(value, out int v) ? v : fallback;
        }

        private static CompressionOptions ChooseCompression(Random rng)
        {
            if (rng.Next(2) == 0)
            {
                return new CompressionOptions { Algorithm = CompressionOptions.CompressionAlgorithm.None };
            }

            var level = (CompressionLevel)(new[] { CompressionLevel.NoCompression, CompressionLevel.Fastest, CompressionLevel.Optimal }[rng.Next(3)]);
            int threshold = (rng.Next(2) == 0) ? 64 : 128;
            return new CompressionOptions
            {
                Algorithm = CompressionOptions.CompressionAlgorithm.Brotli,
                CompressionLevel = level,
                MinimalCompressedLength = threshold,
            };
        }

        private static JObject BuildRandomTopLevelObject(Random rng, int maxProps, int maxArrayLen, int maxStringLen, int maxInnerProps)
        {
            int propCount = rng.Next(3, maxProps + 1);
            JObject obj = new();
            obj["id"] = Guid.NewGuid().ToString();
            obj["PK"] = Guid.NewGuid().ToString();
            obj["NonSensitive"] = "ns";

            for (int i = 0; i < propCount; i++)
            {
                string key = $"K{i}";
                obj[key] = BuildRandomValue(rng, maxArrayLen, maxStringLen, maxInnerProps);
            }

            return obj;
        }

        private static JToken BuildRandomValue(Random rng, int maxArrayLen, int maxStringLen, int maxInnerProps)
        {
            // 0..6: string, long, double, bool, null, array, object
            int t = rng.Next(7);
            switch (t)
            {
                case 0:
                    return new JValue(RandomString(rng, rng.Next(0, maxStringLen + 1)));
                case 1:
                    return new JValue(RandomLong(rng));
                case 2:
                    return new JValue(RandomFiniteDouble(rng));
                case 3:
                    return new JValue(rng.Next(2) == 0);
                case 4:
                    return JValue.CreateNull();
                case 5:
                {
                    int len = rng.Next(0, Math.Min(8, maxArrayLen) + 1);
                    JArray arr = new();
                    for (int i = 0; i < len; i++)
                    {
                        arr.Add(BuildRandomValue(rng, 0, Math.Min(32, maxStringLen), 0)); // keep nested small
                    }
                    return arr;
                }
                default:
                {
                    int len = rng.Next(0, Math.Min(6, maxInnerProps) + 1);
                    JObject o = new();
                    for (int i = 0; i < len; i++)
                    {
                        o[$"I{i}"] = BuildRandomValue(rng, 0, Math.Min(32, maxStringLen), 0);
                    }
                    return o;
                }
            }
        }

        private static long RandomLong(Random rng)
        {
            // Bias toward small/edge values
            return rng.Next(4) switch
            {
                0 => 0,
                1 => long.MaxValue,
                2 => long.MinValue + 1,
                _ => (long)rng.NextInt64(),
            };
        }

        private static double RandomFiniteDouble(Random rng)
        {
            // Generate finite doubles; avoid NaN/Infinity
            double sign = (rng.Next(2) == 0) ? 1.0 : -1.0;
            int exp = rng.Next(-100, 100); // modest exponents to remain JSON-friendly
            double mantissa = rng.NextDouble();
            double val = sign * mantissa * Math.Pow(10, exp);
            if (double.IsNaN(val) || double.IsInfinity(val))
            {
                return 0.0;
            }
            return val;
        }

        private static string RandomString(Random rng, int length)
        {
            if (length == 0) return string.Empty;
            var sb = new StringBuilder(length);
            for (int i = 0; i < length; i++)
            {
                // Mix ASCII and a small set of unicode
                int choice = rng.Next(10);
                char ch = choice switch
                {
                    < 7 => (char)rng.Next(32, 127), // basic printable ASCII
                    7 => '\\',
                    8 => '"',
                    _ => (char)rng.Next(0x0400, 0x04FF), // Cyrillic block as sample unicode
                };
                sb.Append(ch);
            }
            return sb.ToString();
        }

        private static List<string> ChoosePathsToEncrypt(Random rng, string[] presentKeys, int extraMissing)
        {
            List<string> paths = new();
            foreach (string k in presentKeys)
            {
                // Skip id/PK/NonSensitive sometimes to mix encryption and non-encryption
                if (k == "id" || k == "PK" || k == "NonSensitive") continue;
                if (rng.Next(2) == 0)
                {
                    paths.Add("/" + k);
                }
            }
            for (int i = 0; i < extraMissing; i++)
            {
                paths.Add("/Missing_" + i);
            }
            if (paths.Count == 0)
            {
                // Ensure at least one path so _ei is produced
                paths.Add("/Fallback");
            }
            return paths;
        }

        private static void AssertJsonTopLevelEqual(JObject expected, JObject actual, string context)
        {
            foreach (var prop in expected.Properties())
            {
                string name = prop.Name;
                JToken ev = prop.Value;
                JToken av = actual[name];
                if (ev == null || ev.Type == JTokenType.Null)
                {
                    Assert.IsTrue(actual.ContainsKey(name), $"Missing key {name} {context}");
                    Assert.IsTrue(av == null || av.Type == JTokenType.Null, $"Null mismatch for {name} {context}");
                    continue;
                }

                Assert.IsNotNull(av, $"Missing key {name} {context}");
                switch (ev.Type)
                {
                    case JTokenType.Integer:
                        Assert.AreEqual((long)ev, (long)av, $"Int mismatch {name} {context}");
                        break;
                    case JTokenType.Float:
                        Assert.AreEqual((double)ev, (double)av, 0.0, $"Double mismatch {name} {context}");
                        break;
                    default:
                        Assert.IsTrue(JToken.DeepEquals(ev, av), $"Value mismatch at {name} {context}\nExpected: {ev}\nActual: {av}");
                        break;
                }
            }
        }
    }
}
#endif
