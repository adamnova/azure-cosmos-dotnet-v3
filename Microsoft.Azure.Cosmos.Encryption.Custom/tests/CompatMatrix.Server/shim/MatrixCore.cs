// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// ------------------------------------------------------------
// SPIKE (Option B): version-owning core for the "thin server" compat-matrix.
// This is the SAME crypto/document/verify logic as tests/CompatMatrix/src/Program.cs, but
// factored into per-cell operations that an ASP.NET minimal-API shim (Shim.cs) exposes over HTTP
// instead of a stdout text protocol. ONE binary per package version (see the two csproj).
//
// FIDELITY INVARIANT: the hardened document is BUILT, ENCRYPTED and SELF-VERIFIED inside this
// process (the one that owns a specific Encryption.Custom version). The per-cell PASS/FAIL verdict
// (DecOk) is computed HERE by VerifyDoc against this process's own BuildDoc(id); it never depends on
// the transport. Only ids, cell selectors, status strings and a SHA-256 HASH of the canonical
// signature ever cross HTTP -- never any decrypted field value -- so ASP.NET's serializer can neither
// sit in the fidelity path nor leak plaintext. The driver compares status + signature hashes only.
namespace CompatMatrix.Server
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Linq;
    using System.Net;
    using System.Net.Http;
    using System.Reflection;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;
    using Microsoft.Azure.Cosmos;
    using Microsoft.Azure.Cosmos.Encryption.Custom;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;

    public static class MatrixCore
    {
#if CEC_CURRENT
        public const string Version = "current";
        private const string ExpectedPackageVersionKey = "CompatMatrixNewVersion";
#elif CEC_NEW
        public const string Version = "new";
        private const string ExpectedPackageVersionKey = "CompatMatrixNewVersion";
#else
        public const string Version = "old";
        private const string ExpectedPackageVersionKey = "CompatMatrixOldVersion";
#endif
        private const string StreamKey = "encryption-json-processor";
        private const string MdeDekId = "matrix-mde-dek";
        private const string AeadDekId = "matrix-aead-dek";
        private const string Pk = "matrix-pk";
#pragma warning disable CS0618
        private static readonly string AeadAlgo = CosmosEncryptionAlgorithm.AEAes256CbcHmacSha256Randomized;
#pragma warning restore CS0618
        private static readonly string MdeAlgo = CosmosEncryptionAlgorithm.MdeAeadAes256CbcHmac256Randomized;

        // ---- Hardened payload (identical to the subprocess harness): regression coverage for the
        // Stream-processor data-corruption fixes. See tests/CompatMatrix/README.md §"Hardened document". ----
        private const string EncEscapedValue = "q=\" b=\\ nl=\n tab=\t u=\u00e9 ctl=\u0001 end";
        private const string EncAstralValue = "😀𐍈🜨 日本語 العربية \uD83D\uDE00 Z\u0301";
        private const string PlainEscapedValue = "p_q=\" p_b=\\ p_nl=\n p_u=\u00e9 end";
        private const string EscPropName = "esc\"name\\x";
        private const string EscPropPath = "/" + EscPropName;
        private const string EscNameValue = "named-secret";
        private const long EncLongValue = 9007199254740993L;
        private const double EncIntegralDoubleValue = 5.0;
        private const double EncNormalDoubleValue = 1234.5;

        private static readonly string[] HardenedEncryptedPaths =
        {
            "/Sensitive", "/EncEscaped", "/EncAstral", EscPropPath, "/EncObj", "/EncArr", "/EncLong", "/EncIntegralDouble", "/EncNormalDouble",
        };

        private static Container enc;
        private static Container plain;

        public static async Task InitAsync(string endpoint, string key, string db)
        {
            CosmosClient client = new(endpoint, key, new CosmosClientOptions
            {
                ConnectionMode = ConnectionMode.Gateway,
                LimitToEndpoint = true,
                HttpClientFactory = () => new HttpClient(new HttpClientHandler { ServerCertificateCustomValidationCallback = (_, _, _, _) => true }),
            });
            Database database = await client.CreateDatabaseIfNotExistsAsync(db);
            plain = (await database.CreateContainerIfNotExistsAsync("items", "/PK", 400)).Container;
            Container keyC = (await database.CreateContainerIfNotExistsAsync("keys", "/id", 400)).Container;
            CosmosDataEncryptionKeyProvider provider = new(new MatrixWrapProvider(), new MatrixKeyStoreProvider());
            await provider.InitializeAsync(database, keyC.Id);
            enc = plain.WithEncryptor(new MatrixEncryptor(provider));
            await TryCreateDek(provider, MdeDekId, MdeAlgo);
            await TryCreateDek(provider, AeadDekId, AeadAlgo);
        }

        public static VersionResult VersionInfo()
        {
            Assembly assembly = typeof(EncryptionContainerExtensions).Assembly;
            string informational = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "<missing>";
            string assemblyVersion = assembly.GetName().Version?.ToString() ?? "<missing>";
            string expected = ReadExpectedPackageVersion();
            return new VersionResult(Version, expected, informational.Split('+')[0], assemblyVersion);
        }

        private static string ReadExpectedPackageVersion()
        {
            AssemblyMetadataAttribute[] matches = typeof(MatrixCore).Assembly
                .GetCustomAttributes<AssemblyMetadataAttribute>()
                .Where(attribute => string.Equals(attribute.Key, ExpectedPackageVersionKey, StringComparison.Ordinal))
                .ToArray();
            if (matches.Length != 1)
            {
                throw new InvalidOperationException(
                    $"Configured assembly metadata '{ExpectedPackageVersionKey}' must appear exactly once; found {matches.Length} entries.");
            }

            string expected = matches[0].Value;
            if (string.IsNullOrWhiteSpace(expected))
            {
                throw new InvalidOperationException(
                    $"Configured assembly metadata '{ExpectedPackageVersionKey}' must contain a non-empty package version.");
            }

            return expected;
        }

        // Writes ONE cell's hardened doc (BuildDoc(id)) under {family, wproc}. Mirrors Program.Write's per-cell
        // status classification, but returns it as a record (the shim serializes that, never the doc).
        public static async Task<WriteResult> WriteAsync(string family, string wproc, string id)
        {
            string algo = family == "MDE" ? MdeAlgo : AeadAlgo;
            bool aeadStream = family == "AEAD" && wproc == "Stream";
            bool mdeStreamOnOld = Version == "old" && wproc == "Stream";
            string expectedSig = Sha256Hex(Signature(BuildDoc(id)));
            try
            {
                await enc.UpsertItemAsync(BuildDoc(id), new PartitionKey(Pk), Options(algo, wproc));
                string status = aeadStream
                    ? (Version != "old" ? "UNSUPPORTED-DID-NOT-THROW" : "OLD-NO-STREAM-EXPECTED")
                    : "OK";
                return new WriteResult(status, id, expectedSig);
            }
            catch (NotSupportedException) when (aeadStream)
            {
                return new WriteResult("EXPECTED-UNSUPPORTED", "AEAD+Stream rejected", expectedSig);
            }
            catch (Exception ex) when (mdeStreamOnOld)
            {
                return new WriteResult("OLD-NO-STREAM", ex.GetType().Name, expectedSig);
            }
            catch (Exception ex)
            {
                return new WriteResult("FAIL", $"{ex.GetType().Name}: {ex.Message.Split('\n')[0]}", expectedSig);
            }
        }

        // Reads ONE cell via one {rproc, path}. Returns the raw-ciphertext verdict, the decrypted self-verify
        // verdict (VerifyDoc against this process's own BuildDoc(id)) PLUS a number-integrity check, and a
        // SHA-256 hash of the decrypted doc's canonical signature (for the driver's A/B equivalence check).
        public static async Task<ReadResult> ReadAsync(string family, string rproc, string path, string id)
        {
            string expectedPlain = $"secret::{id}";
            (bool rawOk, string rawDetail) = await RawIsEncrypted(id, family, expectedPlain);
            try
            {
                JObject jr = await ReadPath(path, id, rproc);
                Doc r = jr?.ToObject<Doc>();
                (bool decOk, string vdetail) = VerifyDoc(r, id);

                // Number-integrity on the DECRYPTED wire form: each encrypted numeric path must decrypt back to
                // a NUMERIC token, not a stringified/nulled value that a typed long/double would silently coerce
                // and hide. Integer-vs-Float is intentionally NOT asserted: System.Text.Json emits an integral
                // double like 5.0 as "5" and Newtonsoft as "5.0" — both correct and value-equal (see
                // tests/CompatMatrix/RUN-REPORT.md §7) — so a wire-form check would false-fail the Stream path.
                if (decOk && jr != null)
                {
                    (bool numOk, string numDetail) = NumbersAreNumeric(jr);
                    if (!numOk) { decOk = false; vdetail = numDetail; }
                }

                return new ReadResult(rawOk, rawDetail, decOk, decOk ? "all-fields-match" : vdetail, r == null ? "<null-doc>" : Sha256Hex(Signature(r)));
            }
            catch (Exception ex)
            {
                return new ReadResult(rawOk, rawDetail, false, $"{ex.GetType().Name}: {ex.Message.Split('\n')[0]}", "<throw>");
            }
        }

        // Negative control: store a plaintext doc and prove the raw assertion REJECTS it (anti-fake-green).
        public static async Task<TamperResult> TamperAsync(string id)
        {
            await plain.UpsertItemAsync(BuildDoc(id), new PartitionKey(Pk));
            (bool ok, string detail) = await RawIsEncrypted(id, "MDE", $"secret::{id}");
            return new TamperResult(!ok, ok ? "plaintext-passed-as-encrypted" : $"plaintext-rejected:{detail}");
        }

        private static async Task<(bool ok, string detail)> RawIsEncrypted(string id, string family, string expectedPlain)
        {
            JObject raw;
            try { raw = (await plain.ReadItemAsync<JObject>(id, new PartitionKey(Pk))).Resource; }
            catch (CosmosException e) when (e.StatusCode == HttpStatusCode.NotFound) { return (false, "raw-not-found"); }
            if (raw["_ei"] is not JObject ei) { return (false, "no-_ei-metadata"); }
            int ver = ei.Value<int?>("_ef") ?? -1;
            int want = family == "MDE" ? 3 : 2;
            if (ver != want) { return (false, $"fmt-v{ver}-not-v{want}"); }
            JToken sens = raw["Sensitive"];
            if (family == "MDE")
            {
                if (sens == null || sens.Type == JTokenType.Null) { return (false, "MDE-Sensitive-stripped"); }
                if (sens.Type == JTokenType.String && sens.Value<string>() == expectedPlain) { return (false, "Sensitive-is-plaintext"); }
                foreach (string container in new[] { "EncObj", "EncArr" })
                {
                    JToken c = raw[container];
                    if (c == null || c.Type == JTokenType.Null) { return (false, $"MDE-{container}-stripped"); }
                    if (c.Type is JTokenType.Object or JTokenType.Array) { return (false, $"{container}-not-encrypted"); }
                }

                if (ei["_ep"] is not JArray ep) { return (false, "no-_ep-paths"); }
                if (ep.Any(t => t.Type == JTokenType.Null || string.IsNullOrEmpty(t.Value<string>()))) { return (false, "null-path-in-_ep"); }
                foreach (string p in HardenedEncryptedPaths)
                {
                    if (!ep.Any(t => t.Value<string>() == p)) { return (false, $"missing-path:{p}"); }
                }
            }
            else
            {
                if (sens != null && sens.Type != JTokenType.Null) { return (false, "AEAD-plaintext-leaked"); }
                if (string.IsNullOrEmpty(ei.Value<string>("_ed"))) { return (false, "no-_ed-ciphertext"); }
            }
            return (true, $"cipher+v{ver}");
        }

        private static async Task<JObject> ReadPath(string path, string id, string rproc)
        {
            if (path == "point")
            {
                try { return (await enc.ReadItemAsync<JObject>(id, new PartitionKey(Pk), WithProcessor(new ItemRequestOptions(), rproc))).Resource; }
                catch (CosmosException e) when (e.StatusCode == HttpStatusCode.NotFound) { return null; }
            }
            string q = path == "query" ? "SELECT * FROM c WHERE c.id = @id" : "SELECT * FROM c";
            QueryDefinition qd = new(q);
            if (path == "query") { qd = qd.WithParameter("@id", id); }
            using FeedIterator<JObject> it = enc.GetItemQueryIterator<JObject>(qd, requestOptions: WithProcessor(new QueryRequestOptions { PartitionKey = new PartitionKey(Pk) }, rproc));
            while (it.HasMoreResults)
            {
                foreach (JObject d in await it.ReadNextAsync()) { if (d.Value<string>("id") == id) { return d; } }
            }
            return null;
        }

        // Anti-fake-green number-integrity: a decrypted numeric path must be a numeric JSON token. A value
        // that decrypts as a string ("5") or null would round-trip through the typed Doc.EncLong/double fields
        // undetected (coerced back to a number), so the typed field comparison alone cannot see it.
        private static (bool ok, string detail) NumbersAreNumeric(JObject j)
        {
            foreach (string field in new[] { "EncLong", "EncIntegralDouble", "EncNormalDouble" })
            {
                JToken t = j[field];
                if (t == null || (t.Type != JTokenType.Integer && t.Type != JTokenType.Float))
                {
                    return (false, $"{field} decrypted as {(t == null ? "<missing>" : t.Type.ToString())} (want numeric)");
                }
            }
            return (true, "numeric");
        }

        private static EncryptionItemRequestOptions Options(string algo, string proc)
        {
            EncryptionItemRequestOptions requestOptions = new()
            {
                EncryptionOptions = new EncryptionOptions
                {
                    DataEncryptionKeyId = algo == MdeAlgo ? MdeDekId : AeadDekId,
                    EncryptionAlgorithm = algo,
                    PathsToEncrypt = new List<string>(HardenedEncryptedPaths),
                },
            };
            return WithProcessor(requestOptions, proc);
        }

        private static T WithProcessor<T>(T requestOptions, string proc) where T : RequestOptions
        {
            Dictionary<string, object> properties = requestOptions.Properties == null
                ? new Dictionary<string, object>()
                : new Dictionary<string, object>(requestOptions.Properties);
            properties[StreamKey] = proc;
            requestOptions.Properties = properties;
            return requestOptions;
        }

        private static async Task TryCreateDek(CosmosDataEncryptionKeyProvider p, string id, string algo)
        {
            try
            {
                await p.DataEncryptionKeyContainer.CreateDataEncryptionKeyAsync(id, algo, new Microsoft.Azure.Cosmos.Encryption.Custom.EncryptionKeyWrapMetadata("matrix-store", "https://matrix.local"));
            }
            catch (CosmosException e) when (e.StatusCode == HttpStatusCode.Conflict) { }
        }

        private static Doc BuildDoc(string id) => new()
        {
            id = id,
            PK = Pk,
            NonSensitive = "plain",
            Sensitive = $"secret::{id}",
            PlainEscaped = PlainEscapedValue,
            EncEscaped = EncEscapedValue,
            EncAstral = EncAstralValue,
            EscNameValue = EscNameValue,
            EncObj = new JObject { ["a"] = JValue.CreateNull(), ["b"] = 1 },
            EncArr = new JArray { 1, JValue.CreateNull(), 2 },
            EncLong = EncLongValue,
            EncIntegralDouble = EncIntegralDoubleValue,
            EncNormalDouble = EncNormalDoubleValue,
        };

        private static string Signature(Doc d)
        {
            if (d == null) { return "<null-doc>"; }
            string objSig = d.EncObj == null ? "<null-obj>" : $"{{a={Tok(d.EncObj["a"])},b={Tok(d.EncObj["b"])}}}";
            string arrSig = d.EncArr == null ? "<null-arr>" : "[" + string.Join(",", d.EncArr.Select(Tok)) + "]";
            return string.Join("\u001F", new[]
            {
                d.Sensitive ?? "<null>",
                d.NonSensitive ?? "<null>",
                d.PlainEscaped ?? "<null>",
                d.EncEscaped ?? "<null>",
                d.EncAstral ?? "<null>",
                d.EscNameValue ?? "<null>",
                d.EncLong.ToString(CultureInfo.InvariantCulture),
                d.EncIntegralDouble.ToString("R", CultureInfo.InvariantCulture),
                d.EncNormalDouble.ToString("R", CultureInfo.InvariantCulture),
                objSig,
                arrSig,
            });

            static string Tok(JToken t) => t == null ? "<miss>" : t.Type == JTokenType.Null ? "null" : t.ToString(Newtonsoft.Json.Formatting.None);
        }

        private static (bool ok, string detail) VerifyDoc(Doc actual, string id)
        {
            if (actual == null) { return (false, "not-found"); }
            string[] names = { "Sensitive", "NonSensitive", "PlainEscaped", "EncEscaped", "EncAstral", "EscName", "EncLong", "EncIntegralDouble", "EncNormalDouble", "EncObj", "EncArr" };
            string[] a = Signature(actual).Split('\u001F');
            string[] e = Signature(BuildDoc(id)).Split('\u001F');
            if (a.Length != e.Length) { return (false, "field-count-mismatch"); }
            for (int i = 0; i < e.Length; i++)
            {
                if (!string.Equals(a[i], e[i], StringComparison.Ordinal)) { return (false, $"{names[i]} got '{Show(a[i])}' want '{Show(e[i])}'"); }
            }
            return (true, "all-fields-match");

            static string Show(string s) => (s ?? "<null>").Replace("\n", "\\n").Replace("\t", "\\t").Replace("\u0001", "\\u0001");
        }

        // Only the HASH of the canonical signature crosses HTTP, so no decrypted field value ever
        // leaves this process. Equal input -> equal hash, so the driver's A/B equivalence (N-hash ==
        // S-hash == writer-hash) is exact; a single differing field flips the hash.
        private static string Sha256Hex(string s)
            => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s ?? string.Empty)));

        private sealed class Doc
        {
            public string id { get; set; }
            public string PK { get; set; }
            public string NonSensitive { get; set; }
            public string Sensitive { get; set; }
            public string PlainEscaped { get; set; }
            public string EncEscaped { get; set; }
            public string EncAstral { get; set; }

            [Newtonsoft.Json.JsonProperty(EscPropName)]
            public string EscNameValue { get; set; }

            public JObject EncObj { get; set; }
            public JArray EncArr { get; set; }
            public long EncLong { get; set; }
            public double EncIntegralDouble { get; set; }
            public double EncNormalDouble { get; set; }
        }
    }

    // DTOs crossing HTTP. NONE of these carry hardened-doc content — only ids, selectors, status
    // strings and a SHA-256 signature HASH. (See the FIDELITY INVARIANT at the top.)
    public readonly record struct VersionResult(string Version, string Expected, string Informational, string AssemblyVersion);

    public readonly record struct WriteResult(string Status, string Detail, string ExpectedSignatureHash);

    public readonly record struct ReadResult(bool RawOk, string RawDetail, bool DecOk, string Detail, string SignatureHash);

    public readonly record struct TamperResult(bool Pass, string Detail);
}
