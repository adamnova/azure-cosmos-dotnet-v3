//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

namespace CompatMatrix
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Globalization;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Net.Http;
    using System.Reflection;
    using System.Security.Cryptography;
    using System.Text;
    using System.Text.Json;
    using System.Threading.Tasks;
    using EncryptionCustomCompatibility;
    using Microsoft.Azure.Cosmos;
    using Microsoft.Azure.Cosmos.Encryption.Custom;
    using Microsoft.Data.Encryption.Cryptography;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;
    using CustomEncryptionKeyWrapMetadata = Microsoft.Azure.Cosmos.Encryption.Custom.EncryptionKeyWrapMetadata;

    public static class Program
    {
#if COMPAT_CURRENT
        private const string WorkerRole = "current";
#else
        private const string WorkerRole = "released";
#endif

        private const string ActivitySourceName = "Microsoft.Azure.Cosmos.Encryption.Custom";
        private const string AccountKeyEnvironmentVariable = "COSMOS_COMPAT_MATRIX_KEY";
        private const string StreamPropertyName = "encryption-json-processor";
        private const string PartitionKeyValue = "compat-matrix";
        private const string KeyContainerId = "keys";
        private const string ItemContainerId = "items";
        private const string MdeFamily = "MDE";
        private const string AeadFamily = "AEAD";
        private const string PlaintextFamily = "PLAINTEXT";
        private const string NewtonsoftProcessor = "Newtonsoft";
        private const string StreamProcessor = "Stream";
        private const string NoProcessor = "None";
        private const string EncryptOperation = "Encrypt";
        private const string DecryptOperation = "Decrypt";
        private const string ExternalEncryptorKind = "external-preview07-surface";
        private const string CosmosEncryptorKind = "built-in-cosmos-encryptor";
        private const string MdeAlgorithm = CosmosEncryptionAlgorithm.MdeAeadAes256CbcHmac256Randomized;
#pragma warning disable CS0618
        private static readonly string AeadAlgorithm = CosmosEncryptionAlgorithm.AEAes256CbcHmacSha256Randomized;
#pragma warning restore CS0618

        private const string EscapedPropertyName = "esc\"name\\x";
        private const string EscapedPropertyPath = "/" + EscapedPropertyName;
        private const string PlainEscapedValue = "p_q=\" p_b=\\ p_nl=\n p_u=\u00e9 end";
        private const string EncryptedEscapedValue = "q=\" b=\\ nl=\n tab=\t u=\u00e9 ctl=\u0001 end";
        private const string EncryptedAstralValue = "😀𐍈🜨 日本語 العربية \uD83D\uDE00 Z\u0301";
        private const string EscapedPropertyValue = "named-secret";
        private const string EncryptedDateValue = "2024-02-29T12:34:56.7890123Z";
        private const string PlainDateValue = "1999-12-31T23:59:59.0000000Z";
        private const long EncryptedLongValue = 9007199254740993L;
        private const long PlainLongValue = -9007199254740991L;
        private const double EncryptedIntegralDoubleValue = 5.0;
        private const double EncryptedNormalDoubleValue = 1234.5;

        private static readonly string[] EncryptedPropertyNames =
        {
            "Sensitive",
            "EncEscaped",
            "EncAstral",
            EscapedPropertyName,
            "EncObj",
            "EncArr",
            "EncNull",
            "EncLong",
            "EncDate",
            "EncIntegralDouble",
            "EncNormalDouble",
        };

        private static readonly string[] EncryptedPaths =
        {
            "/Sensitive",
            "/EncEscaped",
            "/EncAstral",
            EscapedPropertyPath,
            "/EncObj",
            "/EncArr",
            "/EncNull",
            "/EncLong",
            "/EncDate",
            "/EncIntegralDouble",
            "/EncNormalDouble",
        };

        public static async Task<int> Main(string[] args)
        {
            Dictionary<string, string> arguments = ParseArguments(args);
            string action = arguments.GetValueOrDefault("action", "identity");

            try
            {
                int failures = action switch
                {
                    "identity" => EmitIdentity(),
                    "write" => await WriteAsync(arguments),
                    "read" => await ReadAsync(arguments),
                    "rewrite" => await RewriteAsync(arguments),
                    _ => throw new InvalidOperationException($"Unknown worker action: {action}"),
                };

                Emit(new WorkerRecord
                {
                    Kind = "completion",
                    Role = WorkerRole,
                    Status = failures == 0 ? "pass" : "fail",
                    Detail = $"action={action};failures={failures}",
                });
                return failures == 0 ? 0 : 1;
            }
            catch (Exception exception)
            {
                Emit(new WorkerRecord
                {
                    Kind = "error",
                    Role = WorkerRole,
                    Status = "fail",
                    Detail = Describe(exception),
                });
                Emit(new WorkerRecord
                {
                    Kind = "completion",
                    Role = WorkerRole,
                    Status = "fail",
                    Detail = $"action={action};unhandled",
                });
                return 1;
            }
        }

        private static int EmitIdentity()
        {
            Assembly assembly = typeof(EncryptionContainerExtensions).Assembly;
            string assemblyPath = assembly.Location;
            string informationalVersion = assembly
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
                ?.InformationalVersion ?? "<missing>";

            Emit(new WorkerRecord
            {
                Kind = "identity",
                Role = WorkerRole,
                PackageVersion = informationalVersion.Split('+')[0],
                InformationalVersion = informationalVersion,
                ProductVersion = FileVersionInfo.GetVersionInfo(assemblyPath).ProductVersion,
                AssemblyVersion = assembly.GetName().Version?.ToString(),
                AssemblyMvid = assembly.ManifestModule.ModuleVersionId.ToString("D"),
                AssemblySha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(assemblyPath))),
                AssemblyPath = assemblyPath,
                CosmosVersion = typeof(CosmosClient).Assembly.GetName().Version?.ToString(),
                MdeVersion = typeof(EncryptionKeyStoreProvider).Assembly.GetName().Version?.ToString(),
            });
            return 0;
        }

        private static async Task<int> WriteAsync(IReadOnlyDictionary<string, string> arguments)
        {
            WorkerSettings settings = WorkerSettings.Create(arguments);
            using CosmosClient client = CreateClient(settings);
            Database database = await client.CreateDatabaseIfNotExistsAsync(settings.Database);
            Container keyContainer = await CreateContainerAsync(database, KeyContainerId, "/id");
            ProviderContext setupProvider = await CreateProviderAsync(
                database,
                keyContainer.Id,
                AeadFamily,
                NewtonsoftProcessor);

            await setupProvider.Provider.DataEncryptionKeyContainer.CreateDataEncryptionKeyAsync(
                GetDekId(WorkerRole, MdeFamily),
                MdeAlgorithm,
                new CustomEncryptionKeyWrapMetadata("compat-matrix", GetMasterKeyId(WorkerRole)));
            await setupProvider.Provider.DataEncryptionKeyContainer.CreateDataEncryptionKeyAsync(
                GetDekId(WorkerRole, AeadFamily),
                AeadAlgorithm,
                new CustomEncryptionKeyWrapMetadata("compat-matrix", GetMasterKeyId(WorkerRole)));

            Container plain = await CreateContainerAsync(database, ItemContainerId, "/PK");
            int failures = 0;
            foreach (WriteScenario scenario in GetWriteScenarios())
            {
                string scenarioId = $"write:{WorkerRole}:{scenario.Family}:{scenario.Processor}";
                ProviderContext providerContext = null;
                string encryptorKind = null;
                try
                {
                    providerContext = await CreateProviderAsync(
                        database,
                        keyContainer.Id,
                        scenario.Family,
                        scenario.Processor);
                    Encryptor encryptor = CreateEncryptor(
                        providerContext.Provider,
                        scenario.Family,
                        scenario.Processor);
                    encryptorKind = GetEncryptorKind(scenario.Family, scenario.Processor);
                    Container encrypted = plain.WithEncryptor(encryptor);
                    string documentId = GetDocumentId(WorkerRole, scenario.Family, scenario.Processor);
                    Doc document = BuildDocument(documentId);
                    List<string> writeScopes = await CaptureScopesAsync(async () =>
                    {
                        await encrypted.UpsertItemAsync(
                            document,
                            new PartitionKey(PartitionKeyValue),
                            CreateEncryptionOptions(WorkerRole, scenario.Family, scenario.Processor));
                    });
                    EnsureProcessorScopes(
                        writeScopes,
                        scenario.Family,
                        EncryptOperation,
                        scenario.Processor);

                    Doc selfRead = null;
                    List<string> selfReadScopes = await CaptureScopesAsync(async () =>
                    {
                        selfRead = (await encrypted.ReadItemAsync<Doc>(
                            documentId,
                            new PartitionKey(PartitionKeyValue),
                            WithProcessor(new ItemRequestOptions(), scenario.Processor))).Resource;
                    });
                    EnsureDocumentMatches(selfRead, documentId);
                    string actualReadProcessor = EnsureDecryptProcessorScopes(
                        selfReadScopes,
                        scenario.Family,
                        scenario.Processor,
                        allowNewtonsoftFallback: false);

                    JObject raw = await ReadRawAsync(plain, documentId);
                    EnsureRawFixture(raw, scenario.Family, document);
                    EmitObservation(
                        scenarioId,
                        "pass",
                        "write, raw encryption, and self-read succeeded",
                        scenario.Processor,
                        actualReadProcessor,
                        writeScopes.Concat(selfReadScopes).ToList(),
                        providerContext.Construction,
                        encryptorKind,
                        documentId,
                        HashJson(raw),
                        HashPlaintext(document),
                        DescribeRawShape(raw, scenario.Family));
                }
                catch (Exception exception)
                {
                    failures++;
                    EmitObservation(
                        scenarioId,
                        "fail",
                        Describe(exception),
                        scenario.Processor,
                        null,
                        null,
                        providerContext?.Construction,
                        encryptorKind);
                }
            }

#if !COMPAT_CURRENT
            failures += await WritePlaintextFixtureAsync(plain);
            failures += await WriteRewriteFixturesAsync(database, keyContainer.Id);
#else
            failures += await WriteNonZeroPositionStreamFixtureAsync(
                database,
                keyContainer.Id,
                plain);
            failures += await VerifyReadOnlySdkResponseAsync(
                database,
                keyContainer.Id,
                plain);
            failures += await VerifyLegacyStreamWriteRejectedAsync(
                database,
                keyContainer.Id,
                plain);
#endif
            return failures;
        }

#if COMPAT_CURRENT
        private static async Task<int> WriteNonZeroPositionStreamFixtureAsync(
            Database database,
            string keyContainerId,
            Container plain)
        {
            const string scenarioId = "boundary:current:MDE:Stream:nonzero-input";
            const string documentId = "current-mde-stream-nonzero-input";
            ProviderContext providerContext = null;
            try
            {
                providerContext = await CreateProviderAsync(
                    database,
                    keyContainerId,
                    MdeFamily,
                    StreamProcessor);
                Encryptor encryptor = CreateEncryptor(
                    providerContext.Provider,
                    MdeFamily,
                    StreamProcessor);
                Container encrypted = plain.WithEncryptor(encryptor);
                Doc document = BuildDocument(documentId);
                byte[] prefix = Encoding.UTF8.GetBytes("ignored-prefix:");
                byte[] payload = Encoding.UTF8.GetBytes(
                    JsonConvert.SerializeObject(document, Formatting.None));
                using MemoryStream input = new();
                await input.WriteAsync(prefix);
                await input.WriteAsync(payload);
                input.Position = prefix.Length;

                List<string> scopes = await CaptureScopesAsync(async () =>
                {
                    using ResponseMessage response = await encrypted.UpsertItemStreamAsync(
                        input,
                        new PartitionKey(PartitionKeyValue),
                        CreateEncryptionOptions(
                            WorkerRole,
                            MdeFamily,
                            StreamProcessor));
                    response.EnsureSuccessStatusCode();
                });
                EnsureProcessorScopes(
                    scopes,
                    MdeFamily,
                    EncryptOperation,
                    StreamProcessor);

                JObject raw = await ReadRawAsync(plain, documentId);
                EnsureRawFixture(raw, MdeFamily, document);
                Doc reread = await ReadDocumentAsync(
                    encrypted,
                    documentId,
                    "point",
                    StreamProcessor);
                EnsureDocumentMatches(reread, documentId);
                EmitObservation(
                    scenarioId,
                    "pass",
                    "actual item Stream write consumed the payload from a nonzero input position",
                    StreamProcessor,
                    StreamProcessor,
                    scopes,
                    providerContext.Construction,
                    CosmosEncryptorKind,
                    documentId,
                    HashJson(raw),
                    HashPlaintext(document),
                    DescribeRawShape(raw, MdeFamily));
                return 0;
            }
            catch (Exception exception)
            {
                EmitObservation(
                    scenarioId,
                    "fail",
                    Describe(exception),
                    StreamProcessor,
                    null,
                    null,
                    providerContext?.Construction,
                    CosmosEncryptorKind);
                return 1;
            }
        }

        private static async Task<int> VerifyReadOnlySdkResponseAsync(
            Database database,
            string keyContainerId,
            Container plain)
        {
            const string scenarioId = "boundary:current:MDE:Stream:readonly-response";
            string documentId = GetDocumentId(WorkerRole, MdeFamily, StreamProcessor);
            ProviderContext providerContext = null;
            try
            {
                using ResponseMessage rawResponse = await plain.ReadItemStreamAsync(
                    documentId,
                    new PartitionKey(PartitionKeyValue));
                rawResponse.EnsureSuccessStatusCode();
                if (rawResponse.Content == null || rawResponse.Content.CanWrite)
                {
                    throw new CompatibilityOracleException(
                        "The actual SDK point response was not a read-only input stream.");
                }

                providerContext = await CreateProviderAsync(
                    database,
                    keyContainerId,
                    MdeFamily,
                    StreamProcessor);
                Container encrypted = plain.WithEncryptor(
                    CreateEncryptor(
                        providerContext.Provider,
                        MdeFamily,
                        StreamProcessor));
                List<string> scopes = await CaptureScopesAsync(async () =>
                {
                    await EnsureDecryptedJsonFidelityAsync(
                        encrypted,
                        documentId,
                        "point",
                        StreamProcessor);
                });
                string actualProcessor = EnsureDecryptProcessorScopes(
                    scopes,
                    MdeFamily,
                    StreamProcessor,
                    allowNewtonsoftFallback: false);
                JObject raw = await ReadRawAsync(plain, documentId);
                EmitObservation(
                    scenarioId,
                    "pass",
                    "actual read-only SDK point response decrypted through the requested Stream path",
                    StreamProcessor,
                    actualProcessor,
                    scopes,
                    providerContext.Construction,
                    CosmosEncryptorKind,
                    documentId,
                    HashJson(raw),
                    HashPlaintext(BuildDocument(documentId)),
                    DescribeRawShape(raw, MdeFamily));
                return 0;
            }
            catch (Exception exception)
            {
                EmitObservation(
                    scenarioId,
                    "fail",
                    Describe(exception),
                    StreamProcessor,
                    null,
                    null,
                    providerContext?.Construction,
                    CosmosEncryptorKind);
                return 1;
            }
        }

        private static async Task<int> VerifyLegacyStreamWriteRejectedAsync(
            Database database,
            string keyContainerId,
            Container plain)
        {
            const string scenarioId = "reject:current:AEAD:Stream:write";
            const string documentId = "current-aead-stream-rejected";
            ProviderContext providerContext = null;
            try
            {
                providerContext = await CreateProviderAsync(
                    database,
                    keyContainerId,
                    AeadFamily,
                    StreamProcessor);
                Container encrypted = plain.WithEncryptor(
                    CreateEncryptor(
                        providerContext.Provider,
                        AeadFamily,
                        StreamProcessor));
                NotSupportedException rejection = null;
                try
                {
                    await encrypted.UpsertItemAsync(
                        BuildDocument(documentId),
                        new PartitionKey(PartitionKeyValue),
                        CreateEncryptionOptions(
                            WorkerRole,
                            AeadFamily,
                            StreamProcessor));
                }
                catch (NotSupportedException exception)
                {
                    rejection = exception;
                }

                if (rejection == null)
                {
                    throw new CompatibilityOracleException(
                        "Legacy AEAD Stream write was not rejected.");
                }

                using ResponseMessage rawResponse = await plain.ReadItemStreamAsync(
                    documentId,
                    new PartitionKey(PartitionKeyValue));
                if (rawResponse.StatusCode != HttpStatusCode.NotFound)
                {
                    throw new CompatibilityOracleException(
                        "Legacy AEAD Stream write reached storage before rejection.");
                }

                EmitObservation(
                    scenarioId,
                    "pass",
                    "legacy AEAD Stream write was rejected and no item reached storage",
                    StreamProcessor,
                    "rejected-before-storage",
                    Array.Empty<string>(),
                    providerContext.Construction,
                    ExternalEncryptorKind,
                    documentId,
                    HashText("absent:" + documentId),
                    HashPlaintext(BuildDocument(documentId)),
                    "family=AEAD;absent=true");
                return 0;
            }
            catch (Exception exception)
            {
                EmitObservation(
                    scenarioId,
                    "fail",
                    Describe(exception),
                    StreamProcessor,
                    null,
                    null,
                    providerContext?.Construction,
                    ExternalEncryptorKind);
                return 1;
            }
        }
#endif

        private static async Task<int> ReadAsync(IReadOnlyDictionary<string, string> arguments)
        {
            WorkerSettings settings = WorkerSettings.Create(arguments);
            string writer = GetRequired(arguments, "writer");
            if (writer != "released" && writer != "current")
            {
                throw new InvalidOperationException($"Unknown writer role: {writer}");
            }

            using CosmosClient client = CreateClient(settings);
            Database database = client.GetDatabase(settings.Database);
            Container keyContainer = database.GetContainer(KeyContainerId);
            Container plain = database.GetContainer(ItemContainerId);

            int failures = 0;
            foreach (ReadScenario scenario in GetReadScenarios(writer))
            {
                foreach (string path in scenario.Paths)
                {
                    string scenarioId =
                        $"read:{writer}->{WorkerRole}:{scenario.Family}:{scenario.WriteProcessor}->{GetRequestedProcessorLabel(scenario.ReadProcessor)}:{path}";
                    ProviderContext providerContext = null;
                    string encryptorKind = null;
                    try
                    {
                        providerContext = await CreateProviderAsync(
                            database,
                            keyContainer.Id,
                            scenario.Family,
                            scenario.ReadProcessor);
                        Encryptor encryptor = CreateEncryptor(
                            providerContext.Provider,
                            scenario.Family,
                            scenario.ReadProcessor);
                        encryptorKind = GetEncryptorKind(
                            scenario.Family,
                            scenario.ReadProcessor);
                        Container encrypted = plain.WithEncryptor(encryptor);
                        string documentId = GetDocumentId(writer, scenario.Family, scenario.WriteProcessor);
                        JObject raw = await ReadRawAsync(plain, documentId);
                        EnsureExpectedFixtureHash(arguments, documentId, raw);
                        EnsureRawFixture(raw, scenario.Family, BuildDocument(documentId));

                        Doc document = null;
                        int typedDecryptCallsBefore = GetExternalDecryptCallCount(encryptor);
                        List<string> typedReadScopes = await CaptureScopesAsync(async () =>
                        {
                            document = await ReadDocumentAsync(encrypted, documentId, path, scenario.ReadProcessor);
                        });
                        EnsureDocumentMatches(document, documentId);
                        string typedActualProcessor = EnsureDecryptProcessorScopes(
                            typedReadScopes,
                            scenario.Family,
                            scenario.ReadProcessor,
                            allowNewtonsoftFallback:
                                scenario.ReadProcessor == StreamProcessor &&
                                scenario.Family == AeadFamily,
                            externalDecryptObserved:
                                GetExternalDecryptCallCount(encryptor) > typedDecryptCallsBefore);

                        int streamDecryptCallsBefore = GetExternalDecryptCallCount(encryptor);
                        List<string> streamReadScopes = await CaptureScopesAsync(async () =>
                        {
                            await EnsureDecryptedJsonFidelityAsync(
                                encrypted,
                                documentId,
                                path,
                                scenario.ReadProcessor,
                                scenario.Family == PlaintextFamily ? raw : null);
                        });
                        string streamActualProcessor = EnsureDecryptProcessorScopes(
                            streamReadScopes,
                            scenario.Family,
                            scenario.ReadProcessor,
                            allowNewtonsoftFallback:
                                scenario.ReadProcessor == StreamProcessor &&
                                scenario.Family == AeadFamily,
                            externalDecryptObserved:
                                GetExternalDecryptCallCount(encryptor) > streamDecryptCallsBefore);
                        string actualProcessors =
                            $"typed={typedActualProcessor},stream={streamActualProcessor}";

                        EmitObservation(
                            scenarioId,
                            "pass",
                            $"peer document decrypted exactly; requested={scenario.ReadProcessor}; {actualProcessors}",
                            scenario.ReadProcessor,
                            actualProcessors,
                            typedReadScopes.Concat(streamReadScopes).ToList(),
                            providerContext.Construction,
                            encryptorKind,
                            documentId,
                            HashJson(raw),
                            HashPlaintext(document),
                            DescribeRawShape(raw, scenario.Family));
                    }
                    catch (Exception exception)
                    {
                        failures++;
                        EmitObservation(
                            scenarioId,
                            "fail",
                            Describe(exception),
                            scenario.ReadProcessor,
                            null,
                            null,
                            providerContext?.Construction,
                            encryptorKind);
                    }
                }
            }

            return failures;
        }

        private static async Task<int> WritePlaintextFixtureAsync(Container plain)
        {
            const string scenarioId = "write:released:PLAINTEXT:None";
            string documentId = GetDocumentId("released", PlaintextFamily, NoProcessor);
            try
            {
                Doc document = BuildDocument(documentId);
                await plain.UpsertItemAsync(document, new PartitionKey(PartitionKeyValue));
                Doc selfRead = (await plain.ReadItemAsync<Doc>(
                    documentId,
                    new PartitionKey(PartitionKeyValue))).Resource;
                EnsureDocumentMatches(selfRead, documentId);
                JObject raw = await ReadRawAsync(plain, documentId);
                EnsureRawFixture(raw, PlaintextFamily, document);
                EmitObservation(
                    scenarioId,
                    "pass",
                    "released plaintext fixture write and self-read succeeded",
                    NoProcessor,
                    NoProcessor,
                    Array.Empty<string>(),
                    "released-dual-provider-constructor",
                    ExternalEncryptorKind,
                    documentId,
                    HashJson(raw),
                    HashPlaintext(document),
                    DescribeRawShape(raw, PlaintextFamily));
                return 0;
            }
            catch (Exception exception)
            {
                EmitObservation(
                    scenarioId,
                    "fail",
                    Describe(exception),
                    NoProcessor,
                    null,
                    null,
                    "released-dual-provider-constructor",
                    ExternalEncryptorKind);
                return 1;
            }
        }

        private static async Task<int> WriteRewriteFixturesAsync(
            Database database,
            string keyContainerId)
        {
            ProviderContext providerContext = await CreateProviderAsync(
                database,
                keyContainerId,
                MdeFamily,
                NewtonsoftProcessor);
            Encryptor encryptor = CreateEncryptor(
                providerContext.Provider,
                MdeFamily,
                NewtonsoftProcessor);
            int failures = 0;
            foreach (string rewriteProcessor in new[] { NewtonsoftProcessor, StreamProcessor })
            {
                Container plain = await CreateContainerAsync(
                    database,
                    GetRewriteContainerId(rewriteProcessor),
                    "/PK");
                Container encrypted = plain.WithEncryptor(encryptor);
                string documentId = GetRewriteDocumentId("released", rewriteProcessor);
                string scenarioId = $"fixture:released:rewrite:{rewriteProcessor}";
                try
                {
                    Doc document = BuildDocument(documentId);
                    await encrypted.UpsertItemAsync(
                        document,
                        new PartitionKey(PartitionKeyValue),
                        CreateEncryptionOptions("released", MdeFamily, NewtonsoftProcessor));
                    JObject raw = await ReadRawAsync(plain, documentId);
                    EnsureRawFixture(raw, MdeFamily, document);
                    EmitFixture(
                        scenarioId,
                        documentId,
                        HashJson(raw),
                        HashPlaintext(document),
                        DescribeRawShape(raw, MdeFamily));
                }
                catch (Exception exception)
                {
                    failures++;
                    Emit(new WorkerRecord
                    {
                        Kind = "fixture",
                        Role = WorkerRole,
                        ScenarioId = scenarioId,
                        Status = "fail",
                        Detail = Describe(exception),
                        DocumentId = documentId,
                    });
                }
            }

            return failures;
        }

        private static async Task<int> RewriteAsync(IReadOnlyDictionary<string, string> arguments)
        {
#if !COMPAT_CURRENT
            _ = arguments;
            throw new InvalidOperationException("Only the current package worker can perform rewrites.");
#else
            WorkerSettings settings = WorkerSettings.Create(arguments);
            string writer = GetRequired(arguments, "writer");
            string rewriteProcessor = GetRequired(arguments, "processor");
            if (writer != "released")
            {
                throw new InvalidOperationException($"Unknown rewrite source role: {writer}");
            }

            if (rewriteProcessor != NewtonsoftProcessor && rewriteProcessor != StreamProcessor)
            {
                throw new InvalidOperationException($"Unknown rewrite processor: {rewriteProcessor}");
            }

            using CosmosClient client = CreateClient(settings);
            Database database = client.GetDatabase(settings.Database);
            Container keyContainer = database.GetContainer(KeyContainerId);
            Container plain = database.GetContainer(GetRewriteContainerId(rewriteProcessor));
            string documentId = GetRewriteDocumentId(writer, rewriteProcessor);
            string scenarioId = $"rewrite:{writer}->{WorkerRole}:MDE:{rewriteProcessor}";
            ProviderContext providerContext = null;
            string encryptorKind = null;
            int failures = 0;
            try
            {
                providerContext = await CreateProviderAsync(
                    database,
                    keyContainer.Id,
                    MdeFamily,
                    rewriteProcessor);
                Encryptor encryptor = CreateEncryptor(
                    providerContext.Provider,
                    MdeFamily,
                    rewriteProcessor);
                encryptorKind = GetEncryptorKind(MdeFamily, rewriteProcessor);
                Container encrypted = plain.WithEncryptor(encryptor);
                JObject rawBefore = await ReadRawAsync(plain, documentId);
                EnsureExpectedFixtureHash(arguments, documentId, rawBefore);
                Doc expected = BuildDocument(documentId);
                EnsureRawFixture(rawBefore, MdeFamily, expected);

                Doc source = null;
                int sourceDecryptCallsBefore = GetExternalDecryptCallCount(encryptor);
                List<string> sourceReadScopes = await CaptureScopesAsync(async () =>
                {
                    source = await ReadDocumentAsync(
                        encrypted,
                        documentId,
                        "point",
                        rewriteProcessor);
                });
                EnsureDocumentMatches(source, documentId);
                string sourceActualProcessor = EnsureDecryptProcessorScopes(
                    sourceReadScopes,
                    MdeFamily,
                    rewriteProcessor,
                    allowNewtonsoftFallback: false,
                    externalDecryptObserved:
                        GetExternalDecryptCallCount(encryptor) > sourceDecryptCallsBefore);

                List<string> writeScopes = await CaptureScopesAsync(async () =>
                {
                    await encrypted.UpsertItemAsync(
                        source,
                        new PartitionKey(PartitionKeyValue),
                        CreateEncryptionOptions(WorkerRole, MdeFamily, rewriteProcessor));
                });
                EnsureProcessorScopes(
                    writeScopes,
                    MdeFamily,
                    EncryptOperation,
                    rewriteProcessor);

                JObject rawAfter = await ReadRawAsync(plain, documentId);
                EnsureRawFixture(rawAfter, MdeFamily, source);
                EnsureNonSensitiveTokensPreserved(rawBefore, rawAfter);
                string inputFixtureSha256 = HashJson(rawBefore);
                string outputFixtureSha256 = HashJson(rawAfter);
                if (string.Equals(
                        inputFixtureSha256,
                        outputFixtureSha256,
                        StringComparison.OrdinalIgnoreCase))
                {
                    throw new CompatibilityOracleException(
                        "Rewrite did not replace the released ciphertext fixture.");
                }

                EmitObservation(
                    scenarioId,
                    "pass",
                    $"released MDE fixture read and rewritten; source={sourceActualProcessor}; target={rewriteProcessor}",
                    rewriteProcessor,
                    rewriteProcessor,
                    sourceReadScopes.Concat(writeScopes).ToList(),
                    providerContext.Construction,
                    encryptorKind,
                    documentId,
                    outputFixtureSha256,
                    HashPlaintext(source),
                    $"before={DescribeRawShape(rawBefore, MdeFamily)};after={DescribeRawShape(rawAfter, MdeFamily)}",
                    inputFixtureSha256);

                failures += await RereadRewriteAsync(
                    database,
                    keyContainer.Id,
                    plain,
                    writer,
                    rewriteProcessor,
                    NewtonsoftProcessor,
                    "point",
                    documentId,
                    outputFixtureSha256);
                failures += await RereadRewriteAsync(
                    database,
                    keyContainer.Id,
                    plain,
                    writer,
                    rewriteProcessor,
                    StreamProcessor,
                    "point",
                    documentId,
                    outputFixtureSha256);
                failures += await RereadRewriteAsync(
                    database,
                    keyContainer.Id,
                    plain,
                    writer,
                    rewriteProcessor,
                    rewriteProcessor,
                    "query",
                    documentId,
                    outputFixtureSha256);
                failures += await RereadRewriteAsync(
                    database,
                    keyContainer.Id,
                    plain,
                    writer,
                    rewriteProcessor,
                    rewriteProcessor,
                    "feed",
                    documentId,
                    outputFixtureSha256);
            }
            catch (Exception exception)
            {
                failures++;
                EmitObservation(
                    scenarioId,
                    "fail",
                    Describe(exception),
                    rewriteProcessor,
                    null,
                    null,
                    providerContext?.Construction,
                    encryptorKind);
            }

            return failures;
#endif
        }

        private static async Task<int> RereadRewriteAsync(
            Database database,
            string keyContainerId,
            Container plain,
            string writer,
            string rewriteProcessor,
            string readProcessor,
            string path,
            string documentId,
            string expectedFixtureSha256)
        {
            string scenarioId =
                $"reread:{writer}->{WorkerRole}:rewrite:{rewriteProcessor}->{GetRequestedProcessorLabel(readProcessor)}:{path}";
            ProviderContext providerContext = null;
            string encryptorKind = null;
            try
            {
                providerContext = await CreateProviderAsync(
                    database,
                    keyContainerId,
                    MdeFamily,
                    readProcessor);
                Encryptor encryptor = CreateEncryptor(
                    providerContext.Provider,
                    MdeFamily,
                    readProcessor);
                encryptorKind = GetEncryptorKind(MdeFamily, readProcessor);
                Container encrypted = plain.WithEncryptor(encryptor);
                JObject raw = await ReadRawAsync(plain, documentId);
                string actualFixtureSha256 = HashJson(raw);
                if (!string.Equals(
                        actualFixtureSha256,
                        expectedFixtureSha256,
                        StringComparison.OrdinalIgnoreCase))
                {
                    throw new CompatibilityOracleException(
                        $"Rewritten fixture hash changed before reread. Actual={actualFixtureSha256} Expected={expectedFixtureSha256}");
                }

                Doc document = null;
                int typedDecryptCallsBefore = GetExternalDecryptCallCount(encryptor);
                List<string> typedReadScopes = await CaptureScopesAsync(async () =>
                {
                    document = await ReadDocumentAsync(encrypted, documentId, path, readProcessor);
                });
                EnsureDocumentMatches(document, documentId);
                string typedActualProcessor = EnsureDecryptProcessorScopes(
                    typedReadScopes,
                    MdeFamily,
                    readProcessor,
                    allowNewtonsoftFallback: false,
                    externalDecryptObserved:
                        GetExternalDecryptCallCount(encryptor) > typedDecryptCallsBefore);

                int streamDecryptCallsBefore = GetExternalDecryptCallCount(encryptor);
                List<string> streamReadScopes = await CaptureScopesAsync(async () =>
                {
                    await EnsureDecryptedJsonFidelityAsync(
                        encrypted,
                        documentId,
                        path,
                        readProcessor);
                });
                string streamActualProcessor = EnsureDecryptProcessorScopes(
                    streamReadScopes,
                    MdeFamily,
                    readProcessor,
                    allowNewtonsoftFallback: false,
                    externalDecryptObserved:
                        GetExternalDecryptCallCount(encryptor) > streamDecryptCallsBefore);
                string actualProcessors =
                    $"typed={typedActualProcessor},stream={streamActualProcessor}";
                EmitObservation(
                    scenarioId,
                    "pass",
                    $"rewritten document decrypted exactly; {actualProcessors}",
                    readProcessor,
                    actualProcessors,
                    typedReadScopes.Concat(streamReadScopes).ToList(),
                    providerContext.Construction,
                    encryptorKind,
                    documentId,
                    actualFixtureSha256,
                    HashPlaintext(document),
                    DescribeRawShape(raw, MdeFamily));
                return 0;
            }
            catch (Exception exception)
            {
                EmitObservation(
                    scenarioId,
                    "fail",
                    Describe(exception),
                    readProcessor,
                    null,
                    null,
                    providerContext?.Construction,
                    encryptorKind);
                return 1;
            }
        }

        private static IEnumerable<WriteScenario> GetWriteScenarios()
        {
            yield return new WriteScenario(MdeFamily, NewtonsoftProcessor);
#if COMPAT_CURRENT
            yield return new WriteScenario(MdeFamily, StreamProcessor);
#endif
            yield return new WriteScenario(AeadFamily, NewtonsoftProcessor);
        }

        private static IEnumerable<ReadScenario> GetReadScenarios(string writer)
        {
            if (writer == "released")
            {
                yield return new ReadScenario(MdeFamily, NewtonsoftProcessor, NewtonsoftProcessor, ReadScenario.AllPathsWithReadMany);
#if COMPAT_CURRENT
                yield return new ReadScenario(MdeFamily, NewtonsoftProcessor, StreamProcessor, ReadScenario.AllPathsWithReadMany);
#endif
                yield return new ReadScenario(AeadFamily, NewtonsoftProcessor, NewtonsoftProcessor, ReadScenario.AllPathsWithReadMany);
#if COMPAT_CURRENT
                yield return new ReadScenario(AeadFamily, NewtonsoftProcessor, StreamProcessor, ReadScenario.AllPathsWithReadMany);
                yield return new ReadScenario(PlaintextFamily, NoProcessor, NewtonsoftProcessor, ReadScenario.AllPathsWithReadMany);
                yield return new ReadScenario(PlaintextFamily, NoProcessor, StreamProcessor, ReadScenario.PointOnly);
#endif
                yield break;
            }

#if COMPAT_CURRENT
            yield return new ReadScenario(MdeFamily, NewtonsoftProcessor, StreamProcessor, ReadScenario.AllPathsWithReadMany);
            yield return new ReadScenario(MdeFamily, StreamProcessor, NewtonsoftProcessor, ReadScenario.AllPathsWithReadMany);
#else
            yield return new ReadScenario(MdeFamily, NewtonsoftProcessor, NewtonsoftProcessor, ReadScenario.AllPathsWithReadMany);
            yield return new ReadScenario(MdeFamily, StreamProcessor, NewtonsoftProcessor, ReadScenario.AllPathsWithReadMany);
            yield return new ReadScenario(AeadFamily, NewtonsoftProcessor, NewtonsoftProcessor, ReadScenario.AllPathsWithReadMany);
#endif
        }

        private static CosmosClient CreateClient(WorkerSettings settings)
        {
            return new CosmosClient(
                settings.Endpoint.AbsoluteUri,
                settings.Key,
                new CosmosClientOptions
                {
                    ConnectionMode = ConnectionMode.Gateway,
                    LimitToEndpoint = true,
                    HttpClientFactory = () => new HttpClient(
                        CreateEmulatorHttpClientHandler(settings.Endpoint)),
                });
        }

        private static async Task<Container> CreateContainerAsync(
            Database database,
            string containerId,
            string partitionKeyPath)
        {
            return (await database.CreateContainerIfNotExistsAsync(containerId, partitionKeyPath, 400)).Container;
        }

        private static async Task<ProviderContext> CreateProviderAsync(
            Database database,
            string keyContainerId,
            string family,
            string processor)
        {
            CosmosDataEncryptionKeyProvider provider;
            string construction;
#if COMPAT_CURRENT
            if (family == MdeFamily && processor == StreamProcessor)
            {
                provider = CosmosDataEncryptionKeyProvider.Create(
                    new MatrixKeyStoreProvider(),
                    new DekCacheOptions
                    {
                        DekPropertiesTimeToLive = TimeSpan.FromMinutes(11),
                        RefreshBeforeExpiry = TimeSpan.FromMinutes(2),
                    });
                construction = "factory-store-provider-cache-options";
            }
            else if (family == MdeFamily)
            {
                provider = new CosmosDataEncryptionKeyProvider(
                    new MatrixKeyStoreProvider(),
                    TimeSpan.FromMinutes(7));
                construction = "constructor-store-provider-timespan";
            }
            else
            {
#pragma warning disable CS0618
                provider = CosmosDataEncryptionKeyProvider.Create(
                    new MatrixKeyWrapProvider(),
                    new MatrixKeyStoreProvider(),
                    new DekCacheOptions
                    {
                        DekPropertiesTimeToLive = TimeSpan.FromMinutes(13),
                    });
#pragma warning restore CS0618
                construction = "factory-dual-provider-cache-options";
            }
#else
#pragma warning disable CS0618
            provider = new CosmosDataEncryptionKeyProvider(
                new MatrixKeyWrapProvider(),
                new MatrixKeyStoreProvider(),
                TimeSpan.FromMinutes(5));
#pragma warning restore CS0618
            construction = "released-dual-provider-constructor";
#endif
            await provider.InitializeAsync(database, keyContainerId);
            return new ProviderContext(provider, construction);
        }

        private static Encryptor CreateEncryptor(
            CosmosDataEncryptionKeyProvider provider,
            string family,
            string processor)
        {
#if COMPAT_CURRENT
            if (family == MdeFamily && processor == StreamProcessor)
            {
                return new CosmosEncryptor(provider);
            }
#else
            _ = family;
            _ = processor;
#endif
            return new MatrixEncryptor(provider);
        }

        private static string GetEncryptorKind(string family, string processor)
        {
#if COMPAT_CURRENT
            return family == MdeFamily && processor == StreamProcessor
                ? CosmosEncryptorKind
                : ExternalEncryptorKind;
#else
            _ = family;
            _ = processor;
            return ExternalEncryptorKind;
#endif
        }

        private static int GetExternalDecryptCallCount(Encryptor encryptor)
        {
            return encryptor is MatrixEncryptor matrixEncryptor
                ? matrixEncryptor.DecryptCallCount
                : 0;
        }

        private static Uri ValidateEmulatorEndpoint(string endpoint)
        {
            if (!Uri.TryCreate(endpoint, UriKind.Absolute, out Uri uri) ||
                !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
                !uri.IsLoopback ||
                uri.Port != 8081 ||
                !string.IsNullOrEmpty(uri.UserInfo))
            {
                throw new InvalidOperationException(
                    "The compatibility matrix only accepts an HTTPS loopback Cosmos emulator endpoint on port 8081.");
            }

            return uri;
        }

        private static HttpClientHandler CreateEmulatorHttpClientHandler(Uri emulatorEndpoint)
        {
            return new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (request, _, _, _) =>
                    request?.RequestUri != null &&
                    request.RequestUri.IsLoopback &&
                    string.Equals(
                        request.RequestUri.Scheme,
                        Uri.UriSchemeHttps,
                        StringComparison.OrdinalIgnoreCase) &&
                    request.RequestUri.Port == 8081 &&
                    string.Equals(
                        request.RequestUri.Host,
                        emulatorEndpoint.Host,
                        StringComparison.OrdinalIgnoreCase),
            };
        }

        private static EncryptionItemRequestOptions CreateEncryptionOptions(
            string writer,
            string family,
            string processor)
        {
            EncryptionItemRequestOptions options = new()
            {
                EncryptionOptions = new EncryptionOptions
                {
                    DataEncryptionKeyId = GetDekId(writer, family),
                    EncryptionAlgorithm = family == MdeFamily ? MdeAlgorithm : AeadAlgorithm,
                    PathsToEncrypt = new List<string>(EncryptedPaths),
                },
            };
            return WithProcessor(options, processor);
        }

        private static T WithProcessor<T>(T requestOptions, string processor)
            where T : RequestOptions
        {
            requestOptions.Properties = new Dictionary<string, object>
            {
                [StreamPropertyName] = processor,
            };
            return requestOptions;
        }

        private static async Task<Doc> ReadDocumentAsync(
            Container encrypted,
            string documentId,
            string path,
            string processor)
        {
            if (path == "point")
            {
                return (await encrypted.ReadItemAsync<Doc>(
                    documentId,
                    new PartitionKey(PartitionKeyValue),
                    WithProcessor(new ItemRequestOptions(), processor))).Resource;
            }

            if (path == "readmany")
            {
                IReadOnlyList<(string id, PartitionKey partitionKey)> items =
                    new[] { (documentId, new PartitionKey(PartitionKeyValue)) };
                FeedResponse<Doc> response = await encrypted.ReadManyItemsAsync<Doc>(
                    items,
                    WithProcessor(new ReadManyRequestOptions(), processor));
                return response.SingleOrDefault(document => document.id == documentId);
            }

            QueryDefinition query = path == "query"
                ? new QueryDefinition("SELECT * FROM c WHERE c.id = @id").WithParameter("@id", documentId)
                : null;
            QueryRequestOptions requestOptions = WithProcessor(
                new QueryRequestOptions
                {
                    PartitionKey = new PartitionKey(PartitionKeyValue),
                    MaxItemCount = 1,
                },
                processor);
            using FeedIterator<Doc> iterator = encrypted.GetItemQueryIterator<Doc>(
                queryDefinition: query,
                continuationToken: null,
                requestOptions: requestOptions);
            while (iterator.HasMoreResults)
            {
                foreach (Doc document in await iterator.ReadNextAsync())
                {
                    if (document.id == documentId)
                    {
                        return document;
                    }
                }
            }

            return null;
        }

        private static async Task EnsureDecryptedJsonFidelityAsync(
            Container encrypted,
            string documentId,
            string path,
            string processor,
            JObject expectedPlaintextRaw = null)
        {
            if (path == "point")
            {
                using ResponseMessage response = await encrypted.ReadItemStreamAsync(
                    documentId,
                    new PartitionKey(PartitionKeyValue),
                    WithProcessor(new ItemRequestOptions(), processor));
                response.EnsureSuccessStatusCode();
                using JsonDocument payload = await JsonDocument.ParseAsync(response.Content);
                EnsureDecryptedJsonFidelity(
                    payload.RootElement,
                    documentId,
                    processor,
                    expectedPlaintextRaw);
                return;
            }

            if (path == "readmany")
            {
                IReadOnlyList<(string id, PartitionKey partitionKey)> items =
                    new[] { (documentId, new PartitionKey(PartitionKeyValue)) };
                using ResponseMessage response = await encrypted.ReadManyItemsStreamAsync(
                    items,
                    WithProcessor(new ReadManyRequestOptions(), processor));
                response.EnsureSuccessStatusCode();
                using JsonDocument payload = await JsonDocument.ParseAsync(response.Content);
                EnsureDocumentInArrayResponse(
                    payload.RootElement,
                    documentId,
                    processor,
                    expectedPlaintextRaw);
                return;
            }

            QueryDefinition query = path == "query"
                ? new QueryDefinition("SELECT * FROM c WHERE c.id = @id").WithParameter("@id", documentId)
                : null;
            QueryRequestOptions requestOptions = WithProcessor(
                new QueryRequestOptions
                {
                    PartitionKey = new PartitionKey(PartitionKeyValue),
                    MaxItemCount = 1,
                },
                processor);
            using FeedIterator iterator = encrypted.GetItemQueryStreamIterator(
                queryDefinition: query,
                continuationToken: null,
                requestOptions: requestOptions);
            while (iterator.HasMoreResults)
            {
                using ResponseMessage response = await iterator.ReadNextAsync();
                response.EnsureSuccessStatusCode();
                using JsonDocument payload = await JsonDocument.ParseAsync(response.Content);
                if (EnsureDocumentInArrayResponse(
                    payload.RootElement,
                    documentId,
                    processor,
                    expectedPlaintextRaw,
                    throwIfMissing: false))
                {
                    return;
                }
            }

            throw new CompatibilityOracleException($"Decrypted stream response did not contain document {documentId}.");
        }

        private static bool EnsureDocumentInArrayResponse(
            JsonElement response,
            string documentId,
            string processor,
            JObject expectedPlaintextRaw,
            bool throwIfMissing = true)
        {
            if (!response.TryGetProperty("Documents", out JsonElement documents) ||
                documents.ValueKind != JsonValueKind.Array)
            {
                throw new CompatibilityOracleException(
                    "Decrypted SDK response did not contain a Documents array.");
            }

            foreach (JsonElement document in documents.EnumerateArray())
            {
                if (document.TryGetProperty("id", out JsonElement id) &&
                    string.Equals(id.GetString(), documentId, StringComparison.Ordinal))
                {
                    EnsureDecryptedJsonFidelity(
                        document,
                        documentId,
                        processor,
                        expectedPlaintextRaw);
                    return true;
                }
            }

            if (throwIfMissing)
            {
                throw new CompatibilityOracleException(
                    $"Decrypted SDK response did not contain document {documentId}.");
            }

            return false;
        }

        private static void EnsureDecryptedJsonFidelity(
            JsonElement document,
            string documentId,
            string processor,
            JObject expectedPlaintextRaw = null)
        {
            if (!document.TryGetProperty("id", out JsonElement id) ||
                !string.Equals(id.GetString(), documentId, StringComparison.Ordinal) ||
                !document.TryGetProperty("PK", out JsonElement partitionKey) ||
                !string.Equals(partitionKey.GetString(), PartitionKeyValue, StringComparison.Ordinal))
            {
                throw new CompatibilityOracleException("Decrypted JSON identity fields did not match the expected document.");
            }

            if (document.TryGetProperty("_ei", out _))
            {
                throw new CompatibilityOracleException(
                    "Decrypted JSON retained the encrypted _ei envelope.");
            }

            string expectedJson = JsonConvert.SerializeObject(
                BuildDocument(documentId),
                Formatting.None);
            using JsonDocument expectedDocument = JsonDocument.Parse(expectedJson);
            CompatibilityPayloadOracle.Validate(
                document,
                expectedDocument.RootElement,
                requireLexicalNumbers: string.Equals(
                    processor,
                    StreamProcessor,
                    StringComparison.Ordinal));

            if (expectedPlaintextRaw != null)
            {
                EnsureExactPlaintextTokens(document, expectedPlaintextRaw);
            }
        }

        private static void EnsureExactPlaintextTokens(
            JsonElement document,
            JObject expectedPlaintextRaw)
        {
            foreach (JProperty expectedProperty in expectedPlaintextRaw.Properties()
                .Where(property =>
                    !property.Name.StartsWith("_", StringComparison.Ordinal) &&
                    property.Name != "PK"))
            {
                if (!document.TryGetProperty(expectedProperty.Name, out JsonElement actualProperty))
                {
                    throw new CompatibilityOracleException(
                        $"Plaintext reread omitted token {expectedProperty.Name}.");
                }

                using JsonDocument expectedToken = JsonDocument.Parse(
                    expectedProperty.Value.ToString(Formatting.None));
                CompatibilityPayloadOracle.Validate(
                    actualProperty,
                    expectedToken.RootElement,
                    requireLexicalNumbers: false,
                    path: "$." + expectedProperty.Name);
            }
        }

        private static async Task<JObject> ReadRawAsync(Container plain, string documentId)
        {
            using ResponseMessage response = await plain.ReadItemStreamAsync(
                documentId,
                new PartitionKey(PartitionKeyValue));
            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                throw new InvalidOperationException($"Raw document was not found: {documentId}");
            }

            response.EnsureSuccessStatusCode();
            using StreamReader streamReader = new(
                response.Content,
                Encoding.UTF8,
                detectEncodingFromByteOrderMarks: false,
                leaveOpen: true);
            using JsonTextReader jsonReader = new(streamReader)
            {
                DateParseHandling = DateParseHandling.None,
            };
            return JObject.Load(jsonReader);
        }

        private static void EnsureRawFixture(JObject raw, string family, Doc expected)
        {
            if (family == PlaintextFamily)
            {
                if (raw?["_ei"] != null)
                {
                    throw new CompatibilityOracleException(
                        "Plaintext fixture unexpectedly contains _ei metadata.");
                }

                EnsureNonSensitiveTokensMatchDocument(raw, expected);
                foreach (string propertyName in EncryptedPropertyNames)
                {
                    if (raw?[propertyName] == null)
                    {
                        throw new CompatibilityOracleException(
                            $"Plaintext fixture omitted token {propertyName}.");
                    }
                }

                return;
            }

            if (raw?["_ei"] is not JObject encryptionInfo)
            {
                throw new CompatibilityOracleException("Encrypted document does not contain _ei metadata.");
            }

            int expectedFormatVersion = family == MdeFamily ? 3 : 2;
            int actualFormatVersion = encryptionInfo.Value<int?>("_ef") ?? -1;
            if (actualFormatVersion != expectedFormatVersion)
            {
                throw new CompatibilityOracleException(
                    $"Encrypted document format is v{actualFormatVersion}, expected v{expectedFormatVersion}.");
            }

            if (family == MdeFamily)
            {
                string[] expectedMetadataProperties = { "_ef", "_ea", "_en", "_ed", "_ep" };
                string[] actualMetadataProperties = encryptionInfo.Properties()
                    .Select(property => property.Name)
                    .OrderBy(name => name, StringComparer.Ordinal)
                    .ToArray();
                CollectionEqual(
                    expectedMetadataProperties.OrderBy(name => name, StringComparer.Ordinal),
                    actualMetadataProperties,
                    "MDE metadata shape");
                if (!string.Equals(
                        encryptionInfo.Value<string>("_ea"),
                        MdeAlgorithm,
                        StringComparison.Ordinal) ||
                    string.IsNullOrWhiteSpace(encryptionInfo.Value<string>("_en")))
                {
                    throw new CompatibilityOracleException(
                        "MDE metadata did not contain the exact algorithm and a DEK id.");
                }

                if (encryptionInfo["_ed"]?.Type != JTokenType.Null)
                {
                    throw new CompatibilityOracleException(
                        "MDE-v3 metadata _ed token was not exactly null.");
                }

                foreach (string propertyName in EncryptedPropertyNames)
                {
                    JToken token = raw[propertyName];
                    if (token == null || token.Type != JTokenType.String)
                    {
                        throw new CompatibilityOracleException(
                            $"MDE property {propertyName} was not stored as opaque ciphertext.");
                    }
                }

                if (encryptionInfo["_ep"] is not JArray encryptedPathArray)
                {
                    throw new CompatibilityOracleException("MDE document does not contain _ei._ep.");
                }

                foreach (string encryptedPath in EncryptedPaths)
                {
                    if (!encryptedPathArray.Any(token => token.Value<string>() == encryptedPath))
                    {
                        throw new CompatibilityOracleException($"MDE metadata omitted encrypted path {encryptedPath}.");
                    }
                }

                if (encryptedPathArray.Any(token =>
                    token.Type == JTokenType.Null ||
                    string.IsNullOrWhiteSpace(token.Value<string>())))
                {
                    throw new CompatibilityOracleException("MDE metadata contains a null or empty encrypted path.");
                }

                CollectionEqual(
                    EncryptedPaths,
                    encryptedPathArray.Select(token => token.Value<string>()),
                    "MDE encrypted path order");
                EnsureNonSensitiveTokensMatchDocument(raw, expected);
                EnsureNoSensitivePlaintextAtRest(raw, expected);
            }
            else
            {
                foreach (string propertyName in EncryptedPropertyNames)
                {
                    if (raw[propertyName] != null && raw[propertyName].Type != JTokenType.Null)
                    {
                        throw new CompatibilityOracleException($"AEAD property {propertyName} remained in plaintext.");
                    }
                }

                if (string.IsNullOrWhiteSpace(encryptionInfo.Value<string>("_ed")))
                {
                    throw new CompatibilityOracleException("AEAD document does not contain _ei._ed ciphertext.");
                }

                EnsureNonSensitiveTokensMatchDocument(raw, expected);
                EnsureNoSensitivePlaintextAtRest(raw, expected);
            }
        }

        private static void EnsureNoSensitivePlaintextAtRest(JObject raw, Doc expected)
        {
            JObject expectedDocument = JObject.FromObject(expected);
            foreach (string propertyName in EncryptedPropertyNames)
            {
                JToken rawToken = raw[propertyName];
                JToken expectedToken = expectedDocument[propertyName];
                if (rawToken != null && JToken.DeepEquals(rawToken, expectedToken))
                {
                    throw new CompatibilityOracleException(
                        $"Protected token {propertyName} remained in plaintext at rest.");
                }
            }

            HashSet<string> sensitiveStrings = EncryptedPropertyNames
                .Select(propertyName => expectedDocument[propertyName])
                .Where(token => token != null)
                .SelectMany(token => token is JContainer container
                    ? container.DescendantsAndSelf()
                    : new[] { token })
                .OfType<JValue>()
                .Where(value => value.Type == JTokenType.String)
                .Select(value => value.Value<string>())
                .Where(value => !string.IsNullOrEmpty(value))
                .ToHashSet(StringComparer.Ordinal);
            string leaked = raw
                .DescendantsAndSelf()
                .OfType<JValue>()
                .Where(value => value.Type == JTokenType.String)
                .Select(value => value.Value<string>())
                .FirstOrDefault(value => sensitiveStrings.Contains(value));
            if (leaked != null)
            {
                throw new CompatibilityOracleException(
                    "A protected string remained in plaintext at rest.");
            }
        }

        private static void EnsureNonSensitiveTokensMatchDocument(JObject raw, Doc expected)
        {
            foreach (string propertyName in new[]
            {
                "id",
                "PK",
                "NonSensitive",
                "PlainEscaped",
                "PlainObj",
                "PlainArr",
                "PlainNull",
                "PlainLong",
                "PlainDate",
            })
            {
                if (!JToken.DeepEquals(raw?[propertyName], GetDocumentToken(expected, propertyName)))
                {
                    throw new CompatibilityOracleException(
                        $"Non-sensitive token {propertyName} was not preserved exactly.");
                }
            }
        }

        private static void EnsureNonSensitiveTokensPreserved(JObject before, JObject after)
        {
            foreach (string propertyName in new[]
            {
                "id",
                "PK",
                "NonSensitive",
                "PlainEscaped",
                "PlainObj",
                "PlainArr",
                "PlainNull",
                "PlainLong",
                "PlainDate",
            })
            {
                if (!JToken.DeepEquals(before?[propertyName], after?[propertyName]))
                {
                    throw new CompatibilityOracleException(
                        $"Rewrite changed non-sensitive token {propertyName}.");
                }
            }
        }

        private static JToken GetDocumentToken(Doc document, string propertyName)
        {
            JObject value = JObject.FromObject(document);
            return value[propertyName];
        }

        private static void CollectionEqual(
            IEnumerable<string> expected,
            IEnumerable<string> actual,
            string description)
        {
            string[] expectedArray = expected.ToArray();
            string[] actualArray = actual.ToArray();
            if (!expectedArray.SequenceEqual(actualArray, StringComparer.Ordinal))
            {
                throw new CompatibilityOracleException(
                    $"{description} differed. Actual=[{string.Join(", ", actualArray)}] Expected=[{string.Join(", ", expectedArray)}]");
            }
        }

        private static void EnsureExpectedFixtureHash(
            IReadOnlyDictionary<string, string> arguments,
            string documentId,
            JObject raw)
        {
            string expected = GetRequired(arguments, GetFixtureHashArgumentName(documentId));
            string actual = HashJson(raw);
            if (!string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
            {
                throw new CompatibilityOracleException(
                    $"Fixture hash mismatch for {documentId}. Actual={actual} Expected={expected}");
            }
        }

        private static string GetFixtureHashArgumentName(string documentId)
        {
            return "fixture-sha256-" + documentId;
        }

        private static string HashJson(JToken value)
        {
            return HashText(value.ToString(Formatting.None));
        }

        private static string HashPlaintext(Doc document)
        {
            return HashText(GetSignature(document));
        }

        private static string HashText(string value)
        {
            return Convert.ToHexString(
                SHA256.HashData(Encoding.UTF8.GetBytes(value)));
        }

        private static string DescribeRawShape(JObject raw, string family)
        {
            string rootProperties = string.Join(
                ",",
                raw.Properties().Select(property => $"{property.Name}:{property.Value.Type}"));
            if (family == MdeFamily && raw["_ei"] is JObject encryptionInfo)
            {
                string metadataProperties = string.Join(
                    ",",
                    encryptionInfo.Properties().Select(
                        property => $"{property.Name}:{property.Value.Type}"));
                return $"family=MDE;root=[{rootProperties}];_ei=[{metadataProperties}]";
            }

            return $"family={family};root=[{rootProperties}]";
        }

        private static void EnsureDocumentMatches(Doc actual, string documentId)
        {
            if (actual == null)
            {
                throw new InvalidOperationException($"Document was not found: {documentId}");
            }

            string actualSignature = GetSignature(actual);
            string expectedSignature = GetSignature(BuildDocument(documentId));
            if (!string.Equals(actualSignature, expectedSignature, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"Decrypted document did not round-trip exactly: {documentId}");
            }
        }

        private static async Task<List<string>> CaptureScopesAsync(Func<Task> action)
        {
            List<string> scopes = new();
            using ActivityListener listener = new()
            {
                ShouldListenTo = source => string.Equals(source.Name, ActivitySourceName, StringComparison.Ordinal),
                Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
                ActivityStopped = activity =>
                {
                    if (!string.IsNullOrWhiteSpace(activity?.OperationName))
                    {
                        lock (scopes)
                        {
                            scopes.Add(activity.OperationName);
                        }
                    }
                },
            };

            ActivitySource.AddActivityListener(listener);
            await action();
            lock (scopes)
            {
                return scopes.ToList();
            }
        }

        private static void EnsureProcessorScopes(
            IReadOnlyCollection<string> scopes,
            string family,
            string operation,
            string processor)
        {
#if COMPAT_CURRENT
            if (family != MdeFamily)
            {
                return;
            }

            string prefix = string.Equals(operation, EncryptOperation, StringComparison.Ordinal)
                ? "EncryptionProcessor.Encrypt.Mde."
                : string.Equals(operation, DecryptOperation, StringComparison.Ordinal)
                    ? "EncryptionProcessor.Decrypt.Mde."
                    : throw new InvalidOperationException($"Unknown processor operation: {operation}");
            string expectedScope = prefix + processor;
            string oppositeProcessor = processor == StreamProcessor ? NewtonsoftProcessor : StreamProcessor;
            string oppositeScope = prefix + oppositeProcessor;
            if (!scopes.Contains(expectedScope, StringComparer.Ordinal))
            {
                throw new InvalidOperationException(
                    $"Expected {operation} processor {processor} was not observed. Scopes=[{string.Join(", ", scopes)}]");
            }

            if (scopes.Contains(oppositeScope, StringComparer.Ordinal))
            {
                throw new InvalidOperationException(
                    $"Unexpected {operation} processor {oppositeProcessor} was observed. Scopes=[{string.Join(", ", scopes)}]");
            }
#else
            _ = scopes;
            _ = family;
            _ = operation;
            _ = processor;
#endif
        }

        private static string EnsureDecryptProcessorScopes(
            IReadOnlyCollection<string> scopes,
            string family,
            string requestedProcessor,
            bool allowNewtonsoftFallback,
            bool externalDecryptObserved = false)
        {
#if COMPAT_CURRENT
            if (family == PlaintextFamily)
            {
                string expectedScope =
                    "EncryptionProcessor.Decrypt.Mde." + requestedProcessor;
                string oppositeScope =
                    "EncryptionProcessor.Decrypt.Mde." +
                    (requestedProcessor == StreamProcessor
                        ? NewtonsoftProcessor
                        : StreamProcessor);
                bool expectedObserved = scopes.Contains(expectedScope, StringComparer.Ordinal);
                bool oppositeObserved = scopes.Contains(oppositeScope, StringComparer.Ordinal);
                if (expectedObserved && !oppositeObserved)
                {
                    return requestedProcessor;
                }

                throw new InvalidOperationException(
                    $"Plaintext fixture did not traverse only the requested sealed reader path. Scopes=[{string.Join(", ", scopes)}]");
            }

            string streamScope = "EncryptionProcessor.Decrypt.Mde." + StreamProcessor;
            string newtonsoftScope = "EncryptionProcessor.Decrypt.Mde." + NewtonsoftProcessor;
            bool streamObserved = scopes.Contains(streamScope, StringComparer.Ordinal);
            bool newtonsoftObserved = scopes.Contains(newtonsoftScope, StringComparer.Ordinal);
            if (requestedProcessor == NewtonsoftProcessor)
            {
                if (family == MdeFamily && externalDecryptObserved && !streamObserved)
                {
                    return NewtonsoftProcessor;
                }

                EnsureProcessorScopes(scopes, family, DecryptOperation, NewtonsoftProcessor);
                return NewtonsoftProcessor;
            }

            if (family == AeadFamily &&
                allowNewtonsoftFallback &&
                externalDecryptObserved)
            {
                return "NewtonsoftLegacyFallback";
            }

            if (family == MdeFamily && streamObserved && !newtonsoftObserved)
            {
                return StreamProcessor;
            }

            if (allowNewtonsoftFallback && newtonsoftObserved)
            {
                return "NewtonsoftFallback";
            }

            throw new InvalidOperationException(
                $"Requested {requestedProcessor} decrypt processor was not observed without an unexpected fallback. Scopes=[{string.Join(", ", scopes)}]");
#else
            _ = scopes;
            _ = family;
            _ = allowNewtonsoftFallback;
            _ = externalDecryptObserved;
            return requestedProcessor;
#endif
        }

        private static Doc BuildDocument(string documentId)
        {
            return new Doc
            {
                id = documentId,
                PK = PartitionKeyValue,
                NonSensitive = "plain",
                Sensitive = $"secret::{documentId}",
                PlainEscaped = PlainEscapedValue,
                EncEscaped = EncryptedEscapedValue,
                EncAstral = EncryptedAstralValue,
                EscapedPropertyValue = EscapedPropertyValue,
                EncObj = new JObject { ["a"] = JValue.CreateNull(), ["b"] = 1 },
                EncArr = new JArray { 1, JValue.CreateNull(), 2 },
                EncNull = JValue.CreateNull(),
                EncLong = EncryptedLongValue,
                EncDate = EncryptedDateValue,
                EncIntegralDouble = EncryptedIntegralDoubleValue,
                EncNormalDouble = EncryptedNormalDoubleValue,
                PlainObj = new JObject { ["date"] = PlainDateValue, ["null"] = JValue.CreateNull() },
                PlainArr = new JArray { "plain", JValue.CreateNull(), PlainLongValue },
                PlainNull = JValue.CreateNull(),
                PlainLong = PlainLongValue,
                PlainDate = PlainDateValue,
            };
        }

        private static string GetSignature(Doc document)
        {
            if (document == null)
            {
                return "<null-document>";
            }

            string objectSignature = document.EncObj == null
                ? "<null-object>"
                : $"{{a={GetTokenSignature(document.EncObj["a"])},b={GetTokenSignature(document.EncObj["b"])}}}";
            string arraySignature = document.EncArr == null
                ? "<null-array>"
                : "[" + string.Join(",", document.EncArr.Select(GetTokenSignature)) + "]";
            return string.Join(
                "\u001F",
                new[]
                {
                    document.id ?? "<null>",
                    document.PK ?? "<null>",
                    document.Sensitive ?? "<null>",
                    document.NonSensitive ?? "<null>",
                    document.PlainEscaped ?? "<null>",
                    document.EncEscaped ?? "<null>",
                    document.EncAstral ?? "<null>",
                    document.EscapedPropertyValue ?? "<null>",
                    document.EncLong.ToString(CultureInfo.InvariantCulture),
                    document.EncDate ?? "<null>",
                    document.EncIntegralDouble.ToString("R", CultureInfo.InvariantCulture),
                    document.EncNormalDouble.ToString("R", CultureInfo.InvariantCulture),
                    objectSignature,
                    arraySignature,
                    GetTokenSignature(document.EncNull),
                    GetTokenSignature(document.PlainObj),
                    GetTokenSignature(document.PlainArr),
                    GetTokenSignature(document.PlainNull),
                    document.PlainLong.ToString(CultureInfo.InvariantCulture),
                    document.PlainDate ?? "<null>",
                });
        }

        private static string GetTokenSignature(JToken token)
        {
            return token == null
                ? "<missing>"
                : token.Type == JTokenType.Null
                    ? "null"
                    : token.ToString(Formatting.None);
        }

        private static string GetDekId(string writer, string family)
        {
            return $"{writer}-{family.ToLowerInvariant()}-dek";
        }

        private static string GetMasterKeyId(string writer)
        {
            return $"https://compat.matrix/{writer}";
        }

        private static string GetDocumentId(string writer, string family, string processor)
        {
            return $"{writer}-{family.ToLowerInvariant()}-{processor.ToLowerInvariant()}";
        }

        private static string GetRewriteDocumentId(string writer, string rewriteProcessor)
        {
            return $"{writer}-mde-rewrite-{rewriteProcessor.ToLowerInvariant()}";
        }

        private static string GetRewriteContainerId(string rewriteProcessor)
        {
            return $"items-rewrite-{rewriteProcessor.ToLowerInvariant()}";
        }

        private static string GetRequestedProcessorLabel(string processor)
        {
            return processor == StreamProcessor ? "StreamRequested" : processor;
        }

        private static Dictionary<string, string> ParseArguments(IEnumerable<string> args)
        {
            Dictionary<string, string> parsed = new(StringComparer.OrdinalIgnoreCase);
            foreach (string argument in args)
            {
                int separator = argument.IndexOf('=');
                if (argument.StartsWith("--", StringComparison.Ordinal) && separator > 2)
                {
                    parsed[argument.Substring(2, separator - 2)] = argument[(separator + 1)..];
                }
            }

            return parsed;
        }

        private static string GetRequired(IReadOnlyDictionary<string, string> arguments, string name)
        {
            if (!arguments.TryGetValue(name, out string value) || string.IsNullOrWhiteSpace(value))
            {
                throw new InvalidOperationException($"Missing required argument --{name}=...");
            }

            return value;
        }

        private static void EmitObservation(
            string scenarioId,
            string status,
            string detail,
            string requestedProcessor,
            string actualProcessor,
            IReadOnlyList<string> scopes,
            string providerConstruction,
            string encryptorKind,
            string documentId = null,
            string fixtureSha256 = null,
            string plaintextSha256 = null,
            string rawShape = null,
            string inputFixtureSha256 = null)
        {
            Emit(new WorkerRecord
            {
                Kind = "observation",
                Role = WorkerRole,
                ScenarioId = scenarioId,
                Status = status,
                Detail = detail,
                RequestedProcessor = requestedProcessor,
                ActualProcessor = actualProcessor,
                ObservedScopes = scopes,
                ProviderConstruction = providerConstruction,
                EncryptorKind = encryptorKind,
                DocumentId = documentId,
                FixtureSha256 = fixtureSha256,
                InputFixtureSha256 = inputFixtureSha256,
                PlaintextSha256 = plaintextSha256,
                RawShape = rawShape,
            });
        }

        private static void EmitFixture(
            string scenarioId,
            string documentId,
            string fixtureSha256,
            string plaintextSha256,
            string rawShape)
        {
            Emit(new WorkerRecord
            {
                Kind = "fixture",
                Role = WorkerRole,
                ScenarioId = scenarioId,
                Status = "pass",
                Detail = "released fixture created by released package worker",
                DocumentId = documentId,
                FixtureSha256 = fixtureSha256,
                PlaintextSha256 = plaintextSha256,
                RawShape = rawShape,
            });
        }

        private static void Emit(WorkerRecord record)
        {
            Console.Out.WriteLine(JsonConvert.SerializeObject(record, Formatting.None));
        }

        private static string Describe(Exception exception)
        {
            return $"{exception.GetType().Name}: {Show(exception.Message)}";
        }

        private static string Show(string value)
        {
            return (value ?? "<null>")
                .Replace("\r", "\\r")
                .Replace("\n", "\\n")
                .Replace("\t", "\\t")
                .Replace("\u0001", "\\u0001");
        }

        private sealed class WorkerSettings
        {
            public Uri Endpoint { get; private set; }

            public string Key { get; private set; }

            public string Database { get; private set; }

            public static WorkerSettings Create(IReadOnlyDictionary<string, string> arguments)
            {
                string key = Environment.GetEnvironmentVariable(AccountKeyEnvironmentVariable);
                if (string.IsNullOrWhiteSpace(key))
                {
                    throw new InvalidOperationException(
                        $"Missing required environment variable {AccountKeyEnvironmentVariable}.");
                }

                return new WorkerSettings
                {
                    Endpoint = ValidateEmulatorEndpoint(GetRequired(arguments, "endpoint")),
                    Key = key,
                    Database = GetRequired(arguments, "database"),
                };
            }
        }

        private sealed class WorkerRecord
        {
            public string Kind { get; set; }

            public string Role { get; set; }

            public string ScenarioId { get; set; }

            public string Status { get; set; }

            public string Detail { get; set; }

            public string PackageVersion { get; set; }

            public string InformationalVersion { get; set; }

            public string ProductVersion { get; set; }

            public string AssemblyVersion { get; set; }

            public string AssemblyMvid { get; set; }

            public string AssemblySha256 { get; set; }

            public string AssemblyPath { get; set; }

            public string CosmosVersion { get; set; }

            public string MdeVersion { get; set; }

            public string RequestedProcessor { get; set; }

            public string ActualProcessor { get; set; }

            public IReadOnlyList<string> ObservedScopes { get; set; }

            public string ProviderConstruction { get; set; }

            public string EncryptorKind { get; set; }

            public string DocumentId { get; set; }

            public string FixtureSha256 { get; set; }

            public string InputFixtureSha256 { get; set; }

            public string PlaintextSha256 { get; set; }

            public string RawShape { get; set; }
        }

        private sealed class CompatibilityOracleException : InvalidOperationException
        {
            public CompatibilityOracleException(string message)
                : base(message)
            {
            }
        }

        private sealed class WriteScenario
        {
            public WriteScenario(string family, string processor)
            {
                this.Family = family;
                this.Processor = processor;
            }

            public string Family { get; }

            public string Processor { get; }
        }

        private sealed class ReadScenario
        {
            public static readonly IReadOnlyList<string> AllPaths =
                new[] { "point", "query", "feed" };

            public static readonly IReadOnlyList<string> AllPathsWithReadMany =
                new[] { "point", "query", "feed", "readmany" };

            public static readonly IReadOnlyList<string> PointOnly =
                new[] { "point" };

            public ReadScenario(
                string family,
                string writeProcessor,
                string readProcessor,
                IReadOnlyList<string> paths)
            {
                this.Family = family;
                this.WriteProcessor = writeProcessor;
                this.ReadProcessor = readProcessor;
                this.Paths = paths;
            }

            public string Family { get; }

            public string WriteProcessor { get; }

            public string ReadProcessor { get; }

            public IReadOnlyList<string> Paths { get; }
        }

        private sealed class ProviderContext
        {
            public ProviderContext(
                CosmosDataEncryptionKeyProvider provider,
                string construction)
            {
                this.Provider = provider;
                this.Construction = construction;
            }

            public CosmosDataEncryptionKeyProvider Provider { get; }

            public string Construction { get; }
        }

        private sealed class Doc
        {
            public string id { get; set; }

            public string PK { get; set; }

            public string NonSensitive { get; set; }

            public string Sensitive { get; set; }

            public string PlainEscaped { get; set; }

            public string EncEscaped { get; set; }

            public string EncAstral { get; set; }

            [JsonProperty(EscapedPropertyName)]
            public string EscapedPropertyValue { get; set; }

            public JObject EncObj { get; set; }

            public JArray EncArr { get; set; }

            public JToken EncNull { get; set; }

            public long EncLong { get; set; }

            public string EncDate { get; set; }

            public double EncIntegralDouble { get; set; }

            public double EncNormalDouble { get; set; }

            public JObject PlainObj { get; set; }

            public JArray PlainArr { get; set; }

            public JToken PlainNull { get; set; }

            public long PlainLong { get; set; }

            public string PlainDate { get; set; }
        }
    }
}
