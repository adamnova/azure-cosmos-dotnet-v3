//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

#if NET8_0_OR_GREATER
namespace Microsoft.Azure.Cosmos.Encryption.Custom.EmulatorTests
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.Linq;
    using System.Net.Http;
    using System.Text.Json;
    using EncryptionCustomCompatibility;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    [TestClass]
    public class CompatibilityMatrixInfrastructureTests
    {
        [TestMethod]
        public void ParseRecord_RejectsMalformedJson()
        {
            Assert.ThrowsException<InvalidOperationException>(
                () => CompatibilityMatrixProtocol.ParseRecord("not-json"));
        }

        [TestMethod]
        public void ValidateResults_RejectsDuplicateScenario()
        {
            IReadOnlyCollection<string> expected = new[] { "released-write-mde-newtonsoft" };
            CompatibilityMatrixRecord[] actual =
            {
                Pass("released-write-mde-newtonsoft"),
                Pass("released-write-mde-newtonsoft"),
            };

            Assert.ThrowsException<InvalidOperationException>(
                () => CompatibilityMatrixResultOracle.Validate(expected, actual));
        }

        [TestMethod]
        public void ValidateResults_RejectsMissingScenario()
        {
            IReadOnlyCollection<string> expected = new[]
            {
                "released-write-mde-newtonsoft",
                "released-write-aead-newtonsoft",
            };

            Assert.ThrowsException<InvalidOperationException>(
                () => CompatibilityMatrixResultOracle.Validate(expected, new[] { Pass("released-write-mde-newtonsoft") }));
        }

        [TestMethod]
        public void ValidateResults_RejectsUnexpectedScenario()
        {
            IReadOnlyCollection<string> expected = new[] { "released-write-mde-newtonsoft" };
            CompatibilityMatrixRecord[] actual =
            {
                Pass("released-write-mde-newtonsoft"),
                Pass("unexpected"),
            };

            Assert.ThrowsException<InvalidOperationException>(
                () => CompatibilityMatrixResultOracle.Validate(expected, actual));
        }

        [TestMethod]
        public void ValidateResults_RejectsNonPassingScenario()
        {
            IReadOnlyCollection<string> expected = new[] { "released-write-mde-newtonsoft" };
            CompatibilityMatrixRecord actual = Pass("released-write-mde-newtonsoft");
            actual.Status = "fail";
            actual.Detail = "ciphertext was plaintext";

            Assert.ThrowsException<InvalidOperationException>(
                () => CompatibilityMatrixResultOracle.Validate(expected, new[] { actual }));
        }

        [TestMethod]
        public void ValidateResults_RequiresProcessorEvidenceForPassingScenario()
        {
            IReadOnlyCollection<string> expected = new[] { "released-write-mde-newtonsoft" };
            CompatibilityMatrixRecord actual = Pass("released-write-mde-newtonsoft");
            actual.ActualProcessor = null;

            Assert.ThrowsException<InvalidOperationException>(
                () => CompatibilityMatrixResultOracle.Validate(expected, new[] { actual }));
        }

        [TestMethod]
        public void ValidateResults_RequiresProviderAndEncryptorEvidenceForPassingScenario()
        {
            IReadOnlyCollection<string> expected = new[] { "released-write-mde-newtonsoft" };
            CompatibilityMatrixRecord actual = Pass("released-write-mde-newtonsoft");
            actual.ProviderConstruction = null;

            Assert.ThrowsException<InvalidOperationException>(
                () => CompatibilityMatrixResultOracle.Validate(expected, new[] { actual }));
        }

        [TestMethod]
        public void ValidateResults_RequiresDirectLegacyFallbackEvidence()
        {
            const string scenarioId =
                "read:released->current:AEAD:Newtonsoft->StreamRequested:point";
            CompatibilityMatrixRecord actual = Pass(scenarioId);
            actual.Role = "current";
            actual.ProviderConstruction = "factory-dual-provider-cache-options";
            actual.EncryptorKind = "external-preview07-surface";
            actual.RequestedProcessor = "Stream";
            actual.ActualProcessor = "typed=Stream,stream=Stream";

            Assert.ThrowsException<InvalidOperationException>(
                () => CompatibilityMatrixResultOracle.Validate(
                    new[] { scenarioId },
                    new[] { actual }));

            actual.ActualProcessor =
                "typed=NewtonsoftLegacyFallback,stream=NewtonsoftLegacyFallback";
            CompatibilityMatrixResultOracle.Validate(
                new[] { scenarioId },
                new[] { actual });
        }

        [TestMethod]
        public void ValidateIdentity_RequiresExactPackageVersionsHashesAndDistinctBinaries()
        {
            CompatibilityMatrixRecord released = Identity("released", "1.0.0-preview07", "released-hash");
            CompatibilityMatrixRecord current = Identity("current", "1.1.0-preview01", "current-hash");
            current.InformationalVersion =
                "1.1.0-preview01+8fcd60810fe6f3ac830774912e74e36c2cae4483";
            CompatibilityMatrixPackageProvenance releasedProvenance =
                Provenance("released", "1.0.0-preview07", "released-hash", "released-package");
            CompatibilityMatrixPackageProvenance currentProvenance =
                Provenance(
                    "current",
                    "1.1.0-preview01",
                    "current-hash",
                    "8fcd60810fe6f3ac830774912e74e36c2cae4483");

            CompatibilityMatrixIdentityValidator.Validate(
                released,
                current,
                releasedProvenance,
                currentProvenance);

            released.PackageVersion = "1.0.0-preview08";
            Assert.ThrowsException<InvalidOperationException>(
                () => CompatibilityMatrixIdentityValidator.Validate(
                    released,
                    current,
                    releasedProvenance,
                    currentProvenance));

            released.PackageVersion = "1.0.0-preview07";
            current.AssemblySha256 = released.AssemblySha256;
            Assert.ThrowsException<InvalidOperationException>(
                () => CompatibilityMatrixIdentityValidator.Validate(
                    released,
                    current,
                    releasedProvenance,
                    currentProvenance));

            current.AssemblySha256 = "current-hash";
            currentProvenance.PackageAssemblySha256 = "stale-current-hash";
            Assert.ThrowsException<InvalidOperationException>(
                () => CompatibilityMatrixIdentityValidator.Validate(
                    released,
                    current,
                    releasedProvenance,
                    currentProvenance));

            currentProvenance.PackageAssemblySha256 = "current-hash";
            currentProvenance.ActualSource = @"Q:\wrong-source";
            Assert.ThrowsException<InvalidOperationException>(
                () => CompatibilityMatrixIdentityValidator.Validate(
                    released,
                    current,
                    releasedProvenance,
                    currentProvenance));

            currentProvenance.ActualSource = currentProvenance.ExpectedSource;
            currentProvenance.NupkgSha256 = "wrong-hash";
            Assert.ThrowsException<InvalidOperationException>(
                () => CompatibilityMatrixIdentityValidator.Validate(
                    released,
                    current,
                    releasedProvenance,
                    currentProvenance));
        }

        [TestMethod]
        public void ScenarioCatalog_Contains60UniqueRequiredObservations()
        {
            IReadOnlyCollection<string> scenarios = CompatibilityMatrixScenarios.GetAll();

            Assert.AreEqual(60, scenarios.Count);
            Assert.AreEqual(60, scenarios.Distinct(StringComparer.Ordinal).Count());
            CollectionAssert.IsSubsetOf(
                new[]
                {
                    "read:released->current:AEAD:Newtonsoft->StreamRequested:point",
                    "read:released->current:AEAD:Newtonsoft->StreamRequested:query",
                    "read:released->current:AEAD:Newtonsoft->StreamRequested:feed",
                    "read:released->current:MDE:Newtonsoft->StreamRequested:readmany",
                    "write:current:MDE:Stream",
                    "boundary:current:MDE:Stream:nonzero-input",
                    "boundary:current:MDE:Stream:readonly-response",
                    "reject:current:AEAD:Stream:write",
                    "write:released:PLAINTEXT:None",
                    "read:released->current:PLAINTEXT:None->StreamRequested:point",
                    "read:current->current:MDE:Newtonsoft->StreamRequested:readmany",
                    "read:current->current:MDE:Stream->Newtonsoft:query",
                    "rewrite:released->current:MDE:Newtonsoft",
                    "reread:released->current:rewrite:Newtonsoft->StreamRequested:point",
                    "rewrite:released->current:MDE:Stream",
                    "reread:released->current:rewrite:Stream->StreamRequested:feed",
                    "read:current->released:MDE:Newtonsoft->Newtonsoft:point",
                    "read:current->released:MDE:Stream->Newtonsoft:query",
                    "read:current->released:MDE:Stream->Newtonsoft:feed",
                    "read:current->released:MDE:Stream->Newtonsoft:readmany",
                },
                scenarios.ToArray());
        }

        [TestMethod]
        public void CompletePayloadOracle_RejectsDeletedExpectedProperty()
        {
            using JsonDocument expected = JsonDocument.Parse(CompletePayloadJson);
            using JsonDocument actual = JsonDocument.Parse(
                CompletePayloadJson.Replace(
                    ",\"protectedNull\":null",
                    string.Empty,
                    StringComparison.Ordinal));

            Assert.ThrowsException<InvalidOperationException>(
                () => CompatibilityPayloadOracle.Validate(
                    actual.RootElement,
                    expected.RootElement,
                    requireLexicalNumbers: false));
        }

        [TestMethod]
        public void CompletePayloadOracle_RejectsStringMutation()
        {
            using JsonDocument expected = JsonDocument.Parse(CompletePayloadJson);
            using JsonDocument actual = JsonDocument.Parse(
                CompletePayloadJson.Replace(
                    "\"protected-string\"",
                    "\"mutated-string\"",
                    StringComparison.Ordinal));

            Assert.ThrowsException<InvalidOperationException>(
                () => CompatibilityPayloadOracle.Validate(
                    actual.RootElement,
                    expected.RootElement,
                    requireLexicalNumbers: false));
        }

        [TestMethod]
        public void CompletePayloadOracle_RejectsDateStringMutation()
        {
            using JsonDocument expected = JsonDocument.Parse(CompletePayloadJson);
            using JsonDocument actual = JsonDocument.Parse(
                CompletePayloadJson.Replace(
                    "2024-02-29T12:34:56.7890123Z",
                    "2024-03-01T12:34:56.7890123Z",
                    StringComparison.Ordinal));

            Assert.ThrowsException<InvalidOperationException>(
                () => CompatibilityPayloadOracle.Validate(
                    actual.RootElement,
                    expected.RootElement,
                    requireLexicalNumbers: false));
        }

        [TestMethod]
        public void CompletePayloadOracle_AppliesLexicalNumbersOnlyToStream()
        {
            using JsonDocument expected = JsonDocument.Parse("{\"value\":5.0}");
            using JsonDocument actual = JsonDocument.Parse("{\"value\":5}");

            CompatibilityPayloadOracle.Validate(
                actual.RootElement,
                expected.RootElement,
                requireLexicalNumbers: false);
            Assert.ThrowsException<InvalidOperationException>(
                () => CompatibilityPayloadOracle.Validate(
                    actual.RootElement,
                    expected.RootElement,
                    requireLexicalNumbers: true));
        }

        [TestMethod]
        public void ValidateResults_RequiresRewriteInputAndOutputFixtureEvidence()
        {
            CompatibilityMatrixRecord[] actual = PassingRewriteSet("Newtonsoft");
            actual.Single(record => record.ScenarioId.StartsWith("rewrite:", StringComparison.Ordinal))
                .InputFixtureSha256 = null;

            Assert.ThrowsException<InvalidOperationException>(
                () => CompatibilityMatrixResultOracle.Validate(
                    CompatibilityMatrixScenarios.GetRewriteScenarios("Newtonsoft"),
                    actual));

            actual.Single(record => record.ScenarioId.StartsWith("rewrite:", StringComparison.Ordinal))
                .InputFixtureSha256 = Sha('1');
            CompatibilityMatrixResultOracle.Validate(
                CompatibilityMatrixScenarios.GetRewriteScenarios("Newtonsoft"),
                actual);
        }

        [TestMethod]
        public void ValidateResults_RejectsUnchangedRewriteCiphertext()
        {
            CompatibilityMatrixRecord[] actual = PassingRewriteSet("Newtonsoft");
            CompatibilityMatrixRecord rewrite =
                actual.Single(record => record.ScenarioId.StartsWith("rewrite:", StringComparison.Ordinal));
            rewrite.InputFixtureSha256 = rewrite.FixtureSha256;

            Assert.ThrowsException<InvalidOperationException>(
                () => CompatibilityMatrixResultOracle.Validate(
                    CompatibilityMatrixScenarios.GetRewriteScenarios("Newtonsoft"),
                    actual));
        }

        [TestMethod]
        public void ValidateResults_RejectsSilentRewriteProcessorSubstitution()
        {
            CompatibilityMatrixRecord[] actual = PassingRewriteSet("Stream");
            actual.Single(record => record.ScenarioId == "rewrite:released->current:MDE:Stream")
                .ActualProcessor = "Newtonsoft";

            Assert.ThrowsException<InvalidOperationException>(
                () => CompatibilityMatrixResultOracle.Validate(
                    CompatibilityMatrixScenarios.GetRewriteScenarios("Stream"),
                    actual));
        }

        [TestMethod]
        public void ValidateResults_RejectsPointRereadProcessorSubstitution()
        {
            CompatibilityMatrixRecord[] actual = PassingRewriteSet("Stream");
            actual.Single(record =>
                    record.ScenarioId.EndsWith("->StreamRequested:point", StringComparison.Ordinal))
                .ActualProcessor = "typed=Newtonsoft,stream=Newtonsoft";

            Assert.ThrowsException<InvalidOperationException>(
                () => CompatibilityMatrixResultOracle.Validate(
                    CompatibilityMatrixScenarios.GetRewriteScenarios("Stream"),
                    actual));
        }

        [TestMethod]
        public void ValidateResults_RejectsMdeStreamFallbackAtSdkBoundary()
        {
            CompatibilityMatrixRecord actual = Pass(
                "read:released->current:MDE:Newtonsoft->StreamRequested:readmany");
            actual.Role = "current";
            actual.RequestedProcessor = "Stream";
            actual.ActualProcessor = "typed=NewtonsoftFallback,stream=NewtonsoftFallback";
            actual.ProviderConstruction = "factory-store-provider-cache-options";
            actual.EncryptorKind = "built-in-cosmos-encryptor";

            Assert.ThrowsException<InvalidOperationException>(
                () => CompatibilityMatrixResultOracle.Validate(
                    new[] { actual.ScenarioId },
                    new[] { actual }));
        }

        [TestMethod]
        public void ValidateResults_RejectsChangedPlaintextAcrossRewriteReread()
        {
            CompatibilityMatrixRecord[] actual = PassingRewriteSet("Newtonsoft");
            actual.Single(record =>
                    record.ScenarioId.EndsWith("->Newtonsoft:feed", StringComparison.Ordinal))
                .PlaintextSha256 = Sha('9');

            Assert.ThrowsException<InvalidOperationException>(
                () => CompatibilityMatrixResultOracle.Validate(
                    CompatibilityMatrixScenarios.GetRewriteScenarios("Newtonsoft"),
                    actual));
        }

        [TestMethod]
        public void ValidateResults_RejectsMalformedFixtureHash()
        {
            CompatibilityMatrixRecord actual = Pass("write:released:MDE:Newtonsoft");
            actual.FixtureSha256 = "not-a-sha256";

            Assert.ThrowsException<InvalidOperationException>(
                () => CompatibilityMatrixResultOracle.Validate(
                    new[] { actual.ScenarioId },
                    new[] { actual }));
        }

        [TestMethod]
        public void ValidateResults_RejectsIncompleteMdeV3Shape()
        {
            CompatibilityMatrixRecord actual = Pass("write:released:MDE:Newtonsoft");
            actual.RawShape = "family=MDE;_ei=[_ef:Integer,_en:String,_ea:String,_ep:Array]";

            Assert.ThrowsException<InvalidOperationException>(
                () => CompatibilityMatrixResultOracle.Validate(
                    new[] { actual.ScenarioId },
                    new[] { actual }));
        }

        [TestMethod]
        public void EmulatorEndpoint_RequiresHttpsLoopbackPort8081()
        {
            Uri endpoint = CompatibilityMatrixEndpoint.Validate("https://127.0.0.1:8081/");

            Assert.IsTrue(endpoint.IsLoopback);
            Assert.ThrowsException<InvalidOperationException>(
                () => CompatibilityMatrixEndpoint.Validate("https://example.com:8081/"));
            Assert.ThrowsException<InvalidOperationException>(
                () => CompatibilityMatrixEndpoint.Validate("http://127.0.0.1:8081/"));
            Assert.ThrowsException<InvalidOperationException>(
                () => CompatibilityMatrixEndpoint.Validate("https://127.0.0.1:443/"));
            Assert.ThrowsException<InvalidOperationException>(
                () => CompatibilityMatrixEndpoint.Validate("https://user@127.0.0.1:8081/"));
        }

        [TestMethod]
        public void EmulatorCertificateBypass_FailsClosedForOtherHosts()
        {
            Uri endpoint = CompatibilityMatrixEndpoint.Validate("https://localhost:8081/");
            using HttpClientHandler handler =
                CompatibilityMatrixEndpoint.CreateHttpClientHandler(endpoint);
            using HttpRequestMessage loopback =
                new(HttpMethod.Get, "https://localhost:8081/");
            using HttpRequestMessage remote =
                new(HttpMethod.Get, "https://example.com:8081/");

            Assert.IsTrue(
                handler.ServerCertificateCustomValidationCallback(loopback, null, null, default));
            Assert.IsFalse(
                handler.ServerCertificateCustomValidationCallback(remote, null, null, default));
        }

        [TestMethod]
        public void ParsePackageProvenance_RejectsDuplicateKeys()
        {
            Assert.ThrowsException<InvalidOperationException>(
                () => CompatibilityMatrixPackageProvenance.ParseLines(
                    new[]
                    {
                        "role=released",
                        "role=current",
                    }));
        }

        [TestMethod]
        public void ParseWorkerManifest_RequiresOneReleasedAndOneCurrentWorker()
        {
            string[] lines =
            {
                @"Q:\repo\CompatMatrix.Released.csproj|Q:\repo\bin\Debug\net8.0\CompatMatrix.Released.dll",
                @"Q:\repo\CompatMatrix.Current.csproj|Q:\repo\bin\Debug\net8.0\CompatMatrix.Current.dll",
            };

            IReadOnlyDictionary<string, string> workers = CompatibilityMatrixWorkerManifest.Parse(lines);

            Assert.AreEqual(@"Q:\repo\bin\Debug\net8.0\CompatMatrix.Released.dll", workers["released"]);
            Assert.AreEqual(@"Q:\repo\bin\Debug\net8.0\CompatMatrix.Current.dll", workers["current"]);
        }

        [TestMethod]
        public void CreateWorkerStartInfo_PassesAccountKeyOnlyThroughEnvironment()
        {
            const string accountKey = "secret-key";

            ProcessStartInfo startInfo = CompatibilityMatrixWorkerProcess.CreateStartInfo(
                @"Q:\repo\CompatMatrix.Current.dll",
                accountKey,
                new[] { "--action=write", "--database=test" });

            Assert.AreEqual(
                accountKey,
                startInfo.Environment[CompatibilityMatrixWorkerProcess.AccountKeyEnvironmentVariable]);
            Assert.IsFalse(startInfo.ArgumentList.Any(argument => argument.Contains(accountKey)));
        }

        [TestMethod]
        public void CreateWorkerStartInfo_RejectsAccountKeyArgument()
        {
            Assert.ThrowsException<InvalidOperationException>(
                () => CompatibilityMatrixWorkerProcess.CreateStartInfo(
                    @"Q:\repo\CompatMatrix.Current.dll",
                    "secret-key",
                    new[] { "--key=secret-key" }));
        }

        [TestMethod]
        public void CreateWorkerStartInfo_RemovesAccountKeyForIdentityAction()
        {
            ProcessStartInfo startInfo = CompatibilityMatrixWorkerProcess.CreateStartInfo(
                @"Q:\repo\CompatMatrix.Current.dll",
                null,
                new[] { "--action=identity" });

            Assert.IsFalse(
                startInfo.Environment.ContainsKey(
                    CompatibilityMatrixWorkerProcess.AccountKeyEnvironmentVariable));
        }

        private static CompatibilityMatrixRecord Pass(string scenarioId)
        {
            return new CompatibilityMatrixRecord
            {
                Kind = "observation",
                ScenarioId = scenarioId,
                Status = "pass",
                RequestedProcessor = "Newtonsoft",
                ActualProcessor = "Newtonsoft",
                ProviderConstruction = "released-dual-provider-constructor",
                EncryptorKind = "external-preview07-surface",
                DocumentId = "document-id",
                FixtureSha256 = Sha('2'),
                PlaintextSha256 = Sha('3'),
                RawShape = "family=MDE;_ei=[_ef:Integer,_en:String,_ea:String,_ed:Null,_ep:Array]",
            };
        }

        private static CompatibilityMatrixRecord[] PassingRewriteSet(string rewriteProcessor)
        {
            string fixtureSha256 = Sha('4');
            string plaintextSha256 = Sha('5');
            return CompatibilityMatrixScenarios.GetRewriteScenarios(rewriteProcessor)
                .Select(scenarioId =>
                {
                    CompatibilityMatrixRecord record = Pass(scenarioId);
                    record.Role = "current";
                    record.FixtureSha256 = fixtureSha256;
                    record.PlaintextSha256 = plaintextSha256;
                    bool stream = scenarioId.StartsWith("rewrite:", StringComparison.Ordinal)
                        ? string.Equals(rewriteProcessor, "Stream", StringComparison.Ordinal)
                        : scenarioId.Contains("->StreamRequested:", StringComparison.Ordinal);
                    record.RequestedProcessor = stream ? "Stream" : "Newtonsoft";
                    record.ProviderConstruction = stream
                        ? "factory-store-provider-cache-options"
                        : "constructor-store-provider-timespan";
                    record.EncryptorKind = stream
                        ? "built-in-cosmos-encryptor"
                        : "external-preview07-surface";
                    if (scenarioId.StartsWith("rewrite:", StringComparison.Ordinal))
                    {
                        record.RequestedProcessor = rewriteProcessor;
                        record.ActualProcessor = rewriteProcessor;
                        record.InputFixtureSha256 = Sha('1');
                    }
                    else if (scenarioId.EndsWith("->Newtonsoft:point", StringComparison.Ordinal))
                    {
                        record.ActualProcessor = "typed=Newtonsoft,stream=Newtonsoft";
                    }
                    else if (scenarioId.EndsWith("->StreamRequested:point", StringComparison.Ordinal))
                    {
                        record.ActualProcessor = "typed=Stream,stream=Stream";
                    }
                    else
                    {
                        record.ActualProcessor =
                            $"typed={rewriteProcessor},stream={rewriteProcessor}";
                    }

                    return record;
                })
                .ToArray();
        }

        private static string Sha(char value)
        {
            return new string(value, 64);
        }

        private static CompatibilityMatrixRecord Identity(string role, string version, string sha256)
        {
            return new CompatibilityMatrixRecord
            {
                Kind = "identity",
                Role = role,
                PackageVersion = version,
                InformationalVersion = version + "+commit",
                ProductVersion = version + "+commit",
                AssemblyVersion = "1.0.0.0",
                AssemblySha256 = sha256,
                AssemblyMvid = role + "-mvid",
                AssemblyPath = role + ".dll",
            };
        }

        private static CompatibilityMatrixPackageProvenance Provenance(
            string role,
            string version,
            string assemblySha256,
            string sourceCommit)
        {
            string expectedSource = string.Equals(role, "current", StringComparison.Ordinal)
                ? @"Q:\candidate-feed"
                : "https://api.nuget.org/v3/index.json";
            return new CompatibilityMatrixPackageProvenance
            {
                Role = role,
                PackageId = "Microsoft.Azure.Cosmos.Encryption.Custom",
                PackageVersion = version,
                PackageAssemblySha256 = assemblySha256,
                ExpectedSource = expectedSource,
                ActualSource = expectedSource,
                InputNupkgPath = string.Equals(role, "current", StringComparison.Ordinal)
                    ? Path.Combine(
                        expectedSource,
                        $"Microsoft.Azure.Cosmos.Encryption.Custom.{version}.nupkg")
                    : null,
                NupkgSha256 = Sha('A'),
                SourceCommit = sourceCommit,
            };
        }

        private const string CompletePayloadJson =
            "{\"id\":\"identity\",\"PK\":\"partition\",\"protectedString\":\"protected-string\"," +
            "\"protectedArray\":[1,null,{\"nested\":\"value\"}],\"protectedObject\":{\"null\":null}," +
            "\"protectedNull\":null,\"protectedLong\":9007199254740993," +
            "\"protectedDate\":\"2024-02-29T12:34:56.7890123Z\"," +
            "\"plainString\":\"plain-string\",\"plainArray\":[\"plain\",null]," +
            "\"plainObject\":{\"null\":null},\"plainNull\":null,\"plainLong\":-9007199254740991," +
            "\"plainDate\":\"1999-12-31T23:59:59.0000000Z\"}";
    }
}
#endif
