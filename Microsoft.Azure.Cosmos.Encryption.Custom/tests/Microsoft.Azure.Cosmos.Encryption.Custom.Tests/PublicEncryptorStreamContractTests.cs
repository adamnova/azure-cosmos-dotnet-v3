//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

#if NET8_0_OR_GREATER
namespace Microsoft.Azure.Cosmos.Encryption.Tests
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Reflection;
    using System.Text;
    using System.Text.Json;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.Azure.Cosmos.Encryption.Custom;
    using Microsoft.Azure.Cosmos.Encryption.Custom.Tests;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Moq;
    using Newtonsoft.Json.Linq;

    [TestClass]
    public class PublicEncryptorStreamContractTests
    {
        private const string DekId = "public-dek";
        private const string Algorithm = CosmosEncryptionAlgorithm.MdeAeadAes256CbcHmac256Randomized;
        private const string Preview07FixtureAssemblyName = "Microsoft.Azure.Cosmos.Encryption.Custom.Preview07Compatibility";
        private const string Preview07ProbeTypeName = Preview07FixtureAssemblyName + ".Preview07CompatibilityProbe";
        private const string MultiValueDocument =
            "{\"id\":\"1\",\"First\":\"alpha\",\"Second\":{\"Nested\":[1,true,\"z\"]},\"HighPrecision\":1234567890.1234567890123456789,\"TrailingZero\":42.5000,\"Exponent\":6.022e+23}";

        [TestMethod]
        public async Task Preview07CompiledEncryptor_WorksThroughPublicItemAndStreamOperations()
        {
            Encryptor releasedEncryptor = LoadPreview07Encryptor();
            JsonCosmosSerializer serializer = new ();
            Mock<CosmosResponseFactory> responseFactory = new ();
            Mock<Container> innerContainer = CreateInnerContainer(serializer, responseFactory.Object);
            List<string> transportedPayloads = new ();

            innerContainer
                .Setup(container => container.CreateItemStreamAsync(
                    It.IsAny<Stream>(),
                    It.IsAny<PartitionKey>(),
                    It.IsAny<ItemRequestOptions>(),
                    It.IsAny<CancellationToken>()))
                .Returns((Stream payload, PartitionKey _, ItemRequestOptions __, CancellationToken cancellationToken) =>
                    EchoTransportAsync(payload, transportedPayloads, cancellationToken));

            PreviewItem typedResource = null;
            Mock<ItemResponse<PreviewItem>> typedResponse = new ();
            responseFactory
                .Setup(factory => factory.CreateItemResponse<PreviewItem>(It.IsAny<ResponseMessage>()))
                .Returns((ResponseMessage response) =>
                {
                    typedResource = serializer.FromStream<PreviewItem>(response.Content);
                    return typedResponse.Object;
                });

            Container encryptionContainer = innerContainer.Object.WithEncryptor(releasedEncryptor);
            EncryptionItemRequestOptions requestOptions = CreateRequestOptions("/First", "/Second");

            const string streamDocument = "{\"id\":\"stream\",\"First\":\"one\",\"Second\":{\"value\":2},\"Plain\":true}";
            using ResponseMessage streamResponse = await encryptionContainer.CreateItemStreamAsync(
                ToStream(streamDocument),
                new PartitionKey("stream"),
                requestOptions,
                CancellationToken.None);

            AssertJsonSemanticallyEqual(streamDocument, await ReadToEndAsync(streamResponse.Content));

            PreviewItem item = new ()
            {
                id = "typed",
                First = "two",
                Second = new PreviewNested { value = 3 },
                Plain = true,
            };

            await encryptionContainer.CreateItemAsync(
                item,
                new PartitionKey(item.id),
                requestOptions,
                CancellationToken.None);

            Assert.IsNotNull(typedResource);
            Assert.AreEqual(item.id, typedResource.id);
            Assert.AreEqual(item.First, typedResource.First);
            Assert.AreEqual(item.Second.value, typedResource.Second.value);
            Assert.AreEqual(item.Plain, typedResource.Plain);
            Assert.AreEqual(2, transportedPayloads.Count);
            Assert.IsTrue(transportedPayloads.All(payload => payload.Contains("\"_ei\"", StringComparison.Ordinal)));
        }

        [TestMethod]
        public async Task StreamEncrypt_PublicEncryptor_AcceptsAsyncOnlyReadableInput()
        {
            AsyncTransformEncryptor encryptor = new ();
            using AsyncOnlyReadStream input = new (Encoding.UTF8.GetBytes(MultiValueDocument));
            using MemoryStream output = new ();

            await EncryptToOutputAsync(input, output, encryptor, CancellationToken.None);

            Assert.AreEqual(0, input.SynchronousReadAttempts);
            Assert.AreEqual(2, encryptor.EncryptCalls);
            Assert.IsTrue(output.Length > 0);
        }

        [TestMethod]
        public async Task StreamDecrypt_PublicEncryptor_AcceptsAsyncOnlyReadableInput()
        {
            AsyncTransformEncryptor encryptor = new ();
            byte[] encryptedDocument = await CreateEncryptedDocumentAsync(encryptor);
            using AsyncOnlyReadStream input = new (encryptedDocument);
            using MemoryStream output = new ();

            await DecryptToOutputAsync(input, output, encryptor, CancellationToken.None);

            Assert.AreEqual(0, input.SynchronousReadAttempts);
            Assert.AreEqual(2, encryptor.DecryptCalls);
            AssertJsonSemanticallyEqual(MultiValueDocument, await ReadToEndAsync(output));
        }

        [TestMethod]
        public async Task StreamEncrypt_ProviderFailure_PreservesExceptionAndBorrowedStreams()
        {
            ProviderFailureException expected = new ("encrypt failed");
            FailingTransformEncryptor encryptor = new (failEncryptCall: 1, failDecryptCall: int.MaxValue, expected);
            using TrackingMemoryStream input = new (Encoding.UTF8.GetBytes(MultiValueDocument));
            using TrackingMemoryStream output = TrackingMemoryStream.WithSentinel();

            ProviderFailureException actual = await Assert.ThrowsExceptionAsync<ProviderFailureException>(
                () => EncryptToOutputAsync(input, output, encryptor, CancellationToken.None));

            Assert.AreSame(expected, actual);
            Assert.AreEqual(0, input.DisposeCount);
            Assert.AreEqual(0, output.DisposeCount);
            CollectionAssert.AreEqual(TrackingMemoryStream.Sentinel, output.ToArray());
        }

        [TestMethod]
        public async Task StreamDecrypt_ProviderFailure_PreservesExceptionAndBorrowedStreams()
        {
            byte[] encryptedDocument = await CreateEncryptedDocumentAsync(new AsyncTransformEncryptor());
            ProviderFailureException expected = new ("decrypt failed");
            FailingTransformEncryptor encryptor = new (failEncryptCall: int.MaxValue, failDecryptCall: 1, expected);
            using TrackingMemoryStream input = new (encryptedDocument);
            using TrackingMemoryStream output = TrackingMemoryStream.WithSentinel();

            ProviderFailureException actual = await Assert.ThrowsExceptionAsync<ProviderFailureException>(
                () => DecryptToOutputAsync(input, output, encryptor, CancellationToken.None));

            Assert.AreSame(expected, actual);
            Assert.AreEqual(0, input.DisposeCount);
            Assert.AreEqual(0, output.DisposeCount);
            CollectionAssert.AreEqual(TrackingMemoryStream.Sentinel, output.ToArray());
        }

        [TestMethod]
        public async Task StreamRoundTrip_GenuinelyAsyncPublicEncryptor_PreservesValuesAndRawTokens()
        {
            AsyncTransformEncryptor encryptor = new ();
            using MemoryStream encryptedOutput = new ();

            await EncryptToOutputAsync(
                ToStream(MultiValueDocument),
                encryptedOutput,
                encryptor,
                CancellationToken.None);

            string encryptedJson = await ReadToEndAsync(encryptedOutput);
            AssertRawPassThroughTokens(encryptedJson);
            Assert.AreEqual(2, encryptor.EncryptCalls);
            Assert.IsTrue(encryptor.EncryptCompletedAsynchronously);

            using MemoryStream decryptedOutput = new ();
            await DecryptToOutputAsync(
                ToStream(encryptedJson),
                decryptedOutput,
                encryptor,
                CancellationToken.None);

            string decryptedJson = await ReadToEndAsync(decryptedOutput);
            AssertJsonSemanticallyEqual(MultiValueDocument, decryptedJson);
            AssertRawPassThroughTokens(decryptedJson);
            Assert.AreEqual(2, encryptor.DecryptCalls);
            Assert.IsTrue(encryptor.DecryptCompletedAsynchronously);
        }

        [TestMethod]
        public async Task StreamEncrypt_FailureAfterEarlierValue_DoesNotPublishPartialOutput()
        {
            ProviderFailureException expected = new ("second encrypt failed");
            FailingTransformEncryptor encryptor = new (failEncryptCall: 2, failDecryptCall: int.MaxValue, expected);
            using MemoryStream output = TrackingMemoryStream.WithSentinel();

            ProviderFailureException actual = await Assert.ThrowsExceptionAsync<ProviderFailureException>(
                () => EncryptToOutputAsync(
                    ToStream(MultiValueDocument),
                    output,
                    encryptor,
                    CancellationToken.None));

            Assert.AreSame(expected, actual);
            Assert.AreEqual(2, encryptor.EncryptCalls);
            CollectionAssert.AreEqual(TrackingMemoryStream.Sentinel, output.ToArray());
        }

        [TestMethod]
        public async Task StreamDecrypt_FailureAfterEarlierValue_DoesNotPublishPartialOutput()
        {
            byte[] encryptedDocument = await CreateEncryptedDocumentAsync(new AsyncTransformEncryptor());
            ProviderFailureException expected = new ("second decrypt failed");
            FailingTransformEncryptor encryptor = new (failEncryptCall: int.MaxValue, failDecryptCall: 2, expected);
            using MemoryStream output = TrackingMemoryStream.WithSentinel();

            ProviderFailureException actual = await Assert.ThrowsExceptionAsync<ProviderFailureException>(
                () => DecryptToOutputAsync(
                    ToStream(encryptedDocument),
                    output,
                    encryptor,
                    CancellationToken.None));

            Assert.AreSame(expected, actual);
            Assert.AreEqual(2, encryptor.DecryptCalls);
            CollectionAssert.AreEqual(TrackingMemoryStream.Sentinel, output.ToArray());
        }

        [TestMethod]
        public async Task StreamEncrypt_LateProviderCompletionAfterCancellation_CannotPublishOrReuseInput()
        {
            LateCompletingEncryptor encryptor = new (blockEncrypt: true);
            using TrackingMemoryStream input = new (Encoding.UTF8.GetBytes(MultiValueDocument));
            using TrackingMemoryStream output = TrackingMemoryStream.WithSentinel();
            using CancellationTokenSource cancellation = new ();

            Task operation = EncryptToOutputAsync(input, output, encryptor, cancellation.Token);

            await AssertLateCompletionIsIsolatedAsync(
                operation,
                encryptor,
                input,
                output,
                cancellation);
        }

        [TestMethod]
        public async Task StreamDecrypt_LateProviderCompletionAfterCancellation_CannotPublishOrReuseInput()
        {
            byte[] encryptedDocument = await CreateEncryptedDocumentAsync(new AsyncTransformEncryptor());
            LateCompletingEncryptor encryptor = new (blockEncrypt: false);
            using TrackingMemoryStream input = new (encryptedDocument);
            using TrackingMemoryStream output = TrackingMemoryStream.WithSentinel();
            using CancellationTokenSource cancellation = new ();

            Task operation = DecryptToOutputAsync(input, output, encryptor, cancellation.Token);

            await AssertLateCompletionIsIsolatedAsync(
                operation,
                encryptor,
                input,
                output,
                cancellation);
        }

        private static async Task AssertLateCompletionIsIsolatedAsync(
            Task operation,
            LateCompletingEncryptor encryptor,
            TrackingMemoryStream input,
            TrackingMemoryStream output,
            CancellationTokenSource cancellation)
        {
            await encryptor.OperationStarted.WaitAsync(TimeSpan.FromSeconds(5));
            cancellation.Cancel();

            bool canceledBeforeProviderCompletion = false;
            try
            {
                await operation.WaitAsync(TimeSpan.FromSeconds(2));
            }
            catch (OperationCanceledException exception)
            {
                Assert.AreEqual(cancellation.Token, exception.CancellationToken);
                canceledBeforeProviderCompletion = true;
            }
            catch (TimeoutException)
            {
            }

            byte[] outputAtCancellation = output.ToArray();
            encryptor.Release();
            await encryptor.ProviderCompleted.WaitAsync(TimeSpan.FromSeconds(5));

            try
            {
                await operation.WaitAsync(TimeSpan.FromSeconds(5));
            }
            catch (OperationCanceledException)
            {
            }

            byte[] finalOutput = output.ToArray();
            bool outputStayedUnchanged = outputAtCancellation.SequenceEqual(finalOutput);
            bool outputStayedAtSentinel = TrackingMemoryStream.Sentinel.SequenceEqual(finalOutput);
            Assert.IsTrue(
                canceledBeforeProviderCompletion &&
                encryptor.ProviderInputStayedStable &&
                input.DisposeCount == 0 &&
                output.DisposeCount == 0 &&
                outputStayedUnchanged &&
                outputStayedAtSentinel,
                $"Late completion isolation failed: canceledBeforeCompletion={canceledBeforeProviderCompletion}, " +
                $"providerInputStable={encryptor.ProviderInputStayedStable}, inputDisposeCount={input.DisposeCount}, " +
                $"outputDisposeCount={output.DisposeCount}, outputUnchanged={outputStayedUnchanged}, " +
                $"outputStayedAtSentinel={outputStayedAtSentinel}.");
        }

        private static EncryptionItemRequestOptions CreateRequestOptions(params string[] paths)
        {
            return RequestOptionsOverrideHelper.Create(
                new EncryptionOptions
                {
                    DataEncryptionKeyId = DekId,
                    EncryptionAlgorithm = Algorithm,
                    PathsToEncrypt = paths.ToList(),
                },
                JsonProcessor.Stream);
        }

        private static Task EncryptToOutputAsync(
            Stream input,
            Stream output,
            Encryptor encryptor,
            CancellationToken cancellationToken)
        {
            return EncryptionProcessor.EncryptAsync(
                input,
                output,
                encryptor,
                CreateRequestOptions("/First", "/Second").EncryptionOptions,
                JsonProcessor.Stream,
                new CosmosDiagnosticsContext(),
                cancellationToken);
        }

        private static Task<DecryptionContext> DecryptToOutputAsync(
            Stream input,
            Stream output,
            Encryptor encryptor,
            CancellationToken cancellationToken)
        {
            return EncryptionProcessor.DecryptAsync(
                input,
                output,
                encryptor,
                new CosmosDiagnosticsContext(),
                CreateRequestOptions("/First", "/Second"),
                cancellationToken);
        }

        private static async Task<byte[]> CreateEncryptedDocumentAsync(Encryptor encryptor)
        {
            using MemoryStream output = new ();
            await EncryptToOutputAsync(
                ToStream(MultiValueDocument),
                output,
                encryptor,
                CancellationToken.None);
            return output.ToArray();
        }

        private static Encryptor LoadPreview07Encryptor()
        {
            string assemblyPath = Path.Combine(
                AppContext.BaseDirectory,
                Preview07FixtureAssemblyName + ".dll");
            Assembly fixtureAssembly = Assembly.LoadFrom(assemblyPath);
            Type probeType = fixtureAssembly.GetType(Preview07ProbeTypeName, throwOnError: true);
            MethodInfo method = probeType.GetMethod("CreateEncryptor", BindingFlags.Public | BindingFlags.Static);
            Assert.IsNotNull(method);
            return (Encryptor)method.Invoke(null, null);
        }

        private static Mock<Container> CreateInnerContainer(
            CosmosSerializer serializer,
            CosmosResponseFactory responseFactory)
        {
            CosmosClientOptions clientOptions = new () { Serializer = serializer };
            Mock<CosmosClient> client = new ();
            client.SetupGet(value => value.ClientOptions).Returns(clientOptions);
            client.SetupGet(value => value.ResponseFactory).Returns(responseFactory);

            Mock<Database> database = new ();
            database.SetupGet(value => value.Client).Returns(client.Object);
            database.SetupGet(value => value.Id).Returns("test-database");

            Mock<Container> container = new ();
            container.SetupGet(value => value.Database).Returns(database.Object);
            container.SetupGet(value => value.Id).Returns("test-container");
            return container;
        }

        private static async Task<ResponseMessage> EchoTransportAsync(
            Stream payload,
            ICollection<string> transportedPayloads,
            CancellationToken cancellationToken)
        {
            string encryptedJson = await ReadToEndAsync(payload, cancellationToken);
            transportedPayloads.Add(encryptedJson);
            return new ResponseMessage(HttpStatusCode.OK)
            {
                Content = ToStream(encryptedJson),
            };
        }

        private static void AssertJsonSemanticallyEqual(string expected, string actual)
        {
            Assert.IsTrue(
                JToken.DeepEquals(JToken.Parse(expected), JToken.Parse(actual)),
                $"Expected semantic JSON {expected}, but received {actual}.");
        }

        private static void AssertRawPassThroughTokens(string json)
        {
            using JsonDocument document = JsonDocument.Parse(json);
            Assert.AreEqual(
                "1234567890.1234567890123456789",
                document.RootElement.GetProperty("HighPrecision").GetRawText());
            Assert.AreEqual(
                "42.5000",
                document.RootElement.GetProperty("TrailingZero").GetRawText());
            Assert.AreEqual(
                "6.022e+23",
                document.RootElement.GetProperty("Exponent").GetRawText());
        }

        private static MemoryStream ToStream(string json)
        {
            return new MemoryStream(Encoding.UTF8.GetBytes(json));
        }

        private static MemoryStream ToStream(byte[] bytes)
        {
            return new MemoryStream(bytes, writable: false);
        }

        private static async Task<string> ReadToEndAsync(
            Stream stream,
            CancellationToken cancellationToken = default)
        {
            if (stream.CanSeek)
            {
                stream.Position = 0;
            }

            using StreamReader reader = new (
                stream,
                Encoding.UTF8,
                detectEncodingFromByteOrderMarks: false,
                leaveOpen: true);
            return await reader.ReadToEndAsync(cancellationToken);
        }

        private static byte[] Transform(byte[] input)
        {
            byte[] result = (byte[])input.Clone();
            for (int i = 0; i < result.Length; i++)
            {
                result[i] ^= 0x5A;
            }

            return result;
        }

        public sealed class PreviewItem
        {
            public string id { get; set; }

            public string First { get; set; }

            public PreviewNested Second { get; set; }

            public bool Plain { get; set; }
        }

        public sealed class PreviewNested
        {
            public int value { get; set; }
        }

        private sealed class JsonCosmosSerializer : CosmosSerializer
        {
            public override T FromStream<T>(Stream stream)
            {
                return JsonSerializer.Deserialize<T>(stream);
            }

            public override Stream ToStream<T>(T input)
            {
                MemoryStream stream = new ();
                JsonSerializer.Serialize(stream, input);
                stream.Position = 0;
                return stream;
            }
        }

        private class AsyncTransformEncryptor : Encryptor
        {
            public int EncryptCalls { get; private set; }

            public int DecryptCalls { get; private set; }

            public bool EncryptCompletedAsynchronously { get; private set; }

            public bool DecryptCompletedAsynchronously { get; private set; }

            public override async Task<byte[]> EncryptAsync(
                byte[] plainText,
                string dataEncryptionKeyId,
                string encryptionAlgorithm,
                CancellationToken cancellationToken = default)
            {
                this.EncryptCalls++;
                await Task.Yield();
                cancellationToken.ThrowIfCancellationRequested();
                this.EncryptCompletedAsynchronously = true;
                return Transform(plainText);
            }

            public override async Task<byte[]> DecryptAsync(
                byte[] cipherText,
                string dataEncryptionKeyId,
                string encryptionAlgorithm,
                CancellationToken cancellationToken = default)
            {
                this.DecryptCalls++;
                await Task.Yield();
                cancellationToken.ThrowIfCancellationRequested();
                this.DecryptCompletedAsynchronously = true;
                return Transform(cipherText);
            }
        }

        private sealed class FailingTransformEncryptor : Encryptor
        {
            private readonly int failEncryptCall;
            private readonly int failDecryptCall;
            private readonly ProviderFailureException failure;

            public FailingTransformEncryptor(
                int failEncryptCall,
                int failDecryptCall,
                ProviderFailureException failure)
            {
                this.failEncryptCall = failEncryptCall;
                this.failDecryptCall = failDecryptCall;
                this.failure = failure;
            }

            public int EncryptCalls { get; private set; }

            public int DecryptCalls { get; private set; }

            public override async Task<byte[]> EncryptAsync(
                byte[] plainText,
                string dataEncryptionKeyId,
                string encryptionAlgorithm,
                CancellationToken cancellationToken = default)
            {
                int call = ++this.EncryptCalls;
                await Task.Yield();
                if (call == this.failEncryptCall)
                {
                    throw this.failure;
                }

                return Transform(plainText);
            }

            public override async Task<byte[]> DecryptAsync(
                byte[] cipherText,
                string dataEncryptionKeyId,
                string encryptionAlgorithm,
                CancellationToken cancellationToken = default)
            {
                int call = ++this.DecryptCalls;
                await Task.Yield();
                if (call == this.failDecryptCall)
                {
                    throw this.failure;
                }

                return Transform(cipherText);
            }
        }

        private sealed class LateCompletingEncryptor : Encryptor
        {
            private readonly bool blockEncrypt;
            private readonly TaskCompletionSource<bool> operationStarted = new (
                TaskCreationOptions.RunContinuationsAsynchronously);
            private readonly TaskCompletionSource<bool> release = new (
                TaskCreationOptions.RunContinuationsAsynchronously);
            private readonly TaskCompletionSource<bool> providerCompleted = new (
                TaskCreationOptions.RunContinuationsAsynchronously);

            public LateCompletingEncryptor(bool blockEncrypt)
            {
                this.blockEncrypt = blockEncrypt;
            }

            public Task OperationStarted => this.operationStarted.Task;

            public Task ProviderCompleted => this.providerCompleted.Task;

            public bool ProviderInputStayedStable { get; private set; }

            public void Release()
            {
                this.release.TrySetResult(true);
            }

            public override async Task<byte[]> EncryptAsync(
                byte[] plainText,
                string dataEncryptionKeyId,
                string encryptionAlgorithm,
                CancellationToken cancellationToken = default)
            {
                if (!this.blockEncrypt)
                {
                    return Transform(plainText);
                }

                return await this.CompleteLateAsync(plainText);
            }

            public override async Task<byte[]> DecryptAsync(
                byte[] cipherText,
                string dataEncryptionKeyId,
                string encryptionAlgorithm,
                CancellationToken cancellationToken = default)
            {
                if (this.blockEncrypt)
                {
                    return Transform(cipherText);
                }

                return await this.CompleteLateAsync(cipherText);
            }

            private async Task<byte[]> CompleteLateAsync(byte[] providerInput)
            {
                byte[] snapshot = (byte[])providerInput.Clone();
                this.operationStarted.TrySetResult(true);
                await this.release.Task.ConfigureAwait(false);
                this.ProviderInputStayedStable = snapshot.SequenceEqual(providerInput);
                byte[] result = Transform(providerInput);
                this.providerCompleted.TrySetResult(true);
                return result;
            }
        }

        private sealed class ProviderFailureException : Exception
        {
            public ProviderFailureException(string message)
                : base(message)
            {
            }
        }

        private sealed class TrackingMemoryStream : MemoryStream
        {
            public static readonly byte[] Sentinel = new byte[] { 0x2A, 0x7B, 0x3C };

            public TrackingMemoryStream()
            {
            }

            public TrackingMemoryStream(byte[] bytes)
                : base(bytes, writable: false)
            {
            }

            public int DisposeCount { get; private set; }

            public static TrackingMemoryStream WithSentinel()
            {
                TrackingMemoryStream stream = new ();
                stream.Write(Sentinel, 0, Sentinel.Length);
                return stream;
            }

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    this.DisposeCount++;
                }

                base.Dispose(disposing);
            }
        }

        private sealed class AsyncOnlyReadStream : Stream
        {
            private readonly byte[] bytes;
            private long position;

            public AsyncOnlyReadStream(byte[] bytes)
            {
                this.bytes = bytes;
            }

            public int SynchronousReadAttempts { get; private set; }

            public override bool CanRead => true;

            public override bool CanSeek => true;

            public override bool CanWrite => false;

            public override long Length => this.bytes.Length;

            public override long Position
            {
                get => this.position;
                set => this.position = value;
            }

            public override void Flush()
            {
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                this.SynchronousReadAttempts++;
                throw new InvalidOperationException("Synchronous reads are not supported.");
            }

            public override int Read(Span<byte> buffer)
            {
                this.SynchronousReadAttempts++;
                throw new InvalidOperationException("Synchronous reads are not supported.");
            }

            public override Task<int> ReadAsync(
                byte[] buffer,
                int offset,
                int count,
                CancellationToken cancellationToken)
            {
                return this.ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
            }

            public override ValueTask<int> ReadAsync(
                Memory<byte> buffer,
                CancellationToken cancellationToken = default)
            {
                cancellationToken.ThrowIfCancellationRequested();
                int remaining = this.bytes.Length - (int)this.position;
                if (remaining <= 0)
                {
                    return ValueTask.FromResult(0);
                }

                int count = Math.Min(remaining, buffer.Length);
                this.bytes.AsMemory((int)this.position, count).CopyTo(buffer);
                this.position += count;
                return ValueTask.FromResult(count);
            }

            public override long Seek(long offset, SeekOrigin origin)
            {
                this.position = origin switch
                {
                    SeekOrigin.Begin => offset,
                    SeekOrigin.Current => this.position + offset,
                    SeekOrigin.End => this.bytes.Length + offset,
                    _ => throw new ArgumentOutOfRangeException(nameof(origin)),
                };
                return this.position;
            }

            public override void SetLength(long value)
            {
                throw new NotSupportedException();
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                throw new NotSupportedException();
            }
        }
    }
}
#endif
