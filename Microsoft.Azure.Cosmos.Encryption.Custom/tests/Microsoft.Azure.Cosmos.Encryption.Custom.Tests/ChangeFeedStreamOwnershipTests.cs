//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

namespace Microsoft.Azure.Cosmos.Encryption.Tests
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.Azure.Cosmos;
    using Microsoft.Azure.Cosmos.Encryption.Custom;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Moq;
    using Newtonsoft.Json.Linq;

    [TestClass]
    public class ChangeFeedStreamOwnershipTests
    {
#if NET8_0_OR_GREATER
        private const string DekId = "change-feed-dek";
        private const string PlaintextFeed =
            "{\"Documents\":[{\"id\":\"item-1\",\"pk\":\"pk-1\",\"Sensitive\":\"secret\",\"Nested\":{\"enabled\":true},\"Number\":9007199254740993}],\"_count\":1}";

        [DataTestMethod]
        [DynamicData(nameof(GetHandlerAndCallbackOutcomes), DynamicDataSourceType.Method)]
        public async Task TransformedOutput_IsOwnedReadableAndDisposedAfterCallback(
            string handlerKind,
            bool callbackThrows)
        {
            Mock<Encryptor> encryptor = TestEncryptorFactory.CreateMde(DekId, out _);
            string encryptedFeed = await CreateEncryptedFeedAsync(encryptor.Object);
            TrackingReadOnlyStream borrowedInput = CreateTrackingStream(encryptedFeed);
            byte[] originalInput = borrowedInput.ToArray();
            ChangeFeedHarness harness = new (encryptor.Object);
            Stream delivered = null;
            InvalidOperationException callbackException = new ("application callback failed");

            Func<Stream, Func<Task>, CancellationToken, Task> applicationCallback =
                async (changes, checkpoint, cancellationToken) =>
                {
                    delivered = changes;
                    Assert.AreNotSame(borrowedInput, changes);
                    Assert.IsFalse(IsDisposed(changes));
                    AssertPlaintextFeed(changes);
                    await Task.Yield();
                    cancellationToken.ThrowIfCancellationRequested();
                    AssertPlaintextFeed(changes);
                    await InvokeCheckpointIfManualAsync(handlerKind, checkpoint);

                    if (callbackThrows)
                    {
                        throw callbackException;
                    }
                };

            Func<Stream, CancellationToken, Task> wrappedHandler = harness.Wire(
                handlerKind,
                applicationCallback);
            Exception actualException = await CaptureExceptionAsync(
                () => wrappedHandler(borrowedInput, CancellationToken.None));

            if (callbackThrows)
            {
                Assert.AreSame(callbackException, actualException);
            }
            else
            {
                Assert.IsNull(actualException);
            }

            Assert.IsNotNull(delivered);
            Assert.IsTrue(IsDisposed(delivered), "Owned transformed callback output must be disposed after callback completion.");
            AssertBorrowedInputPreserved(borrowedInput, originalInput);
            Assert.AreEqual(handlerKind == "ManualCheckpoint" ? 1 : 0, harness.CheckpointCalls);
            borrowedInput.Dispose();
        }

        [DataTestMethod]
        [DynamicData(nameof(GetHandlerAndCallbackOutcomes), DynamicDataSourceType.Method)]
        public async Task UnchangedOutput_RemainsBorrowedAndReadableAfterCallback(
            string handlerKind,
            bool callbackThrows)
        {
            Mock<Encryptor> encryptor = TestEncryptorFactory.CreateMde(DekId, out _);
            TrackingReadOnlyStream borrowedInput = CreateTrackingStream(PlaintextFeed);
            byte[] originalInput = borrowedInput.ToArray();
            ChangeFeedHarness harness = new (encryptor.Object);
            Stream delivered = null;
            InvalidOperationException callbackException = new ("application callback failed");

            Func<Stream, Func<Task>, CancellationToken, Task> applicationCallback =
                async (changes, checkpoint, cancellationToken) =>
                {
                    delivered = changes;
                    Assert.AreSame(borrowedInput, changes);
                    AssertPlaintextFeed(changes);
                    await Task.Yield();
                    cancellationToken.ThrowIfCancellationRequested();
                    AssertPlaintextFeed(changes);
                    await InvokeCheckpointIfManualAsync(handlerKind, checkpoint);

                    if (callbackThrows)
                    {
                        throw callbackException;
                    }
                };

            Func<Stream, CancellationToken, Task> wrappedHandler = harness.Wire(
                handlerKind,
                applicationCallback);
            Exception actualException = await CaptureExceptionAsync(
                () => wrappedHandler(borrowedInput, CancellationToken.None));

            if (callbackThrows)
            {
                Assert.AreSame(callbackException, actualException);
            }
            else
            {
                Assert.IsNull(actualException);
            }

            Assert.AreSame(borrowedInput, delivered);
            AssertBorrowedInputPreserved(borrowedInput, originalInput);
            Assert.AreEqual(handlerKind == "ManualCheckpoint" ? 1 : 0, harness.CheckpointCalls);
            borrowedInput.Dispose();
        }

        [DataTestMethod]
        [DynamicData(nameof(GetHandlerAndFailureOutcomes), DynamicDataSourceType.Method)]
        public async Task DecryptionFailure_PreventsCallbackAndPreservesBorrowedInput(
            string handlerKind,
            string failureKind)
        {
            Mock<Encryptor> workingEncryptor = TestEncryptorFactory.CreateMde(DekId, out _);
            string encryptedFeed = await CreateEncryptedFeedAsync(workingEncryptor.Object);
            Encryptor runtimeEncryptor = workingEncryptor.Object;
            Exception expectedException = null;
            CancellationTokenSource cancellation = null;

            if (failureKind == "Provider")
            {
                InvalidOperationException providerException = new ("provider failure");
                Mock<Encryptor> failingEncryptor = new ();
                failingEncryptor
                    .Setup(encryptor => encryptor.GetEncryptionKeyAsync(
                        It.IsAny<string>(),
                        It.IsAny<string>(),
                        It.IsAny<CancellationToken>()))
                    .ThrowsAsync(providerException);
                runtimeEncryptor = failingEncryptor.Object;
                expectedException = providerException;
            }
            else if (failureKind == "UnknownAlgorithm")
            {
                JObject feed = JObject.Parse(encryptedFeed);
                feed["Documents"][0][Constants.EncryptedInfo]["_ea"] = "UnknownEncryptionAlgorithm";
                encryptedFeed = feed.ToString(Newtonsoft.Json.Formatting.None);
            }
            else if (failureKind == "Cancellation")
            {
                cancellation = new CancellationTokenSource();
                cancellation.Cancel();
            }
            else
            {
                throw new ArgumentOutOfRangeException(nameof(failureKind), failureKind, "Unknown failure kind.");
            }

            TrackingReadOnlyStream borrowedInput = CreateTrackingStream(encryptedFeed);
            byte[] originalInput = borrowedInput.ToArray();
            ChangeFeedHarness harness = new (runtimeEncryptor);
            bool callbackInvoked = false;
            Func<Stream, CancellationToken, Task> wrappedHandler = harness.Wire(
                handlerKind,
                (_, _, _) =>
                {
                    callbackInvoked = true;
                    return Task.CompletedTask;
                });

            Exception actualException = await CaptureExceptionAsync(
                () => wrappedHandler(
                    borrowedInput,
                    cancellation?.Token ?? CancellationToken.None));

            Assert.IsFalse(callbackInvoked, "Application callback must not observe partial output after decryption failure.");
            Assert.AreEqual(0, harness.CheckpointCalls);

            if (failureKind == "Provider")
            {
                Assert.AreSame(expectedException, actualException);
            }
            else if (failureKind == "UnknownAlgorithm")
            {
                Assert.IsInstanceOfType(actualException, typeof(NotSupportedException));
                workingEncryptor.Verify(
                    encryptor => encryptor.GetEncryptionKeyAsync(
                        It.IsAny<string>(),
                        "UnknownEncryptionAlgorithm",
                        It.IsAny<CancellationToken>()),
                    Times.Never);
            }
            else
            {
                Assert.IsInstanceOfType(actualException, typeof(OperationCanceledException));
                Assert.AreEqual(
                    cancellation.Token,
                    ((OperationCanceledException)actualException).CancellationToken);
            }

            AssertBorrowedInputPreserved(borrowedInput, originalInput);
            borrowedInput.Dispose();
            cancellation?.Dispose();
        }

        public static IEnumerable<object[]> GetHandlerAndCallbackOutcomes()
        {
            foreach (string handlerKind in new[] { "Automatic", "ManualCheckpoint" })
            {
                yield return new object[] { handlerKind, false };
                yield return new object[] { handlerKind, true };
            }
        }

        public static IEnumerable<object[]> GetHandlerAndFailureOutcomes()
        {
            foreach (string handlerKind in new[] { "Automatic", "ManualCheckpoint" })
            {
                yield return new object[] { handlerKind, "Provider" };
                yield return new object[] { handlerKind, "UnknownAlgorithm" };
                yield return new object[] { handlerKind, "Cancellation" };
            }
        }

        private static async Task<string> CreateEncryptedFeedAsync(Encryptor encryptor)
        {
            JObject document = (JObject)JObject.Parse(PlaintextFeed)["Documents"][0];
            EncryptionOptions options = new ()
            {
                DataEncryptionKeyId = DekId,
                EncryptionAlgorithm = CosmosEncryptionAlgorithm.MdeAeadAes256CbcHmac256Randomized,
                PathsToEncrypt = new[] { "/Sensitive" },
            };

            using MemoryStream input = new (Encoding.UTF8.GetBytes(document.ToString(Newtonsoft.Json.Formatting.None)));
            using MemoryStream output = new ();
            await EncryptionProcessor.EncryptAsync(
                input,
                output,
                encryptor,
                options,
                JsonProcessor.Stream,
                CosmosDiagnosticsContext.Create(null),
                CancellationToken.None);

            string encryptedDocument = Encoding.UTF8.GetString(output.ToArray());
            return $"{{\"Documents\":[{encryptedDocument}],\"_count\":1}}";
        }

        private static TrackingReadOnlyStream CreateTrackingStream(string content)
        {
            return new TrackingReadOnlyStream(Encoding.UTF8.GetBytes(content));
        }

        private static async Task InvokeCheckpointIfManualAsync(
            string handlerKind,
            Func<Task> checkpoint)
        {
            if (handlerKind == "ManualCheckpoint")
            {
                Assert.IsNotNull(checkpoint);
                await checkpoint();
            }
            else
            {
                Assert.IsNull(checkpoint);
            }
        }

        private static void AssertPlaintextFeed(Stream stream)
        {
            string actual = ReadAll(stream);
            Assert.IsTrue(
                JToken.DeepEquals(JToken.Parse(PlaintextFeed), JToken.Parse(actual)),
                $"Callback did not receive the complete decrypted feed. Actual: {actual}");
        }

        private static void AssertBorrowedInputPreserved(
            TrackingReadOnlyStream borrowedInput,
            byte[] originalInput)
        {
            Assert.IsFalse(borrowedInput.IsDisposed, "Change-feed wrapper must not dispose the borrowed SDK input.");
            CollectionAssert.AreEqual(originalInput, borrowedInput.ToArray(), "Borrowed SDK input bytes were modified.");
            string reread = ReadAll(borrowedInput);
            CollectionAssert.AreEqual(
                originalInput,
                Encoding.UTF8.GetBytes(reread),
                "Borrowed SDK input must remain readable after wrapper completion.");
        }

        private static string ReadAll(Stream stream)
        {
            if (stream.CanSeek)
            {
                stream.Position = 0;
            }

            using StreamReader reader = new (stream, Encoding.UTF8, true, 1024, leaveOpen: true);
            return reader.ReadToEnd();
        }

        private static bool IsDisposed(Stream stream)
        {
            if (!stream.CanRead)
            {
                return true;
            }

            try
            {
                stream.ReadByte();
                return false;
            }
            catch (ObjectDisposedException)
            {
                return true;
            }
        }

        private static async Task<Exception> CaptureExceptionAsync(Func<Task> action)
        {
            try
            {
                await action();
                return null;
            }
            catch (Exception exception)
            {
                return exception;
            }
        }

        private sealed class ChangeFeedHarness
        {
            private readonly Mock<Container> inner = new ();
            private readonly EncryptionContainer container;

            public ChangeFeedHarness(Encryptor encryptor)
            {
                Mock<CosmosClient> client = new ();
                client.SetupGet(value => value.ResponseFactory).Returns(Mock.Of<CosmosResponseFactory>());
                client.SetupGet(value => value.ClientOptions).Returns(new CosmosClientOptions());
                Mock<Database> database = new ();
                database.SetupGet(value => value.Client).Returns(client.Object);
                this.inner.SetupGet(value => value.Database).Returns(database.Object);
                this.container = new EncryptionContainer(this.inner.Object, encryptor);
                this.container.UseStreamingJsonProcessingByDefault();
            }

            public int CheckpointCalls { get; private set; }

            public Func<Stream, CancellationToken, Task> Wire(
                string handlerKind,
                Func<Stream, Func<Task>, CancellationToken, Task> applicationCallback)
            {
                if (handlerKind == "Automatic")
                {
                    Container.ChangeFeedStreamHandler capturedHandler = null;
                    this.inner
                        .Setup(container => container.GetChangeFeedProcessorBuilder(
                            "ownership",
                            It.IsAny<Container.ChangeFeedStreamHandler>()))
                        .Callback<string, Container.ChangeFeedStreamHandler>(
                            (_, handler) => capturedHandler = handler)
                        .Returns((ChangeFeedProcessorBuilder)null);

                    this.container.GetChangeFeedProcessorBuilder(
                        "ownership",
                        (context, changes, cancellationToken) =>
                            applicationCallback(changes, null, cancellationToken));
                    Assert.IsNotNull(capturedHandler);
                    return (changes, cancellationToken) => capturedHandler(
                        Mock.Of<ChangeFeedProcessorContext>(),
                        changes,
                        cancellationToken);
                }

                if (handlerKind == "ManualCheckpoint")
                {
                    Container.ChangeFeedStreamHandlerWithManualCheckpoint capturedHandler = null;
                    this.inner
                        .Setup(container => container.GetChangeFeedProcessorBuilderWithManualCheckpoint(
                            "ownership",
                            It.IsAny<Container.ChangeFeedStreamHandlerWithManualCheckpoint>()))
                        .Callback<string, Container.ChangeFeedStreamHandlerWithManualCheckpoint>(
                            (_, handler) => capturedHandler = handler)
                        .Returns((ChangeFeedProcessorBuilder)null);

                    this.container.GetChangeFeedProcessorBuilderWithManualCheckpoint(
                        "ownership",
                        (context, changes, checkpoint, cancellationToken) =>
                            applicationCallback(changes, checkpoint, cancellationToken));
                    Assert.IsNotNull(capturedHandler);
                    return (changes, cancellationToken) => capturedHandler(
                        Mock.Of<ChangeFeedProcessorContext>(),
                        changes,
                        () =>
                        {
                            this.CheckpointCalls++;
                            return Task.CompletedTask;
                        },
                        cancellationToken);
                }

                throw new ArgumentOutOfRangeException(nameof(handlerKind), handlerKind, "Unknown handler kind.");
            }
        }

        private sealed class TrackingReadOnlyStream : MemoryStream
        {
            public TrackingReadOnlyStream(byte[] buffer)
                : base(buffer, index: 0, count: buffer.Length, writable: false, publiclyVisible: true)
            {
            }

            public bool IsDisposed { get; private set; }

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    this.IsDisposed = true;
                }

                base.Dispose(disposing);
            }
        }
#endif
    }
}
