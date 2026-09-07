//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

namespace Microsoft.Azure.Cosmos.Encryption.Custom
{
    using System;
    using System.Linq;
    using Microsoft.Azure.Cosmos.Linq;

    /// <summary>
    /// This class provides extension methods for <see cref="EncryptionContainer"/>.
    /// </summary>
    public static class EncryptionContainerExtensions
    {
        /// <summary>
        /// Get container with <see cref="Encryptor"/> for performing operations using client-side encryption.
        /// </summary>
        /// <param name="container">Regular cosmos container.</param>
        /// <param name="encryptor">Provider that allows encrypting and decrypting data.</param>
        /// <returns>Container to perform operations supporting client-side encryption / decryption.</returns>
        public static Container WithEncryptor(
            this Container container,
            Encryptor encryptor)
        {
            return new EncryptionContainer(
                container,
                encryptor);
        }

#if NET8_0_OR_GREATER
        /// <summary>
        /// Configures the specified <see cref="Container"/> to use streaming JSON processing by default.
        /// </summary>
        /// <param name="container">The <see cref="Container"/> instance to configure. Must be an <see cref="EncryptionContainer"/>.</param>
        /// <returns>The configured <see cref="EncryptionContainer"/> instance.</returns>
        /// <exception cref="ArgumentException">Thrown if <paramref name="container"/> is not an <see cref="EncryptionContainer"/>.</exception>
        /// <remarks>
        /// <para>
        /// Newtonsoft JSON processing remains the default. Streaming JSON processing is an opt-in implementation;
        /// it does not guarantee a performance improvement or zero-copy processing.
        /// </para>
        /// <para>
        /// This method selects streaming for supported operations that consult the container default. It does not
        /// change every API path: typed encrypted Create, Replace, and Upsert operations continue to start with
        /// Newtonsoft unless that call supplies an override; <c>ReadItemAsync&lt;DecryptableItem&gt;</c> and typed
        /// change-feed processor callbacks continue to use their existing JObject-based lazy/materialized paths.
        /// </para>
        /// <para>
        /// To select a processor on a supported individual call, set the override on that call's
        /// <see cref="RequestOptions.Properties"/> bag using the key <c>"encryption-json-processor"</c> and the string
        /// value <c>"Stream"</c> or <c>"Newtonsoft"</c>:
        /// <code language="c#">
        /// <![CDATA[
        /// QueryRequestOptions requestOptions = new QueryRequestOptions
        /// {
        ///     Properties = new Dictionary<string, object> { ["encryption-json-processor"] = "Stream" }
        /// };
        /// ]]>
        /// </code>
        /// The per-call override takes precedence over the container default. LINQ entry points capture the override
        /// supplied to <see cref="Container.GetItemLinqQueryable{T}(bool, string, QueryRequestOptions, CosmosLinqSerializerOptions)"/>
        /// and honor it when <see cref="ToEncryptionFeedIterator{T}"/> or <see cref="ToEncryptionStreamIterator{T}"/>
        /// creates the iterator. Streaming writes support only
        /// <see cref="CosmosEncryptionAlgorithm.MdeAeadAes256CbcHmac256Randomized"/>; reads can also consume valid
        /// historical legacy-encrypted documents.
        /// </para>
        /// <para>
        /// <strong>Disposal contract for <c>FeedResponse&lt;DecryptableItem&gt;</c>.</strong> The <c>FeedResponse&lt;T&gt;</c>
        /// returned from <c>FeedIterator&lt;DecryptableItem&gt;.ReadNextAsync</c> implements <see cref="IAsyncDisposable"/>
        /// at runtime, but the compile-time return type does not advertise it. Callers SHOULD cast each page to
        /// <see cref="IAsyncDisposable"/> and dispose it (typically in a <c>finally</c> block) so that any items the
        /// caller skipped, did not enumerate, or did not call <c>GetItemAsync</c> on promptly return their pooled
        /// buffers to the pool. Disposal is the prompt path; if it is missed, a finalizer on the underlying pooled
        /// stream still returns and zeroes the buffer when the page is garbage-collected, so a missed dispose degrades
        /// to a delayed cleanup rather than a permanent pool leak or lingering plaintext. See the example on
        /// <see cref="DecryptableItem"/> for the recommended pattern.
        /// </para>
        /// </remarks>
        public static Container UseStreamingJsonProcessingByDefault(this Container container)
        {
            if (container is not EncryptionContainer encryptionContainer)
            {
                throw new ArgumentException(
                    $"{nameof(UseStreamingJsonProcessingByDefault)} is only supported with {nameof(EncryptionContainer)}.",
                    nameof(container));
            }

            encryptionContainer.UseStreamingJsonProcessingByDefault();

            return encryptionContainer;
        }
#endif

        /// <summary>
        /// This method gets the FeedIterator from LINQ IQueryable to execute query asynchronously.
        /// This will create the fresh new FeedIterator when called which will support decryption.
        /// </summary>
        /// <typeparam name="T">the type of object to query.</typeparam>
        /// <param name="container">the encryption container.</param>
        /// <param name="query">the IQueryable{T} to be converted.</param>
        /// <returns>An iterator to go through the items.</returns>
        /// <remarks>
        /// On .NET 8+, this iterator uses the JSON processor selected when the query was created. A processor override
        /// in the <see cref="QueryRequestOptions"/> passed to <c>GetItemLinqQueryable</c> takes precedence over the
        /// container default.
        /// </remarks>
        /// <example>
        /// This example shows how to get FeedIterator from LINQ.
        ///
        /// <code language="c#">
        /// <![CDATA[
        /// IOrderedQueryable<ToDoActivity> linqQueryable = this.container.GetItemLinqQueryable<ToDoActivity>();
        /// FeedIterator setIterator = this.container.ToEncryptionFeedIterator<ToDoActivity>(linqQueryable);
        /// ]]>
        /// </code>
        /// </example>
        public static FeedIterator<T> ToEncryptionFeedIterator<T>(
            this Container container,
            IQueryable<T> query)
        {
            if (container is not EncryptionContainer encryptionContainer)
            {
                throw new ArgumentOutOfRangeException(nameof(query), $"{nameof(ToEncryptionFeedIterator)} is only supported with {nameof(EncryptionContainer)}.");
            }

            FeedIterator innerIterator = query.ToStreamIterator();
            JsonProcessor jsonProcessor = encryptionContainer.ResolveLinqJsonProcessor(query);
            return new EncryptionFeedIterator<T>(
                new EncryptionFeedIterator(
                    innerIterator,
                    encryptionContainer.Encryptor,
                    jsonProcessor),
                encryptionContainer.ResponseFactory,
                encryptionContainer.Encryptor,
                encryptionContainer.CosmosSerializer,
                jsonProcessor);
        }

        /// <summary>
        /// This method gets the FeedIterator from LINQ IQueryable to execute query asynchronously.
        /// This will create the fresh new FeedIterator when called which will support decryption.
        /// </summary>
        /// <typeparam name="T">the type of object to query.</typeparam>
        /// <param name="container">the encryption container.</param>
        /// <param name="query">the IQueryable{T} to be converted.</param>
        /// <returns>An iterator to go through the items.</returns>
        /// <remarks>
        /// On .NET 8+, this iterator uses the JSON processor selected when the query was created. A processor override
        /// in the <see cref="QueryRequestOptions"/> passed to <c>GetItemLinqQueryable</c> takes precedence over the
        /// container default.
        /// </remarks>
        /// <example>
        /// This example shows how to get FeedIterator from LINQ.
        ///
        /// <code language="c#">
        /// <![CDATA[
        /// IOrderedQueryable<ToDoActivity> linqQueryable = this.container.GetItemLinqQueryable<ToDoActivity>();
        /// FeedIterator setIterator = this.container.ToEncryptionStreamIterator<ToDoActivity>(linqQueryable);
        /// ]]>
        /// </code>
        /// </example>
        public static FeedIterator ToEncryptionStreamIterator<T>(
            this Container container,
            IQueryable<T> query)
        {
            if (container is not EncryptionContainer encryptionContainer)
            {
                throw new ArgumentOutOfRangeException(nameof(query), $"{nameof(ToEncryptionStreamIterator)} is only supported with {nameof(EncryptionContainer)}.");
            }

            FeedIterator innerIterator = query.ToStreamIterator();
            return new EncryptionFeedIterator(
                innerIterator,
                encryptionContainer.Encryptor,
                encryptionContainer.ResolveLinqJsonProcessor(query));
        }
    }
}
