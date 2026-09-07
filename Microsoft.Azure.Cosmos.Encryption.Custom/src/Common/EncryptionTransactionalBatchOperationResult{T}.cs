//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

namespace Microsoft.Azure.Cosmos.Encryption.Custom
{
    using System;
    using System.Net;

    internal sealed class EncryptionTransactionalBatchOperationResult<T> : TransactionalBatchOperationResult<T>
    {
        private readonly TransactionalBatchOperationResult response;

        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptionTransactionalBatchOperationResult{T}"/> class.
        /// </summary>
        /// <param name="response">Original per-operation response.</param>
        /// <param name="resource">Deserialized resource.</param>
        internal EncryptionTransactionalBatchOperationResult(
            TransactionalBatchOperationResult response,
            T resource)
        {
            this.response = response;
            this.Resource = resource;
        }

        public override HttpStatusCode StatusCode => this.response.StatusCode;

        public override bool IsSuccessStatusCode => this.response.IsSuccessStatusCode;

        public override string ETag => this.response.ETag;

        public override TimeSpan RetryAfter => this.response.RetryAfter;

        /// <summary>
        /// Gets or sets the content of the resource.
        /// </summary>
        public override T Resource { get; set; }
    }
}