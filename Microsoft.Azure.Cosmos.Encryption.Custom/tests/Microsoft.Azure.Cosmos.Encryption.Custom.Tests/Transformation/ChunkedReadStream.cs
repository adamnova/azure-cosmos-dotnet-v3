//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

namespace Microsoft.Azure.Cosmos.Encryption.Tests.Transformation
{
    using System;
    using System.IO;
    using System.Threading;
    using System.Threading.Tasks;

    /// <summary>
    /// A seekable stream wrapper that limits the maximum bytes returned per Read/ReadAsync call.
    /// Useful to simulate small incremental reads for streaming pipelines.
    /// </summary>
    internal sealed class ChunkedReadStream : Stream
    {
        private readonly Stream inner;
        private readonly int maxChunkSize;

        public ChunkedReadStream(Stream inner, int maxChunkSize)
        {
            this.inner = inner ?? throw new ArgumentNullException(nameof(inner));
            if (!inner.CanSeek)
            {
                throw new ArgumentException("Inner stream must be seekable.", nameof(inner));
            }

            if (maxChunkSize <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(maxChunkSize));
            }

            this.maxChunkSize = maxChunkSize;
        }

        public override bool CanRead => this.inner.CanRead;

        public override bool CanSeek => this.inner.CanSeek;

        public override bool CanWrite => false;

        public override long Length => this.inner.Length;

        public override long Position
        {
            get => this.inner.Position;
            set => this.inner.Position = value;
        }

        public override void Flush()
        {
            // no-op
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int toRead = Math.Min(count, this.maxChunkSize);
            return this.inner.Read(buffer, offset, toRead);
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            int toRead = Math.Min(buffer.Length, this.maxChunkSize);
            return await this.inner.ReadAsync(buffer.Slice(0, toRead), cancellationToken).ConfigureAwait(false);
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            int toRead = Math.Min(count, this.maxChunkSize);
            return this.inner.ReadAsync(buffer, offset, toRead, cancellationToken);
        }

        public override long Seek(long offset, SeekOrigin origin) => this.inner.Seek(offset, origin);

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            // do not own the inner stream; leave it to the caller
        }
    }
}
