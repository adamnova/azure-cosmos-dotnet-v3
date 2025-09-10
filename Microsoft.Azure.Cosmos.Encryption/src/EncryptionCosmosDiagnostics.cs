// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// ------------------------------------------------------------

namespace Microsoft.Azure.Cosmos.Encryption
{
    using System;
    using System.Buffers;
    using System.Collections.Generic;
    using System.IO;
    using System.Text;
    using System.Text.Json;

    internal sealed class EncryptionCosmosDiagnostics : CosmosDiagnostics
    {
        private readonly CosmosDiagnostics coreDiagnostics;
        private readonly EncryptionDiagnosticsContext.OperationDiagnostics encryptOperation;
        private readonly EncryptionDiagnosticsContext.OperationDiagnostics decryptOperation;
        private readonly TimeSpan processingDuration;

        public EncryptionCosmosDiagnostics(
                CosmosDiagnostics coreDiagnostics,
                EncryptionDiagnosticsContext.OperationDiagnostics encryptOperation,
                EncryptionDiagnosticsContext.OperationDiagnostics decryptOperation,
                TimeSpan processingDuration)
        {
            this.coreDiagnostics = coreDiagnostics ?? throw new ArgumentNullException(nameof(coreDiagnostics));
            this.encryptOperation = encryptOperation;
            this.decryptOperation = decryptOperation;
            this.processingDuration = processingDuration;
        }

        public override IReadOnlyList<(string regionName, Uri uri)> GetContactedRegions() => this.coreDiagnostics.GetContactedRegions();

        public override TimeSpan GetClientElapsedTime()
        {
            TimeSpan clientElapsedTime = this.coreDiagnostics.GetClientElapsedTime();
            if (this.processingDuration.Ticks > 0)
            {
                clientElapsedTime += this.processingDuration;
            }

            return clientElapsedTime;
        }

        public override string ToString()
        {
            string core = this.coreDiagnostics.ToString();
            int estimatedCapacity = EstimateInitialCapacity(core?.Length ?? 0, this.encryptOperation, this.decryptOperation);

            PooledArrayBufferWriter bufferWriter = new PooledArrayBufferWriter(estimatedCapacity);
            try
            {
                using (Utf8JsonWriter writer = new Utf8JsonWriter(bufferWriter))
                {
                    writer.WriteStartObject();

                    // Core diagnostics
                    writer.WritePropertyName(Constants.DiagnosticsCoreDiagnostics);
                    bool wroteCore = false;
                    if (!string.IsNullOrEmpty(core))
                    {
                        try
                        {
                            using JsonDocument doc = JsonDocument.Parse(core);
                            doc.RootElement.WriteTo(writer);
                            wroteCore = true;
                        }
                        catch
                        {
                            // fall back below
                        }
                    }

                    if (!wroteCore)
                    {
                        writer.WriteStringValue(core ?? string.Empty);
                    }

                    writer.WritePropertyName(Constants.DiagnosticsEncryptionDiagnostics);
                    writer.WriteStartObject();

                    if (this.encryptOperation.HasValue)
                    {
                        writer.WritePropertyName(Constants.DiagnosticsEncryptOperation);
                        writer.WriteStartObject();
                        writer.WriteString(Constants.DiagnosticsStartTime, this.encryptOperation.StartTimeUtc);
                        writer.WriteString(Constants.DiagnosticsDuration, this.encryptOperation.Duration.ToString());
                        if (this.encryptOperation.HasPropertiesCount)
                        {
                            writer.WriteNumber(Constants.DiagnosticsPropertiesEncryptedCount, this.encryptOperation.PropertiesCount);
                        }

                        writer.WriteEndObject();
                    }

                    if (this.decryptOperation.HasValue)
                    {
                        writer.WritePropertyName(Constants.DiagnosticsDecryptOperation);
                        writer.WriteStartObject();
                        writer.WriteString(Constants.DiagnosticsStartTime, this.decryptOperation.StartTimeUtc);
                        writer.WriteString(Constants.DiagnosticsDuration, this.decryptOperation.Duration.ToString());
                        if (this.decryptOperation.HasPropertiesCount)
                        {
                            writer.WriteNumber(Constants.DiagnosticsPropertiesDecryptedCount, this.decryptOperation.PropertiesCount);
                        }

                        writer.WriteEndObject();
                    }

                    writer.WriteEndObject(); // EncryptionDiagnostics
                    writer.WriteEndObject(); // root
                    writer.Flush();
                }

                byte[] bytes = bufferWriter.ToArray();
                return Encoding.UTF8.GetString(bytes, 0, bytes.Length);
            }
            finally
            {
                bufferWriter.Dispose();
            }
        }

        // Rough estimation of required capacity:
        // Base JSON punctuation + property names (~120 bytes) + core diagnostics length
        // Each operation block (Encrypt/Decrypt) adds ~160-220 bytes depending on presence of counts.
        private static int EstimateInitialCapacity(int coreLength, in EncryptionDiagnosticsContext.OperationDiagnostics encryptOp, in EncryptionDiagnosticsContext.OperationDiagnostics decryptOp)
        {
            const int BaseOverhead = 128; // braces + field names
            const int OperationOverheadNoCount = 170; // property name + object with start + duration
            const int OperationOverheadWithCount = 200; // above + property count

            int overhead = BaseOverhead;
            if (encryptOp.HasValue)
            {
                overhead += encryptOp.HasPropertiesCount ? OperationOverheadWithCount : OperationOverheadNoCount;
            }

            if (decryptOp.HasValue)
            {
                overhead += decryptOp.HasPropertiesCount ? OperationOverheadWithCount : OperationOverheadNoCount;
            }

            long total = (long)coreLength + overhead;

            // Clamp between sensible bounds to avoid huge single rents or very small buffers.
            if (total < 512)
            {
                total = 512;
            }
            else if (total > 64 * 1024)
            {
                total = 64 * 1024; // cap at 64KB; larger cases will grow dynamically
            }

            return (int)total;
        }

        private sealed class PooledArrayBufferWriter : IBufferWriter<byte>, IDisposable
        {
            private const int MinGrow = 256;
            private byte[] buffer;

            internal PooledArrayBufferWriter(int initialCapacity)
            {
                this.buffer = ArrayPool<byte>.Shared.Rent(initialCapacity);
                this.Length = 0;
            }

            public int Length { get; private set; }

            public void Advance(int count)
            {
                this.Length += count;
            }

            public Memory<byte> GetMemory(int sizeHint = 0)
            {
                this.Ensure(sizeHint);
                return new Memory<byte>(this.buffer, this.Length, this.buffer.Length - this.Length);
            }

            public Span<byte> GetSpan(int sizeHint = 0)
            {
                this.Ensure(sizeHint);
                return new Span<byte>(this.buffer, this.Length, this.buffer.Length - this.Length);
            }

            public byte[] ToArray()
            {
                byte[] result = new byte[this.Length];
                Buffer.BlockCopy(this.buffer, 0, result, 0, this.Length);
                return result;
            }

            public void Dispose()
            {
                byte[] toReturn = this.buffer;
                this.buffer = Array.Empty<byte>();
                if (toReturn.Length > 0)
                {
                    ArrayPool<byte>.Shared.Return(toReturn, clearArray: false);
                }
            }

            private void Ensure(int sizeHint)
            {
                if (sizeHint < 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(sizeHint));
                }

                if (sizeHint == 0)
                {
                    sizeHint = 1;
                }

                int remaining = this.buffer.Length - this.Length;
                if (remaining >= sizeHint)
                {
                    return;
                }

                int growBy = Math.Max(sizeHint, Math.Max(this.buffer.Length / 2, MinGrow));
                int newSize = checked(this.buffer.Length + growBy);
                byte[] newBuffer = ArrayPool<byte>.Shared.Rent(newSize);
                Buffer.BlockCopy(this.buffer, 0, newBuffer, 0, this.Length);
                ArrayPool<byte>.Shared.Return(this.buffer, clearArray: false);
                this.buffer = newBuffer;
            }
        }

#if SDKPROJECTREF
        public override DateTime? GetStartTimeUtc()
        {
            return this.coreDiagnostics.GetStartTimeUtc();
        }

        public override int GetFailedRequestCount()
        {
            return this.coreDiagnostics.GetFailedRequestCount();
        }
#endif

    }
}