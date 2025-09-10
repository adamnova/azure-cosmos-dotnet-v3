// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// ------------------------------------------------------------

namespace Microsoft.Azure.Cosmos.Encryption
{
    using System;
    using System.Diagnostics;
    using System.Text.Json;

    internal sealed class EncryptionDiagnosticsContext
    {
        private DateTime startTime;
    private ValueStopwatch valueStopwatch;
        private bool isDecryptionOperation;

        public EncryptionDiagnosticsContext()
        {
            this.TotalProcessingDuration = TimeSpan.Zero;
        }

        // Internal light-weight representation of a diagnostics operation entry
        internal sealed class OperationDiagnostics
        {
            public DateTime StartTimeUtc { get; init; }
            public TimeSpan Duration { get; init; }
            public int? PropertiesCount { get; init; }
        }

        // time taken for encryption + decryption
        public TimeSpan TotalProcessingDuration { get; private set; }

        internal OperationDiagnostics EncryptOperation { get; private set; }

        internal OperationDiagnostics DecryptOperation { get; private set; }

        public void Begin(string operation)
        {
            this.valueStopwatch = ValueStopwatch.StartNew();
            this.startTime = DateTime.UtcNow;

            switch (operation)
            {
                case Constants.DiagnosticsEncryptOperation:
                    this.isDecryptionOperation = false;
                    break;

                case Constants.DiagnosticsDecryptOperation:
                    this.isDecryptionOperation = true;
                    break;

                default:
                    throw new NotSupportedException($"Operation: {operation} is not supported. " +
                        $"Should be either {Constants.DiagnosticsEncryptOperation} or {Constants.DiagnosticsDecryptOperation}.");
            }
        }

        public void End(int? propertiesCount = null)
        {
            TimeSpan elapsed = this.valueStopwatch.GetElapsedTime();
            this.TotalProcessingDuration += elapsed;

            OperationDiagnostics op = new OperationDiagnostics
            {
                StartTimeUtc = this.startTime,
                Duration = elapsed,
                PropertiesCount = propertiesCount
            };

            if (this.isDecryptionOperation)
            {
                this.DecryptOperation = op;
            }
            else
            {
                this.EncryptOperation = op;
            }
        }

        public void AddEncryptionDiagnosticsToResponseMessage(
            ResponseMessage responseMessage)
        {
            EncryptionCosmosDiagnostics encryptionDiagnostics = new EncryptionCosmosDiagnostics(
                responseMessage.Diagnostics,
                this.EncryptOperation,
                this.DecryptOperation,
                this.TotalProcessingDuration);

            responseMessage.Diagnostics = encryptionDiagnostics;
        }
    }

    // Lightweight value-type stopwatch to avoid allocating System.Diagnostics.Stopwatch.
    internal struct ValueStopwatch
    {
        private readonly long startTimestamp;

        private ValueStopwatch(long startTimestamp)
        {
            this.startTimestamp = startTimestamp;
        }

        public static ValueStopwatch StartNew() => new ValueStopwatch(Stopwatch.GetTimestamp());

        public bool IsStarted => this.startTimestamp != 0;

        public TimeSpan GetElapsedTime()
        {
            if (!this.IsStarted)
            {
                return TimeSpan.Zero;
            }

            long end = Stopwatch.GetTimestamp();
            long delta = end - this.startTimestamp;
            double seconds = (double)delta / Stopwatch.Frequency;
            return TimeSpan.FromSeconds(seconds);
        }
    }
}
