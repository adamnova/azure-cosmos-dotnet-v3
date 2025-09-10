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

        public TimeSpan TotalProcessingDuration { get; private set; }

        internal OperationDiagnostics EncryptOperation { get; private set; }

        internal OperationDiagnostics DecryptOperation { get; private set; }

        public void Begin(string operation)
        {
            this.valueStopwatch = ValueStopwatch.StartNew();
            this.startTime = DateTime.UtcNow;

            this.isDecryptionOperation = operation switch
            {
                Constants.DiagnosticsEncryptOperation => false,
                Constants.DiagnosticsDecryptOperation => true,
                _ => throw new NotSupportedException($"Operation: {operation} is not supported. " +
                                        $"Should be either {Constants.DiagnosticsEncryptOperation} or {Constants.DiagnosticsDecryptOperation}."),
            };
        }

        public void End(int? propertiesCount = null)
        {
            TimeSpan elapsed = this.valueStopwatch.GetElapsedTime();
            this.TotalProcessingDuration += elapsed;

            OperationDiagnostics op = new OperationDiagnostics
            {
                HasValue = true,
                StartTimeUtc = this.startTime,
                Duration = elapsed,
            };
            if (propertiesCount.HasValue)
            {
                op.PropertiesCount = propertiesCount.Value;
                op.HasPropertiesCount = true;
            }

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

        internal struct OperationDiagnostics
        {
            public bool HasValue;
            public bool HasPropertiesCount;
            public DateTime StartTimeUtc;
            public TimeSpan Duration;
            public int PropertiesCount;
        }
    }
}
