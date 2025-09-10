//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------
#if ENCRYPTION_CUSTOM_PREVIEW && NET8_0_OR_GREATER
namespace Microsoft.Azure.Cosmos.Encryption.Custom
{
    using System;
    using System.Collections.Generic;
    using Microsoft.Azure.Cosmos;

    /// <summary>
    /// Diagnostics decorator adding which encryption feed decrypt path was used (Stream vs Legacy).
    /// Internal and preview-only.
    /// </summary>
    internal sealed class EncryptionFeedDiagnostics : CosmosDiagnostics
    {
        private readonly CosmosDiagnostics inner;
        private readonly string decryptPath;

        public EncryptionFeedDiagnostics(CosmosDiagnostics inner, string decryptPath)
        {
            this.inner = inner;
            this.decryptPath = decryptPath;
        }

        public override string ToString()
        {
            string baseString = this.inner?.ToString() ?? string.Empty;
            if (string.IsNullOrEmpty(baseString))
            {
                // Return minimal JSON object
                return "{\"encryptionFeedDecryptPath\":\"" + this.decryptPath + "\"}";
            }

            // If diagnostics look like JSON object, append a property.
            string trimmed = baseString.TrimEnd('\r', '\n');
            if (trimmed.EndsWith("}"))
            {
                return trimmed[..^1] + ",\"encryptionFeedDecryptPath\":\"" + this.decryptPath + "\"}";
            }

            return baseString + " | encryptionFeedDecryptPath=" + this.decryptPath;
        }

        public override IReadOnlyList<(string regionName, Uri uri)> GetContactedRegions()
        {
            return this.inner?.GetContactedRegions();
        }

        public override TimeSpan GetClientElapsedTime()
        {
            return this.inner?.GetClientElapsedTime() ?? TimeSpan.Zero;
        }

        public override DateTime? GetStartTimeUtc()
        {
            return this.inner?.GetStartTimeUtc();
        }

        public override int GetFailedRequestCount()
        {
            return this.inner?.GetFailedRequestCount() ?? 0;
        }

        public override ServerSideCumulativeMetrics GetQueryMetrics()
        {
            return this.inner?.GetQueryMetrics();
        }
    }
}
#endif
