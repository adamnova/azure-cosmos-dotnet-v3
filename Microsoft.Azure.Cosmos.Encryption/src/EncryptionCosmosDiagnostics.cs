// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// ------------------------------------------------------------

namespace Microsoft.Azure.Cosmos.Encryption
{
    using System;
    using System.Collections.Generic;
    using System.Text;
    using System.Text.Encodings.Web;

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
            string core = this.coreDiagnostics.ToString() ?? string.Empty;
            bool coreIsJson = LooksLikeJson(core);

            int capacity = core.Length + 320;
            if (this.encryptOperation.HasValue)
            {
                capacity += 100;
            }

            if (this.decryptOperation.HasValue)
            {
                capacity += 100;
            }

            StringBuilder sb = new StringBuilder(capacity);
            sb.Append('{');
            AppendPropertyName(sb, Constants.DiagnosticsCoreDiagnostics);
            if (coreIsJson)
            {
                sb.Append(core);
            }
            else
            {
                AppendEscapedString(sb, core);
            }

            sb.Append(',');
            AppendPropertyName(sb, Constants.DiagnosticsEncryptionDiagnostics);
            sb.Append('{');

            bool needComma = false;
            if (this.encryptOperation.HasValue)
            {
                AppendOperation(
                    sb,
                    Constants.DiagnosticsEncryptOperation,
                    this.encryptOperation.StartTimeUtc,
                    this.encryptOperation.Duration,
                    this.encryptOperation.HasPropertiesCount,
                    this.encryptOperation.PropertiesCount,
                    Constants.DiagnosticsPropertiesEncryptedCount);
                needComma = true;
            }

            if (this.decryptOperation.HasValue)
            {
                if (needComma)
                {
                    sb.Append(',');
                }

                AppendOperation(
                    sb,
                    Constants.DiagnosticsDecryptOperation,
                    this.decryptOperation.StartTimeUtc,
                    this.decryptOperation.Duration,
                    this.decryptOperation.HasPropertiesCount,
                    this.decryptOperation.PropertiesCount,
                    Constants.DiagnosticsPropertiesDecryptedCount);
            }

            sb.Append('}'); // EncryptionDiagnostics
            sb.Append('}'); // root
            return sb.ToString();
        }

        private static void AppendOperation(
            StringBuilder sb,
            string opName,
            DateTime start,
            TimeSpan duration,
            bool hasCount,
            int count,
            string countPropertyName)
        {
            AppendPropertyName(sb, opName);
            sb.Append('{');
            AppendPropertyName(sb, Constants.DiagnosticsStartTime);
            AppendEscapedString(sb, start.ToString("O"));
            sb.Append(',');
            AppendPropertyName(sb, Constants.DiagnosticsDuration);
            AppendEscapedString(sb, duration.ToString());
            if (hasCount)
            {
                sb.Append(',');
                AppendPropertyName(sb, countPropertyName);
                sb.Append(count.ToString(System.Globalization.CultureInfo.InvariantCulture));
            }

            sb.Append('}');
        }

        private static void AppendPropertyName(StringBuilder sb, string name)
        {
            sb.Append('"').Append(name).Append('"').Append(':');
        }

        private static void AppendEscapedString(StringBuilder sb, string value)
        {
            string encoded = JavaScriptEncoder.Default.Encode(value);
            sb.Append('"').Append(encoded).Append('"');
        }

        private static bool LooksLikeJson(string s)
        {
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (char.IsWhiteSpace(c))
                {
                    continue;
                }

                return c == '{' || c == '[';
            }

            return false; // empty treated as string
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