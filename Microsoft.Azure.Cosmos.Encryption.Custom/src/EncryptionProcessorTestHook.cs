//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------
#if ENCRYPTION_CUSTOM_PREVIEW && NET8_0_OR_GREATER
namespace Microsoft.Azure.Cosmos.Encryption.Custom
{
    /// <summary>
    /// Test-only hook to count which feed decryption path was used.
    /// Wrapped in preview conditional symbols and excluded from shipping scenarios.
    /// </summary>
#pragma warning disable SA1516 // Elements should be separated by blank line
    internal static class EncryptionProcessorTestHook
    {
        private static int legacyFeedDecryptCalls;
        private static int streamingFeedDecryptCalls;

        internal static ref int LegacyFeedDecryptCallsRef => ref legacyFeedDecryptCalls;
        internal static ref int StreamingFeedDecryptCallsRef => ref streamingFeedDecryptCalls;

        internal static int LegacyFeedDecryptCalls => legacyFeedDecryptCalls;
        internal static int StreamingFeedDecryptCalls => streamingFeedDecryptCalls;

        internal static void Reset()
        {
            legacyFeedDecryptCalls = 0;
            streamingFeedDecryptCalls = 0;
        }
    }
#pragma warning restore SA1516 // Elements should be separated by blank line
}
#endif
