//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

namespace Microsoft.Azure.Cosmos.Encryption.Custom
{
    /// <summary>
    /// Wrapper to carry a JsonProcessor selection for Patch item operations (PatchItemRequestOptions is sealed).
    /// </summary>
    internal sealed class EncryptionPatchJsonProcessorOptions
    {
#if ENCRYPTION_CUSTOM_PREVIEW && NET8_0_OR_GREATER
        public JsonProcessor JsonProcessor { get; set; } = JsonProcessor.Newtonsoft;
#endif
    }
}
