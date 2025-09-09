//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

namespace Microsoft.Azure.Cosmos.Encryption.Custom
{
    /// <summary>
    /// ReadMany request options for encryption extension allowing per-request Json processor selection.
    /// </summary>
    internal class EncryptionReadManyRequestOptions : ReadManyRequestOptions
    {
#if ENCRYPTION_CUSTOM_PREVIEW && NET8_0_OR_GREATER
        public JsonProcessor JsonProcessor { get; set; } = JsonProcessor.Newtonsoft;
#endif
    }
}
