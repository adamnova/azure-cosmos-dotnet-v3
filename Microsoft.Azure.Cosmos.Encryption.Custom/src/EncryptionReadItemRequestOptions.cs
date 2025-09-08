//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

namespace Microsoft.Azure.Cosmos.Encryption.Custom
{
    using Microsoft.Azure.Cosmos;

    /// <summary>
    /// Request options for item read operations that allows selecting JSON processing implementation for decryption.
    /// </summary>
    /// <remarks>
    /// Streaming processor option is available only under ENCRYPTION_CUSTOM_PREVIEW and .NET 8 or greater.
    /// </remarks>
    public sealed class EncryptionReadItemRequestOptions : ItemRequestOptions
    {
#if ENCRYPTION_CUSTOM_PREVIEW && NET8_0_OR_GREATER
        /// <summary>
        /// Gets or sets the JSON processor to use for decryption of the read item.
        /// </summary>
        public JsonProcessor JsonProcessor { get; set; } = JsonProcessor.Newtonsoft;
#endif
    }
}
