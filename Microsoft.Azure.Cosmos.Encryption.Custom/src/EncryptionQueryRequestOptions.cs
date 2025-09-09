//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

namespace Microsoft.Azure.Cosmos.Encryption.Custom
{
    using System;

    /// <summary>
    /// Query request options for encryption extension allowing per-request Json processor selection.
    /// </summary>
    internal class EncryptionQueryRequestOptions : QueryRequestOptions
    {
    /// <summary>
    /// Gets or sets API used for Json processing for this query.
    /// </summary>
    /// <remarks>
    /// The streaming Json processor option is only available when built with preview symbols on .NET 8 or greater.
    /// For other target frameworks only the Newtonsoft option is available.
    /// </remarks>
    public JsonProcessor JsonProcessor { get; set; } = JsonProcessor.Newtonsoft;
    }
}
