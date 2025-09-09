//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

namespace Microsoft.Azure.Cosmos.Encryption.Custom
{
    using System.Collections.Generic;
    using System.Linq;

    /// <summary>
    /// Wrapper to carry a JsonProcessor selection for change feed APIs (since ChangeFeedRequestOptions is sealed).
    /// </summary>
    internal sealed class EncryptionChangeFeedJsonProcessorOptions
    {
        internal const string JsonProcessorPropertyKey = "EncryptionCustom_JsonProcessor";

        public JsonProcessor JsonProcessor { get; set; } = JsonProcessor.Newtonsoft;

        public void Apply(ChangeFeedRequestOptions options)
        {
            if (options == null)
            {
                return;
            }

            Dictionary<string, object> dict = options.Properties != null
                ? new Dictionary<string, object>(options.Properties.ToDictionary(kvp => kvp.Key, kvp => kvp.Value))
                : new Dictionary<string, object>();
            dict[JsonProcessorPropertyKey] = this.JsonProcessor;
            options.Properties = dict;
        }

        internal static bool TryGet(ChangeFeedRequestOptions options, out JsonProcessor jsonProcessor)
        {
            jsonProcessor = JsonProcessor.Newtonsoft;
            if (options?.Properties != null
                && options.Properties.TryGetValue(JsonProcessorPropertyKey, out object value)
                && value is JsonProcessor jp)
            {
                jsonProcessor = jp;
                return true;
            }

            return false;
        }
    }
}
