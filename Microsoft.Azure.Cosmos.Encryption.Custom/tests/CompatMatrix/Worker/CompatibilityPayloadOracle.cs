//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

namespace EncryptionCustomCompatibility
{
    using System;
    using System.Globalization;
    using System.Text.Json;

    internal static class CompatibilityPayloadOracle
    {
        public static void Validate(
            JsonElement actual,
            JsonElement expected,
            bool requireLexicalNumbers,
            string path = "$")
        {
            if (actual.ValueKind != expected.ValueKind)
            {
                throw new InvalidOperationException(
                    $"Compatibility payload token {path} changed JSON type. Actual={actual.ValueKind} Expected={expected.ValueKind}");
            }

            switch (expected.ValueKind)
            {
                case JsonValueKind.Object:
                    foreach (JsonProperty expectedProperty in expected.EnumerateObject())
                    {
                        if (!actual.TryGetProperty(expectedProperty.Name, out JsonElement actualProperty))
                        {
                            throw new InvalidOperationException(
                                $"Compatibility payload omitted expected token {path}.{expectedProperty.Name}.");
                        }

                        Validate(
                            actualProperty,
                            expectedProperty.Value,
                            requireLexicalNumbers,
                            path + "." + expectedProperty.Name);
                    }

                    break;
                case JsonValueKind.Array:
                    JsonElement.ArrayEnumerator actualItems = actual.EnumerateArray();
                    JsonElement.ArrayEnumerator expectedItems = expected.EnumerateArray();
                    int index = 0;
                    while (expectedItems.MoveNext())
                    {
                        if (!actualItems.MoveNext())
                        {
                            throw new InvalidOperationException(
                                $"Compatibility payload array {path} omitted element {index}.");
                        }

                        Validate(
                            actualItems.Current,
                            expectedItems.Current,
                            requireLexicalNumbers,
                            $"{path}[{index}]");
                        index++;
                    }

                    if (actualItems.MoveNext())
                    {
                        throw new InvalidOperationException(
                            $"Compatibility payload array {path} contained unexpected elements.");
                    }

                    break;
                case JsonValueKind.String:
                    if (!string.Equals(actual.GetString(), expected.GetString(), StringComparison.Ordinal))
                    {
                        throw new InvalidOperationException(
                            $"Compatibility payload string {path} changed. Actual={actual.GetString()} Expected={expected.GetString()}");
                    }

                    break;
                case JsonValueKind.Number:
                    if (requireLexicalNumbers)
                    {
                        if (!string.Equals(actual.GetRawText(), expected.GetRawText(), StringComparison.Ordinal))
                        {
                            throw new InvalidOperationException(
                                $"Compatibility Stream token {path} changed numeric lexical form. Actual={actual.GetRawText()} Expected={expected.GetRawText()}");
                        }
                    }
                    else if (!decimal.TryParse(
                            actual.GetRawText(),
                            NumberStyles.Float,
                            CultureInfo.InvariantCulture,
                            out decimal actualNumber) ||
                        !decimal.TryParse(
                            expected.GetRawText(),
                            NumberStyles.Float,
                            CultureInfo.InvariantCulture,
                            out decimal expectedNumber) ||
                        actualNumber != expectedNumber)
                    {
                        throw new InvalidOperationException(
                            $"Compatibility Newtonsoft token {path} changed numeric value. Actual={actual.GetRawText()} Expected={expected.GetRawText()}");
                    }

                    break;
                case JsonValueKind.True:
                case JsonValueKind.False:
                    if (actual.GetBoolean() != expected.GetBoolean())
                    {
                        throw new InvalidOperationException(
                            $"Compatibility payload boolean {path} changed.");
                    }

                    break;
                case JsonValueKind.Null:
                    break;
                default:
                    throw new InvalidOperationException(
                        $"Unsupported compatibility payload token kind at {path}: {expected.ValueKind}");
            }
        }
    }
}
