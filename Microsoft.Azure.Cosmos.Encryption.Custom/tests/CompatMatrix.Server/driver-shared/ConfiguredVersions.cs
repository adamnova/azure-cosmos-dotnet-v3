// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// ------------------------------------------------------------
namespace CompatMatrix.Server.Harness;

using System.Reflection;

internal static class ConfiguredVersions
{
    public static string Old { get; } = ReadRequired(
        typeof(ConfiguredVersions).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>(),
        "CompatMatrixOldVersion");

    public static string New { get; } = ReadRequired(
        typeof(ConfiguredVersions).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>(),
        "CompatMatrixNewVersion");

    internal static string ReadRequired(IEnumerable<AssemblyMetadataAttribute> metadata, string key)
    {
        AssemblyMetadataAttribute[] matches = metadata
            .Where(attribute => string.Equals(attribute.Key, key, StringComparison.Ordinal))
            .ToArray();
        if (matches.Length != 1)
        {
            throw new InvalidOperationException(
                $"Configured assembly metadata '{key}' must appear exactly once; found {matches.Length} entries.");
        }

        string? value = matches[0].Value;
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException(
                $"Configured assembly metadata '{key}' must contain a non-empty package version.");
        }

        return value;
    }
}
