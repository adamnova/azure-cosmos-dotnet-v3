# System.Text.Json Compatibility Testing

## Overview

This document describes how the compatibility test suite handles the experimental System.Text.Json streaming processor feature introduced in PR #5403.

## Feature Detection

The test suite automatically detects whether a version supports the System.Text.Json experimental switch using the `FeatureAvailability` helper class:

```csharp
bool supportsSwitch = FeatureAvailability.SupportsSystemTextJsonSwitch(loader);
```

This detection works by checking for the presence of:
- `EncryptionRequestOptionsExperimental` class
- `SetExperimentalJsonProcessorMode` extension method

## Test Organization

### CrossVersionSystemTextJsonTests

A new test class `CrossVersionSystemTextJsonTests` validates compatibility across:
- Different versions (e.g., 1.0.0-preview07 ↔ current)
- Different JSON processor modes (Newtonsoft ↔ System.Text.Json)

#### Test Matrix

For each version pair, the tests validate:

1. **Newtonsoft → System.Text.Json**: Data encrypted with Newtonsoft can be decrypted with System.Text.Json
2. **System.Text.Json → Newtonsoft**: Data encrypted with System.Text.Json can be decrypted with Newtonsoft
3. **System.Text.Json → System.Text.Json**: Both sides using the new processor

#### Automatic Skipping

Tests automatically skip when:
- The version doesn't support the System.Text.Json switch
- Deterministic encryption is not available in the version

This ensures backward compatibility with older versions that don't have these features.

## How It Works

### 1. Feature Availability Check

Before running each test, the framework checks if the required features are available:

```csharp
private bool CheckFeatureAvailability(string version, JsonProcessorMode mode)
{
    if (mode == JsonProcessorMode.Newtonsoft)
    {
        return true; // Always available
    }

    using (VersionLoader loader = VersionLoader.Load(version))
    {
        if (!FeatureAvailability.SupportsSystemTextJsonSwitch(loader))
        {
            this.LogInfo($"Skipping: {version} does not support System.Text.Json switch");
            return false;
        }
    }

    return true;
}
```

### 2. Version Loader

The `VersionLoader` class loads different versions in isolated contexts, allowing side-by-side testing:

```csharp
using (VersionLoader encryptLoader = VersionLoader.Load("1.0.0-preview07"))
using (VersionLoader decryptLoader = VersionLoader.Load("current"))
{
    // Encrypt with old version, decrypt with new version
}
```

### 3. RequestOptions Helper

The `RequestOptionsHelper` class configures RequestOptions via reflection:

```csharp
bool configured = RequestOptionsHelper.TrySetSystemTextJsonMode(
    loader, 
    requestOptions, 
    useSystemTextJsonStreamProcessor: true);
```

## Adding New Features

To add compatibility testing for a new feature:

1. **Update FeatureAvailability.cs**

   Add a new feature detection method:

   ```csharp
   public static bool SupportsNewFeature(VersionLoader loader)
   {
       Type newType = loader.GetType("Microsoft.Azure.Cosmos.Encryption.Custom.NewFeatureClass");
       return newType != null;
   }
   ```

2. **Update GetFeatureSummary**

   Include the new feature in the summary:

   ```csharp
   var features = new[]
   {
       ("SystemTextJsonSwitch", SupportsSystemTextJsonSwitch(loader)),
       ("NewFeature", SupportsNewFeature(loader)),
   };
   ```

3. **Create Tests**

   Use the feature detection in your tests:

   ```csharp
   if (!FeatureAvailability.SupportsNewFeature(loader))
   {
       this.LogInfo($"Skipping: feature not available in {version}");
       return;
   }
   ```

## Running Tests

### Run all compatibility tests
```bash
dotnet test --filter "Category=Compatibility"
```

### Run only System.Text.Json tests
```bash
dotnet test --filter "Feature=SystemTextJson"
```

### Run with specific version
Edit `testconfig.json` to specify which versions to test:

```json
{
  "VersionMatrix": {
    "Baseline": "1.0.0-preview07",
    "Versions": [
      "1.0.0-preview07",
      "current"
    ]
  }
}
```

## Expected Behavior

### When Feature is Available

✅ **Version 1.0.0-preview08+ (with PR #5403)**
- All JSON processor mode combinations are tested
- Tests validate cross-mode compatibility
- Both Newtonsoft and System.Text.Json paths are exercised

### When Feature is Unavailable

⊘ **Version 1.0.0-preview07 and earlier**
- System.Text.Json mode tests are automatically skipped
- Only Newtonsoft mode is tested (via CrossVersionEncryptionTests)
- Log message: "Skipping: version does not support System.Text.Json switch"

## Test Output Example

```
🔍 Version Validation:
   Testing 2 version(s):
   • 1.0.0-preview07 → 1.0.0-preview07+abc123
   • current → 1.0.0-preview08+def456

   Feature Availability:
   • 1.0.0-preview07: Available: DeterministicEncryption; Unavailable: SystemTextJsonSwitch
   • current: All features available: SystemTextJsonSwitch, DeterministicEncryption
✅ All versions are distinct - compatibility testing is valid

Testing: Encrypt with 1.0.0-preview07[Newtonsoft] → Decrypt with current[SystemTextJson]
  ✓ Encrypted with 1.0.0-preview07[Newtonsoft]: 256 bytes
  ✓ Decrypted with current[SystemTextJson]: 256 bytes
✓ SUCCESS: 1.0.0-preview07[Newtonsoft] → current[SystemTextJson] compatibility verified

Testing: Encrypt with current[SystemTextJson] → Decrypt with 1.0.0-preview07[Newtonsoft]
  ⊘ Skipping: 1.0.0-preview07 does not support System.Text.Json switch (feature not available)
```

## Important Notes

### Low-Level vs High-Level Testing

The current `CrossVersionSystemTextJsonTests` focuses on **binary-level encryption compatibility**:
- Tests use `DataEncryptionKey.EncryptData/DecryptData` directly
- The JSON processor mode doesn't affect byte-level encryption format
- This validates that the encrypted binary format remains compatible

For **high-level JSON document testing** (where the JSON processor choice matters):
- Future tests should use `EncryptionContainer` operations
- Test with actual JSON documents being encrypted/decrypted
- Validate that JSON serialization/deserialization works across modes

### Thread Safety

The `VersionLoader` uses isolated `AssemblyLoadContext` instances to prevent conflicts when loading multiple versions simultaneously.

## Troubleshooting

### "Package version X not found"
- Ensure NuGet packages are restored: `dotnet restore`
- Check that the version exists in your global NuGet cache or local packages folder

### "Feature not available" for current version
- Ensure you've built the current version: `dotnet build`
- The package is automatically built on first test run
- Check that PR #5403 changes are present in your workspace

### Tests are skipped unexpectedly
- Check the test output for feature availability information
- Verify the version being tested includes the expected features
- Use `--verbosity detailed` to see more diagnostic information
