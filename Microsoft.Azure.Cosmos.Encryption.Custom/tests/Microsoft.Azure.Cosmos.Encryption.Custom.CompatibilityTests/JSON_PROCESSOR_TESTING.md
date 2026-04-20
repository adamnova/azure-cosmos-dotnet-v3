# JSON Processor Compatibility Testing

This document describes the approach for testing System.Text.Json compatibility across different versions of the Encryption.Custom library.

## Overview

PR #5403 introduces an experimental System.Text.Json streaming API as an alternative to the default Newtonsoft.Json processor. This feature is:
- **Conditional**: Only available in PREVIEW builds targeting .NET 8.0+
- **Experimental**: Marked with `[Experimental("COSMOSENC0001")]` attribute
- **Opt-in**: Users must explicitly configure `JsonProcessor.Stream` via `EncryptionRequestOptionsExperimental.ConfigureJsonProcessor()`

## Challenge

Compatibility tests must work across versions where:
1. **Old versions** don't have the System.Text.Json feature at all
2. **New versions (non-PREVIEW or .NET Standard)** have the API but not the `JsonProcessor.Stream` enum value
3. **New versions (PREVIEW + .NET 8.0+)** have full System.Text.Json support

## Solution: Feature Detection Pattern

### 1. FeatureAvailability Class

The `FeatureAvailability` class provides standardized feature detection:

```csharp
// Checks if ConfigureJsonProcessor API exists
bool SupportsSystemTextJsonSwitch(VersionLoader loader)

// Checks if JsonProcessor enum exists
bool HasJsonProcessorEnum(VersionLoader loader)

// Checks if JsonProcessor.Stream value exists
bool HasStreamJsonProcessorValue(VersionLoader loader)
```

### 2. RequestOptionsHelper Class

The `RequestOptionsHelper` class provides version-agnostic configuration:

```csharp
bool TryConfigureJsonProcessor(
    VersionLoader loader, 
    object requestOptions, 
    bool useSystemTextJsonStreamProcessor)
```

This method:
- Returns `false` if feature is not available (graceful degradation)
- Uses reflection to invoke the API from the loaded version
- Handles both `JsonProcessor.Stream` and `JsonProcessor.Newtonsoft` enum values

### 3. Test Pattern

Tests use a standardized skip pattern:

```csharp
[Theory]
[MemberData(nameof(GetJsonProcessorTestCombinations))]
public void TestMethod(string version, JsonProcessorMode mode)
{
    // Check feature availability BEFORE running test
    bool isAvailable = this.CheckModeAvailability(version, mode, out string skipReason);
    if (!isAvailable)
    {
        this.LogInfo($"  ⊘ Skipping: {skipReason}");
        return; // Graceful skip - not a failure
    }
    
    // Run test...
}
```

### 4. Test Coverage

#### JsonProcessorCompatibilityTests

Tests all combinations of:
- **Encrypt Version** × **Decrypt Version** × **Encrypt Mode** × **Decrypt Mode**

Example combinations:
- `1.0.0[Newtonsoft]` → `current[SystemTextJson]`
- `current[SystemTextJson]` → `1.0.0[Newtonsoft]`
- `current[SystemTextJson]` → `current[Newtonsoft]`

Combinations are automatically filtered:
- Skips `Newtonsoft` → `Newtonsoft` (covered by base compatibility tests)
- Skips tests where either version doesn't support the required mode

## Test Execution Matrix

### Scenario 1: Testing with Old Version (Pre-PR #5403)

```
Old Version (1.0.0) - No System.Text.Json support
├─ Newtonsoft mode: ✓ Available
└─ SystemTextJson mode: ⊘ Skipped (API not available)

Result: Only Newtonsoft tests run
```

### Scenario 2: Testing with New Version (Non-PREVIEW or .NET Standard)

```
New Version (current, .NET Standard) - API exists but Stream value doesn't
├─ Newtonsoft mode: ✓ Available
└─ SystemTextJson mode: ⊘ Skipped (JsonProcessor.Stream not available)

Result: Only Newtonsoft tests run
```

### Scenario 3: Testing with New Version (PREVIEW + .NET 8.0+)

```
New Version (current, PREVIEW, .NET 8.0+) - Full support
├─ Newtonsoft mode: ✓ Available
└─ SystemTextJson mode: ✓ Available

Result: All combinations tested
```

### Scenario 4: Cross-Version Testing

```
Old (1.0.0) ←→ New (current, PREVIEW, .NET 8.0+)

Encrypt[Old,Newtonsoft] → Decrypt[New,Newtonsoft]: ✓ Run
Encrypt[Old,Newtonsoft] → Decrypt[New,SystemTextJson]: ✓ Run (validates compatibility)
Encrypt[New,SystemTextJson] → Decrypt[Old,Newtonsoft]: ✓ Run (validates compatibility)
Encrypt[Old,SystemTextJson] → Decrypt[New,Newtonsoft]: ⊘ Skipped (Old doesn't support)
```

## Benefits

### 1. **Backward Compatibility**
Tests gracefully skip unsupported features instead of failing

### 2. **Forward Compatibility**  
New tests work with old versions automatically

### 3. **Conditional Compilation Support**
Handles PREVIEW builds, target framework differences, etc.

### 4. **Clear Skip Reasons**
Logs explain exactly why a test was skipped:
```
⊘ Skipping: 1.0.0 does not have EncryptionRequestOptionsExperimental.ConfigureJsonProcessor API
⊘ Skipping: current does not have JsonProcessor.Stream enum value (requires PREVIEW build + .NET 8.0+)
```

### 5. **No False Failures**
Skipped tests don't count as failures in CI/CD

### 6. **Comprehensive Coverage**
When full support is available, tests all combinations automatically

## Usage in CI/CD

The compatibility test pipeline can run against multiple versions:

```yaml
- job: CompatibilityTests
  strategy:
    matrix:
      OldVsOld:
        ENCRYPT_VERSION: '1.0.0'
        DECRYPT_VERSION: '1.0.0'
      OldVsCurrent:
        ENCRYPT_VERSION: '1.0.0'
        DECRYPT_VERSION: 'current'
      CurrentVsOld:
        ENCRYPT_VERSION: 'current'
        DECRYPT_VERSION: '1.0.0'
      CurrentVsCurrent:
        ENCRYPT_VERSION: 'current'
        DECRYPT_VERSION: 'current'
```

Each matrix entry will automatically:
- Run all supported tests
- Skip unsupported tests
- Report results clearly

## Future Extensions

This pattern can easily extend to support:
- New encryption algorithms
- New serialization modes
- New compression algorithms
- Any conditional or experimental feature

Simply add a new `FeatureAvailability.SupportsXYZ()` method and update the test skip logic.
