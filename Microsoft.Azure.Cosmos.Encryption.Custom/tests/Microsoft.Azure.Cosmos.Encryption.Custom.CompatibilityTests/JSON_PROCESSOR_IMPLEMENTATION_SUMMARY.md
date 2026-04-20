# Summary: JSON Processor Compatibility Testing Implementation

## What Was Implemented

I've added comprehensive compatibility testing support for the System.Text.Json feature introduced in PR #5403, with proper handling for versions before and after the PR.

## Files Modified

### 1. `FeatureAvailability.cs`
**Added Methods:**
- `SupportsSystemTextJsonSwitch()` - Checks for `EncryptionRequestOptionsExperimental.ConfigureJsonProcessor` API
- `HasJsonProcessorEnum()` - Checks if `JsonProcessor` enum exists
- `HasStreamJsonProcessorValue()` - Checks if `JsonProcessor.Stream` enum value exists (PREVIEW + .NET 8.0+ only)

**Updated:**
- `GetFeatureSummary()` - Now includes `StreamJsonProcessorValue` in feature summary

### 2. `RequestOptionsHelper.cs`
**Added Method:**
- `TryConfigureJsonProcessor()` - Configures JSON processor mode using reflection
  - Validates feature availability before attempting configuration
  - Uses `JsonProcessor.Stream` or `JsonProcessor.Newtonsoft` enum values
  - Returns `false` for graceful skipping if feature unavailable

**Backward Compatibility:**
- Added `[Obsolete]` `TrySetSystemTextJsonMode()` wrapper for existing code

### 3. `JsonProcessorCompatibilityTests.cs` (NEW FILE)
**Purpose:** Comprehensive test coverage for JSON processor compatibility

**Test Methods:**
- `CanEncryptAndDecrypt_AcrossJsonProcessorModes()` - Tests all version/mode combinations
- `CanEncryptAndDecryptDeterministic_AcrossJsonProcessorModes()` - Tests deterministic encryption compatibility

**Key Features:**
- Tests 4 mode combinations: Newtonsoft→Newtonsoft, Newtonsoft→SystemTextJson, SystemTextJson→Newtonsoft, SystemTextJson→SystemTextJson
- Skips combinations where either version doesn't support the required mode
- Validates cross-version compatibility (old ↔ new)
- Provides clear skip reasons in logs

## How It Works

### Feature Detection Pattern

```csharp
// 1. Check if mode is available in version
bool isAvailable = this.CheckModeAvailability(version, mode, out string skipReason);

// 2. If not available, skip gracefully (not a failure)
if (!isAvailable)
{
    this.LogInfo($"  ⊘ Skipping: {skipReason}");
    return;
}

// 3. Run test only if feature is available
// ... test code ...
```

### Standardized Skip Reasons

Tests provide clear explanations when skipping:
- `"1.0.0 does not have EncryptionRequestOptionsExperimental.ConfigureJsonProcessor API"`
- `"current does not have JsonProcessor.Stream enum value (requires PREVIEW build + .NET 8.0+)"`
- `"1.0.0 does not support deterministic encryption"`

### Test Execution Matrix

| Scenario | Newtonsoft Tests | SystemTextJson Tests |
|----------|------------------|----------------------|
| Old version (pre-PR #5403) | ✓ Run | ⊘ Skipped (API unavailable) |
| New version (.NET Standard) | ✓ Run | ⊘ Skipped (enum value unavailable) |
| New version (PREVIEW + .NET 8.0+) | ✓ Run | ✓ Run |
| Cross-version (old ↔ new PREVIEW) | ✓ Run | ✓ Run (validates compatibility!) |

## Test Coverage

### For Each Version Pair (encryptVer, decryptVer)

Tests run with these mode combinations:
1. Encrypt[Newtonsoft] → Decrypt[SystemTextJson]
2. Encrypt[SystemTextJson] → Decrypt[Newtonsoft]  
3. Encrypt[SystemTextJson] → Decrypt[SystemTextJson]

(Newtonsoft→Newtonsoft is skipped as it's covered by base compatibility tests)

### Example: Testing `1.0.0` ↔ `current` (PREVIEW, .NET 8.0+)

```
✓ Encrypt[1.0.0, Newtonsoft] → Decrypt[current, Newtonsoft]
✓ Encrypt[1.0.0, Newtonsoft] → Decrypt[current, SystemTextJson] ← Validates backward compatibility!
✓ Encrypt[current, SystemTextJson] → Decrypt[1.0.0, Newtonsoft] ← Validates forward compatibility!
⊘ Encrypt[1.0.0, SystemTextJson] → ... (Skipped: 1.0.0 doesn't have API)
```

## Benefits

### 1. **Automatic Version Support**
- No manual test updates needed when testing new versions
- Tests automatically detect and skip unsupported features

### 2. **No False Failures**
- Skipped tests don't fail CI/CD pipelines
- Clear logging explains why tests were skipped

### 3. **Comprehensive Coverage**
- When both versions support the feature, all combinations are tested
- Validates that Newtonsoft and System.Text.Json are interoperable

### 4. **Future-Proof Pattern**
- Same pattern can be used for future experimental features
- Standardized approach across all compatibility tests

### 5. **Validates Key Compatibility Scenarios**
- Old SDK encrypting → New SDK decrypting (with System.Text.Json)
- New SDK encrypting → Old SDK decrypting
- Ensures wire format is compatible regardless of JSON processor

## Running the Tests

### Locally
```powershell
# Run all compatibility tests
dotnet test Microsoft.Azure.Cosmos.Encryption.Custom.CompatibilityTests

# Run only JSON processor tests
dotnet test --filter "Category=Compatibility&Feature=JsonProcessor"
```

### In CI/CD Pipeline
The existing compatibility test pipeline automatically:
- Runs tests against all version combinations in `VersionMatrix`
- Skips unsupported feature combinations gracefully
- Reports clear results for each scenario

## Documentation

- **JSON_PROCESSOR_TESTING.md** - Detailed explanation of the testing approach
- **Code comments** - Inline documentation in all methods
- **Test output** - Clear logging with ✓/⊘/✗ indicators

## Next Steps

To enable these tests in your pipeline:

1. **Ensure PREVIEW builds are available** in your package feed (for .NET 8.0+ testing)
2. **Update VersionMatrix.cs** to include versions with/without the feature
3. **Run tests** - they'll automatically detect and test appropriately

The tests are ready to use and will work correctly whether the System.Text.Json feature is available or not!
