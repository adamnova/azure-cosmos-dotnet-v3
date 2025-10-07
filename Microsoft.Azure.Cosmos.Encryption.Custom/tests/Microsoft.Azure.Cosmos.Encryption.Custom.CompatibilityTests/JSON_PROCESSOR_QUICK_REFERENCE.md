# Quick Reference: Using JSON Processor Compatibility Testing

## For Test Developers

### Adding a New Test with JSON Processor Support

```csharp
[Theory]
[MemberData(nameof(GetJsonProcessorTestCombinations))]
public void MyNewTest(
    string encryptVersion,
    string decryptVersion,
    JsonProcessorMode encryptMode,
    JsonProcessorMode decryptMode)
{
    // 1. Check feature availability (REQUIRED)
    if (!this.CheckModeAvailability(encryptVersion, encryptMode, out string encryptSkipReason))
    {
        this.LogInfo($"  ⊘ Skipping: {encryptSkipReason}");
        return;
    }
    
    if (!this.CheckModeAvailability(decryptVersion, decryptMode, out string decryptSkipReason))
    {
        this.LogInfo($"  ⊘ Skipping: {decryptSkipReason}");
        return;
    }
    
    // 2. Run your test
    // ... test logic ...
}
```

### Checking Feature Availability Manually

```csharp
using (VersionLoader loader = VersionLoader.Load(version))
{
    // Check if ConfigureJsonProcessor API exists
    bool hasApi = FeatureAvailability.SupportsSystemTextJsonSwitch(loader);
    
    // Check if JsonProcessor.Stream enum value exists
    bool hasStreamValue = FeatureAvailability.HasStreamJsonProcessorValue(loader);
    
    // Check if version supports deterministic encryption
    bool hasDeterministic = FeatureAvailability.SupportsDeterministicEncryption(loader);
    
    // Get summary of all features
    string summary = FeatureAvailability.GetFeatureSummary(loader);
    this.LogInfo(summary);
}
```

### Configuring RequestOptions with JSON Processor

```csharp
using (VersionLoader loader = VersionLoader.Load(version))
{
    // Create RequestOptions from the loaded version
    object requestOptions = RequestOptionsHelper.CreateRequestOptions(loader);
    
    // Try to configure System.Text.Json mode
    bool configured = RequestOptionsHelper.TryConfigureJsonProcessor(
        loader, 
        requestOptions, 
        useSystemTextJsonStreamProcessor: true);
    
    if (configured)
    {
        // Feature was configured successfully
        this.LogInfo("System.Text.Json mode enabled");
    }
    else
    {
        // Feature not available - gracefully handle
        this.LogInfo("System.Text.Json mode not available in this version");
    }
}
```

## For CI/CD Pipeline Developers

### Running All Compatibility Tests

```powershell
# Run all compatibility tests
dotnet test Microsoft.Azure.Cosmos.Encryption.Custom.CompatibilityTests

# Run only JSON processor tests
dotnet test --filter "Feature=JsonProcessor"

# Run with verbose logging
dotnet test --logger "console;verbosity=detailed"
```

### Understanding Test Results

**Test Output Indicators:**
- `✓` - Test passed
- `⊘` - Test skipped (feature not available)
- `✗` - Test failed

**Common Skip Reasons:**
```
⊘ Skipping: 1.0.0 does not have EncryptionRequestOptionsExperimental.ConfigureJsonProcessor API
⊘ Skipping: current does not have JsonProcessor.Stream enum value (requires PREVIEW build + .NET 8.0+)
⊘ Skipping: 1.0.0 does not support deterministic encryption
```

### Expected Test Matrix

| Scenario | Expected Result |
|----------|----------------|
| Old → Old | Only Newtonsoft tests run |
| Old → New (non-PREVIEW) | Only Newtonsoft tests run |
| Old → New (PREVIEW) | Newtonsoft + SystemTextJson tests run |
| New (PREVIEW) → New (PREVIEW) | All combinations run |

## For Package Publishers

### Building Packages with System.Text.Json Support

**Required Conditions:**
1. Define `ENCRYPTION_CUSTOM_PREVIEW` preprocessor directive
2. Target `.NET 8.0` or greater

**Project Configuration:**
```xml
<PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <DefineConstants>$(DefineConstants);ENCRYPTION_CUSTOM_PREVIEW</DefineConstants>
</PropertyGroup>
```

**Verify Feature Availability:**
```powershell
# Build PREVIEW package
dotnet pack -c Release /p:DefineConstants="ENCRYPTION_CUSTOM_PREVIEW"

# Verify enum value exists
dotnet run --project YourTestProject -- check-feature
```

## Troubleshooting

### "All JSON processor tests are being skipped"

**Possible Causes:**
1. Testing against non-PREVIEW build
2. Testing against .NET Standard 2.0 target
3. Testing against old version (pre-PR #5403)

**Solution:** Ensure you're testing with a PREVIEW build targeting .NET 8.0+

### "Tests are failing with NotSupportedException"

**Likely Cause:** Test is not properly checking feature availability before running

**Solution:** Add feature availability check:
```csharp
if (!this.CheckModeAvailability(version, mode, out string skipReason))
{
    this.LogInfo($"  ⊘ Skipping: {skipReason}");
    return;
}
```

### "Want to test only Newtonsoft mode"

**Solution:** Filter out SystemTextJson tests:
```csharp
if (encryptMode == JsonProcessorMode.SystemTextJson || 
    decryptMode == JsonProcessorMode.SystemTextJson)
{
    return; // Skip SystemTextJson tests
}
```

## Best Practices

### DO ✓

- Always check feature availability before running tests
- Log clear skip reasons
- Use `CheckModeAvailability()` helper method
- Test all version combinations in CI/CD
- Document why tests are skipped

### DON'T ✗

- Assume features are available in all versions
- Fail tests when features are unavailable
- Hard-code version numbers in feature checks
- Skip error logging
- Test only same-version scenarios

## Quick Decision Tree

```
Need to test JSON processor compatibility?
│
├─ Testing across versions? → Use JsonProcessorCompatibilityTests
│
├─ Testing single version? → Check feature availability first
│
├─ Adding new test? → Follow pattern in JsonProcessorCompatibilityTests.cs
│
└─ Debugging skipped tests? → Check FeatureAvailability.GetFeatureSummary()
```

## Additional Resources

- **JSON_PROCESSOR_TESTING.md** - Detailed testing approach
- **JSON_PROCESSOR_IMPLEMENTATION_SUMMARY.md** - Implementation details
- **FeatureAvailability.cs** - Source code with inline docs
- **RequestOptionsHelper.cs** - Helper methods with examples
