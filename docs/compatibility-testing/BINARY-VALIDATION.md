# Binary Validation for Compatibility Testing

## Overview

The `AssemblyBinaryValidation_AllVersionsShouldBePhysicallyDistinct` test ensures that the compatibility test framework is actually testing different package versions, not accidentally loading the same assembly multiple times.

## What It Validates

### 1. **SHA256 File Hash** ✅ Most Reliable
- Computes SHA256 hash of the actual DLL file
- **Assertion:** Each version must have a unique hash
- **Why:** Different binaries = different hashes. This is cryptographic proof the files are different.

### 2. **Assembly Location Paths**
- Verifies each version is loaded from a different file path
- **Assertion:** No two versions can have the same path
- **Why:** Ensures isolation and prevents accidental reuse

### 3. **File Size**
- Compares the size in bytes of each DLL
- **Informational:** Different sizes suggest different binaries (but not guaranteed)
- **Why:** Quick sanity check; versions often have different sizes

### 4. **Version Attributes**
Extracts and compares three version attributes from each assembly:

- **AssemblyVersion:** `[assembly: AssemblyVersion("x.x.x.x")]`
- **AssemblyFileVersion:** `[assembly: AssemblyFileVersion("x.x.x.x")]`
- **AssemblyInformationalVersion:** `[assembly: AssemblyInformationalVersion("x.x.x-preview08")]`

**Assertion:** Informational versions should be distinct across packages

### 5. **Strong Name / Public Key Token**
- Extracts the public key token if assemblies are signed
- **Validation:** All versions should use the same signing key
- **Why:** Ensures we're testing official builds, not mixed signed/unsigned versions

## Test Output Example

```
========================================
🔍 Binary Validation - Deep Dive
========================================

📦 Package: 1.0.0-preview07
   Resolved: 1.0.0-preview07
   Path: /home/runner/.nuget/packages/microsoft.azure.cosmos.encryption.custom/1.0.0-preview07/lib/netstandard2.0/Microsoft.Azure.Cosmos.Encryption.Custom.dll
   File Size: 145,920 bytes
   SHA256: 3f4a5b2c1d6e7f8a...9b8c7d6e5f4a3b2c
   Assembly Version: 1.0.0.0
   File Version: 1.0.0.0
   Informational Version: 1.0.0-preview07
   Public Key Token: 31bf3856ad364e35

📦 Package: 1.0.0-preview08-pr4-9
   Resolved: 1.0.0-preview08-pr4-9
   Path: /home/runner/work/azure-cosmos-dotnet-v3/artifacts/local-packages/Microsoft.Azure.Cosmos.Encryption.Custom.1.0.0-preview08-pr4-9/lib/netstandard2.0/Microsoft.Azure.Cosmos.Encryption.Custom.dll
   File Size: 147,456 bytes
   SHA256: 8a9b0c1d2e3f4a5b...2c3d4e5f6a7b8c9d
   Assembly Version: 1.0.0.0
   File Version: 1.0.0.0
   Informational Version: 1.0.0-preview08-pr4-9
   Public Key Token: 31bf3856ad364e35

========================================
🔬 Binary Comparison Matrix
========================================

Unique binary hashes: 2 / 2
Unique file sizes: 2 / 2
✅ All assemblies signed with same key: 31bf3856ad364e35

========================================
✅ Binary Validation Results
========================================
Total versions tested: 2
Unique binary hashes: 2 ✓
Unique assembly paths: 2 ✓
Unique file sizes: 2

🎯 Conclusion: All versions are physically distinct binaries
========================================
```

## When This Test Fails

### ❌ Same Hash for Multiple Versions
```
❌ WARNING: Multiple versions share the same binary hash:
   Hash: 3f4a5b2c1d6e7f8a9b0c1d2e3f4a5b2c
   Versions: 1.0.0-preview07, 1.0.0-preview08-pr4-9
```

**Cause:** The workflow might be:
- Building the same code with different version labels
- Not actually pulling different NuGet packages
- Path resolution issue (both loading from same location)

**Fix:**
1. Verify the `build-current-package` job is actually changing code
2. Check that `testconfig.json` has correct version strings
3. Ensure `artifacts/local-packages` contains the right `.nupkg` file

### ❌ Same Assembly Path
```
Assertion failed: expected 2 unique paths but found 1
```

**Cause:** Both versions resolving to the same file location

**Fix:**
- Check `VersionLoader.GetPackagePath()` logic
- Verify NuGet package restore is working correctly
- Ensure local packages folder is being checked first for current builds

### ⚠️ Mixed Public Key Tokens
```
⚠️  Mixed signing: 31bf3856ad364e35, none
```

**Cause:** Some assemblies signed, others not

**Impact:** Not necessarily a failure, but worth investigating
**Check:** Are we mixing official signed builds with local unsigned builds?

## Integration with CI

This test runs automatically as part of the compatibility test suite in GitHub Actions:

```yaml
- name: Run compatibility tests
  run: |
    dotnet test .../CompatibilityTests.csproj \
      --logger "trx;LogFileName=compatibility-results.trx"
```

The test output is captured in:
- Console output (for debugging)
- TRX test results (for CI reporting)
- GitHub test reporter UI (visual test results)

## Benefits

✅ **Confidence:** Proves you're actually testing cross-version compatibility
✅ **Early Detection:** Catches configuration errors before wasting time on meaningless tests  
✅ **Debugging:** Detailed output helps diagnose version resolution issues  
✅ **Documentation:** Test output serves as a record of what was tested  

## Related Files

- **Test:** `VersionValidationTests.cs` - Contains the validation logic
- **Loader:** `VersionLoader.cs` - Exposes `AssemblyPath` property for inspection
- **Workflow:** `.github/workflows/encryption-custom-compatibility.yml` - CI integration
- **Config:** `testconfig.json` - Version matrix configuration

## See Also

- [Compatibility Testing README](README.md) - Overall testing approach
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Common issues and fixes
- [VersionLoader Implementation](../../Microsoft.Azure.Cosmos.Encryption.Custom/tests/Microsoft.Azure.Cosmos.Encryption.Custom.CompatibilityTests/SideBySide/VersionLoader.cs)
