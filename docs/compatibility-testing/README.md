# Compatibility Testing Documentation

## 📖 Quick Navigation

Welcome to the compatibility testing documentation for `Microsoft.Azure.Cosmos.Encryption.Custom`.

### 🚀 Getting Started

- **Want to run tests quickly?** → Jump to [QUICKSTART.md](./QUICKSTART.md)
- **Working with CI/CD?** → Check [PIPELINE-GUIDE.md](./PIPELINE-GUIDE.md)
- **Need to troubleshoot?** → See [TROUBLESHOOTING.md](./TROUBLESHOOTING.md)

### 📘 Reference Documentation

| Topic | Document | Use When |
|-------|----------|----------|
| Quick Start | [QUICKSTART.md](./QUICKSTART.md) | Running tests for the first time |
| Pipeline Guide | [PIPELINE-GUIDE.md](./PIPELINE-GUIDE.md) | Working with GitHub Actions |
| API Changes | [API-CHANGES.md](./API-CHANGES.md) | Documenting breaking changes |
| Troubleshooting | [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) | Something isn't working |
| Maintenance | [MAINTENANCE.md](./MAINTENANCE.md) | Regular upkeep tasks |
| Cheat Sheet | [CHEATSHEET.md](./CHEATSHEET.md) | Quick command reference |

## 🎯 Common Tasks

### Run Tests Locally

```bash
cd Microsoft.Azure.Cosmos.Encryption.Custom/tests/Microsoft.Azure.Cosmos.Encryption.Custom.CompatibilityTests
dotnet test
```

### Configure Version Matrix in CI/CD

The GitHub Actions workflow automatically:

1. **Builds current source** as a NuGet package with unique version (e.g., `1.0.0-pr123-45` or `1.0.0-ci-789`)
2. **Runs full matrix** testing current version against all published versions
3. **No quick check mode** - always runs comprehensive matrix

#### Manual Workflow Dispatch (UI)

1. Go to **Actions** → **Encryption.Custom Compatibility Tests**
2. Click **Run workflow**
3. (Optional) Override version matrix:
   - **version_matrix**: Comma-separated versions (e.g., `1.0.0-preview08,1.0.0-preview07,1.0.0-preview06`)
4. Click **Run workflow**

The current source version will automatically be added to your specified matrix.

#### GitHub CLI

```bash
# Test against default matrix + current source
gh workflow run encryption-custom-compatibility.yml

# Test against custom version matrix + current source
gh workflow run encryption-custom-compatibility.yml \
  -f version_matrix="1.0.0-preview08,1.0.0-preview07,1.0.0-preview06"
```

#### What Gets Tested

**Every run tests**:

- Current source code (built as `1.0.0-pr{number}-{run}` or `1.0.0-ci-{run}`)
- Plus all versions in matrix (default or custom)

**Example PR #42, run #100**:

- Tests: `1.0.0-pr42-100`, `1.0.0-preview07`, `1.0.0-preview06`, `1.0.0-preview05`, `1.0.0-preview04`

#### Default Behavior

- **All triggers** (PR/push/schedule): Full matrix + current source
- **Default matrix**: `["1.0.0-preview07","1.0.0-preview06","1.0.0-preview05","1.0.0-preview04"]`

### Update Default Versions

To permanently change the default versions, edit `.github/workflows/encryption-custom-compatibility.yml`:

```yaml
env:
  BASELINE_VERSION: '1.0.0-preview08'  # Change here
  DEFAULT_VERSION_MATRIX: '["1.0.0-preview08","1.0.0-preview07","1.0.0-preview06"]'  # Change here
```

---

## 📚 Documentation

For detailed information, see the reference documents above.
