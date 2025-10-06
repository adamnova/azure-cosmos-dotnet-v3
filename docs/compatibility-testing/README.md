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

The GitHub Actions workflow supports dynamic version matrix configuration without code changes.

#### Option 1: Manual Workflow Dispatch (UI)

1. Go to **Actions** → **Encryption.Custom Compatibility Tests**
2. Click **Run workflow**
3. Fill in parameters:
   - **baseline_version**: Override baseline (e.g., `1.0.0-preview08`)
   - **version_matrix**: Comma-separated versions (e.g., `1.0.0-preview08,1.0.0-preview07,1.0.0-preview06`)
4. Click **Run workflow**

#### Option 2: GitHub CLI

```bash
# Test custom baseline version
gh workflow run encryption-custom-compatibility.yml \
  -f baseline_version=1.0.0-preview08

# Test custom version matrix
gh workflow run encryption-custom-compatibility.yml \
  -f version_matrix="1.0.0-preview08,1.0.0-preview07,1.0.0-preview06"

# Test both
gh workflow run encryption-custom-compatibility.yml \
  -f baseline_version=1.0.0-preview08 \
  -f version_matrix="1.0.0-preview08,1.0.0-preview07,1.0.0-preview06,1.0.0-preview05"
```

#### Default Behavior

- **PR/Push**: Tests baseline version only (`1.0.0-preview07`)
- **Scheduled/Manual** (no inputs): Tests default matrix: `["1.0.0-preview07","1.0.0-preview06","1.0.0-preview05","1.0.0-preview04"]`

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
