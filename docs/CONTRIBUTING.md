# Contributing

## Local Git Hooks

Enable repo-local hooks once after cloning:

```bash
git config core.hooksPath .githooks
chmod +x .githooks/pre-commit
```

The pre-commit hook runs:

```bash
cargo fmt --all -- --check
```

This prevents formatting-only drift from reaching commits and keeps CI formatting checks green.
