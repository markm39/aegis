# Vendored Coding Runtime

Aegis vendors an upstream coding runtime snapshot under:

- `vendor/coding-runtime/`

This snapshot is sourced from the local Codex mirror and is pinned by SHA in:

- `vendor/coding-runtime/VENDOR_MANIFEST.yaml`

## Syncing

Refresh the snapshot:

```bash
scripts/sync-coding-runtime.sh
```

Use a custom mirror path:

```bash
scripts/sync-coding-runtime.sh --source /path/to/codex-mirror
```

Check drift without mutating files:

```bash
scripts/sync-coding-runtime.sh --check
```

## Provenance

Attribution and upstream metadata are documented in:

- `vendor/coding-runtime/UPSTREAM_Codex.md`
