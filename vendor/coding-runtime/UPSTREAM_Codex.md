# Upstream Attribution: Codex

This directory contains vendored source snapshots from the OpenAI Codex project.

- Upstream project: https://github.com/openai/codex
- Local mirror source: `/Users/markmiller/codex-mirror`
- Sync mechanism: `scripts/sync-coding-runtime.sh`
- Pinned revision: see `VENDOR_MANIFEST.yaml` (`upstream_sha`)

## Why the neutral path name

Aegis intentionally stores this under `vendor/coding-runtime/` instead of an
upstream-branded path so internal runtime wiring stays product-neutral while
still preserving explicit provenance.

## Licensing

- Upstream Codex source files retain their original license notices.
- Root license/notice files from upstream are mirrored in this snapshot.
- Aegis-specific glue code and wrappers are maintained in Aegis crates/scripts.

## Local modification policy

Local edits inside `vendor/coding-runtime/` should be avoided when possible.
If a local patch is unavoidable, record it in `VENDOR_MANIFEST.yaml` under
`local_patches`.
