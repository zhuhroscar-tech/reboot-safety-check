# Changelog

All notable user-facing changes are tracked here. This project uses GitHub Releases for downloadable artifacts; this file keeps the repository history visible from a checkout.

## v0.3.3 - 2026-09-25

- Made CI run explicitly on `v*` release tags so published releases exercise the same build and smoke-test path as `main`.
- Added package metadata pointing to this changelog and repository-contract coverage for both release-tag CI and changelog metadata.
- No runtime behavior changes.

## v0.3.2 - 2026-09-24

- Added this changelog and repository-contract coverage so release history, license links, CI wiring, and release artifact expectations stay documented in the repository.
- No runtime behavior changes.

## v0.3.1 - 2026-09-24

- Modernized packaging license metadata to the SPDX `license = "MIT"` form.
- Added `license-files = ["LICENSE"]`, removed the deprecated MIT license classifier, and raised the setuptools build floor to keep package builds warning-free.
- Added regression coverage for the packaging metadata contract.

## v0.3.0 - 2026-09-20

- Fixed `dkms status` parsing for module-level `added` and `broken` lines that have no kernel field.
- Prevented false all-clear reports when a DKMS module had never been built or its source directory was missing.
- Added regression coverage for the real DKMS output shapes.

## v0.2.9 - 2026-09-19

- Recognized the newer DKMS wording for built/installed module differences.
- Preserved the actionable finding instead of degrading it to a generic unexpected-status warning.

## v0.2.8 - 2026-09-18

- Reported DKMS `broken` entries as failures with targeted remediation.
- Reported installed modules with built/installed differences as a specific reboot risk.
- Added regression tests for both DKMS status shapes.

## v0.2.7 - 2026-09-13

- Fixed false positives for older fallback kernels that are installed but not newer than the running kernel.
- Kept genuinely newer, not-yet-booted kernels in scope for DKMS/header checks.
