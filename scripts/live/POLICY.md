# Release policy

This repository ships through a guarded pipeline. Changes reach `main` only by a
pull request approved by the policy reviewer. Official builds and releases are
produced by the `build` and `release` workflows and carry a provenance
attestation.

- Releases must not contain tokens matching `SPCI-MARKER-*`.
- Changes to `.github/workflows/`, `CODEOWNERS`, or this file require review.
