# Immutable Release Candidate Procedure

Proposed Phase 2 candidate: `v0.2.0-rc.1`.

The candidate is a GitHub Release only. Do not publish this verifier to npm. The RC workflow runs the full test suite, builds, packs, installs the tarball into an isolated temporary consumer, and invokes `sigil-verify --help`. After the Phase 6 real-token golden tests pass, create `v0.2.0` on the exact `v0.2.0-rc.1` commit. The promotion workflow downloads the RC tarball and checksum, verifies the checksum, and attaches those exact unchanged artifacts to the final release. Any code or artifact change requires `v0.2.0-rc.2`. Neither workflow overwrites an existing release.

The release workflow prepares `sigil-attestations-0.2.0-rc.1.tgz` and its SHA-256 checksum, then attaches both to the matching immutable GitHub Release. Consumers install the verified tarball with `npm install ./sigil-attestations-0.2.0-rc.1.tgz` after checking the published checksum. Use `sigil-verify --bundle ./proof-bundle --trust ./sigil-trust.v1.json --mode audit` after installation.

The phase boundary prohibits tagging, publishing, or creating a release in this worktree.
