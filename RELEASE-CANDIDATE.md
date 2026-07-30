# Release Candidate Procedure

Proposed CC-1 verifier candidate: `v0.2.1-rc.1`.

The RC workflow runs the full test suite, builds, packs, installs the tarball into an isolated temporary consumer, and invokes `sigil-verify --help`. It creates the matching GitHub Release with `--verify-tag`, attaches the tested tarball and checksum, then publishes the same package as `sigil-attestations@0.2.1-rc.1` under the npm `next` dist-tag through npm trusted publishing with provenance. The release command fails instead of replacing an existing release for that tag, but the workflow does not make GitHub release assets immutable. Consumers must verify the checksum and attestation. npm package versions cannot be overwritten after publication, so any code or artifact change requires a new release-candidate version.

The release workflow prepares `sigil-attestations-0.2.1-rc.1.tgz` and its SHA-256 checksum, then attaches both to the matching GitHub Release. Reproducible consumers install the exact registry version with `npm install --save-exact sigil-attestations@0.2.1-rc.1`. Tarball consumers may download the GitHub Release asset and verify its companion checksum first. Use `sigil-verify --bundle ./proof-bundle --trust ./sigil-trust.v1.json --mode audit` after installation.

Do not promote this candidate to stable `v0.2.1`. Historical-verifier work must use a later immutable candidate such as `v0.2.1-rc.2`.
