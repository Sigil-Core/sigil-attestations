# Release Candidate Procedure

Approved RC-2 verifier candidate: `v0.2.1-rc.2`.

The RC workflow runs the full test suite, builds, packs, installs the tarball into an isolated temporary consumer, and invokes `sigil-verify --help`. It creates the matching GitHub Release with `--verify-tag` and attaches the tested tarball and checksum. GitHub immutable releases were enabled before the tag was created.

The first direct CI publication could not claim the new unscoped package name: npm trusted publishing, granular package tokens, and staged publishing all require an existing package. RC-1 was therefore published interactively from the exact immutable GitHub Release tarball with npm provenance explicitly disabled. The registry shasum matches that GitHub-attested artifact. npm assigned the first version to both `next` and `latest`, and rejected removal of `latest` with HTTP 400. The one-time credentials were revoked. RC-2 is configured to publish only through the package's trusted publisher for `Sigil-Core/sigil-attestations` and `release-rc.yml`. The workflow uses GitHub Actions OIDC without a repository npm token and requests npm registry provenance.

The release command fails instead of replacing an existing release for a tag. npm package versions cannot be overwritten after publication, so any code, artifact, README, or provenance correction requires a new release-candidate version. npm dist-tags are mutable release-channel metadata and may be retargeted separately. On successful RC-2 publication, `next` points to RC-2. The bootstrap RC-1 publication remains `latest` until a stable release receives separate approval.

The release workflow is configured to prepare `sigil-attestations-0.2.1-rc.2.tgz` and its SHA-256 checksum, then attach both to the matching GitHub Release. After successful publication, reproducible consumers can install the exact registry version with `npm install --save-exact sigil-attestations@0.2.1-rc.2`. Tarball consumers can download the GitHub Release asset and verify its companion checksum first. Use `sigil-verify --bundle ./proof-bundle --trust ./sigil-trust.v1.json --mode audit` after installation.

Do not promote this candidate to stable `v0.2.1`.
