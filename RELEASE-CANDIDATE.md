# Release Candidate Procedure

Released RC-1 verifier candidate: `v0.2.1-rc.1`.

The RC workflow runs the full test suite, builds, packs, installs the tarball into an isolated temporary consumer, and invokes `sigil-verify --help`. It creates the matching GitHub Release with `--verify-tag` and attaches the tested tarball and checksum. GitHub immutable releases were enabled before the tag was created.

The first direct CI publication could not claim the new unscoped package name: npm trusted publishing, granular package tokens, and staged publishing all require an existing package. RC-1 was therefore published interactively from the exact immutable GitHub Release tarball with npm provenance explicitly disabled. The registry shasum matches that GitHub-attested artifact. npm assigned the first version to both `next` and `latest`, and rejected removal of `latest` with HTTP 400. The one-time credentials were revoked. The package now trusts only `Sigil-Core/sigil-attestations` through `release-rc.yml`, and later approved candidates use that tokenless workflow with npm provenance.

The release command fails instead of replacing an existing release for a tag. npm package versions cannot be overwritten after publication, so any code, artifact, README, or provenance correction requires a new release-candidate version. npm dist-tags are mutable release-channel metadata and may be retargeted separately. npm rejected removing `latest` while RC-1 is the package's only version, so operators must install RC-1 exactly until an approved later version can replace that alias.

The release workflow prepares `sigil-attestations-0.2.1-rc.1.tgz` and its SHA-256 checksum, then attaches both to the matching GitHub Release. Reproducible consumers install the exact registry version with `npm install --save-exact sigil-attestations@0.2.1-rc.1`. Tarball consumers may download the GitHub Release asset and verify its companion checksum first. Use `sigil-verify --bundle ./proof-bundle --trust ./sigil-trust.v1.json --mode audit` after installation.

Do not promote this candidate to stable `v0.2.1`. Historical-verifier work must use a later immutable candidate such as `v0.2.1-rc.2`.
