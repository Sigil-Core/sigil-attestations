# CANONICALIZER_VERSION advance to 0.4.0: measurement evidence

Date: 2026-08-24
Change: `CANONICALIZER_VERSION` advanced from `@sigilcore/warrant-core@0.2.3` to
`@sigilcore/warrant-core@0.4.0`; `HISTORICAL_CANONICALIZER_VERSIONS` retains
`0.2.3` and `0.2.1`.

## Why the identifier moved

`package.json` has pinned `0.4.0` since #41 (2026-08-21) while the identifier
stayed at `0.2.3`. The identifier is an acceptance allowlist and this package
has no emit path, so the practical effect was that an envelope stamped with the
canonicalizer this package actually loads would have been rejected as an
unsupported envelope.

## Method

Both questions were answered by running the releases side by side, not by
comparing version strings and not by diffing published tarballs. A tarball diff
proves a file changed; it does not prove canonicalization output changed, and
output is what the identifier names.

Corpus: 20 policy bodies extracted from the shipped `sigil-open-framework`
examples and developer toolkit, the `sigil-sign` fixtures and lex example, the
`oee` warranty examples, and this package's own test Warrant. Fenced policy
bodies were extracted from documentation files; signature blocks were stripped.

For each policy and each of `0.2.1`, `0.2.3`, `0.2.4`, `0.3.0` and `0.4.0`:

    parsePolicyMarkdown -> canonicalizePolicyObject -> hashPolicy

Canonical output bytes and policy hashes were compared across releases.

## Result 1: output is unchanged on the shared domain

| Outcome | Count |
| --- | --- |
| Identical canonical bytes and identical policy hash across all five releases | 13 |
| Divergent canonical output | 0 |
| Accepted only by `0.4.0` | 2 |
| Rejected by every release, identically | 5 |

The five universal rejections fail with the identical error string in every
release, so they are not evidence of drift:

| Count | Exact error | Declared version |
| --- | --- | --- |
| 3 | `Policy syntax requires version 2.0.0` | `1.0.0` |
| 2 | `Unknown policy block ## class 1: hard rules` | `1.0.0` |

Note that these are parse-level rejections, not policy-version-range
rejections. The range table in Result 2 lists `0.x` and `1.x` as inside every
release's accepted range; these five files are rejected because of the syntax
and block names they use, not because their declared version is outside that
range. An earlier draft of this document conflated the two and is corrected
here.

Because divergence is zero across the measured corpus, advancing the identifier
changed no policy hash for any policy in that corpus. The corpus is every
`warranty*.md` reachable in the cloned Sigil repositories on the measurement
date, not a sample of bundles issued in the field, so this is evidence that the
canonicalization behavior is unchanged rather than a census of issued bundles.
That is what justifies retaining `0.2.3` and `0.2.1` rather than dropping
them, and the retention invariant is asserted continuously by
`tests/canonicalizer-corpus.test.ts`.

`canonicalizePgCommitV1` was checked separately over four representative
intents and is also identical across all five releases, so `txCommit`
agreement is unaffected.

## Result 2: the accepted policy-version range widened

| Release | Accepted policy versions |
| --- | --- |
| `0.2.3` | `0.x`, `1.x`, `2.0.x`, `2.1.x` |
| `0.3.0` | adds `2.2.x` |
| `0.4.0` | adds `2.3.x` |

The two policies accepted only by `0.4.0` are
`sigil-open-framework/developer-toolkit/warranty-policy.md` and
`sigil-open-framework/examples/mcp-server-agent/warranty.md`, both Policy
`2.3.0`. Earlier releases reject them outright with
`Policy version 2.3.0 is newer than this engine`, rather than canonicalizing
them differently.

`0.4.0` also adds a compiled response-policy surface and a
`response.deny_string` custom rule. These are new emission paths reachable only
by policies earlier releases already reject, which is why they do not appear as
divergence above.

## Why 0.2.2, 0.2.4 and 0.3.0 stay rejected

Acceptance is an allowlist of identifier values a bundle may legitimately
carry, not a compatibility claim about every release whose output happens to
match. `0.2.4` and `0.3.0` were never shipped as `CANONICALIZER_VERSION`, so no
legitimate emitter ever stamped them; `0.2.2` was never pinned at all. `0.1.1`
and `0.2.0` were pinned early but predate the identifier stabilizing and remain
rejected as before. Each is asserted rejected in
`tests/proving-ground.test.ts`.

## Regression coverage

`tests/proving-ground.test.ts` pins the identifier and the historical list,
asserts that `0.2.1` and `0.2.3` canonicalize the test Warrant to bytes
identical to the pinned release, verifies a bundle whose canonical policy was
produced by the real `0.2.1` and real `0.2.3` modules through the
`warrant-core-0-2-1-fixture` and `warrant-core-0-2-3-fixture` aliases, and
asserts rejection of `0.1.1`, `0.2.0`, `0.2.2`, `0.2.4` and `0.3.0`. The suite
runs on pull requests through `dependency-audit.yml`.

## Corpus

The 20 policy bodies were extracted from these files, in the repositories as
cloned on 2026-08-24. Documentation files carry their policy inside a fenced
block; those bodies were extracted and signature blocks stripped.

`sigil-open-framework`: `developer-toolkit/warranty-policy.md`, `demo/warranty.md`,
and `examples/{defi-agent, claude-code-agent, cms-publisher-agent,
outbound-email-agent, customer-support-agent, api-agent,
stablecoin-treasury-agent, data-etl-agent, mcp-server-agent,
rwa-rebalancing-agent, read-only-auditor}/warranty.md`.
`sigil-sign`: `config/warranty.example.md`, `src/lex/warranty.example.md`,
`tests/fixtures/default-policy/config/warranty.md`, and the format reference
example. `oee`: `core/warranty.example.md`, `verticals/venture/warranty.md`.
This package: the `WARRANTY` constant in `tests/proving-ground.test.ts`.

The two accepted only by `0.4.0` are named in Result 2. The five rejected by
every release are the three `sigil-sign` version-1.0.0 examples and the two
`oee` files using `## class 1`.

## Reproducing

Install the releases side by side under npm aliases, then for each policy
compare `canonicalizePolicyObject(parsePolicyMarkdown(text))` and
`hashPolicy(...)` across versions. The test for whether the identifier must
move is behavioral: compare output bytes across the shared accepted domain,
then compare the accepted domains themselves.

The corpus above spans repositories and cannot be checked in wholesale, so the
standing regression guard is `tests/canonicalizer-corpus.test.ts`, which runs
the same comparison on every pull request over nine in-repo fixtures in
`tests/fixtures/canonicalizer-corpus/`. Those fixtures deliberately exercise
multiple typed blocks, list values, repeated per-token keys, `allow_only` and
`deny_if` expressions, quoted `deny_string` literals, non-ASCII values, and
decimal formatting, and span four policy versions including `0.9.0` and
`1.0.0`. The legacy versions matter because `0.x` and `1.x` are inside every
release's accepted range, yet every `1.0.0` file in the corpus above happened
to be rejected for unrelated syntax reasons, so that version family would
otherwise have gone unmeasured. The same test also asserts
`canonicalizePgCommitV1` agreement across the three releases, which backs the
`txCommit` claim in `ATTESTATION-CONTRACT.md`. A future release that changes canonicalization output for
any of those shapes fails CI rather than being caught by re-running this
document by hand.
