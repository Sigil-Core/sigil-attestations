# Cross-version canonicalizer corpus

Policy bodies used to assert that every identifier in
`HISTORICAL_CANONICALIZER_VERSIONS` canonicalizes to bytes identical to
`CANONICALIZER_VERSION`. That equality is the invariant that justifies
retaining an older identifier, so it is asserted here rather than assumed.

Shapes are chosen to exercise the parts of the canonicalizer most likely to
drift between releases: multiple typed blocks, list values, per-token rules
with repeated keys, custom `allow_only` and `deny_if` expressions, quoted
`deny_string` literals, non-ASCII values, decimal formatting, and multi-block
ordering.

Every file here must parse under the pinned release and under every retained
historical release. A policy that only newer releases accept does not belong in
this corpus; see `docs/evidence/canonicalizer-0.4.0-advance.md` for the
domain-expansion measurement, which is a separate question.
