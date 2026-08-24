import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { canonicalizePgCommitV1, canonicalizePolicyObject, hashPolicy, parsePolicyMarkdown } from "@sigilcore/warrant-core";
import { createNodeCryptoAdapter } from "@sigilcore/warrant-core/crypto/node";
import {
  canonicalizePgCommitV1 as pgCommitFrom021,
  canonicalizePolicyObject as canonicalizeFrom021,
  hashPolicy as hashPolicyFrom021,
  parsePolicyMarkdown as parseFrom021,
} from "warrant-core-0-2-1-fixture";
import { createNodeCryptoAdapter as adapterFrom021 } from "warrant-core-0-2-1-fixture/crypto/node";
import {
  canonicalizePgCommitV1 as pgCommitFrom023,
  canonicalizePolicyObject as canonicalizeFrom023,
  hashPolicy as hashPolicyFrom023,
  parsePolicyMarkdown as parseFrom023,
} from "warrant-core-0-2-3-fixture";
import { createNodeCryptoAdapter as adapterFrom023 } from "warrant-core-0-2-3-fixture/crypto/node";
import { CANONICALIZER_VERSION, HISTORICAL_CANONICALIZER_VERSIONS } from "../src/bundle.js";

const CORPUS_DIR = join(import.meta.dirname, "fixtures", "canonicalizer-corpus");
const corpus = readdirSync(CORPUS_DIR)
  .filter((name) => name.endsWith(".md") && name !== "README.md")
  .sort()
  .map((name) => [name, readFileSync(join(CORPUS_DIR, name), "utf8")] as const);

/**
 * Retaining a historical canonicalizer identifier is only safe while that
 * release produces byte-identical canonical output to the pinned release. The
 * verifier always re-derives with the pinned release, so a divergence would not
 * forge a bundle, but it would silently stop verifying already-issued evidence.
 * These assertions are the standing guard on that invariant.
 */
describe("canonicalizer cross-version agreement", () => {
  it("has a corpus covering more than one policy shape", () => {
    // it.each([]) runs zero cases and passes silently, so this is the vacuity
    // floor. It cannot detect diversity collapse; that is what review of the
    // fixture directory is for.
    expect(corpus.length).toBeGreaterThanOrEqual(9);
    const versions = new Set(corpus.map(([, text]) => /^version:\s*(\S+)/m.exec(text)?.[1]));
    expect(versions.size).toBeGreaterThanOrEqual(4);
  });

  it("pins the releases under comparison to the retained identifiers", () => {
    expect(CANONICALIZER_VERSION).toBe("@sigilcore/warrant-core@0.4.0");
    expect(HISTORICAL_CANONICALIZER_VERSIONS).toStrictEqual([
      "@sigilcore/warrant-core@0.2.3",
      "@sigilcore/warrant-core@0.2.1",
    ]);
  });

  it.each(corpus)("canonicalizes %s identically under 0.4.0, 0.2.3 and 0.2.1", async (_name, text) => {
    const pinned = canonicalizePolicyObject(parsePolicyMarkdown(text));
    expect(canonicalizeFrom023(parseFrom023(text))).toBe(pinned);
    expect(canonicalizeFrom021(parseFrom021(text))).toBe(pinned);

    const pinnedHash = await hashPolicy(createNodeCryptoAdapter(), parsePolicyMarkdown(text));
    expect(await hashPolicyFrom023(adapterFrom023(), parseFrom023(text))).toBe(pinnedHash);
    expect(await hashPolicyFrom021(adapterFrom021(), parseFrom021(text))).toBe(pinnedHash);
  });

  // ATTESTATION-CONTRACT.md states that txCommit agreement is unaffected by
  // which accepted release the emitting proxy pinned. That claim needs a
  // standing test, not a one-off measurement.
  it.each([
    ["web_fetch", { action: "web_fetch", url: "https://docs.sigilcore.com/getting-started", metadata: { job_type: "documentation" } }],
    ["wallet.transfer", { action: "wallet.transfer", amount: "1.5", chainId: 1, targetAddress: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" }],
    ["email.send", { action: "email.send", to: "a@b.com", subject: "x", metadata: { nested: { deep: [1, 2, { k: "v" }] } } }],
    ["non-ascii", { action: "bash", command: "echo contraseña", metadata: { note: "パスワード" } }],
  ])("commits %s identically under 0.4.0, 0.2.3 and 0.2.1", (_name, intent) => {
    const pinned = canonicalizePgCommitV1(intent);
    expect(pgCommitFrom023(intent)).toBe(pinned);
    expect(pgCommitFrom021(intent)).toBe(pinned);
  });
});
