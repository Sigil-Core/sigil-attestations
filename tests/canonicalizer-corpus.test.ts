import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { canonicalizePolicyObject, hashPolicy, parsePolicyMarkdown } from "@sigilcore/warrant-core";
import { createNodeCryptoAdapter } from "@sigilcore/warrant-core/crypto/node";
import {
  canonicalizePolicyObject as canonicalizeFrom021,
  hashPolicy as hashPolicyFrom021,
  parsePolicyMarkdown as parseFrom021,
} from "warrant-core-0-2-1-fixture";
import { createNodeCryptoAdapter as adapterFrom021 } from "warrant-core-0-2-1-fixture/crypto/node";
import {
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
    expect(corpus.length).toBeGreaterThanOrEqual(7);
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
});
