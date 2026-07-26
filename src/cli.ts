#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { verifyProofBundle } from "./node.js";
import { SigilVerificationError } from "./errors.js";
import { validateTrustManifest } from "./trust.js";
import type { VerificationMode } from "./types.js";

interface Arguments {
  bundle?: string;
  trust?: string;
  mode: VerificationMode;
  json: boolean;
}

const usage = `Usage: sigil-verify --bundle <directory> --trust <sigil-trust.v1.json> [--mode execution|audit] [--json]\n\nThe trust manifest must be acquired separately from the proof bundle.`;

const parseArgs = (argv: string[]): Arguments => {
  const result: Arguments = { mode: "execution", json: false };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--json") result.json = true;
    else if (argument === "--bundle" || argument === "--trust" || argument === "--mode") {
      const value = argv[index + 1];
      if (!value) throw new Error(`Missing value for ${argument}`);
      if (argument === "--bundle") result.bundle = value;
      if (argument === "--trust") result.trust = value;
      if (argument === "--mode") {
        if (value !== "execution" && value !== "audit") throw new Error("--mode must be execution or audit");
        result.mode = value;
      }
      index += 1;
    } else if (argument === "--help" || argument === "-h") {
      throw new Error(usage);
    } else {
      throw new Error(`Unknown argument: ${argument}`);
    }
  }
  if (!result.bundle || !result.trust) throw new Error(usage);
  return result;
};

const main = async (): Promise<void> => {
  const args = parseArgs(process.argv.slice(2));
  const trustPath = resolve(args.trust as string);
  const trust = validateTrustManifest(JSON.parse(await readFile(trustPath, "utf8")));
  const result = await verifyProofBundle({ bundlePath: resolve(args.bundle as string), trust, mode: args.mode });
  const output = {
    ok: true,
    mode: result.mode,
    authorizationExpired: result.authorizationExpired,
    operatorSignatureValid: result.operatorSignatureValid,
    policyHash: result.derivedPolicyHash,
    intentHash: result.commitment.intentHash,
  };
  if (args.json) console.log(JSON.stringify(output));
  else {
    console.log(output.authorizationExpired ? "Historical proof verified. Authorization expired." : "Proof bundle verified and currently executable.");
    console.log(`Mode: ${output.mode}`);
    console.log(`Authorization expired: ${output.authorizationExpired ? "yes" : "no"}`);
    console.log(`Policy hash: ${output.policyHash}`);
  }
};

if (process.argv.includes("--help") || process.argv.includes("-h")) {
  console.log(usage);
} else {
  main().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    const code = error instanceof SigilVerificationError ? error.code : "INVALID_ARGUMENT";
    if (process.argv.includes("--json")) console.error(JSON.stringify({ ok: false, code, error: message }));
    else console.error(`Verification failed [${code}]: ${message}`);
    process.exitCode = 1;
  });
}
