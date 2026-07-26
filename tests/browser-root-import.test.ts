import { build } from "esbuild";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

describe("browser and Workers root import", () => {
  it("bundles the public root without Node-only modules", async () => {
    const result = await build({
      entryPoints: [fileURLToPath(new URL("../src/index.ts", import.meta.url))],
      bundle: true,
      format: "esm",
      platform: "browser",
      write: false,
    });
    const output = result.outputFiles[0]?.text ?? "";
    expect(output).not.toContain("node:crypto");
    expect(output).not.toContain("node:fs");
    expect(output).not.toContain("node:path");
  });
});
