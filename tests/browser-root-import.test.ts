import { build } from "esbuild";
import { describe, expect, it } from "vitest";

describe("browser and Workers root import", () => {
  it("bundles the public root without Node-only modules", async () => {
    const result = await build({
      entryPoints: [new URL("../src/index.ts", import.meta.url).pathname],
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
