import { execFile } from "node:child_process";
import { mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const repository = resolve(fileURLToPath(new URL("..", import.meta.url)));
const stagingDirectory = await mkdtemp(join(tmpdir(), "sigil-attestations-pack-"));
const consumerDirectory = await mkdtemp(join(tmpdir(), "sigil-attestations-consumer-"));

try {
  await execFileAsync("npm", ["pack", "--pack-destination", stagingDirectory], { cwd: repository });
  const packageName = (await readdir(stagingDirectory)).find((entry) => entry.endsWith(".tgz"));
  if (!packageName) throw new Error("npm pack did not produce a tarball");
  await writeFile(join(consumerDirectory, "package.json"), JSON.stringify({ private: true, type: "module" }));
  await execFileAsync("npm", ["install", "--ignore-scripts", join(stagingDirectory, packageName)], { cwd: consumerDirectory });
  const binary = join(consumerDirectory, "node_modules", ".bin", "sigil-verify");
  const { stdout } = await execFileAsync(binary, ["--help"], { cwd: consumerDirectory });
  if (!stdout.includes("Usage: sigil-verify")) throw new Error("packed sigil-verify did not print its usage");
  await execFileAsync(binary, ["--bundle", "--trust", "trust.json"], { cwd: consumerDirectory })
    .then(() => { throw new Error("sigil-verify accepted an option as a --bundle value"); })
    .catch((error) => {
      if (!(error instanceof Error) || !String(error?.stderr ?? "").includes("Missing value for --bundle")) {
        throw error;
      }
    });
  process.stdout.write("packed sigil-verify install and invocation passed\n");
} finally {
  await Promise.all([
    rm(stagingDirectory, { recursive: true, force: true }),
    rm(consumerDirectory, { recursive: true, force: true }),
  ]);
}
