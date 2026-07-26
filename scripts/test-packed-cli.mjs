import { execFile } from "node:child_process";
import { mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const repository = resolve(new URL("..", import.meta.url).pathname);
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
  process.stdout.write("packed sigil-verify install and invocation passed\n");
} finally {
  await Promise.all([
    rm(stagingDirectory, { recursive: true, force: true }),
    rm(consumerDirectory, { recursive: true, force: true }),
  ]);
}
