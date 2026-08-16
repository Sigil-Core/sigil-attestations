import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

const workflowPath = new URL("../.github/workflows/promote-final.yml", import.meta.url);
const releaseWorkflowPath = new URL("../.github/workflows/release-rc.yml", import.meta.url);
const shellVariable = (name: string): string => [String.fromCharCode(36), "{", name, "}"].join("");
const workflowStep = (workflow: string, name: string): string => {
  const marker = `      - name: ${name}`;
  const start = workflow.indexOf(marker);
  expect(start).toBeGreaterThanOrEqual(0);
  const next = workflow.indexOf("\n      - name:", start + marker.length);
  return workflow.slice(start, next === -1 ? undefined : next);
};

describe("final promotion workflow", () => {
  it("requires one same-commit immutable candidate release", async () => {
    const workflow = await readFile(workflowPath, "utf8");
    const finalTagVariable = shellVariable("FINAL_TAG");
    const candidateTagsVariable = shellVariable("#candidate_tags[@]");
    const candidateOutput = [String.fromCharCode(36), "{{ steps.candidate.outputs.tag }}"].join("");
    expect(workflow).toContain(['git tag --points-at "$final_commit" --list "', finalTagVariable, '-rc.*"'].join(""));
    expect(workflow).toContain(['[ "', candidateTagsVariable, '" -ne 1 ]'].join(""));
    expect(workflow).toContain('gh release view "$candidate_tag"');
    expect(workflow).toContain(["CANDIDATE_TAG: ", candidateOutput].join(""));
    expect(workflow).toContain("gh attestation verify");
    expect(workflow).not.toContain(['candidate_tag="', finalTagVariable, '-rc.1"'].join(""));
  });

  it("attests candidate artifacts with a credential-free checkout", async () => {
    const workflow = await readFile(releaseWorkflowPath, "utf8");
    const githubRefName = shellVariable("GITHUB_REF_NAME");
    expect(workflow).toContain("permissions:\n  contents: read");
    expect(workflow).toContain("build:");
    expect(workflow).toContain("release:\n    needs: build");
    expect(workflow).toContain("persist-credentials: false");
    expect(workflow).toContain("id-token: write");
    expect(workflow).toContain("attestations: write");
    expect(workflow).toContain("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a");
    expect(workflow).toContain("actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093");
    expect(workflow).toContain(`git rev-parse "refs/tags/${githubRefName}^{commit}"`);
    expect(workflow).toContain('= "$GITHUB_SHA"');
    expect(workflow).toContain("actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6");
    expect(workflow).toContain("subject-path:");
    expect(workflow).not.toContain('gh release view "$GITHUB_REF_NAME"');
  });

  it("publishes prereleases only through npm trusted publishing", async () => {
    const workflow = await readFile(releaseWorkflowPath, "utf8");
    const publishStep = workflowStep(
      workflow,
      "Publish prerelease with npm trusted publishing and provenance",
    );
    expect(workflow).toContain(
      "publish:\n    needs: [build, release]\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n      id-token: write",
    );
    expect(workflow).toContain("registry-url: https://registry.npmjs.org");
    expect(workflow).toContain("execFileSync('npm', ['--version']");
    expect(workflow).toContain("minor < 5 || (minor === 5 && patch < 1)");
    expect(workflow).not.toContain("npm install --global");
    expect(workflow).toContain("Refuse an existing immutable npm version");
    expect(workflow).not.toContain("NPM_BOOTSTRAP_TOKEN");
    expect(workflow).not.toContain("NODE_AUTH_TOKEN");
    expect(publishStep).toContain(
      'npm publish "$package_file" --access public --tag next --provenance',
    );
    expect(publishStep).not.toContain("NPM_TOKEN");
  });
});
