import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

const workflowPath = new URL("../.github/workflows/promote-final.yml", import.meta.url);
const releaseWorkflowPath = new URL("../.github/workflows/release-rc.yml", import.meta.url);
const shellVariable = (name: string): string => [String.fromCharCode(36), "{", name, "}"].join("");

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
    expect(workflow).toContain("actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02");
    expect(workflow).toContain("actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093");
    expect(workflow).toContain(`git rev-parse "refs/tags/${githubRefName}^{commit}"`);
    expect(workflow).toContain('= "$GITHUB_SHA"');
    expect(workflow).toContain("actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6");
    expect(workflow).toContain("subject-path:");
    expect(workflow).not.toContain('gh release view "$GITHUB_REF_NAME"');
  });
});
