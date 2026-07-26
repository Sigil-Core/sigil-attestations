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
    expect(workflow).toContain("persist-credentials: false");
    expect(workflow).toContain("id-token: write");
    expect(workflow).toContain("attestations: write");
    expect(workflow).toContain("actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6");
    expect(workflow).toContain("subject-path:");
  });
});
