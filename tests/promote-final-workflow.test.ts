import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

const workflowPath = new URL("../.github/workflows/promote-final.yml", import.meta.url);
const releaseWorkflowPath = new URL("../.github/workflows/release-rc.yml", import.meta.url);

describe("final promotion workflow", () => {
  it("requires one same-commit immutable candidate release", async () => {
    const workflow = await readFile(workflowPath, "utf8");
    const finalTagVariable = "$" + "{FINAL_TAG}";
    const candidateTagsVariable = "$" + "{#candidate_tags[@]}";
    const candidateOutput = "$" + "{{ steps.candidate.outputs.tag }}";
    expect(workflow).toContain('git tag --points-at "$final_commit" --list "' + finalTagVariable + '-rc.*"');
    expect(workflow).toContain('[ "' + candidateTagsVariable + '" -ne 1 ]');
    expect(workflow).toContain('gh release view "$candidate_tag"');
    expect(workflow).toContain("CANDIDATE_TAG: " + candidateOutput);
    expect(workflow).toContain("gh attestation verify");
    expect(workflow).not.toContain('candidate_tag="' + finalTagVariable + '-rc.1"');
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
