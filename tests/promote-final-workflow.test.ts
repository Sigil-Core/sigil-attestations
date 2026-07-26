import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

const workflowPath = new URL("../.github/workflows/promote-final.yml", import.meta.url);

describe("final promotion workflow", () => {
  it("requires one same-commit immutable candidate release", async () => {
    const workflow = await readFile(workflowPath, "utf8");
    expect(workflow).toContain('git tag --points-at "$final_commit" --list "${FINAL_TAG}-rc.*"');
    expect(workflow).toContain('[ "${#candidate_tags[@]}" -ne 1 ]');
    expect(workflow).toContain('gh release view "$candidate_tag"');
    expect(workflow).toContain('CANDIDATE_TAG: ${{ steps.candidate.outputs.tag }}');
    expect(workflow).not.toContain('candidate_tag="${FINAL_TAG}-rc.1"');
  });
});
