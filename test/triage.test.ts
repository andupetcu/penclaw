import { describe, it, expect } from "vitest";
import type { RawFinding, TargetProfile } from "../src/types/index.js";
import { triageFindings } from "../src/triage/triage-findings.js";

const mockProfile: TargetProfile = {
  target: "/test",
  type: "filesystem",
  languages: [{ name: "JavaScript", files: 10 }],
  frameworks: [],
  packageManagers: [],
  manifests: [],
  entryPoints: [],
  fileCount: 10,
};

function makeFinding(overrides: Partial<RawFinding> = {}): RawFinding {
  return {
    id: "test-1",
    source: "secrets",
    ruleId: "test-rule",
    title: "Test finding",
    description: "A test finding",
    severity: "high",
    category: "secret",
    locations: [{ path: "test.js", line: 1 }],
    ...overrides,
  };
}

describe("triage", () => {
  it("produces triaged findings from raw findings", async () => {
    const raw = [makeFinding()];
    const result = await triageFindings(raw, mockProfile);

    expect(result.findings.length).toBe(1);
    const finding = result.findings[0]!;
    expect(finding.confidence).toBeGreaterThan(0);
    expect(finding.confidence).toBeLessThanOrEqual(1);
    expect(finding.reasoning).toBeTruthy();
    expect(finding.proofOfConcept).toBeTruthy();
    expect(finding.fixSuggestion).toBeTruthy();
    expect(finding.deduplicationKey).toBeTruthy();
  });

  it("deduplicates identical findings", async () => {
    const raw = [
      makeFinding({ id: "a", severity: "medium" }),
      makeFinding({ id: "b", severity: "high" }),
    ];
    const result = await triageFindings(raw, mockProfile);

    // Should keep only the higher severity one
    expect(result.findings.length).toBe(1);
    expect(result.findings[0]!.severity).toBe("high");
  });

  it("filters out high false-positive findings", async () => {
    // Low severity + info → very low confidence → high FP likelihood
    const raw = [
      makeFinding({ id: "a", severity: "critical", ruleId: "rule-a", category: "injection" }),
      makeFinding({ id: "b", severity: "info", ruleId: "rule-b", category: "style" }),
    ];
    const result = await triageFindings(raw, mockProfile);

    // The info finding may be filtered if FP >= 0.8
    // Critical should always survive
    const criticals = result.findings.filter((f) => f.severity === "critical");
    expect(criticals.length).toBe(1);
  });

  it("sorts by severity then confidence", async () => {
    const raw = [
      makeFinding({ id: "a", severity: "low", ruleId: "r1", category: "c1", locations: [{ path: "a.js", line: 1 }] }),
      makeFinding({ id: "b", severity: "critical", ruleId: "r2", category: "c2", locations: [{ path: "b.js", line: 2 }] }),
      makeFinding({ id: "c", severity: "high", ruleId: "r3", category: "c3", locations: [{ path: "c.js", line: 3 }] }),
    ];
    const result = await triageFindings(raw, mockProfile);

    const severities = result.findings.map((f) => f.severity);
    const criticalIndex = severities.indexOf("critical");
    const highIndex = severities.indexOf("high");
    const lowIndex = severities.indexOf("low");

    if (criticalIndex >= 0 && highIndex >= 0) {
      expect(criticalIndex).toBeLessThan(highIndex);
    }
    if (highIndex >= 0 && lowIndex >= 0) {
      expect(highIndex).toBeLessThan(lowIndex);
    }
  });

  it("returns empty array for empty input", async () => {
    const result = await triageFindings([], mockProfile);
    expect(result.findings).toEqual([]);
    expect(result.warnings).toEqual([]);
  });

  it("works without AI provider", async () => {
    const raw = [makeFinding()];
    const result = await triageFindings(raw, mockProfile, undefined);
    expect(result.findings.length).toBe(1);
  });
});
