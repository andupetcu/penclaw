import { describe, it, expect } from "vitest";
import { normalizeSeverity, severityWeight, countFindings, createEmptyCounts } from "../src/utils/severity.js";

describe("normalizeSeverity", () => {
  it("normalizes known severities", () => {
    expect(normalizeSeverity("CRITICAL")).toBe("critical");
    expect(normalizeSeverity("High")).toBe("high");
    expect(normalizeSeverity("MEDIUM")).toBe("medium");
    expect(normalizeSeverity("low")).toBe("low");
    expect(normalizeSeverity("INFO")).toBe("info");
  });

  it("defaults to info for unknown input", () => {
    expect(normalizeSeverity("unknown")).toBe("info");
    expect(normalizeSeverity(undefined)).toBe("info");
    expect(normalizeSeverity("")).toBe("info");
  });
});

describe("severityWeight", () => {
  it("returns correct weights", () => {
    expect(severityWeight("critical")).toBe(5);
    expect(severityWeight("high")).toBe(4);
    expect(severityWeight("medium")).toBe(3);
    expect(severityWeight("low")).toBe(2);
    expect(severityWeight("info")).toBe(1);
  });
});

describe("countFindings", () => {
  it("counts by severity", () => {
    const findings = [
      { severity: "critical" as const },
      { severity: "high" as const },
      { severity: "high" as const },
      { severity: "medium" as const },
    ] as any[];
    const counts = countFindings(findings);
    expect(counts.critical).toBe(1);
    expect(counts.high).toBe(2);
    expect(counts.medium).toBe(1);
    expect(counts.low).toBe(0);
    expect(counts.info).toBe(0);
  });

  it("returns zeros for empty input", () => {
    const counts = countFindings([]);
    expect(counts).toEqual(createEmptyCounts());
  });
});
