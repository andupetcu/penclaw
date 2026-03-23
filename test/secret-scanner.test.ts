import { describe, it, expect } from "vitest";
import path from "node:path";
import { runSecretScan } from "../src/scanners/secret-scanner.js";

const fixturesPath = path.resolve(import.meta.dirname, "fixtures");
const cleanPath = path.resolve(import.meta.dirname, "fixtures/clean");

describe("secret-scanner", () => {
  it("detects hardcoded secrets in .env file", async () => {
    const result = await runSecretScan(fixturesPath, {});
    const envFindings = result.findings.filter((f) =>
      f.locations.some((l) => l.path.endsWith(".env")),
    );
    expect(envFindings.length).toBeGreaterThan(0);

    const ruleIds = envFindings.map((f) => f.ruleId);
    expect(ruleIds).toContain("aws-access-key");
    expect(ruleIds).toContain("github-token");
    expect(ruleIds).toContain("slack-token");
  });

  it("detects hardcoded secrets in JS source files", async () => {
    const result = await runSecretScan(fixturesPath, {});
    const jsFindings = result.findings.filter((f) =>
      f.locations.some((l) => l.path.endsWith(".js")),
    );
    expect(jsFindings.length).toBeGreaterThan(0);

    const hasGithubToken = jsFindings.some((f) => f.ruleId === "github-token");
    expect(hasGithubToken).toBe(true);
  });

  it("detects hardcoded secrets in Python source files", async () => {
    const result = await runSecretScan(fixturesPath, {});
    const pyFindings = result.findings.filter((f) =>
      f.locations.some((l) => l.path.endsWith(".py")),
    );
    expect(pyFindings.length).toBeGreaterThan(0);

    const hasAwsKey = pyFindings.some((f) => f.ruleId === "aws-access-key");
    expect(hasAwsKey).toBe(true);
  });

  it("detects high-entropy strings", async () => {
    const result = await runSecretScan(fixturesPath, {});
    const entropyFindings = result.findings.filter(
      (f) => f.ruleId === "high-entropy-string",
    );
    expect(entropyFindings.length).toBeGreaterThan(0);
  });

  it("returns no findings for clean projects", async () => {
    const result = await runSecretScan(cleanPath, {});
    expect(result.findings.length).toBe(0);
    expect(result.warnings.length).toBe(0);
  });

  it("respects excludePaths config", async () => {
    const result = await runSecretScan(fixturesPath, {
      scan: { excludePaths: ["*.env", "**/.env"] },
    });
    const envFindings = result.findings.filter((f) =>
      f.locations.some((l) => l.path.endsWith(".env")),
    );
    expect(envFindings.length).toBe(0);
  });

  it("produces correct finding shape", async () => {
    const result = await runSecretScan(fixturesPath, {});
    expect(result.scanner).toBe("secrets");
    expect(typeof result.executionMs).toBe("number");

    for (const finding of result.findings) {
      expect(finding.source).toBe("secrets");
      expect(finding.category).toBe("secret");
      expect(finding.id).toBeTruthy();
      expect(finding.title).toBeTruthy();
      expect(finding.locations.length).toBeGreaterThan(0);
      expect(["critical", "high", "medium", "low", "info"]).toContain(
        finding.severity,
      );
    }
  });
});
