import { describe, it, expect } from "vitest";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { promises as fs } from "node:fs";

const execFileAsync = promisify(execFile);
const cliPath = path.resolve(import.meta.dirname, "../src/cli/index.ts");
const fixturesPath = path.resolve(import.meta.dirname, "fixtures");
const cleanPath = path.resolve(import.meta.dirname, "fixtures/clean");

async function runCli(args: string[]): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  try {
    const result = await execFileAsync("npx", ["tsx", cliPath, ...args], {
      timeout: 120_000,
      maxBuffer: 20 * 1024 * 1024,
      env: { ...process.env, NO_COLOR: "1" },
    });
    return { stdout: result.stdout, stderr: result.stderr, exitCode: 0 };
  } catch (error: any) {
    return {
      stdout: error.stdout ?? "",
      stderr: error.stderr ?? "",
      exitCode: error.code ?? 1,
    };
  }
}

describe("E2E: penclaw scan", () => {
  it("scans vulnerable fixtures and finds issues", async () => {
    const { stdout } = await runCli(["scan", fixturesPath]);
    // Should complete and report findings
    expect(stdout).toContain("PenClaw");
    // The secret scanner should find things
    expect(stdout).toMatch(/critical \d|high \d|medium \d/);
  }, 120_000);

  it("outputs valid JSON when --format json is used", async () => {
    const outPath = path.resolve(import.meta.dirname, "../tmp-test-report.json");
    try {
      await runCli(["scan", fixturesPath, "-f", "json", "-o", outPath]);
      const raw = await fs.readFile(outPath, "utf8");
      const report = JSON.parse(raw);
      expect(report.tool.name).toBe("PenClaw");
      expect(Array.isArray(report.findings)).toBe(true);
      expect(report.counts).toBeDefined();
      expect(report.targetProfile).toBeDefined();
    } finally {
      await fs.unlink(outPath).catch(() => {});
    }
  }, 120_000);

  it("outputs valid Markdown when --format markdown is used", async () => {
    const outPath = path.resolve(import.meta.dirname, "../tmp-test-report.md");
    try {
      await runCli(["scan", fixturesPath, "-f", "markdown", "-o", outPath]);
      const raw = await fs.readFile(outPath, "utf8");
      expect(raw).toContain("# PenClaw Security Report");
      expect(raw).toContain("## Summary");
      expect(raw).toContain("## Findings");
    } finally {
      await fs.unlink(outPath).catch(() => {});
    }
  }, 120_000);

  it("handles clean project with zero findings gracefully", async () => {
    const { stdout, stderr } = await runCli(["scan", cleanPath]);
    const combined = stdout + stderr;
    expect(combined).toContain("PenClaw");
    // Should not crash, and report zero findings
    expect(combined).toMatch(/0 actionable findings|critical 0/);
  }, 120_000);

  it("does not crash on nonexistent target", async () => {
    const { stdout, stderr } = await runCli(["scan", "/nonexistent/path/xyz"]);
    // Should report error but not crash with unhandled exception
    const combined = stdout + stderr;
    expect(combined).toMatch(/failed|does not exist|error/i);
  }, 120_000);

  it("shows help text for scan command", async () => {
    const { stdout } = await runCli(["scan", "--help"]);
    expect(stdout).toContain("target");
    expect(stdout).toContain("--output");
    expect(stdout).toContain("--format");
  }, 30_000);
});
