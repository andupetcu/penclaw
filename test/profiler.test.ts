import { describe, it, expect } from "vitest";
import path from "node:path";
import { profileTarget } from "../src/profiler/profile-target.js";

const fixturesPath = path.resolve(import.meta.dirname, "fixtures");
const cleanPath = path.resolve(import.meta.dirname, "fixtures/clean");

describe("profiler", () => {
  it("detects languages in fixture directory", async () => {
    const profile = await profileTarget(fixturesPath, {});
    const languageNames = profile.languages.map((l) => l.name);
    expect(languageNames).toContain("JavaScript");
    expect(languageNames).toContain("Python");
  });

  it("detects TypeScript in clean directory", async () => {
    const profile = await profileTarget(cleanPath, {});
    const languageNames = profile.languages.map((l) => l.name);
    expect(languageNames).toContain("TypeScript");
  });

  it("detects package.json manifests", async () => {
    const profile = await profileTarget(fixturesPath, {});
    expect(profile.manifests.length).toBeGreaterThan(0);
  });

  it("returns filesystem type", async () => {
    const profile = await profileTarget(fixturesPath, {});
    expect(profile.type).toBe("filesystem");
  });

  it("counts files", async () => {
    const profile = await profileTarget(fixturesPath, {});
    expect(profile.fileCount).toBeGreaterThan(0);
  });

  it("throws on nonexistent path", async () => {
    await expect(
      profileTarget("/nonexistent/path/xyz", {}),
    ).rejects.toThrow("does not exist");
  });
});
