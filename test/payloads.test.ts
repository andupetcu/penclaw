import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { loadPayloads, loadDirectoryPaths } from "../src/utils/payloads.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const payloadsDir = resolve(__dirname, "../data/payloads");

describe("payload JSON files", () => {
  const payloadFiles = [
    { name: "sqli", minCount: 150, requiredFields: ["value", "technique", "description", "dbms"] },
    { name: "xss", minCount: 80, requiredFields: ["value", "technique", "description", "context"] },
    { name: "ssrf", minCount: 30, requiredFields: ["value", "technique", "description"] },
    { name: "path-traversal", minCount: 40, requiredFields: ["value", "technique", "description"] },
    { name: "open-redirect", minCount: 20, requiredFields: ["value", "technique", "description"] },
  ];

  for (const { name, minCount, requiredFields } of payloadFiles) {
    describe(`${name}.json`, () => {
      it("parses as valid JSON array", () => {
        const raw = JSON.parse(readFileSync(resolve(payloadsDir, `${name}.json`), "utf-8"));
        expect(Array.isArray(raw)).toBe(true);
      });

      it(`has at least ${minCount} payloads`, () => {
        const raw = JSON.parse(readFileSync(resolve(payloadsDir, `${name}.json`), "utf-8")) as unknown[];
        expect(raw.length).toBeGreaterThanOrEqual(minCount);
      });

      it("every entry has required fields", () => {
        const raw = JSON.parse(readFileSync(resolve(payloadsDir, `${name}.json`), "utf-8")) as Record<string, unknown>[];
        for (const entry of raw) {
          for (const field of requiredFields) {
            expect(entry).toHaveProperty(field);
            expect(typeof entry[field]).toBe("string");
            expect((entry[field] as string).length).toBeGreaterThan(0);
          }
        }
      });

      it("no duplicate values", () => {
        const raw = JSON.parse(readFileSync(resolve(payloadsDir, `${name}.json`), "utf-8")) as Array<{ value: string }>;
        const values = raw.map((e) => e.value);
        const unique = new Set(values);
        expect(unique.size).toBe(values.length);
      });
    });
  }

  describe("directories.json", () => {
    it("parses as valid JSON array of strings", () => {
      const raw = JSON.parse(readFileSync(resolve(payloadsDir, "directories.json"), "utf-8"));
      expect(Array.isArray(raw)).toBe(true);
      for (const entry of raw.slice(0, 20)) {
        expect(typeof entry).toBe("string");
      }
    });

    it("has at least 4000 paths", () => {
      const raw = JSON.parse(readFileSync(resolve(payloadsDir, "directories.json"), "utf-8")) as string[];
      expect(raw.length).toBeGreaterThanOrEqual(4000);
    });

    it("all paths start with /", () => {
      const raw = JSON.parse(readFileSync(resolve(payloadsDir, "directories.json"), "utf-8")) as string[];
      for (const entry of raw) {
        expect(entry.startsWith("/")).toBe(true);
      }
    });
  });
});

describe("loadPayloads()", () => {
  it("loads sqli payloads with correct shape", () => {
    const payloads = loadPayloads("sqli");
    expect(payloads.length).toBeGreaterThan(100);
    for (const p of payloads.slice(0, 10)) {
      expect(p.value).toBeDefined();
      expect(p.technique).toBeDefined();
      expect(p.description).toBeDefined();
    }
  });

  it("loads xss payloads", () => {
    const payloads = loadPayloads("xss");
    expect(payloads.length).toBeGreaterThan(50);
  });

  it("caches repeated calls", () => {
    const a = loadPayloads("ssrf");
    const b = loadPayloads("ssrf");
    expect(a).toBe(b); // same reference
  });
});

describe("loadDirectoryPaths()", () => {
  it("returns array of strings", () => {
    const paths = loadDirectoryPaths();
    expect(paths.length).toBeGreaterThan(4000);
    expect(typeof paths[0]).toBe("string");
  });
});
