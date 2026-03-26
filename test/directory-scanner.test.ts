import { describe, it, expect, vi, beforeEach } from "vitest";
import { runDirectoryScan } from "../src/dynamic/directory-scanner.js";
import type { PenClawConfig } from "../src/types/index.js";

// Mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

// Mock the payload loader to avoid reading the large JSON
vi.mock("../src/utils/payloads.js", () => ({
  loadDirectoryPaths: () => [
    "/admin",
    "/.env",
    "/.git/config",
    "/swagger-ui",
    "/backup.sql",
    "/debug",
    "/nonexistent",
    "/robots.txt",
  ],
}));

function mockResponse(status: number, body: string): Response {
  return {
    status,
    ok: status >= 200 && status < 300,
    text: () => Promise.resolve(body),
    headers: new Headers(),
  } as unknown as Response;
}

const config: PenClawConfig = {
  scan: { maxConcurrentRequests: 5, requestDelayMs: 0 },
};

describe("directory-scanner", () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it("finds accessible paths and categorizes them", async () => {
    mockFetch.mockImplementation((url: string) => {
      const u = typeof url === "string" ? url : String(url);
      if (u.includes("__penclaw_baseline")) return Promise.resolve(mockResponse(404, "Not Found"));
      if (u.includes("/admin")) return Promise.resolve(mockResponse(200, "<html><title>Admin Panel</title><body>Admin Dashboard</body></html>"));
      if (u.includes("/.env")) return Promise.resolve(mockResponse(200, "DB_HOST=localhost\nDB_PASS=secret123\nSECRET_KEY=abc"));
      if (u.includes("/.git/config")) return Promise.resolve(mockResponse(200, "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]"));
      if (u.includes("/backup.sql")) return Promise.resolve(mockResponse(200, "CREATE TABLE users (id INT PRIMARY KEY);"));
      return Promise.resolve(mockResponse(404, "Not Found"));
    });

    const result = await runDirectoryScan("https://example.com", config);

    expect(result.scanner).toBe("directory");
    expect(result.findings.length).toBeGreaterThanOrEqual(3);

    const categories = result.findings.map((f) => f.category);
    expect(categories).toContain("admin-panel");
    expect(categories).toContain("config-exposure");
  });

  it("filters SPA catch-all responses", async () => {
    const spaShell = "<html><head><title>My App</title></head><body><div id='root'></div><script src='/app.js'></script></body></html>";

    mockFetch.mockImplementation((url: string) => {
      const u = typeof url === "string" ? url : String(url);
      // Baseline returns 200 with SPA shell
      if (u.includes("__penclaw_baseline")) return Promise.resolve(mockResponse(200, spaShell));
      // All paths return the same SPA shell
      return Promise.resolve(mockResponse(200, spaShell));
    });

    const result = await runDirectoryScan("https://example.com", config);

    // SPA filtering should remove all identical responses
    expect(result.findings.length).toBe(0);
  });

  it("includes 403 responses as low severity", async () => {
    mockFetch.mockImplementation((url: string) => {
      const u = typeof url === "string" ? url : String(url);
      if (u.includes("__penclaw_baseline")) return Promise.resolve(mockResponse(404, "Not Found"));
      if (u.includes("/admin")) return Promise.resolve(mockResponse(403, "Forbidden - Access Denied - You do not have permission"));
      return Promise.resolve(mockResponse(404, "Not Found"));
    });

    const result = await runDirectoryScan("https://example.com", config);

    const adminFinding = result.findings.find((f) => f.locations[0]?.path.includes("/admin"));
    expect(adminFinding).toBeDefined();
    expect(adminFinding!.severity).toBe("low");
  });

  it("handles fetch errors gracefully", async () => {
    mockFetch.mockImplementation(() => Promise.reject(new Error("ECONNREFUSED")));

    const result = await runDirectoryScan("https://example.com", config);

    expect(result.findings.length).toBe(0);
    expect(result.warnings.length).toBe(0); // Individual failures don't produce warnings
  });

  it("skips very short responses", async () => {
    mockFetch.mockImplementation((url: string) => {
      const u = typeof url === "string" ? url : String(url);
      if (u.includes("__penclaw_baseline")) return Promise.resolve(mockResponse(404, ""));
      return Promise.resolve(mockResponse(200, "OK")); // 2 chars — too short
    });

    const result = await runDirectoryScan("https://example.com", config);
    expect(result.findings.length).toBe(0);
  });
});
