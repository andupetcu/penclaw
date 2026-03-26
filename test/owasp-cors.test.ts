import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { checkCorsMisconfiguration, checkCsrfProtection } from "../src/dynamic/owasp-checks.js";
import type { DiscoveredForm, UrlProfileInfo } from "../src/types/index.js";

// Mock global fetch
const mockFetch = vi.fn();

beforeEach(() => {
  vi.stubGlobal("fetch", mockFetch);
});

afterEach(() => {
  vi.restoreAllMocks();
});

function makeUrlInfo(headers: Record<string, string> = {}): UrlProfileInfo {
  return {
    baseUrl: "https://example.com",
    technologies: [],
    headers,
    statusCode: 200,
  };
}

describe("checkCorsMisconfiguration", () => {
  it("detects reflected arbitrary origin", async () => {
    mockFetch.mockResolvedValue({
      headers: new Map([
        ["access-control-allow-origin", "https://evil.com"],
        ["access-control-allow-credentials", "false"],
      ]) as unknown as Headers,
    });

    // Override headers.get for proper Headers API
    mockFetch.mockResolvedValue({
      headers: {
        get: (name: string) => {
          if (name === "access-control-allow-origin") return "https://evil.com";
          if (name === "access-control-allow-credentials") return "false";
          return null;
        },
      },
    });

    const findings = await checkCorsMisconfiguration(makeUrlInfo());
    const corsFindings = findings.filter((f) => f.ruleId === "owasp-cors-misconfiguration");
    expect(corsFindings.length).toBeGreaterThanOrEqual(1);
    expect(corsFindings[0]!.severity).toBe("medium");
  });

  it("detects reflected origin with credentials (high severity)", async () => {
    mockFetch.mockResolvedValue({
      headers: {
        get: (name: string) => {
          if (name === "access-control-allow-origin") return "https://evil.com";
          if (name === "access-control-allow-credentials") return "true";
          return null;
        },
      },
    });

    const findings = await checkCorsMisconfiguration(makeUrlInfo());
    const highFindings = findings.filter((f) => f.severity === "high");
    expect(highFindings.length).toBeGreaterThanOrEqual(1);
  });

  it("does not flag when origin is not reflected", async () => {
    mockFetch.mockResolvedValue({
      headers: {
        get: () => null,
      },
    });

    const findings = await checkCorsMisconfiguration(makeUrlInfo());
    expect(findings.length).toBe(0);
  });

  it("detects wildcard ACAO", async () => {
    mockFetch.mockResolvedValue({
      headers: {
        get: (name: string) => {
          if (name === "access-control-allow-origin") return "*";
          return null;
        },
      },
    });

    const findings = await checkCorsMisconfiguration(makeUrlInfo());
    // Wildcard matches when we check acao === "*"
    // It won't match the specific origin tests but will match for those where origin === acao is false
    // Actually: acao === origin || acao === "*" — so * matches all 3 origins
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("handles fetch errors gracefully", async () => {
    mockFetch.mockRejectedValue(new Error("Network error"));

    const findings = await checkCorsMisconfiguration(makeUrlInfo());
    expect(findings.length).toBe(0);
  });
});

describe("checkCsrfProtection", () => {
  it("flags POST form without CSRF token", () => {
    const forms: DiscoveredForm[] = [
      {
        action: "/submit",
        method: "POST",
        inputs: [
          { name: "username", type: "text" },
          { name: "password", type: "password" },
        ],
        pageUrl: "https://example.com/login",
      },
    ];

    const findings = checkCsrfProtection(forms, makeUrlInfo());
    expect(findings.length).toBe(1);
    expect(findings[0]!.ruleId).toBe("owasp-missing-csrf-protection");
    expect(findings[0]!.severity).toBe("medium");
  });

  it("does not flag form with CSRF token", () => {
    const forms: DiscoveredForm[] = [
      {
        action: "/submit",
        method: "POST",
        inputs: [
          { name: "username", type: "text" },
          { name: "_csrf", type: "hidden" },
        ],
        pageUrl: "https://example.com/login",
      },
    ];

    const findings = checkCsrfProtection(forms, makeUrlInfo());
    expect(findings.length).toBe(0);
  });

  it("does not flag form with authenticity_token", () => {
    const forms: DiscoveredForm[] = [
      {
        action: "/submit",
        method: "POST",
        inputs: [
          { name: "data", type: "text" },
          { name: "authenticity_token", type: "hidden" },
        ],
        pageUrl: "https://example.com/form",
      },
    ];

    const findings = checkCsrfProtection(forms, makeUrlInfo());
    expect(findings.length).toBe(0);
  });

  it("skips GET forms", () => {
    const forms: DiscoveredForm[] = [
      {
        action: "/search",
        method: "GET",
        inputs: [{ name: "q", type: "text" }],
        pageUrl: "https://example.com/search",
      },
    ];

    const findings = checkCsrfProtection(forms, makeUrlInfo());
    expect(findings.length).toBe(0);
  });

  it("does not flag if SameSite cookie is present", () => {
    const forms: DiscoveredForm[] = [
      {
        action: "/submit",
        method: "POST",
        inputs: [{ name: "data", type: "text" }],
        pageUrl: "https://example.com/form",
      },
    ];

    const urlInfo = makeUrlInfo({ "set-cookie": "session=abc; SameSite=Lax; HttpOnly" });
    const findings = checkCsrfProtection(forms, urlInfo);
    expect(findings.length).toBe(0);
  });
});
