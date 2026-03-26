import { describe, it, expect } from "vitest";
import {
  decodeJwtParts,
  buildToken,
  signHs256,
  base64urlEncode,
  base64urlDecode,
  testJwtSecurity,
  COMMON_SECRETS,
} from "../src/dynamic/jwt-scanner.js";
import type { CrawlResult, DynamicScanConfig } from "../src/types/index.js";

describe("JWT base64url helpers", () => {
  it("encodes and decodes round-trip", () => {
    const original = '{"alg":"HS256","typ":"JWT"}';
    const encoded = base64urlEncode(original);
    expect(encoded).not.toContain("+");
    expect(encoded).not.toContain("/");
    expect(encoded).not.toContain("=");
    expect(base64urlDecode(encoded)).toBe(original);
  });

  it("handles special characters", () => {
    const data = "hello+world/foo=bar";
    expect(base64urlDecode(base64urlEncode(data))).toBe(data);
  });
});

describe("decodeJwtParts", () => {
  it("decodes a valid JWT", () => {
    const header = { alg: "HS256", typ: "JWT" };
    const payload = { sub: "1234567890", name: "Test", iat: 1516239022 };
    const jwt = buildToken(header, payload, "secret");

    const decoded = decodeJwtParts(jwt);
    expect(decoded).not.toBeNull();
    expect(decoded!.header.alg).toBe("HS256");
    expect(decoded!.payload.sub).toBe("1234567890");
  });

  it("returns null for invalid JWT", () => {
    expect(decodeJwtParts("not-a-jwt")).toBeNull();
    expect(decodeJwtParts("a.b")).toBeNull();
  });
});

describe("signHs256", () => {
  it("produces deterministic signatures", () => {
    const h = base64urlEncode('{"alg":"HS256","typ":"JWT"}');
    const p = base64urlEncode('{"sub":"test"}');
    const sig1 = signHs256(h, p, "mysecret");
    const sig2 = signHs256(h, p, "mysecret");
    expect(sig1).toBe(sig2);
  });

  it("different secrets produce different signatures", () => {
    const h = base64urlEncode('{"alg":"HS256","typ":"JWT"}');
    const p = base64urlEncode('{"sub":"test"}');
    expect(signHs256(h, p, "secret1")).not.toBe(signHs256(h, p, "secret2"));
  });
});

describe("buildToken", () => {
  it("builds alg:none token with empty signature", () => {
    const token = buildToken({ alg: "none", typ: "JWT" }, { sub: "test" });
    expect(token.endsWith(".")).toBe(true);
    const parts = token.split(".");
    expect(parts.length).toBe(3);
    expect(parts[2]).toBe("");
  });

  it("builds HS256 token with valid signature", () => {
    const header = { alg: "HS256", typ: "JWT" };
    const payload = { sub: "test", iat: 1000 };
    const token = buildToken(header, payload, "secret");
    const parts = token.split(".");
    expect(parts.length).toBe(3);
    expect(parts[2]!.length).toBeGreaterThan(0);

    // Verify the signature matches
    const expectedSig = signHs256(parts[0]!, parts[1]!, "secret");
    expect(parts[2]).toBe(expectedSig);
  });
});

describe("testJwtSecurity", () => {
  const config: DynamicScanConfig = { baseUrl: "https://example.com" };

  it("returns empty findings when no JWTs found", async () => {
    const crawlResult: CrawlResult = { pages: [], endpoints: [], forms: [] };
    const result = await testJwtSecurity(crawlResult, config);
    expect(result.scanner).toBe("jwt");
    expect(result.findings.length).toBe(0);
  });

  it("detects missing claims", async () => {
    // Token with no exp, no iss, no iat
    const token = buildToken(
      { alg: "HS256", typ: "JWT" },
      { sub: "user123" },
      "secret",
    );

    const crawlResult: CrawlResult = {
      pages: [],
      endpoints: [{
        url: "https://example.com/api/me",
        method: "GET",
        parameters: [],
        headers: { authorization: `Bearer ${token}` },
      }],
      forms: [],
    };

    const result = await testJwtSecurity(crawlResult, config);
    const missingClaimsFinding = result.findings.find((f) => f.ruleId === "jwt-missing-claims");
    expect(missingClaimsFinding).toBeDefined();
    expect(missingClaimsFinding!.severity).toBe("low");
  });

  it("detects expired token", async () => {
    const token = buildToken(
      { alg: "HS256", typ: "JWT" },
      { sub: "user123", exp: 1000000, iat: 999000, iss: "test" },
      "secret",
    );

    const crawlResult: CrawlResult = {
      pages: [],
      endpoints: [{
        url: "https://example.com/api/me",
        method: "GET",
        parameters: [],
        headers: { authorization: `Bearer ${token}` },
      }],
      forms: [],
    };

    const result = await testJwtSecurity(crawlResult, config);
    const expiredFinding = result.findings.find((f) => f.ruleId === "jwt-expired-accepted");
    expect(expiredFinding).toBeDefined();
    expect(expiredFinding!.severity).toBe("high");
  });

  it("produces alg:none bypass finding", async () => {
    const token = buildToken(
      { alg: "HS256", typ: "JWT" },
      { sub: "user123", exp: Math.floor(Date.now() / 1000) + 3600, iat: Math.floor(Date.now() / 1000), iss: "test" },
      "randomsecret",
    );

    const crawlResult: CrawlResult = {
      pages: [],
      endpoints: [{
        url: "https://example.com/api/me",
        method: "GET",
        parameters: [],
        headers: { authorization: `Bearer ${token}` },
      }],
      forms: [],
    };

    const result = await testJwtSecurity(crawlResult, config);
    const algNone = result.findings.find((f) => f.ruleId === "jwt-alg-none");
    expect(algNone).toBeDefined();
    expect(algNone!.severity).toBe("critical");
    expect(algNone!.metadata?.testTokens).toBeDefined();
  });

  it("detects weak secret", async () => {
    // Sign with "secret" — one of COMMON_SECRETS
    const token = buildToken(
      { alg: "HS256", typ: "JWT" },
      { sub: "admin", exp: Math.floor(Date.now() / 1000) + 3600, iat: Math.floor(Date.now() / 1000), iss: "test" },
      "secret",
    );

    expect(COMMON_SECRETS).toContain("secret");

    const crawlResult: CrawlResult = {
      pages: [],
      endpoints: [{
        url: "https://example.com/api/me",
        method: "GET",
        parameters: [],
        headers: { authorization: `Bearer ${token}` },
      }],
      forms: [],
    };

    const result = await testJwtSecurity(crawlResult, config);
    const weakSecret = result.findings.find((f) => f.ruleId === "jwt-weak-secret");
    expect(weakSecret).toBeDefined();
    expect(weakSecret!.severity).toBe("critical");
    expect(weakSecret!.title).toContain("secret");
  });

  it("does not flag strong secret", async () => {
    const token = buildToken(
      { alg: "HS256", typ: "JWT" },
      { sub: "admin", exp: Math.floor(Date.now() / 1000) + 3600, iat: Math.floor(Date.now() / 1000), iss: "test" },
      "a-very-long-and-secure-random-secret-key-2024!@#",
    );

    const crawlResult: CrawlResult = {
      pages: [],
      endpoints: [{
        url: "https://example.com/api/me",
        method: "GET",
        parameters: [],
        headers: { authorization: `Bearer ${token}` },
      }],
      forms: [],
    };

    const result = await testJwtSecurity(crawlResult, config);
    const weakSecret = result.findings.find((f) => f.ruleId === "jwt-weak-secret");
    expect(weakSecret).toBeUndefined();
  });

  it("extracts JWTs from page URLs", async () => {
    const token = buildToken(
      { alg: "HS256", typ: "JWT" },
      { sub: "user", exp: 1000, iat: 999, iss: "test" },
      "secret",
    );

    const crawlResult: CrawlResult = {
      pages: [{ url: `https://example.com/callback?token=${token}`, statusCode: 200, links: [] }],
      endpoints: [],
      forms: [],
    };

    const result = await testJwtSecurity(crawlResult, config);
    expect(result.findings.length).toBeGreaterThan(0);
  });
});
