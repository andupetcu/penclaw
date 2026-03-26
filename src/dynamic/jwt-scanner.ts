import type { CrawlResult, DynamicScanConfig, RawFinding, ScannerResult } from "../types/index.js";
import { createHmac } from "node:crypto";

const JWT_REGEX = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g;

const COMMON_SECRETS = [
  "", "secret", "password", "key", "123456", "jwt_secret", "changeme",
  "admin", "test", "default", "jwt", "token", "s3cr3t", "pass",
  "qwerty", "letmein", "welcome", "monkey", "abc123", "supersecret",
];

// --- Base64url helpers (no deps) ---

function base64urlEncode(data: string): string {
  return Buffer.from(data, "utf-8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64urlDecode(str: string): string {
  // Restore standard base64
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4 !== 0) base64 += "=";
  return Buffer.from(base64, "base64").toString("utf-8");
}

function decodeJwtParts(jwt: string): { header: Record<string, unknown>; payload: Record<string, unknown>; signature: string } | null {
  const parts = jwt.split(".");
  if (parts.length < 2) return null;
  try {
    const header = JSON.parse(base64urlDecode(parts[0]!)) as Record<string, unknown>;
    const payload = JSON.parse(base64urlDecode(parts[1]!)) as Record<string, unknown>;
    return { header, payload, signature: parts[2] ?? "" };
  } catch {
    return null;
  }
}

function signHs256(headerB64: string, payloadB64: string, secret: string): string {
  const data = `${headerB64}.${payloadB64}`;
  return createHmac("sha256", secret)
    .update(data)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function buildToken(header: Record<string, unknown>, payload: Record<string, unknown>, secret?: string): string {
  const headerB64 = base64urlEncode(JSON.stringify(header));
  const payloadB64 = base64urlEncode(JSON.stringify(payload));
  if (secret === undefined) {
    // No signature (alg:none)
    return `${headerB64}.${payloadB64}.`;
  }
  const sig = signHs256(headerB64, payloadB64, secret);
  return `${headerB64}.${payloadB64}.${sig}`;
}

// --- JWT extraction ---

function extractJwts(crawlResult: CrawlResult): string[] {
  const jwts = new Set<string>();

  for (const page of crawlResult.pages) {
    // Check page URL for JWTs (rare but possible)
    for (const match of page.url.matchAll(JWT_REGEX)) {
      jwts.add(match[0]);
    }
  }

  for (const endpoint of crawlResult.endpoints) {
    if (endpoint.headers) {
      for (const value of Object.values(endpoint.headers)) {
        for (const match of value.matchAll(JWT_REGEX)) {
          jwts.add(match[0]);
        }
      }
    }
  }

  return [...jwts];
}

// --- Test functions ---

function checkMissingClaims(jwt: string, decoded: ReturnType<typeof decodeJwtParts>): RawFinding[] {
  if (!decoded) return [];
  const findings: RawFinding[] = [];
  const requiredClaims = ["exp", "iat", "iss"] as const;
  const missing = requiredClaims.filter((c) => !(c in decoded.payload));

  if (missing.length > 0) {
    findings.push({
      id: `jwt-missing-claims-${missing.join("-")}`,
      source: "jwt",
      ruleId: "jwt-missing-claims",
      title: `JWT missing recommended claims: ${missing.join(", ")}`,
      description: `The JWT is missing claims: ${missing.join(", ")}. These claims help prevent token misuse.`,
      severity: "low",
      category: "jwt-security",
      locations: [{ path: "JWT token", snippet: jwt.slice(0, 80) + "..." }],
      metadata: { missingClaims: missing },
    });
  }

  return findings;
}

function checkExpiredToken(jwt: string, decoded: ReturnType<typeof decodeJwtParts>): RawFinding[] {
  if (!decoded) return [];
  const findings: RawFinding[] = [];
  const exp = decoded.payload.exp;

  if (typeof exp === "number") {
    const now = Math.floor(Date.now() / 1000);
    if (exp < now) {
      findings.push({
        id: `jwt-expired-accepted`,
        source: "jwt",
        ruleId: "jwt-expired-accepted",
        title: "Expired JWT token found in use",
        description: `A JWT with exp=${exp} (expired ${Math.floor((now - exp) / 3600)} hours ago) was found being used. If the server accepts this token, it indicates missing expiration validation.`,
        severity: "high",
        category: "jwt-security",
        locations: [{ path: "JWT token", snippet: jwt.slice(0, 80) + "..." }],
        metadata: { exp, expiredAgo: now - exp },
      });
    }
  }

  return findings;
}

function buildAlgNoneTokens(decoded: ReturnType<typeof decodeJwtParts>): string[] {
  if (!decoded) return [];
  const tokens: string[] = [];
  for (const alg of ["none", "None", "NONE", "nOnE"]) {
    tokens.push(buildToken({ ...decoded.header, alg }, decoded.payload));
  }
  return tokens;
}

function checkAlgNoneVulnerability(jwt: string, decoded: ReturnType<typeof decodeJwtParts>): { tokens: string[]; finding: RawFinding } | null {
  if (!decoded) return null;
  const tokens = buildAlgNoneTokens(decoded);
  return {
    tokens,
    finding: {
      id: `jwt-alg-none-bypass`,
      source: "jwt",
      ruleId: "jwt-alg-none",
      title: "JWT alg:none bypass — token crafted for testing",
      description: `The JWT header alg was changed to "none" with an empty signature. If the server accepts this token on a protected endpoint, it is critically vulnerable to authentication bypass.`,
      severity: "critical",
      category: "jwt-security",
      locations: [{ path: "JWT token", snippet: tokens[0]?.slice(0, 80) + "..." }],
      metadata: { originalAlg: decoded.header.alg, testTokens: tokens },
    },
  };
}

function checkWeakSecret(jwt: string, decoded: ReturnType<typeof decodeJwtParts>): RawFinding[] {
  if (!decoded) return [];
  const alg = String(decoded.header.alg ?? "").toUpperCase();
  if (alg !== "HS256") return [];

  const parts = jwt.split(".");
  if (parts.length < 3) return [];

  const headerB64 = parts[0]!;
  const payloadB64 = parts[1]!;
  const originalSig = parts[2]!;

  for (const secret of COMMON_SECRETS) {
    const testSig = signHs256(headerB64, payloadB64, secret);
    if (testSig === originalSig) {
      return [{
        id: `jwt-weak-secret-${secret || "empty"}`,
        source: "jwt",
        ruleId: "jwt-weak-secret",
        title: `JWT signed with weak secret: "${secret || "(empty string)"}"`,
        description: `The JWT HS256 signature was successfully verified using the secret "${secret || "(empty string)"}". An attacker can forge arbitrary tokens.`,
        severity: "critical",
        category: "jwt-security",
        locations: [{ path: "JWT token", snippet: jwt.slice(0, 80) + "..." }],
        metadata: { secret, alg },
      }];
    }
  }

  return [];
}

// --- Main export ---

export async function testJwtSecurity(
  crawlResult: CrawlResult,
  _config: DynamicScanConfig,
): Promise<ScannerResult> {
  const startedAt = Date.now();
  const warnings: string[] = [];
  const findings: RawFinding[] = [];

  try {
    const jwts = extractJwts(crawlResult);

    if (jwts.length === 0) {
      return { scanner: "jwt", findings: [], warnings: [], executionMs: Date.now() - startedAt };
    }

    for (const jwt of jwts) {
      const decoded = decodeJwtParts(jwt);
      if (!decoded) continue;

      // Missing claims check
      findings.push(...checkMissingClaims(jwt, decoded));

      // Expired token check
      findings.push(...checkExpiredToken(jwt, decoded));

      // alg:none bypass — produce the finding with crafted tokens in metadata
      const algNone = checkAlgNoneVulnerability(jwt, decoded);
      if (algNone) {
        findings.push(algNone.finding);
      }

      // Weak secret brute force
      findings.push(...checkWeakSecret(jwt, decoded));
    }
  } catch (error) {
    warnings.push(`JWT testing failed: ${error instanceof Error ? error.message : String(error)}`);
  }

  return { scanner: "jwt", findings, warnings, executionMs: Date.now() - startedAt };
}

// Exported for testing
export { decodeJwtParts, buildToken, signHs256, base64urlEncode, base64urlDecode, extractJwts, COMMON_SECRETS };
