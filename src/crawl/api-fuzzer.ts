import { request } from "undici";
import type { DiscoveredEndpoint, RawFinding, ScannerResult } from "../types/index.js";

const injectionPayloads = [
  { name: "sql-injection", payloads: ["' OR '1'='1", "1; DROP TABLE users--", "' UNION SELECT NULL--"], category: "injection" },
  { name: "nosql-injection", payloads: ['{"$gt":""}', '{"$ne":null}'], category: "injection" },
  { name: "command-injection", payloads: ["; ls /", "| cat /etc/passwd", "$(whoami)"], category: "injection" },
  { name: "path-traversal", payloads: ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam"], category: "path-traversal" },
  { name: "xss-reflected", payloads: ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>'], category: "xss" },
];

const authBypassHeaders: Array<{ name: string; headers: Record<string, string> }> = [
  { name: "X-Forwarded-For bypass", headers: { "X-Forwarded-For": "127.0.0.1" } },
  { name: "X-Original-URL bypass", headers: { "X-Original-URL": "/admin" } },
  { name: "X-Rewrite-URL bypass", headers: { "X-Rewrite-URL": "/admin" } },
];

export async function fuzzEndpoints(
  endpoints: DiscoveredEndpoint[],
  baseUrl: string,
): Promise<ScannerResult> {
  const startedAt = Date.now();
  const warnings: string[] = [];
  const findings: RawFinding[] = [];

  const limited = endpoints.slice(0, 30);

  try {
    for (const endpoint of limited) {
      findings.push(...await fuzzSingleEndpoint(endpoint));
      findings.push(...await testAuthBypass(endpoint));
      findings.push(...await testIdor(endpoint));
    }
  } catch (error) {
    warnings.push(`API fuzzing failed: ${error instanceof Error ? error.message : String(error)}`);
  }

  return { scanner: "fuzzer", findings, warnings, executionMs: Date.now() - startedAt };
}

async function fuzzSingleEndpoint(endpoint: DiscoveredEndpoint): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];

  for (const group of injectionPayloads) {
    for (const payload of group.payloads) {
      try {
        const url = buildFuzzedUrl(endpoint.url, endpoint.parameters, payload);
        const { statusCode, body: bodyStream } = await request(url, {
          method: endpoint.method as "GET" | "POST",
          headers: {
            "User-Agent": "PenClaw/0.1.0 Security Scanner",
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: endpoint.method === "POST" ? buildPostBody(endpoint.parameters, payload) : undefined,
          signal: AbortSignal.timeout(5_000),
        });

        const body = await bodyStream.text();

        if (isErrorResponse(body, group.name)) {
          findings.push({
            id: `fuzz-${group.name}-${endpoint.url}-${findings.length}`,
            source: "fuzzer",
            ruleId: `fuzzer-${group.name}`,
            title: `Potential ${group.name} in ${endpoint.url}`,
            description: `The endpoint ${endpoint.url} returned an error response when injected with a ${group.name} payload, suggesting the input is not properly sanitized.`,
            severity: group.category === "injection" ? "high" : "medium",
            category: group.category,
            locations: [{ path: endpoint.url, snippet: payload }],
            metadata: {
              statusCode,
              payload,
              method: endpoint.method,
              responseSnippet: body.slice(0, 300),
            },
          });
          break; // One confirmed payload per group per endpoint
        }
      } catch {
        // Request failed — skip
      }
    }
  }

  return findings;
}

async function testAuthBypass(endpoint: DiscoveredEndpoint): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];

  // First make an unauthenticated request
  let baselineStatus: number;
  try {
    const { statusCode } = await request(endpoint.url, {
      method: endpoint.method as "GET" | "POST",
      headers: { "User-Agent": "PenClaw/0.1.0 Security Scanner" },
      signal: AbortSignal.timeout(5_000),
    });
    baselineStatus = statusCode;
  } catch {
    return findings;
  }

  // If already accessible, no bypass needed
  if (baselineStatus === 200) return findings;

  // Try bypass headers
  for (const bypass of authBypassHeaders) {
    try {
      const { statusCode } = await request(endpoint.url, {
        method: endpoint.method as "GET" | "POST",
        headers: {
          "User-Agent": "PenClaw/0.1.0 Security Scanner",
          ...bypass.headers,
        },
        signal: AbortSignal.timeout(5_000),
      });

      if (statusCode === 200 && baselineStatus !== 200) {
        findings.push({
          id: `fuzz-auth-bypass-${bypass.name}-${endpoint.url}`,
          source: "fuzzer",
          ruleId: "fuzzer-auth-bypass",
          title: `Authentication bypass via ${bypass.name}`,
          description: `The endpoint ${endpoint.url} returned 200 when using ${bypass.name} header, but returned ${baselineStatus} without it.`,
          severity: "critical",
          category: "auth-bypass",
          locations: [{ path: endpoint.url, snippet: JSON.stringify(bypass.headers) }],
          metadata: { bypassMethod: bypass.name, baselineStatus, bypassStatus: statusCode },
        });
      }
    } catch {
      // Skip
    }
  }

  return findings;
}

async function testIdor(endpoint: DiscoveredEndpoint): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];

  // Look for numeric IDs in the URL
  const idMatch = endpoint.url.match(/\/(\d+)(?:\/|$|\?)/);
  if (!idMatch) return findings;

  const originalId = idMatch[1]!;
  const testIds = [
    String(Number(originalId) + 1),
    String(Number(originalId) - 1),
    "1",
    "0",
  ];

  try {
    const { statusCode: originalStatus, body: originalBody } = await request(endpoint.url, {
      method: "GET",
      headers: { "User-Agent": "PenClaw/0.1.0 Security Scanner" },
      signal: AbortSignal.timeout(5_000),
    });
    const originalText = await originalBody.text();

    if (originalStatus !== 200) return findings;

    for (const testId of testIds) {
      const testUrl = endpoint.url.replace(`/${originalId}`, `/${testId}`);
      try {
        const { statusCode, body: testBody } = await request(testUrl, {
          method: "GET",
          headers: { "User-Agent": "PenClaw/0.1.0 Security Scanner" },
          signal: AbortSignal.timeout(5_000),
        });
        const testText = await testBody.text();

        if (statusCode === 200 && testText !== originalText && testText.length > 50) {
          findings.push({
            id: `fuzz-idor-${endpoint.url}-${testId}`,
            source: "fuzzer",
            ruleId: "fuzzer-idor",
            title: `Potential IDOR: different data returned for ID ${testId}`,
            description: `Changing the ID parameter from ${originalId} to ${testId} returned different content, suggesting missing authorization checks.`,
            severity: "high",
            category: "idor",
            locations: [{ path: testUrl }],
            metadata: { originalId, testId, originalUrl: endpoint.url },
          });
          break;
        }
      } catch {
        // Skip
      }
    }
  } catch {
    // Skip
  }

  return findings;
}

function buildFuzzedUrl(url: string, params: string[], payload: string): string {
  if (params.length === 0) return url;
  const urlObj = new URL(url);
  for (const param of params) {
    urlObj.searchParams.set(param, payload);
  }
  return urlObj.href;
}

function buildPostBody(params: string[], payload: string): string {
  if (params.length === 0) return `test=${encodeURIComponent(payload)}`;
  return params.map((p) => `${encodeURIComponent(p)}=${encodeURIComponent(payload)}`).join("&");
}

function isErrorResponse(body: string, payloadType: string): boolean {
  const lower = body.toLowerCase();
  if (payloadType.includes("sql")) {
    return /sql.*error|syntax.*error|mysql|postgres|sqlite|ORA-\d|ODBC|unclosed.*quotation/i.test(body);
  }
  if (payloadType.includes("command")) {
    return /root:|bin\/|\/etc\/passwd|uid=\d|drwx/i.test(body);
  }
  if (payloadType.includes("path")) {
    return /root:|bin\/|\/etc\/passwd|\[boot loader\]|NTLDR/i.test(body);
  }
  if (payloadType.includes("xss")) {
    return body.includes("<script>alert(1)</script>") || body.includes('onerror=alert(1)');
  }
  return false;
}
