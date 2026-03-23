import type { RawFinding, ScannerResult, UrlProfileInfo } from "../types/index.js";

export async function runOwaspChecks(urlInfo: UrlProfileInfo): Promise<ScannerResult> {
  const startedAt = Date.now();
  const warnings: string[] = [];
  const findings: RawFinding[] = [];

  try {
    findings.push(...checkSecurityHeaders(urlInfo));
    findings.push(...checkCookieSecurity(urlInfo));
    findings.push(...checkInformationDisclosure(urlInfo));
    findings.push(...await checkCommonEndpoints(urlInfo.baseUrl));
  } catch (error) {
    warnings.push(`OWASP checks failed: ${error instanceof Error ? error.message : String(error)}`);
  }

  return { scanner: "dynamic", findings, warnings, executionMs: Date.now() - startedAt };
}

function checkSecurityHeaders(urlInfo: UrlProfileInfo): RawFinding[] {
  const findings: RawFinding[] = [];
  const headers = urlInfo.headers;
  const baseUrl = urlInfo.baseUrl;

  const requiredHeaders: Array<{
    name: string;
    ruleId: string;
    title: string;
    severity: "high" | "medium" | "low";
    description: string;
  }> = [
    {
      name: "strict-transport-security",
      ruleId: "owasp-missing-hsts",
      title: "Missing HTTP Strict Transport Security header",
      severity: "medium",
      description: "The Strict-Transport-Security header is not set, allowing potential downgrade attacks.",
    },
    {
      name: "x-content-type-options",
      ruleId: "owasp-missing-xcto",
      title: "Missing X-Content-Type-Options header",
      severity: "low",
      description: "The X-Content-Type-Options header is not set to 'nosniff', allowing MIME-type sniffing.",
    },
    {
      name: "x-frame-options",
      ruleId: "owasp-missing-xfo",
      title: "Missing X-Frame-Options header",
      severity: "medium",
      description: "The X-Frame-Options header is not set, making the application vulnerable to clickjacking.",
    },
    {
      name: "content-security-policy",
      ruleId: "owasp-missing-csp",
      title: "Missing Content-Security-Policy header",
      severity: "medium",
      description: "No Content-Security-Policy header is set, increasing risk of XSS and data injection attacks.",
    },
    {
      name: "x-xss-protection",
      ruleId: "owasp-missing-xxp",
      title: "Missing X-XSS-Protection header",
      severity: "low",
      description: "The X-XSS-Protection header is not set. While deprecated in modern browsers, its absence may affect older clients.",
    },
    {
      name: "referrer-policy",
      ruleId: "owasp-missing-referrer-policy",
      title: "Missing Referrer-Policy header",
      severity: "low",
      description: "The Referrer-Policy header is not set, potentially leaking URL information to third parties.",
    },
    {
      name: "permissions-policy",
      ruleId: "owasp-missing-permissions-policy",
      title: "Missing Permissions-Policy header",
      severity: "low",
      description: "The Permissions-Policy header is not set, allowing unrestricted access to browser features.",
    },
  ];

  for (const required of requiredHeaders) {
    if (!headers[required.name]) {
      findings.push({
        id: `owasp-${required.ruleId}-${baseUrl}`,
        source: "dynamic",
        ruleId: required.ruleId,
        title: required.title,
        description: required.description,
        severity: required.severity,
        category: "security-header",
        locations: [{ path: baseUrl }],
        references: ["https://owasp.org/www-project-secure-headers/"],
      });
    }
  }

  // Check for insecure CSP
  const csp = headers["content-security-policy"];
  if (csp && /unsafe-inline|unsafe-eval/i.test(csp)) {
    findings.push({
      id: `owasp-insecure-csp-${baseUrl}`,
      source: "dynamic",
      ruleId: "owasp-insecure-csp",
      title: "Insecure Content-Security-Policy directives",
      description: `The CSP contains unsafe directives: ${csp}`,
      severity: "medium",
      category: "security-header",
      locations: [{ path: baseUrl, snippet: csp }],
    });
  }

  return findings;
}

function checkCookieSecurity(urlInfo: UrlProfileInfo): RawFinding[] {
  const findings: RawFinding[] = [];
  const setCookie = urlInfo.headers["set-cookie"];
  if (!setCookie) return findings;

  const cookies = setCookie.split(/,(?=[^ ])/);
  for (const cookie of cookies) {
    const cookieName = cookie.split("=")[0]?.trim() ?? "unknown";

    if (!/;\s*Secure/i.test(cookie)) {
      findings.push({
        id: `owasp-cookie-no-secure-${cookieName}`,
        source: "dynamic",
        ruleId: "owasp-cookie-no-secure",
        title: `Cookie '${cookieName}' missing Secure flag`,
        description: "Cookie is transmitted over unencrypted connections.",
        severity: "medium",
        category: "cookie-security",
        locations: [{ path: urlInfo.baseUrl, snippet: cookie.trim() }],
      });
    }

    if (!/;\s*HttpOnly/i.test(cookie)) {
      findings.push({
        id: `owasp-cookie-no-httponly-${cookieName}`,
        source: "dynamic",
        ruleId: "owasp-cookie-no-httponly",
        title: `Cookie '${cookieName}' missing HttpOnly flag`,
        description: "Cookie is accessible via JavaScript, increasing XSS risk.",
        severity: "medium",
        category: "cookie-security",
        locations: [{ path: urlInfo.baseUrl, snippet: cookie.trim() }],
      });
    }

    if (!/;\s*SameSite/i.test(cookie)) {
      findings.push({
        id: `owasp-cookie-no-samesite-${cookieName}`,
        source: "dynamic",
        ruleId: "owasp-cookie-no-samesite",
        title: `Cookie '${cookieName}' missing SameSite attribute`,
        description: "Cookie lacks SameSite attribute, increasing CSRF risk.",
        severity: "low",
        category: "cookie-security",
        locations: [{ path: urlInfo.baseUrl, snippet: cookie.trim() }],
      });
    }
  }

  return findings;
}

function checkInformationDisclosure(urlInfo: UrlProfileInfo): RawFinding[] {
  const findings: RawFinding[] = [];
  const headers = urlInfo.headers;

  if (headers["server"] && /\/[\d.]+/.test(headers["server"])) {
    findings.push({
      id: `owasp-server-version-${urlInfo.baseUrl}`,
      source: "dynamic",
      ruleId: "owasp-server-version-disclosure",
      title: "Server version disclosed in headers",
      description: `The Server header reveals version information: ${headers["server"]}`,
      severity: "low",
      category: "information-disclosure",
      locations: [{ path: urlInfo.baseUrl, snippet: `Server: ${headers["server"]}` }],
    });
  }

  if (headers["x-powered-by"]) {
    findings.push({
      id: `owasp-powered-by-${urlInfo.baseUrl}`,
      source: "dynamic",
      ruleId: "owasp-x-powered-by-disclosure",
      title: "Technology stack disclosed via X-Powered-By",
      description: `The X-Powered-By header reveals: ${headers["x-powered-by"]}`,
      severity: "low",
      category: "information-disclosure",
      locations: [{ path: urlInfo.baseUrl, snippet: `X-Powered-By: ${headers["x-powered-by"]}` }],
    });
  }

  return findings;
}

async function checkCommonEndpoints(baseUrl: string): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const sensitiveEndpoints = [
    { path: "/.env", title: "Exposed .env file" },
    { path: "/.git/config", title: "Exposed .git directory" },
    { path: "/wp-admin/", title: "WordPress admin panel exposed" },
    { path: "/phpinfo.php", title: "PHP info page exposed" },
    { path: "/server-status", title: "Server status page exposed" },
    { path: "/actuator/health", title: "Spring Boot actuator exposed" },
    { path: "/.well-known/openid-configuration", title: "OpenID configuration exposed" },
    { path: "/api/swagger.json", title: "Swagger API documentation exposed" },
    { path: "/graphql", title: "GraphQL endpoint exposed" },
    { path: "/debug", title: "Debug endpoint exposed" },
  ];

  const checks = sensitiveEndpoints.map(async (endpoint) => {
    try {
      const url = new URL(endpoint.path, baseUrl).href;
      const response = await fetch(url, {
        method: "GET",
        redirect: "follow",
        signal: AbortSignal.timeout(5_000),
        headers: { "User-Agent": "PenClaw/0.1.0 Security Scanner" },
      });

      if (response.status === 200) {
        const body = await response.text();
        // Heuristic: if it returns HTML error page or empty, skip
        if (body.length > 10 && !/<html.*<title>404/i.test(body)) {
          findings.push({
            id: `owasp-endpoint-${endpoint.path.replace(/\W/g, "-")}`,
            source: "dynamic",
            ruleId: "owasp-sensitive-endpoint",
            title: endpoint.title,
            description: `The endpoint ${endpoint.path} returned a 200 response and may expose sensitive information.`,
            severity: endpoint.path.includes(".env") || endpoint.path.includes(".git")
              ? "high" : "medium",
            category: "information-disclosure",
            locations: [{ path: url, snippet: body.slice(0, 200) }],
          });
        }
      }
    } catch {
      // Endpoint unreachable — not a finding
    }
  });

  await Promise.all(checks);
  return findings;
}
