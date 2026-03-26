import type { DiscoveredEndpoint, DiscoveredForm, RawFinding, ScannerResult, UrlProfileInfo } from "../types/index.js";

export async function runOwaspChecks(
  urlInfo: UrlProfileInfo,
  forms?: DiscoveredForm[],
  endpoints?: DiscoveredEndpoint[],
): Promise<ScannerResult> {
  const startedAt = Date.now();
  const warnings: string[] = [];
  const findings: RawFinding[] = [];

  try {
    findings.push(...checkSecurityHeaders(urlInfo));
    findings.push(...checkCookieSecurity(urlInfo));
    findings.push(...checkInformationDisclosure(urlInfo));
    findings.push(...await checkCommonEndpoints(urlInfo.baseUrl));
    findings.push(...await checkCorsMisconfiguration(urlInfo));
    if (forms && forms.length > 0) {
      findings.push(...checkCsrfProtection(forms, urlInfo));
    }
    if (endpoints && endpoints.length > 0) {
      findings.push(...await checkOpenRedirect(urlInfo, endpoints));
    }
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
    { path: "/.env", title: "Exposed .env file", contentHint: /^\s*\w+=.+/m },
    { path: "/.git/config", title: "Exposed .git directory", contentHint: /\[core\]|\[remote/ },
    { path: "/wp-admin/", title: "WordPress admin panel exposed", contentHint: /wp-login|wordpress/i },
    { path: "/phpinfo.php", title: "PHP info page exposed", contentHint: /phpinfo|PHP Version|php\.ini/i },
    { path: "/server-status", title: "Server status page exposed", contentHint: /Apache Server Status|Server Version/i },
    { path: "/actuator/health", title: "Spring Boot actuator exposed", contentHint: /"status"\s*:\s*"(UP|DOWN)"/i },
    { path: "/.well-known/openid-configuration", title: "OpenID configuration exposed", contentHint: /"issuer"|"authorization_endpoint"/i },
    { path: "/api/swagger.json", title: "Swagger API documentation exposed", contentHint: /"swagger"|"openapi"/i },
    { path: "/graphql", title: "GraphQL endpoint exposed", contentHint: /"data"|"errors"|__schema/i },
    { path: "/debug", title: "Debug endpoint exposed", contentHint: /debug|stack\s*trace|traceback/i },
  ];

  // First, fetch a baseline response for a random non-existent path to detect SPA catch-all routing
  let baselineBody: string | null = null;
  try {
    const randomPath = `/__penclaw_baseline_${Date.now()}_${Math.random().toString(36).slice(2)}`;
    const baselineUrl = new URL(randomPath, baseUrl).href;
    const baselineResponse = await fetch(baselineUrl, {
      method: "GET",
      redirect: "follow",
      signal: AbortSignal.timeout(5_000),
      headers: { "User-Agent": "PenClaw/0.1.0 Security Scanner" },
    });
    if (baselineResponse.status === 200) {
      baselineBody = await baselineResponse.text();
    }
  } catch {
    // Could not establish baseline — proceed without it
  }

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

        // Skip empty or trivially short responses
        if (body.length <= 10) return;

        // Skip HTML 404/error pages
        if (/<html.*<title>404/i.test(body)) return;

        // SPA detection: if the response body is substantially similar to the
        // baseline (random non-existent path), this is a catch-all SPA route, not a real endpoint
        if (baselineBody && isSimilarResponse(body, baselineBody)) return;

        // Content-hint validation: check that the response actually looks like
        // what the endpoint is supposed to return (not just a generic SPA shell)
        if (endpoint.contentHint && !endpoint.contentHint.test(body)) return;

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
    } catch {
      // Endpoint unreachable — not a finding
    }
  });

  await Promise.all(checks);
  return findings;
}

// ---------------------------------------------------------------------------
// CORS Misconfiguration check
// ---------------------------------------------------------------------------

export async function checkCorsMisconfiguration(urlInfo: UrlProfileInfo): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const baseUrl = urlInfo.baseUrl;

  const origins = [
    { origin: "https://evil.com", label: "arbitrary origin" },
    { origin: "null", label: "null origin" },
    { origin: `https://${new URL(baseUrl).hostname}.evil.com`, label: "subdomain bypass" },
  ];

  for (const { origin, label } of origins) {
    try {
      const response = await fetch(baseUrl, {
        method: "GET",
        headers: {
          "User-Agent": "PenClaw/0.1.0 Security Scanner",
          "Origin": origin,
        },
        redirect: "follow",
        signal: AbortSignal.timeout(5_000),
      });

      const acao = response.headers.get("access-control-allow-origin");
      const acac = response.headers.get("access-control-allow-credentials");

      if (acao && (acao === origin || acao === "*")) {
        const hasCredentials = acac?.toLowerCase() === "true";
        findings.push({
          id: `owasp-cors-${label.replace(/\s+/g, "-")}-${baseUrl}`,
          source: "dynamic",
          ruleId: "owasp-cors-misconfiguration",
          title: `CORS misconfiguration: ${label} reflected`,
          description: `The server reflects the Origin header '${origin}' in Access-Control-Allow-Origin${hasCredentials ? " with credentials allowed" : ""}. This may allow cross-origin attacks.`,
          severity: hasCredentials ? "high" : "medium",
          category: "cors",
          locations: [{ path: baseUrl, snippet: `ACAO: ${acao}${hasCredentials ? ", ACAC: true" : ""}` }],
          references: ["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
          metadata: {
            testedOrigin: origin,
            reflectedOrigin: acao,
            credentialsAllowed: hasCredentials,
          },
        });
      }
    } catch {
      // Request failed — skip this origin test
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// CSRF Protection check
// ---------------------------------------------------------------------------

const CSRF_TOKEN_NAMES = /csrf|_token|authenticity_token|__requestverificationtoken|xsrf/i;

export function checkCsrfProtection(forms: DiscoveredForm[], urlInfo: UrlProfileInfo): RawFinding[] {
  const findings: RawFinding[] = [];

  const postForms = forms.filter((f) => f.method.toUpperCase() === "POST");

  for (const form of postForms) {
    const hasCsrfToken = form.inputs.some((input) => CSRF_TOKEN_NAMES.test(input.name));

    if (!hasCsrfToken) {
      // Check if cookies have SameSite protection
      const setCookie = urlInfo.headers["set-cookie"] ?? "";
      const hasSameSite = /SameSite=(Strict|Lax)/i.test(setCookie);

      if (!hasSameSite) {
        findings.push({
          id: `owasp-csrf-${form.action.replace(/\W/g, "-")}-${form.pageUrl.replace(/\W/g, "-")}`,
          source: "dynamic",
          ruleId: "owasp-missing-csrf-protection",
          title: `Missing CSRF protection on POST form`,
          description: `A POST form (action: ${form.action}) on ${form.pageUrl} has no CSRF token and no SameSite cookie protection.`,
          severity: "medium",
          category: "csrf",
          locations: [{ path: form.pageUrl, snippet: `action="${form.action}" method="POST"` }],
          references: ["https://owasp.org/www-community/attacks/csrf"],
          metadata: {
            formAction: form.action,
            formInputs: form.inputs.map((i) => i.name),
          },
        });
      }
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Open Redirect check
// ---------------------------------------------------------------------------

const REDIRECT_PARAM_PATTERN = /^(redirect|url|next|return|goto|continue|dest|redirect_uri|return_to|redir|forward)$/i;

const OPEN_REDIRECT_PAYLOADS = [
  "//evil.com",
  "https://evil.com",
  "/\\evil.com",
  "//evil.com/%2f..",
  "///evil.com",
  "////evil.com",
  "https:evil.com",
];

export async function checkOpenRedirect(
  urlInfo: UrlProfileInfo,
  endpoints: DiscoveredEndpoint[],
): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];

  for (const endpoint of endpoints) {
    const redirectParams = endpoint.parameters.filter((p) => REDIRECT_PARAM_PATTERN.test(p));
    if (redirectParams.length === 0) continue;

    for (const param of redirectParams) {
      for (const payload of OPEN_REDIRECT_PAYLOADS) {
        try {
          const urlObj = new URL(endpoint.url);
          urlObj.searchParams.set(param, payload);

          const response = await fetch(urlObj.href, {
            method: "GET",
            redirect: "manual",
            headers: { "User-Agent": "PenClaw/0.1.0 Security Scanner" },
            signal: AbortSignal.timeout(5_000),
          });

          const location = response.headers.get("location");
          if (location && isExternalRedirect(location)) {
            findings.push({
              id: `owasp-open-redirect-${param}-${endpoint.url.replace(/\W/g, "-")}`,
              source: "dynamic",
              ruleId: "owasp-open-redirect",
              title: `Open redirect via parameter '${param}'`,
              description: `The parameter '${param}' at ${endpoint.url} redirects to an external URL when injected with '${payload}'. Location: ${location}`,
              severity: "medium",
              category: "open-redirect",
              locations: [{ path: endpoint.url, snippet: `${param}=${payload} → ${location}` }],
              references: ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect"],
              metadata: {
                parameter: param,
                payload,
                redirectLocation: location,
              },
            });
            break; // One confirmed per param is enough
          }
        } catch {
          // Skip
        }
      }
    }
  }

  return findings;
}

function isExternalRedirect(location: string): boolean {
  // Check if the Location header points to a domain containing "evil.com"
  try {
    if (location.startsWith("//")) {
      const url = new URL(`https:${location}`);
      return url.hostname.includes("evil.com");
    }
    const url = new URL(location);
    return url.hostname.includes("evil.com");
  } catch {
    return location.includes("evil.com");
  }
}

/**
 * Compares two response bodies for similarity. Used to detect SPA catch-all routing
 * where every path returns the same HTML shell.
 */
function isSimilarResponse(bodyA: string, bodyB: string): boolean {
  // Exact match
  if (bodyA === bodyB) return true;

  // Length-based similarity — if both are HTML and within 5% size, likely the same SPA shell
  const lenA = bodyA.length;
  const lenB = bodyB.length;
  if (lenA === 0 || lenB === 0) return false;

  const ratio = Math.min(lenA, lenB) / Math.max(lenA, lenB);
  if (ratio < 0.9) return false;

  // Compare the first 500 chars (the <head> / shell is usually identical in SPAs)
  const headA = bodyA.slice(0, 500).replace(/\s+/g, " ");
  const headB = bodyB.slice(0, 500).replace(/\s+/g, " ");
  return headA === headB;
}
