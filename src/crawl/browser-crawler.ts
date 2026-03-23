import type { CrawlResult, CrawledPage, DynamicScanConfig, DiscoveredEndpoint, DiscoveredForm, RawFinding, ScannerResult } from "../types/index.js";

let playwright: typeof import("playwright") | null = null;

async function loadPlaywright(): Promise<typeof import("playwright") | null> {
  try {
    return await import("playwright");
  } catch {
    return null;
  }
}

export async function crawlTarget(config: DynamicScanConfig): Promise<CrawlResult> {
  playwright = await loadPlaywright();
  if (!playwright) {
    return { pages: [], endpoints: [], forms: [] };
  }

  const maxPages = config.maxPages ?? 50;
  const maxDepth = config.maxCrawlDepth ?? 3;
  const visited = new Set<string>();
  const pages: CrawledPage[] = [];
  const endpoints: DiscoveredEndpoint[] = [];
  const forms: DiscoveredForm[] = [];
  const queue: Array<{ url: string; depth: number }> = [{ url: config.baseUrl, depth: 0 }];

  const browser = await playwright.chromium.launch({ headless: true });
  const context = await browser.newContext({
    userAgent: "PenClaw/0.1.0 Security Scanner",
    ignoreHTTPSErrors: true,
  });

  // Handle auth if configured
  if (config.auth?.bearerToken) {
    await context.setExtraHTTPHeaders({
      Authorization: `Bearer ${config.auth.bearerToken}`,
    });
  } else if (config.auth?.cookieHeader) {
    const cookies = parseCookieHeader(config.auth.cookieHeader, config.baseUrl);
    if (cookies.length > 0) {
      await context.addCookies(cookies);
    }
  } else if (config.auth?.loginUrl && config.auth?.username && config.auth?.password) {
    await performLogin(context, config.auth.loginUrl, config.auth.username, config.auth.password);
  }

  // Intercept API calls
  context.on("request", (request) => {
    const url = request.url();
    const method = request.method();
    if (isApiEndpoint(url) && !endpoints.some((e) => e.url === url && e.method === method)) {
      endpoints.push({ url, method, parameters: extractQueryParams(url) });
    }
  });

  try {
    while (queue.length > 0 && pages.length < maxPages) {
      const item = queue.shift()!;
      const normalized = normalizeUrl(item.url);
      if (visited.has(normalized) || item.depth > maxDepth) continue;
      if (!isSameOrigin(normalized, config.baseUrl)) continue;

      visited.add(normalized);

      try {
        const page = await context.newPage();
        const response = await page.goto(normalized, {
          waitUntil: "domcontentloaded",
          timeout: 10_000,
        });

        if (!response) {
          await page.close();
          continue;
        }

        const title = await page.title().catch(() => undefined);
        const links = await extractLinks(page, config.baseUrl);
        const pageForms = await extractForms(page, normalized);

        pages.push({
          url: normalized,
          statusCode: response.status(),
          title,
          links,
        });

        forms.push(...pageForms);

        for (const link of links) {
          if (!visited.has(normalizeUrl(link))) {
            queue.push({ url: link, depth: item.depth + 1 });
          }
        }

        await page.close();
      } catch {
        // Page navigation failed — skip
      }
    }
  } finally {
    await browser.close();
  }

  return { pages, endpoints, forms };
}

export async function verifyXss(
  baseUrl: string,
  forms: DiscoveredForm[],
): Promise<ScannerResult> {
  const startedAt = Date.now();
  const warnings: string[] = [];
  const findings: RawFinding[] = [];

  playwright = await loadPlaywright();
  if (!playwright) {
    warnings.push("Playwright not available; skipping XSS verification.");
    return { scanner: "dynamic", findings, warnings, executionMs: Date.now() - startedAt };
  }

  const xssPayloads = [
    '<script>alert("XSS")</script>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    "'-alert(1)-'",
  ];

  const browser = await playwright.chromium.launch({ headless: true });
  const context = await browser.newContext({
    userAgent: "PenClaw/0.1.0 Security Scanner",
    ignoreHTTPSErrors: true,
  });

  try {
    for (const form of forms.slice(0, 20)) {
      for (const payload of xssPayloads) {
        try {
          const page = await context.newPage();
          let alertTriggered = false;

          page.on("dialog", async (dialog) => {
            alertTriggered = true;
            await dialog.dismiss();
          });

          await page.goto(form.pageUrl, { waitUntil: "domcontentloaded", timeout: 8_000 });

          for (const input of form.inputs) {
            if (input.type === "submit" || input.type === "hidden") continue;
            try {
              await page.fill(`[name="${input.name}"]`, payload);
            } catch {
              // Input not fillable
            }
          }

          try {
            await page.click('[type="submit"]', { timeout: 3_000 });
            await page.waitForTimeout(1_000);
          } catch {
            // No submit button
          }

          const pageContent = await page.content();
          const reflected = pageContent.includes(payload);

          if (alertTriggered || reflected) {
            findings.push({
              id: `xss-${form.action}-${form.inputs[0]?.name ?? "unknown"}`,
              source: "dynamic",
              ruleId: alertTriggered ? "xss-verified" : "xss-reflected",
              title: alertTriggered
                ? "Verified XSS — JavaScript execution confirmed"
                : "Reflected input detected — potential XSS",
              description: `Form at ${form.pageUrl} (action: ${form.action}) ${
                alertTriggered ? "executed injected JavaScript" : "reflected user input without sanitization"
              }.`,
              severity: alertTriggered ? "high" : "medium",
              category: "xss",
              locations: [{ path: form.pageUrl, snippet: payload }],
              metadata: {
                formAction: form.action,
                alertTriggered,
                reflected,
                payload,
              },
            });

            await page.close();
            break; // One confirmed payload per form is enough
          }

          await page.close();
        } catch {
          // XSS check failed for this form/payload
        }
      }
    }
  } finally {
    await browser.close();
  }

  return { scanner: "dynamic", findings, warnings, executionMs: Date.now() - startedAt };
}

async function performLogin(
  context: import("playwright").BrowserContext,
  loginUrl: string,
  username: string,
  password: string,
): Promise<void> {
  const page = await context.newPage();
  try {
    await page.goto(loginUrl, { waitUntil: "domcontentloaded", timeout: 10_000 });

    // Try common username field selectors
    const usernameSelectors = [
      'input[name="username"]', 'input[name="email"]', 'input[name="user"]',
      'input[type="email"]', 'input[id="username"]', 'input[id="email"]',
    ];
    const passwordSelectors = [
      'input[name="password"]', 'input[type="password"]', 'input[id="password"]',
    ];

    for (const sel of usernameSelectors) {
      try { await page.fill(sel, username); break; } catch { /* skip */ }
    }
    for (const sel of passwordSelectors) {
      try { await page.fill(sel, password); break; } catch { /* skip */ }
    }

    try {
      await page.click('[type="submit"]', { timeout: 3_000 });
      await page.waitForLoadState("domcontentloaded", { timeout: 5_000 });
    } catch {
      // Submit not found or navigation failed
    }
  } finally {
    await page.close();
  }
}

async function extractLinks(page: import("playwright").Page, baseUrl: string): Promise<string[]> {
  const hrefs = await page.$$eval("a[href]", (anchors) =>
    anchors.map((a) => a.getAttribute("href")).filter(Boolean) as string[],
  );

  return hrefs
    .map((href) => {
      try { return new URL(href, baseUrl).href; } catch { return null; }
    })
    .filter((url): url is string => url !== null && isSameOrigin(url, baseUrl));
}

async function extractForms(page: import("playwright").Page, pageUrl: string): Promise<DiscoveredForm[]> {
  return page.$$eval("form", (formElements, currentUrl) => {
    return formElements.map((form) => {
      const inputs = Array.from(form.querySelectorAll("input, textarea, select")).map((el) => ({
        name: el.getAttribute("name") ?? "",
        type: el.getAttribute("type") ?? (el.tagName === "TEXTAREA" ? "textarea" : "text"),
        value: el.getAttribute("value") ?? undefined,
      }));
      return {
        action: form.getAttribute("action") ?? currentUrl,
        method: (form.getAttribute("method") ?? "GET").toUpperCase(),
        inputs,
        pageUrl: currentUrl,
      };
    });
  }, pageUrl);
}

function normalizeUrl(url: string): string {
  try {
    const parsed = new URL(url);
    parsed.hash = "";
    return parsed.href;
  } catch {
    return url;
  }
}

function isSameOrigin(url: string, baseUrl: string): boolean {
  try {
    return new URL(url).origin === new URL(baseUrl).origin;
  } catch {
    return false;
  }
}

function isApiEndpoint(url: string): boolean {
  return /\/api\/|\/graphql|\.json$/i.test(url);
}

function extractQueryParams(url: string): string[] {
  try {
    return [...new URL(url).searchParams.keys()];
  } catch {
    return [];
  }
}

function parseCookieHeader(
  cookieStr: string,
  baseUrl: string,
): Array<{ name: string; value: string; domain: string; path: string }> {
  try {
    const domain = new URL(baseUrl).hostname;
    return cookieStr.split(";").map((pair) => {
      const [name, ...rest] = pair.trim().split("=");
      return { name: name?.trim() ?? "", value: rest.join("=").trim(), domain, path: "/" };
    }).filter((c) => c.name.length > 0);
  } catch {
    return [];
  }
}
