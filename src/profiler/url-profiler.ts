import type { TargetProfile, UrlProfileInfo } from "../types/index.js";

const techPatterns: Array<{ name: string; header?: string; pattern?: RegExp; meta?: RegExp }> = [
  { name: "Nginx", header: "server", pattern: /nginx/i },
  { name: "Apache", header: "server", pattern: /apache/i },
  { name: "Express", header: "x-powered-by", pattern: /express/i },
  { name: "ASP.NET", header: "x-powered-by", pattern: /asp\.net/i },
  { name: "PHP", header: "x-powered-by", pattern: /php/i },
  { name: "Next.js", header: "x-powered-by", pattern: /next\.js/i },
  { name: "Django", header: "x-framework", pattern: /django/i },
  { name: "Rails", header: "x-powered-by", pattern: /phusion|rails/i },
  { name: "Cloudflare", header: "server", pattern: /cloudflare/i },
];

const htmlTechPatterns: Array<{ name: string; pattern: RegExp }> = [
  { name: "React", pattern: /react[-.]|__react|data-reactroot/i },
  { name: "Vue.js", pattern: /vue[-.]|__vue|data-v-/i },
  { name: "Angular", pattern: /ng-version|angular/i },
  { name: "jQuery", pattern: /jquery[.-]\d/i },
  { name: "WordPress", pattern: /wp-content|wp-includes/i },
  { name: "Drupal", pattern: /drupal|sites\/default/i },
  { name: "Laravel", pattern: /laravel/i },
  { name: "Bootstrap", pattern: /bootstrap[.-]\d/i },
  { name: "Tailwind CSS", pattern: /tailwindcss/i },
];

export async function profileUrl(baseUrl: string): Promise<TargetProfile> {
  const url = normalizeUrl(baseUrl);
  let response: Response;
  try {
    response = await fetch(url, {
      redirect: "follow",
      signal: AbortSignal.timeout(15_000),
      headers: { "User-Agent": "PenClaw/0.1.0 Security Scanner" },
    });
  } catch (error) {
    throw new Error(`Failed to reach ${url}: ${error instanceof Error ? error.message : String(error)}`);
  }

  const headers: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    headers[key] = value;
  });

  const body = await response.text();
  const technologies = detectTechnologies(headers, body);

  const urlInfo: UrlProfileInfo = {
    baseUrl: url,
    server: headers["server"],
    poweredBy: headers["x-powered-by"],
    technologies,
    headers,
    statusCode: response.status,
  };

  const frameworks = technologies.filter((t) =>
    ["Express", "Next.js", "Django", "Rails", "Laravel", "React", "Vue.js", "Angular"].includes(t),
  );

  return {
    target: url,
    type: "url",
    languages: [],
    frameworks,
    packageManagers: [],
    manifests: [],
    entryPoints: [url],
    fileCount: 0,
    url: urlInfo,
  };
}

function detectTechnologies(headers: Record<string, string>, body: string): string[] {
  const detected = new Set<string>();

  for (const tech of techPatterns) {
    if (tech.header && tech.pattern) {
      const value = headers[tech.header];
      if (value && tech.pattern.test(value)) {
        detected.add(tech.name);
      }
    }
  }

  for (const tech of htmlTechPatterns) {
    if (tech.pattern.test(body)) {
      detected.add(tech.name);
    }
  }

  // Cookie-based detection
  const cookies = headers["set-cookie"] ?? "";
  if (/PHPSESSID/i.test(cookies)) detected.add("PHP");
  if (/JSESSIONID/i.test(cookies)) detected.add("Java");
  if (/ASP\.NET_SessionId/i.test(cookies)) detected.add("ASP.NET");
  if (/csrftoken/i.test(cookies) && /sessionid/i.test(cookies)) detected.add("Django");
  if (/_rails_session/i.test(cookies)) detected.add("Rails");

  return [...detected];
}

function normalizeUrl(input: string): string {
  if (!/^https?:\/\//i.test(input)) {
    return `https://${input}`;
  }
  return input;
}
