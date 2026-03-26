import type { PenClawConfig, RawFinding, ScannerResult } from "../types/index.js";
import { loadDirectoryPaths } from "../utils/payloads.js";
import { Semaphore, isSimilarResponse, fetchWithDelay, fetchSpaBaseline } from "../utils/http.js";

interface DirectoryFinding {
  path: string;
  status: number;
  category: string;
  severity: "critical" | "high" | "medium" | "low";
  snippet: string;
}

const categoryRules: Array<{
  pattern: RegExp;
  category: string;
  severity: "critical" | "high" | "medium" | "low";
}> = [
  { pattern: /\.(bak|backup|old|orig|save|swp|sav|copy|tmp)$/i, category: "backup-file", severity: "critical" },
  { pattern: /\.(sql|dump|db|sqlite|mdb)$/i, category: "backup-file", severity: "critical" },
  { pattern: /\.(zip|tar|gz|tgz|rar|7z)$/i, category: "backup-file", severity: "critical" },
  { pattern: /\.env|\.env\.|config\.(php|yml|yaml|json|xml|ini|toml)|web\.config|settings\.py|application\.properties/i, category: "config-exposure", severity: "high" },
  { pattern: /wp-config|database\.yml|credentials|\.htpasswd/i, category: "config-exposure", severity: "high" },
  { pattern: /admin|manager|cpanel|phpmyadmin|adminer|dashboard/i, category: "admin-panel", severity: "high" },
  { pattern: /swagger|api-doc|graphi?ql|redoc|openapi/i, category: "api-docs", severity: "medium" },
  { pattern: /debug|trace|phpinfo|server-status|server-info|elmah|actuator/i, category: "debug-endpoint", severity: "high" },
  { pattern: /\.git|\.svn|\.hg|\.bzr|CVS/i, category: "vcs-exposure", severity: "high" },
  { pattern: /\.github|\.gitlab|jenkins|\.circleci|\.travis/i, category: "ci-artifact", severity: "medium" },
];

function categorize(path: string): { category: string; severity: "critical" | "high" | "medium" | "low" } {
  for (const rule of categoryRules) {
    if (rule.pattern.test(path)) {
      return { category: rule.category, severity: rule.severity };
    }
  }
  return { category: "discovered-path", severity: "medium" };
}

export async function runDirectoryScan(
  baseUrl: string,
  config: PenClawConfig,
): Promise<ScannerResult> {
  const startedAt = Date.now();
  const warnings: string[] = [];
  const findings: RawFinding[] = [];

  try {
    const paths = loadDirectoryPaths();
    const concurrency = config.scan?.maxConcurrentRequests ?? 10;
    const delayMs = config.scan?.requestDelayMs ?? 0;
    const semaphore = new Semaphore(concurrency);

    // SPA baseline detection
    const baselineBody = await fetchSpaBaseline(baseUrl);

    const results: DirectoryFinding[] = [];

    const tasks = paths.map((dirPath) =>
      semaphore.run(async () => {
        try {
          const url = new URL(dirPath, baseUrl).href;
          const { status, body } = await fetchWithDelay(url, { delayMs, timeoutMs: 5_000 });

          // Only interested in 200 and 403
          if (status !== 200 && status !== 403) return;

          // Skip empty or trivially short responses
          if (body.length <= 10) return;

          // Skip HTML 404/error pages served with 200 status
          if (/<html.*<title>404/i.test(body)) return;

          // SPA detection
          if (status === 200 && baselineBody && isSimilarResponse(body, baselineBody)) return;

          const { category, severity } = categorize(dirPath);

          results.push({
            path: dirPath,
            status,
            category,
            severity,
            snippet: body.slice(0, 200),
          });
        } catch {
          // Request failed — skip
        }
      }),
    );

    await Promise.all(tasks);

    for (const result of results) {
      const url = new URL(result.path, baseUrl).href;
      findings.push({
        id: `dir-${result.path.replace(/\W/g, "-")}`,
        source: "directory",
        ruleId: `directory-${result.category}`,
        title: `Discovered ${result.category}: ${result.path}`,
        description: `Directory scan found ${result.path} (HTTP ${result.status}). Category: ${result.category}.`,
        severity: result.status === 403 ? "low" : result.severity,
        category: result.category,
        locations: [{ path: url, snippet: result.snippet }],
        metadata: { statusCode: result.status, technique: "directory-bruteforce" },
      });
    }
  } catch (error) {
    warnings.push(`Directory scan failed: ${error instanceof Error ? error.message : String(error)}`);
  }

  return { scanner: "directory", findings, warnings, executionMs: Date.now() - startedAt };
}
