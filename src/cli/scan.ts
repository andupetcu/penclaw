import path from "node:path";
import ora from "ora";
import chalk from "chalk";
import type { PenClawConfig, RawFinding, ScanOptions, ScanReport, Severity, TargetProfile } from "../types/index.js";
import { loadConfig } from "../config/load-config.js";
import { profileTarget } from "../profiler/profile-target.js";
import { profileUrl } from "../profiler/url-profiler.js";
import { renderJsonReport } from "../reporters/json.js";
import { renderMarkdownReport } from "../reporters/markdown.js";
import { renderSarifReport } from "../reporters/sarif.js";
import { renderHtmlReport } from "../reporters/html.js";
import { runSecretScan } from "../scanners/secret-scanner.js";
import { runSemgrepScan } from "../scanners/semgrep-scanner.js";
import { runTrivyScan } from "../scanners/trivy-scanner.js";
import { runNucleiScan } from "../dynamic/nuclei-scanner.js";
import { runOwaspChecks } from "../dynamic/owasp-checks.js";
import { crawlTarget, verifyXss } from "../crawl/browser-crawler.js";
import { fuzzEndpoints } from "../crawl/api-fuzzer.js";
import { triageFindings } from "../triage/triage-findings.js";
import { ensureDirectory, writeTextFile } from "../utils/fs.js";
import { countFindings, severityWeight } from "../utils/severity.js";

export async function runScanCommand(options: ScanOptions): Promise<void> {
  const startedAt = Date.now();
  const spinner = ora({ text: "Loading PenClaw config", isSilent: false }).start();

  try {
    // Parse targets — could be mix of URLs and paths
    const targets = parseTargets(options.target);
    const cwdConfig = await loadConfig(process.cwd(), options.configPath);
    const mergedConfig = mergeConfig(cwdConfig, options);

    const allRawFindings: RawFinding[] = [];
    const allWarnings: string[] = [];
    let profile: TargetProfile | undefined;

    // Static scanning (filesystem targets)
    for (const fsTarget of targets.paths) {
      const resolvedTarget = path.resolve(fsTarget);

      spinner.text = `Profiling ${resolvedTarget}`;
      const targetConfig = options.configPath ? {} : await loadConfig(resolvedTarget, undefined);
      const localConfig = mergeConfig({ ...targetConfig, ...mergedConfig }, options);

      const fsProfile = await profileTarget(resolvedTarget, localConfig);
      if (!profile) profile = fsProfile;

      if (localConfig.scan?.static !== false) {
        spinner.text = `Running static scanners on ${path.basename(resolvedTarget)}`;
        const scannerResults = await Promise.all([
          runTrivyScan(resolvedTarget, localConfig),
          runSemgrepScan(resolvedTarget, localConfig),
          runSecretScan(resolvedTarget, localConfig),
        ]);

        allRawFindings.push(...scannerResults.flatMap((r) => r.findings));
        allWarnings.push(...scannerResults.flatMap((r) => r.warnings));
      }
    }

    // Dynamic scanning (URL targets)
    const doDynamic = mergedConfig.scan?.dynamic === true;

    for (const urlTarget of targets.urls) {
      spinner.text = `Profiling ${urlTarget}`;
      const urlProfile = await profileUrl(urlTarget);
      if (!profile) profile = urlProfile;

      if (doDynamic && urlProfile.url) {
        // Nuclei scanning
        spinner.text = `Running Nuclei templates on ${urlTarget}`;
        const nucleiResult = await runNucleiScan(urlTarget, mergedConfig);
        allRawFindings.push(...nucleiResult.findings);
        allWarnings.push(...nucleiResult.warnings);

        // OWASP header + endpoint checks
        spinner.text = `Running OWASP checks on ${urlTarget}`;
        const owaspResult = await runOwaspChecks(urlProfile.url);
        allRawFindings.push(...owaspResult.findings);
        allWarnings.push(...owaspResult.warnings);

        // Playwright crawl + XSS verification
        spinner.text = `Crawling ${urlTarget}`;
        const crawlResult = await crawlTarget({
          baseUrl: urlTarget,
          maxPages: 50,
          maxCrawlDepth: 3,
        });

        if (crawlResult.forms.length > 0) {
          spinner.text = `Verifying XSS on ${crawlResult.forms.length} forms`;
          const xssResult = await verifyXss(urlTarget, crawlResult.forms);
          allRawFindings.push(...xssResult.findings);
          allWarnings.push(...xssResult.warnings);
        }

        // API fuzzing
        if (crawlResult.endpoints.length > 0) {
          spinner.text = `Fuzzing ${crawlResult.endpoints.length} API endpoints`;
          const fuzzResult = await fuzzEndpoints(crawlResult.endpoints, urlTarget);
          allRawFindings.push(...fuzzResult.findings);
          allWarnings.push(...fuzzResult.warnings);
        }
      } else if (!doDynamic && targets.urls.length > 0) {
        allWarnings.push("URL target provided but dynamic scanning is disabled. Use --dynamic or --full to enable.");
      }
    }

    // If no profile was created (no valid targets), error out
    if (!profile) {
      throw new Error("No valid targets to scan.");
    }

    // Triage all findings (static + dynamic)
    spinner.text = "Triaging findings";
    const triage = await triageFindings(allRawFindings, profile, mergedConfig.ai);
    allWarnings.push(...triage.warnings);

    const report: ScanReport = {
      tool: { name: "PenClaw", version: "0.1.0" },
      generatedAt: new Date().toISOString(),
      durationMs: Date.now() - startedAt,
      targetProfile: profile,
      findings: triage.findings,
      rawFindings: allRawFindings,
      warnings: allWarnings,
      counts: countFindings(triage.findings),
    };

    const format = resolveFormat(options, mergedConfig);
    const output = options.output ?? mergedConfig.output?.path;
    const rendered = renderReport(report, format);

    if (output) {
      await ensureDirectory(output);
      await writeTextFile(output, rendered);
    }

    spinner.succeed(`Scan complete: ${triage.findings.length} actionable findings`);
    printSummary(report, output, format);

    if (!output) {
      process.stdout.write(`${rendered}\n`);
    }

    // CI mode exit codes
    if (options.ci) {
      const exitCode = computeCiExitCode(report, options.failOn ?? "high");
      if (exitCode > 0) {
        process.exitCode = exitCode;
      }
    }
  } catch (error) {
    spinner.fail(`Scan failed: ${getErrorMessage(error)}`);
    process.exitCode = 1;
  }
}

interface ParsedTargets {
  paths: string[];
  urls: string[];
}

function parseTargets(target: string): ParsedTargets {
  const parts = target.split(/\s+/).filter(Boolean);
  const paths: string[] = [];
  const urls: string[] = [];

  for (const part of parts) {
    if (/^https?:\/\//i.test(part) || /^[a-z0-9][\w.-]*\.[a-z]{2,}/i.test(part)) {
      urls.push(part);
    } else {
      paths.push(part);
    }
  }

  return { paths, urls };
}

function mergeConfig(config: PenClawConfig, options: ScanOptions): PenClawConfig {
  return {
    ...config,
    target: {
      ...config.target,
      source: options.target,
    },
    ai: {
      ...config.ai,
      provider: options.provider ?? config.ai?.provider,
      model: options.model ?? config.ai?.model,
    },
    output: {
      ...config.output,
      format: options.format ?? config.output?.format,
      path: options.output ?? config.output?.path,
    },
    scan: {
      ...config.scan,
      dynamic: options.dynamic ?? options.full ?? config.scan?.dynamic ?? false,
      static: config.scan?.static ?? true,
    },
  };
}

function resolveFormat(options: ScanOptions, config: PenClawConfig): "markdown" | "json" | "sarif" | "html" {
  if (options.format) return options.format;

  const outputPath = options.output ?? config.output?.path;
  if (outputPath?.endsWith(".json")) return "json";
  if (outputPath?.endsWith(".sarif")) return "sarif";
  if (outputPath?.endsWith(".html")) return "html";

  return config.output?.format ?? "markdown";
}

function renderReport(report: ScanReport, format: "markdown" | "json" | "sarif" | "html"): string {
  switch (format) {
    case "json":
      return renderJsonReport(report);
    case "sarif":
      return renderSarifReport(report);
    case "html":
      return renderHtmlReport(report);
    default:
      return renderMarkdownReport(report);
  }
}

function computeCiExitCode(report: ScanReport, failOn: Severity): number {
  const threshold = severityWeight(failOn);
  const hasCritical = report.counts.critical > 0;
  const hasAboveThreshold = report.findings.some(
    (f) => severityWeight(f.severity) >= threshold,
  );

  if (hasCritical) return 2;
  if (hasAboveThreshold) return 1;
  return 0;
}

function printSummary(report: ScanReport, output: string | undefined, format: string): void {
  process.stdout.write(`${chalk.bold("PenClaw")} analyzed ${report.targetProfile.fileCount} files.\n`);
  process.stdout.write(
    `${chalk.red(`critical ${report.counts.critical}`)}  ${chalk.hex("#ff8c00")(`high ${report.counts.high}`)}  ${chalk.yellow(
      `medium ${report.counts.medium}`,
    )}  ${chalk.blue(`low ${report.counts.low}`)}  ${chalk.gray(`info ${report.counts.info}`)}\n`,
  );

  if (report.warnings.length > 0) {
    process.stdout.write(`${chalk.yellow("Warnings:")}\n`);
    for (const warning of report.warnings) {
      process.stdout.write(`- ${warning}\n`);
    }
  }

  if (output) {
    process.stdout.write(`Report written to ${output} (${format}).\n`);
  }
}

function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
