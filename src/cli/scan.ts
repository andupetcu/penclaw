import path from "node:path";
import ora from "ora";
import chalk from "chalk";
import type { PenClawConfig, ScanOptions, ScanReport } from "../types/index.js";
import { loadConfig } from "../config/load-config.js";
import { profileTarget } from "../profiler/profile-target.js";
import { renderJsonReport } from "../reporters/json.js";
import { renderMarkdownReport } from "../reporters/markdown.js";
import { runSecretScan } from "../scanners/secret-scanner.js";
import { runSemgrepScan } from "../scanners/semgrep-scanner.js";
import { runTrivyScan } from "../scanners/trivy-scanner.js";
import { triageFindings } from "../triage/triage-findings.js";
import { ensureDirectory, writeTextFile } from "../utils/fs.js";
import { countFindings } from "../utils/severity.js";

export async function runScanCommand(options: ScanOptions): Promise<void> {
  const startedAt = Date.now();
  const target = path.resolve(options.target);
  const spinner = ora({ text: `Loading PenClaw config for ${target}`, isSilent: false }).start();

  try {
    const cwdConfig = await loadConfig(process.cwd(), options.configPath);
    const targetConfig = options.configPath ? {} : await loadConfig(target, undefined);
    const mergedConfig = mergeConfig({ ...targetConfig, ...cwdConfig }, options);

    spinner.text = "Profiling target";
    const profile = await profileTarget(target, mergedConfig);

    spinner.text = "Running static scanners";
    const scannerResults = await Promise.all([
      runTrivyScan(target, mergedConfig),
      runSemgrepScan(target, mergedConfig),
      runSecretScan(target, mergedConfig),
    ]);

    spinner.text = "Triaging findings";
    const rawFindings = scannerResults.flatMap((result) => result.findings);
    const triage = await triageFindings(rawFindings, profile, mergedConfig.ai);
    const warnings = [...scannerResults.flatMap((result) => result.warnings), ...triage.warnings];

    const report: ScanReport = {
      tool: {
        name: "PenClaw",
        version: "0.1.0",
      },
      generatedAt: new Date().toISOString(),
      durationMs: Date.now() - startedAt,
      targetProfile: profile,
      findings: triage.findings,
      rawFindings,
      warnings,
      counts: countFindings(triage.findings),
    };

    const format = resolveFormat(options, mergedConfig);
    const output = options.output ?? mergedConfig.output?.path;
    const rendered = format === "json" ? renderJsonReport(report) : renderMarkdownReport(report);

    if (output) {
      await ensureDirectory(output);
      await writeTextFile(output, rendered);
    }

    spinner.succeed(`Scan complete: ${triage.findings.length} actionable findings`);
    printSummary(report, output, format);

    if (!output) {
      process.stdout.write(`${rendered}\n`);
    }
  } catch (error) {
    spinner.fail(`Scan failed: ${getErrorMessage(error)}`);
    process.exitCode = 1;
  }
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
      dynamic: options.dynamic ?? config.scan?.dynamic ?? false,
      static: config.scan?.static ?? true,
    },
  };
}

function resolveFormat(options: ScanOptions, config: PenClawConfig): "markdown" | "json" {
  if (options.format) {
    return options.format;
  }

  const outputPath = options.output ?? config.output?.path;
  if (outputPath?.endsWith(".json")) {
    return "json";
  }

  return config.output?.format ?? "markdown";
}

function printSummary(report: ScanReport, output: string | undefined, format: "markdown" | "json"): void {
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
