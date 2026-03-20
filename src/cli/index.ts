#!/usr/bin/env node
import { Command } from "commander";
import { runScanCommand } from "./scan.js";

const program = new Command();

program
  .name("penclaw")
  .description("AI-powered penetration testing CLI")
  .version("0.1.0");

program
  .command("scan")
  .argument("<target>", "Filesystem path to scan")
  .option("-o, --output <path>", "Write the report to a file")
  .option("-f, --format <format>", "Output format: markdown or json")
  .option("--config <path>", "Path to a PenClaw config file")
  .option("--provider <provider>", "AI provider: anthropic, openai, ollama")
  .option("--model <model>", "AI model identifier")
  .option("--dynamic", "Enable dynamic scanning if supported by config", false)
  .action(async (target: string, commandOptions: Record<string, unknown>) => {
    await runScanCommand({
      target,
      output: commandOptions.output as string | undefined,
      format: commandOptions.format as "markdown" | "json" | undefined,
      configPath: commandOptions.config as string | undefined,
      provider: commandOptions.provider as "anthropic" | "openai" | "ollama" | undefined,
      model: commandOptions.model as string | undefined,
      dynamic: commandOptions.dynamic as boolean | undefined,
    });
  });

await program.parseAsync(process.argv);
