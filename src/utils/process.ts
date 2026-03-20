import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export interface CommandResult {
  stdout: string;
  stderr: string;
}

export async function commandExists(command: string): Promise<boolean> {
  try {
    await execFileAsync("which", [command]);
    return true;
  } catch {
    return false;
  }
}

export async function runCommand(
  command: string,
  args: string[],
  cwd: string,
  timeout = 300_000,
): Promise<CommandResult> {
  const result = await execFileAsync(command, args, {
    cwd,
    timeout,
    maxBuffer: 20 * 1024 * 1024,
  });

  return {
    stdout: result.stdout,
    stderr: result.stderr,
  };
}
