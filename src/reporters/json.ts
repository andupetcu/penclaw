import type { ScanReport } from "../types/index.js";

export function renderJsonReport(report: ScanReport): string {
  return JSON.stringify(report, null, 2);
}
