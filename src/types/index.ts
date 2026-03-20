export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type FindingSource = "trivy" | "semgrep" | "secrets" | "ai";

export interface EvidenceLocation {
  path: string;
  line?: number;
  column?: number;
  snippet?: string;
}

export interface RawFinding {
  id: string;
  source: FindingSource;
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  category: string;
  locations: EvidenceLocation[];
  references?: string[];
  metadata?: Record<string, unknown>;
}

export interface TriageFinding extends RawFinding {
  confidence: number;
  deduplicationKey: string;
  falsePositiveLikelihood: number;
  reasoning: string;
  proofOfConcept: string;
  fixSuggestion: string;
  relatedFindings: string[];
}

export interface ScanCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ScannerResult {
  scanner: FindingSource;
  findings: RawFinding[];
  warnings: string[];
  executionMs: number;
}

export interface DetectedLanguage {
  name: string;
  files: number;
}

export interface TargetProfile {
  target: string;
  type: "filesystem";
  languages: DetectedLanguage[];
  frameworks: string[];
  packageManagers: string[];
  manifests: string[];
  entryPoints: string[];
  fileCount: number;
}

export interface AIProviderConfig {
  provider?: "anthropic" | "openai" | "ollama";
  model?: string;
  apiKey?: string;
  baseUrl?: string;
}

export interface PenClawConfig {
  target?: {
    source?: string;
  };
  scan?: {
    dynamic?: boolean;
    static?: boolean;
    excludePaths?: string[];
    excludeVulns?: string[];
    customRules?: string;
  };
  ai?: AIProviderConfig;
  output?: {
    format?: "markdown" | "json";
    path?: string;
  };
}

export interface ScanOptions {
  target: string;
  output?: string;
  format?: "markdown" | "json";
  configPath?: string;
  provider?: AIProviderConfig["provider"];
  model?: string;
  dynamic?: boolean;
}

export interface ScanReport {
  tool: {
    name: string;
    version: string;
  };
  generatedAt: string;
  durationMs: number;
  targetProfile: TargetProfile;
  findings: TriageFinding[];
  rawFindings: RawFinding[];
  warnings: string[];
  counts: ScanCounts;
}
