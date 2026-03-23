export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type FindingSource = "trivy" | "semgrep" | "secrets" | "ai" | "nuclei" | "dynamic" | "fuzzer";

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
  type: "filesystem" | "url";
  languages: DetectedLanguage[];
  frameworks: string[];
  packageManagers: string[];
  manifests: string[];
  entryPoints: string[];
  fileCount: number;
  url?: UrlProfileInfo;
}

export interface UrlProfileInfo {
  baseUrl: string;
  server?: string;
  poweredBy?: string;
  technologies: string[];
  headers: Record<string, string>;
  statusCode: number;
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
    format?: "markdown" | "json" | "sarif" | "html";
    path?: string;
  };
}

export interface ScanOptions {
  target: string;
  output?: string;
  format?: "markdown" | "json" | "sarif" | "html";
  configPath?: string;
  provider?: AIProviderConfig["provider"];
  model?: string;
  dynamic?: boolean;
  full?: boolean;
  ci?: boolean;
  failOn?: Severity;
}

export interface DynamicScanConfig {
  baseUrl: string;
  auth?: {
    loginUrl?: string;
    username?: string;
    password?: string;
    cookieHeader?: string;
    bearerToken?: string;
  };
  maxCrawlDepth?: number;
  maxPages?: number;
  excludePatterns?: string[];
}

export interface CrawlResult {
  pages: CrawledPage[];
  endpoints: DiscoveredEndpoint[];
  forms: DiscoveredForm[];
}

export interface CrawledPage {
  url: string;
  statusCode: number;
  title?: string;
  links: string[];
}

export interface DiscoveredEndpoint {
  url: string;
  method: string;
  parameters: string[];
  headers?: Record<string, string>;
}

export interface DiscoveredForm {
  action: string;
  method: string;
  inputs: Array<{ name: string; type: string; value?: string }>;
  pageUrl: string;
}

export interface SarifReport {
  version: "2.1.0";
  $schema: string;
  runs: SarifRun[];
}

export interface SarifRun {
  tool: { driver: SarifDriver };
  results: SarifResult[];
}

export interface SarifDriver {
  name: string;
  version: string;
  informationUri: string;
  rules: SarifRule[];
}

export interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription?: { text: string };
  defaultConfiguration: { level: "error" | "warning" | "note" | "none" };
  helpUri?: string;
}

export interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: "error" | "warning" | "note" | "none";
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region?: { startLine?: number; startColumn?: number };
    };
  }>;
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
