import type { AIProviderConfig, RawFinding, TargetProfile, TriageFinding } from "../types/index.js";
import { normalizeSeverity, severityWeight } from "../utils/severity.js";
import { createTriageProvider } from "./providers.js";

export async function triageFindings(
  findings: RawFinding[],
  profile: TargetProfile,
  providerConfig?: AIProviderConfig,
): Promise<{ findings: TriageFinding[]; warnings: string[] }> {
  const warnings: string[] = [];
  const deduplicated = deduplicateFindings(findings);
  const provider = createTriageProvider(providerConfig);

  if (providerConfig?.provider && !provider) {
    warnings.push(`AI provider ${providerConfig.provider} is not configured correctly; using deterministic triage fallback.`);
  }

  const triagedFindings: TriageFinding[] = [];
  for (const finding of deduplicated) {
    const fallback = buildFallbackTriage(finding, deduplicated, profile);
    if (!provider) {
      triagedFindings.push(fallback);
      continue;
    }

    try {
      const aiResponse = await provider.summarize(buildPrompt(finding, profile));
      const parsed = parseAiTriage(aiResponse);
      triagedFindings.push({
        ...fallback,
        reasoning: parsed.reasoning || aiResponse || fallback.reasoning,
        proofOfConcept: parsed.proofOfConcept || fallback.proofOfConcept,
        fixSuggestion: parsed.fixSuggestion || fallback.fixSuggestion,
      });
    } catch (error) {
      warnings.push(`AI triage failed for ${finding.ruleId}: ${getErrorMessage(error)}`);
      triagedFindings.push(fallback);
    }
  }

  const filtered = triagedFindings
    .filter((finding) => finding.falsePositiveLikelihood < 0.8)
    .sort((left, right) => severityWeight(right.severity) - severityWeight(left.severity) || right.confidence - left.confidence);

  return {
    findings: filtered,
    warnings,
  };
}

function deduplicateFindings(findings: RawFinding[]): RawFinding[] {
  const deduped = new Map<string, RawFinding>();

  for (const finding of findings) {
    const key = createDeduplicationKey(finding);
    const existing = deduped.get(key);
    if (!existing || severityWeight(finding.severity) > severityWeight(existing.severity)) {
      deduped.set(key, finding);
    }
  }

  return [...deduped.values()];
}

function buildFallbackTriage(
  finding: RawFinding,
  allFindings: RawFinding[],
  profile: TargetProfile,
): TriageFinding {
  const deduplicationKey = createDeduplicationKey(finding);
  // Find related findings: exact dedup key match OR same category from different source type (static/dynamic correlation)
  const relatedFindings = allFindings
    .filter((candidate) => {
      if (candidate === finding) return false;
      if (createDeduplicationKey(candidate) === deduplicationKey) return true;
      // Cross-source correlation: static finding + dynamic finding for same category boosts confidence
      return candidate.category === finding.category && isStaticDynamicPair(finding.source, candidate.source);
    })
    .map((candidate) => candidate.id);

  const severity = normalizeSeverity(finding.severity);
  const confidence = calculateConfidence(finding, relatedFindings.length);
  const falsePositiveLikelihood = Math.max(0.05, 1 - confidence);

  return {
    ...finding,
    severity,
    confidence,
    deduplicationKey,
    falsePositiveLikelihood,
    reasoning: buildReasoning(finding, profile, confidence),
    proofOfConcept: buildProofOfConcept(finding),
    fixSuggestion: buildFixSuggestion(finding),
    relatedFindings,
  };
}

function createDeduplicationKey(finding: RawFinding): string {
  const primaryLocation = finding.locations[0];
  return [
    finding.category.toLowerCase(),
    finding.ruleId.toLowerCase(),
    primaryLocation?.path?.toLowerCase() ?? "unknown",
    primaryLocation?.line ?? 0,
  ].join(":");
}

function calculateConfidence(finding: RawFinding, relatedCount: number): number {
  const base = 0.45 + severityWeight(finding.severity) * 0.08;
  const correlationBoost = Math.min(0.2, relatedCount * 0.08);
  const sourceBoost = getSourceBoost(finding.source);
  return Math.min(0.98, Number((base + correlationBoost + sourceBoost).toFixed(2)));
}

function getSourceBoost(source: string): number {
  switch (source) {
    case "semgrep":
    case "trivy":
      return 0.08;
    case "nuclei":
    case "dynamic":
      return 0.10;
    case "fuzzer":
      return 0.12;
    default:
      return 0.03;
  }
}

function buildReasoning(finding: RawFinding, profile: TargetProfile, confidence: number): string {
  const location = finding.locations[0];
  return `${finding.source} identified ${finding.title} in ${location?.path ?? "the target"} with ${Math.round(
    confidence * 100,
  )}% confidence. The repository profile indicates ${profile.languages.map((language) => language.name).join(", ") || "an unknown stack"}, which makes ${finding.category} findings in this area worth review.`;
}

function buildProofOfConcept(finding: RawFinding): string {
  const location = finding.locations[0];
  switch (finding.category) {
    case "secret":
      return `Inspect ${location?.path}:${location?.line ?? 1} and rotate the exposed credential immediately. Confirm by verifying whether the token authenticates against the intended provider.`;
    case "dependency":
      return `Run the vulnerable package through the published advisory reproduction steps, then verify whether ${String(
        finding.metadata?.packageName ?? "the dependency",
      )} is reachable from the application code path.`;
    case "xss":
      return `Submit the payload shown in the evidence to ${location?.path ?? "the endpoint"} and check whether it is reflected unsanitized in the DOM or triggers JavaScript execution.`;
    case "injection":
      return `Send the injection payload to ${location?.path ?? "the endpoint"} and observe error messages, timing differences, or unexpected data in the response.`;
    case "auth-bypass":
      return `Replay the request with the bypass headers shown and compare the response status/body against an unauthenticated baseline.`;
    case "idor":
      return `Change the numeric ID in the URL and verify whether a different user's data is returned without authorization.`;
    case "security-header":
      return `Inspect the response headers from ${location?.path ?? "the target"} and confirm the missing security header is not set on any response.`;
    default:
      return `Review ${location?.path}:${location?.line ?? 1}, exercise the affected code path with attacker-controlled input, and confirm the vulnerable behavior before treating this finding as exploitable.`;
  }
}

function buildFixSuggestion(finding: RawFinding): string {
  switch (finding.category) {
    case "secret":
      return "Remove the secret from source control, rotate it in the upstream service, and load replacement values from environment variables or a secret manager.";
    case "dependency":
      return `Upgrade the affected dependency to a patched version and validate the transitive tree. Add a version pin or renovate rule if this package frequently regresses.`;
    case "misconfiguration":
      return "Apply the secure default recommended by the scanner, then add a configuration test to prevent the setting from regressing.";
    case "xss":
      return "Sanitize or encode all user-supplied data before rendering in HTML. Use a context-aware output encoding library and implement a strict Content-Security-Policy.";
    case "security-header":
      return "Add the missing security header to all responses. Configure at the reverse proxy or application middleware level and verify with automated header checks.";
    case "auth-bypass":
      return "Ensure authorization checks are performed server-side independent of request headers. Do not trust X-Forwarded-For or similar proxy headers for access control.";
    case "idor":
      return "Implement proper authorization checks that verify the requesting user has access to the specific resource, not just any valid session.";
    default:
      return "Refactor the code path to use safe APIs, add validation on untrusted input, and cover the fix with a regression test.";
  }
}

function buildPrompt(finding: RawFinding, profile: TargetProfile): string {
  return JSON.stringify(
    {
      targetProfile: profile,
      finding,
      instruction:
        "Respond with exactly 3 sections labeled REASONING:, PROOF_OF_CONCEPT:, and FIX:. " +
        "REASONING: Assess exploitability and false positive likelihood in 2-3 sentences. " +
        "PROOF_OF_CONCEPT: Give a specific, actionable proof of concept (curl command, code snippet, or step-by-step). " +
        "FIX: Provide a concrete fix with code or config changes.",
    },
    null,
    2,
  );
}

function parseAiTriage(response: string): {
  reasoning: string;
  proofOfConcept: string;
  fixSuggestion: string;
} {
  const sections: Record<string, string> = {};
  const sectionPattern = /(?:^|\n)\s*\**\s*(REASONING|PROOF_OF_CONCEPT|FIX)\s*:?\s*\**\s*/gi;
  const markers: Array<{ key: string; index: number; matchStart: number }> = [];

  let match: RegExpExecArray | null;
  while ((match = sectionPattern.exec(response)) !== null) {
    markers.push({ key: match[1]!.toUpperCase(), index: match.index + match[0].length, matchStart: match.index });
  }

  for (let i = 0; i < markers.length; i++) {
    const start = markers[i]!.index;
    const end = i + 1 < markers.length ? markers[i + 1]!.matchStart : response.length;
    sections[markers[i]!.key] = response.slice(start, end).trim();
  }

  return {
    reasoning: sections["REASONING"] ?? "",
    proofOfConcept: sections["PROOF_OF_CONCEPT"] ?? "",
    fixSuggestion: sections["FIX"] ?? "",
  };
}

const staticSources = new Set(["trivy", "semgrep", "secrets"]);
const dynamicSources = new Set(["nuclei", "dynamic", "fuzzer"]);

function isStaticDynamicPair(sourceA: string, sourceB: string): boolean {
  return (staticSources.has(sourceA) && dynamicSources.has(sourceB)) ||
    (dynamicSources.has(sourceA) && staticSources.has(sourceB));
}

function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
