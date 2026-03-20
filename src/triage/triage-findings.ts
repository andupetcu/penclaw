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
      triagedFindings.push({
        ...fallback,
        reasoning: aiResponse || fallback.reasoning,
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
  const relatedFindings = allFindings
    .filter((candidate) => candidate !== finding && createDeduplicationKey(candidate) === deduplicationKey)
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
  const sourceBoost = finding.source === "semgrep" || finding.source === "trivy" ? 0.08 : 0.03;
  return Math.min(0.98, Number((base + correlationBoost + sourceBoost).toFixed(2)));
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
        "Summarize exploitability, false positive risk, a proof of concept approach, and a concrete fix suggestion in 4 short paragraphs.",
    },
    null,
    2,
  );
}

function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
