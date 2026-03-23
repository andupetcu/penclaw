import type { ScanReport, TriageFinding } from "../types/index.js";

export function renderHtmlReport(report: ScanReport): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PenClaw Security Report</title>
<style>
  :root { --bg: #0d1117; --surface: #161b22; --border: #30363d; --text: #e6edf3; --muted: #8b949e; --critical: #f85149; --high: #f0883e; --medium: #d29922; --low: #3fb950; --info: #58a6ff; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; }
  .container { max-width: 1200px; margin: 0 auto; }
  h1 { font-size: 1.8rem; margin-bottom: 0.5rem; }
  h2 { font-size: 1.3rem; margin: 2rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }
  .meta { color: var(--muted); font-size: 0.9rem; margin-bottom: 2rem; }
  .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .stat { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; text-align: center; }
  .stat .count { font-size: 2rem; font-weight: bold; }
  .stat .label { font-size: 0.85rem; color: var(--muted); text-transform: uppercase; }
  .stat.critical .count { color: var(--critical); }
  .stat.high .count { color: var(--high); }
  .stat.medium .count { color: var(--medium); }
  .stat.low .count { color: var(--low); }
  .stat.info .count { color: var(--info); }
  .finding { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 1rem; overflow: hidden; }
  .finding-header { padding: 1rem; cursor: pointer; display: flex; align-items: center; gap: 0.75rem; user-select: none; }
  .finding-header:hover { background: rgba(255,255,255,0.03); }
  .badge { padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
  .badge.critical { background: var(--critical); color: #fff; }
  .badge.high { background: var(--high); color: #fff; }
  .badge.medium { background: var(--medium); color: #000; }
  .badge.low { background: var(--low); color: #000; }
  .badge.info { background: var(--info); color: #000; }
  .finding-title { flex: 1; font-weight: 600; }
  .finding-meta { color: var(--muted); font-size: 0.85rem; }
  .finding-body { padding: 0 1rem 1rem; display: none; }
  .finding.open .finding-body { display: block; }
  .finding.open .chevron { transform: rotate(90deg); }
  .chevron { transition: transform 0.2s; color: var(--muted); }
  .detail { margin-bottom: 0.75rem; }
  .detail-label { font-size: 0.8rem; color: var(--muted); text-transform: uppercase; margin-bottom: 0.25rem; }
  pre { background: var(--bg); border: 1px solid var(--border); border-radius: 4px; padding: 0.75rem; overflow-x: auto; font-size: 0.85rem; white-space: pre-wrap; word-break: break-all; }
  .confidence { display: inline-block; }
  .confidence-bar { display: inline-block; width: 60px; height: 6px; background: var(--border); border-radius: 3px; vertical-align: middle; margin-left: 0.5rem; }
  .confidence-fill { height: 100%; border-radius: 3px; }
  .profile { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 0.5rem; }
  .profile-item { font-size: 0.9rem; }
  .profile-item strong { color: var(--muted); }
  .warnings { background: rgba(210,153,34,0.1); border: 1px solid var(--medium); border-radius: 8px; padding: 1rem; }
  .warnings li { margin-left: 1.5rem; font-size: 0.9rem; }
  .filter-bar { display: flex; gap: 0.5rem; margin-bottom: 1rem; flex-wrap: wrap; }
  .filter-btn { background: var(--surface); border: 1px solid var(--border); border-radius: 4px; padding: 0.3rem 0.75rem; color: var(--text); cursor: pointer; font-size: 0.85rem; }
  .filter-btn.active { border-color: var(--info); background: rgba(88,166,255,0.1); }
</style>
</head>
<body>
<div class="container">
  <h1>PenClaw Security Report</h1>
  <div class="meta">
    <div>Target: <code>${escHtml(report.targetProfile.target)}</code></div>
    <div>Generated: ${escHtml(report.generatedAt)} &middot; Duration: ${formatDuration(report.durationMs)} &middot; Files: ${report.targetProfile.fileCount}</div>
  </div>

  <div class="summary">
    <div class="stat critical"><div class="count">${report.counts.critical}</div><div class="label">Critical</div></div>
    <div class="stat high"><div class="count">${report.counts.high}</div><div class="label">High</div></div>
    <div class="stat medium"><div class="count">${report.counts.medium}</div><div class="label">Medium</div></div>
    <div class="stat low"><div class="count">${report.counts.low}</div><div class="label">Low</div></div>
    <div class="stat info"><div class="count">${report.counts.info}</div><div class="label">Info</div></div>
  </div>

  <h2>Target Profile</h2>
  <div class="profile">
    <div class="profile-item"><strong>Languages:</strong> ${escHtml(report.targetProfile.languages.map((l) => `${l.name} (${l.files})`).join(", ") || "Unknown")}</div>
    <div class="profile-item"><strong>Frameworks:</strong> ${escHtml(report.targetProfile.frameworks.join(", ") || "None")}</div>
    <div class="profile-item"><strong>Package Managers:</strong> ${escHtml(report.targetProfile.packageManagers.join(", ") || "None")}</div>
  </div>

  <h2>Findings (${report.findings.length})</h2>
  <div class="filter-bar">
    <button class="filter-btn active" data-severity="all">All</button>
    <button class="filter-btn" data-severity="critical">Critical (${report.counts.critical})</button>
    <button class="filter-btn" data-severity="high">High (${report.counts.high})</button>
    <button class="filter-btn" data-severity="medium">Medium (${report.counts.medium})</button>
    <button class="filter-btn" data-severity="low">Low (${report.counts.low})</button>
    <button class="filter-btn" data-severity="info">Info (${report.counts.info})</button>
  </div>

  ${report.findings.length === 0 ? "<p>No actionable findings survived triage.</p>" : report.findings.map((f) => renderFinding(f)).join("\n")}

  ${report.warnings.length > 0 ? `<h2>Warnings</h2><div class="warnings"><ul>${report.warnings.map((w) => `<li>${escHtml(w)}</li>`).join("")}</ul></div>` : ""}
</div>

<script>
document.querySelectorAll('.finding-header').forEach(h => {
  h.addEventListener('click', () => h.parentElement.classList.toggle('open'));
});
document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const sev = btn.dataset.severity;
    document.querySelectorAll('.finding').forEach(f => {
      f.style.display = (sev === 'all' || f.dataset.severity === sev) ? '' : 'none';
    });
  });
});
</script>
</body>
</html>`;
}

function renderFinding(finding: TriageFinding): string {
  const loc = finding.locations[0];
  const pct = Math.round(finding.confidence * 100);
  const color = finding.confidence > 0.7 ? "var(--low)" : finding.confidence > 0.4 ? "var(--medium)" : "var(--critical)";

  return `<div class="finding" data-severity="${finding.severity}">
  <div class="finding-header">
    <span class="chevron">&#9656;</span>
    <span class="badge ${finding.severity}">${finding.severity}</span>
    <span class="finding-title">${escHtml(finding.title)}</span>
    <span class="finding-meta">${escHtml(finding.source)} &middot; ${escHtml(loc?.path ?? "unknown")}${loc?.line ? `:${loc.line}` : ""}</span>
  </div>
  <div class="finding-body">
    <div class="detail"><div class="detail-label">Rule</div><code>${escHtml(finding.ruleId)}</code></div>
    <div class="detail"><div class="detail-label">Confidence</div><span class="confidence">${pct}%<span class="confidence-bar"><span class="confidence-fill" style="width:${pct}%;background:${color}"></span></span></span></div>
    <div class="detail"><div class="detail-label">Description</div><p>${escHtml(finding.description)}</p></div>
    <div class="detail"><div class="detail-label">Triage</div><p>${escHtml(finding.reasoning)}</p></div>
    <div class="detail"><div class="detail-label">Proof of Concept</div><pre>${escHtml(finding.proofOfConcept)}</pre></div>
    <div class="detail"><div class="detail-label">Fix Suggestion</div><pre>${escHtml(finding.fixSuggestion)}</pre></div>
    ${loc?.snippet ? `<div class="detail"><div class="detail-label">Evidence</div><pre>${escHtml(loc.snippet)}</pre></div>` : ""}
  </div>
</div>`;
}

function escHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function formatDuration(ms: number): string {
  const seconds = Math.round(ms / 1000);
  const minutes = Math.floor(seconds / 60);
  const rem = seconds % 60;
  return minutes > 0 ? `${minutes}m ${rem}s` : `${rem}s`;
}
