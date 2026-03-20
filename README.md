# PenClaw

PenClaw is an AI-powered penetration testing CLI focused on static analysis and AI-assisted triage.

## Phase 1 MVP

- Commander.js CLI with `penclaw scan <path>`
- Target profiling for languages, frameworks, manifests, and entry points
- Trivy filesystem integration with JSON parsing
- Semgrep integration with security rulesets
- Regex and entropy-based secret detection
- Multi-provider AI triage abstraction for Anthropic, OpenAI, and Ollama
- Proof-of-concept and fix suggestion generation
- Markdown and JSON report output
- `.penclaw.yml` config support through cosmiconfig

## Usage

```bash
npm install
npm run build
node dist/cli/index.js scan ./src --output report.md
```

## Example Config

```yaml
ai:
  provider: ollama
  model: llama3.1

scan:
  excludePaths:
    - node_modules/
    - dist/

output:
  format: markdown
  path: ./report.md
```

If `trivy`, `semgrep`, or AI credentials are unavailable, PenClaw continues with the remaining scanners and reports those conditions as warnings.
