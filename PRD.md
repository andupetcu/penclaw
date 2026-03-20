# PenClaw — AI-Powered Penetration Testing Tool

## PRD v1.0 | 2026-03-20

---

## 1. Vision

**One-liner:** Point an AI agent at your app → get a pentest report with only proven, exploitable findings.

PenClaw is an opinionated AI pentest tool for developers and small teams. It orchestrates best-in-class open-source security scanners, correlates their output with an AI triage layer, and reports only what it can actually exploit. No noise. No theoretical findings. Every vulnerability comes with a working proof-of-concept.

### Why This Exists

The security tooling market has two extremes:
- **Too simple:** `npm audit` / Trivy / Snyk — finds CVEs in dependencies, zero dynamic testing, floods you with noise
- **Too complex:** Redamon / Burp Suite Pro / full red team frameworks — powerful but require security expertise, complex setup, expensive

**Nobody serves the middle:** the solo dev or small team that wants real penetration testing without hiring a pentester or deploying a Kali VM.

### Key Differentiators
1. **Proven findings only** — if PenClaw can't exploit it, it doesn't report it (borrowed from Shannon's philosophy)
2. **Single command** — `npx penclaw scan https://myapp.com` or `penclaw scan ./src`
3. **AI-native** — not bolted-on AI; the AI *is* the pentester, tools are its hands
4. **Fix generation** — doesn't just find problems, generates patches and opens PRs
5. **CI/CD native** — GitHub Action, blocks PRs on critical findings

---

## 2. Target Users

### Primary: Solo Devs & Small Teams (1-10 engineers)
- Ship fast, don't have dedicated security
- Know they *should* pentest but never do
- Want actionable results, not a 200-page PDF of maybes

### Secondary: DevSecOps Engineers
- Already use Trivy/Snyk/Semgrep individually
- Want unified orchestration + AI correlation
- Need CI/CD integration that doesn't slow deploys

### Tertiary: Security Consultants
- Run pentests for clients
- Want to automate the boring parts (recon, known vuln scanning)
- Use PenClaw as force multiplier, focus on business logic

---

## 3. Architecture

```
                    ┌─────────────────────┐
                    │    CLI / GitHub      │
                    │    Action / API      │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │    Orchestrator      │
                    │    (Node.js/TS)      │
                    │                     │
                    │  • Target profiler  │
                    │  • Attack planner   │
                    │  • Tool dispatcher  │
                    │  • Result collector │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
              ▼                ▼                ▼
      ┌──────────────┐ ┌────────────┐ ┌──────────────┐
      │ Static Phase │ │ Dynamic    │ │ Dependency   │
      │              │ │ Phase      │ │ Monitor      │
      ├──────────────┤ ├────────────┤ ├──────────────┤
      │ • Semgrep    │ │ • Nuclei   │ │ • Commit     │
      │ • Trivy FS   │ │ • SQLMap   │ │   diff watch │
      │ • Secret     │ │ • Playwright│ │ • CVE pre-  │
      │   detection  │ │   browser  │ │   disclosure │
      │ • Custom     │ │ • API fuzz │ │ • Dep graph  │
      │   rules      │ │ • Auth     │ │   analysis   │
      │              │ │   bypass   │ │              │
      └──────┬───────┘ └─────┬──────┘ └──────┬───────┘
              │               │               │
              └───────────────┼───────────────┘
                              │
                              ▼
                    ┌─────────────────────┐
                    │   AI Triage Layer   │
                    │   (Claude API)      │
                    │                     │
                    │  • Correlate static │
                    │    + dynamic results│
                    │  • Verify exploit-  │
                    │    ability          │
                    │  • Filter false     │
                    │    positives        │
                    │  • Generate PoC     │
                    │  • Write fix code   │
                    │  • Severity scoring │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   Output Layer      │
                    │                     │
                    │  • Markdown report  │
                    │  • HTML dashboard   │
                    │  • JSON (machine)   │
                    │  • GitHub Issues    │
                    │  • Fix PRs          │
                    │  • SARIF (CodeQL)   │
                    └─────────────────────┘
```

### Core Components

#### 3.1 Target Profiler
First step of every scan. Determines what we're looking at:
- **URL target** → tech stack fingerprinting (headers, meta tags, JS frameworks), sitemap/robots.txt, API endpoint discovery
- **Source target** → language detection, framework detection, entry point mapping, dependency graph
- **Combined** → correlates source routes with live endpoints

Output: `TargetProfile` object that informs the Attack Planner.

#### 3.2 Attack Planner
AI-driven (Claude) component that:
1. Reads the `TargetProfile`
2. Selects relevant tools and checks based on stack (no point running SQLMap against a static site)
3. Orders attacks by likelihood of findings (quick wins first)
4. Allocates time budget across phases

#### 3.3 Tool Dispatcher
Manages external tool execution:
- Installs missing tools on first run (or prompts user)
- Runs tools in parallel where safe (static checks)
- Serializes where needed (dynamic tests that modify state)
- Captures structured output (JSON/SARIF) from each tool
- Enforces timeouts and resource limits

**Bundled tool integrations (Phase 1):**

| Tool | Type | Purpose |
|------|------|---------|
| Trivy | Static | CVE scanning, secrets, IaC misconfig |
| Semgrep | Static | Code pattern matching, custom rules |
| Nuclei | Dynamic | Template-based vuln scanning |
| Playwright | Dynamic | Browser automation for auth + complex flows |
| Custom fuzzer | Dynamic | API parameter fuzzing, injection testing |

**Phase 2 additions:**
| Tool | Type | Purpose |
|------|------|---------|
| SQLMap | Dynamic | SQL injection specialist |
| ffuf | Dynamic | Web fuzzing (dirs, params, vhosts) |
| httpx | Recon | HTTP probing, tech detection |
| katana | Recon | Crawling, JS parsing, endpoint extraction |

#### 3.4 AI Triage Layer
The brain. Takes raw findings from all tools and:

1. **Deduplicates** — same vuln found by Trivy AND Semgrep → one finding
2. **Correlates** — static code pattern + dynamic confirmation = high confidence
3. **Verifies** — attempts to generate and execute a PoC for each finding
4. **Scores** — CVSS-like severity, but contextual (exposed to internet? auth required? data sensitivity?)
5. **Filters** — removes false positives using Trail of Bits-style systematic verification
6. **Generates fixes** — writes actual patch code for each confirmed vulnerability
7. **Writes report** — human-readable narrative, not just a table of CVEs

#### 3.5 Dependency Monitor (Phase 3)
Inspired by vulnerability-spoiler-alert:
- Watches commits in your dependency repos
- AI analyzes diffs for stealth security patches
- Alerts you before CVE is published ("negative-day" detection)
- Runs on cron (configurable: hourly → daily)

---

## 4. CLI Interface

### Basic Commands

```bash
# External scan (black-box)
penclaw scan https://myapp.com

# Source scan (white-box)  
penclaw scan ./src

# Combined scan (the killer mode)
penclaw scan --full https://myapp.com ./src

# Quick scan (static only, fast)
penclaw scan --quick ./src

# API-only scan
penclaw scan --api https://api.myapp.com/v1 --openapi ./openapi.yaml

# With auth
penclaw scan https://myapp.com --auth-url https://myapp.com/login \
  --auth-user test@test.com --auth-pass secret123

# Watch mode (dependency monitor)
penclaw watch --deps ./package.json

# Output options
penclaw scan ./src --output report.md --format markdown
penclaw scan ./src --output report.html --format html
penclaw scan ./src --format sarif  # for GitHub Code Scanning

# CI mode (non-interactive, exit code = severity)
penclaw scan ./src --ci --fail-on critical,high
```

### Configuration File (`.penclaw.yml`)

```yaml
target:
  url: https://myapp.com
  source: ./src

auth:
  url: https://myapp.com/login
  credentials:
    username: ${PENCLAW_AUTH_USER}
    password: ${PENCLAW_AUTH_PASS}
  
scan:
  # What to check
  static: true
  dynamic: true
  dependencies: true
  
  # OWASP Top 10 categories to test
  categories:
    - injection
    - broken-auth
    - sensitive-data
    - xxe
    - broken-access
    - misconfig
    - xss
    - deserialization
    - known-vulns
    - insufficient-logging

  # Custom Semgrep rules
  custom_rules: ./security-rules/

  # Exclusions
  exclude_paths:
    - node_modules/
    - test/
    - "*.test.ts"
  exclude_vulns:
    - CVE-2024-XXXX  # known, accepted risk

ai:
  provider: anthropic  # or openai
  model: claude-sonnet-4-20250514
  # API key from env: ANTHROPIC_API_KEY

output:
  format: markdown
  path: ./security-report.md
  github_issues: true
  fix_prs: true
  
ci:
  fail_on: [critical, high]
  timeout: 600  # seconds
```

### GitHub Action

```yaml
name: Security Scan
on: [pull_request]

jobs:
  penclaw:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: penclaw/scan-action@v1
        with:
          target-url: ${{ secrets.STAGING_URL }}  # optional
          source: ./src
          fail-on: critical,high
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

---

## 5. Report Format

### Executive Summary
```markdown
# PenClaw Security Report
**Target:** https://myapp.com + ./src
**Date:** 2026-03-20
**Duration:** 4m 32s

## Summary
- 🔴 Critical: 1
- 🟠 High: 3  
- 🟡 Medium: 7
- ⚪ Low: 12
- ✅ Passed checks: 847

## Critical Findings

### [CRIT-001] SQL Injection in User Search
**Location:** `src/routes/users.ts:47`
**Endpoint:** `GET /api/users?search=`
**CVSS:** 9.8

**Description:**
User input from the `search` query parameter is concatenated directly 
into a SQL query without sanitization or parameterization.

**Proof of Concept:**
\`\`\`bash
curl "https://myapp.com/api/users?search=' OR '1'='1' --"
# Returns: all 12,847 user records including emails and hashed passwords
\`\`\`

**Source Code:**
\`\`\`typescript
// src/routes/users.ts:47
const results = await db.query(`SELECT * FROM users WHERE name LIKE '%${req.query.search}%'`);
//                                                              ^^^^^^^^^^^^^^^^^^^^^^^^ VULNERABLE
\`\`\`

**Fix:**
\`\`\`typescript
const results = await db.query('SELECT * FROM users WHERE name LIKE $1', [`%${req.query.search}%`]);
\`\`\`

**Auto-fix PR:** #142
```

---

## 6. Tech Stack

| Component | Technology | Why |
|-----------|-----------|-----|
| CLI | Node.js + TypeScript | Fast to build, npm distribution, same ecosystem as targets |
| AI | Claude API (Anthropic) | Best for code analysis, supports long context for full-file review |
| Static scanning | Trivy + Semgrep | Industry standard, structured output |
| Dynamic scanning | Nuclei + custom | Template-based = extensible |
| Browser automation | Playwright | Handles SPAs, auth flows, JS-heavy apps |
| API fuzzing | Custom (built on `undici`) | Lightweight, controllable |
| Report generation | Handlebars templates | Markdown + HTML from same data |
| GitHub integration | Octokit | Issues, PRs, Actions |
| Config | cosmiconfig | Standard `.penclaw.yml` / `.penclawrc` / `package.json` |

### Dependencies on External Tools
Users need these installed (PenClaw will check and guide installation):
- **Required:** Node.js 18+
- **Optional (enhanced scanning):** Trivy, Semgrep, Nuclei
- PenClaw works without them (AI-only mode) but is much better with them

---

## 7. Phased Delivery

### Phase 1 — MVP: Static + AI Triage (Week 1)
**Goal:** `penclaw scan ./src` works end-to-end.

- [ ] CLI scaffolding (Commander.js)
- [ ] Target profiler (language/framework detection)
- [ ] Trivy integration (filesystem scan, JSON output parsing)
- [ ] Semgrep integration (with bundled security rulesets)
- [ ] Secret detection (regex + entropy)
- [ ] AI triage layer — correlate, deduplicate, filter false positives
- [ ] PoC generation for static findings
- [ ] Fix suggestion generation
- [ ] Markdown report output
- [ ] JSON output (machine-readable)
- [ ] `.penclaw.yml` config support
- [ ] npm package (`npx penclaw`)

**Ship criteria:** Can scan a Node.js/Python project and produce a useful report with < 10% false positive rate.

### Phase 2 — Dynamic Testing (Week 2-3)
**Goal:** `penclaw scan https://myapp.com` works. Combined mode unlocked.

- [ ] URL target profiling (tech fingerprinting, endpoint discovery)
- [ ] Nuclei integration (web vuln templates)
- [ ] Playwright browser automation
- [ ] Auth flow handling (form login, cookie/token capture)
- [ ] API endpoint fuzzing (injection, auth bypass, IDOR)
- [ ] OWASP Top 10 automated checks
- [ ] Static + dynamic correlation (code vuln confirmed by live exploit)
- [ ] HTML report with interactive findings
- [ ] SARIF output (GitHub Code Scanning integration)
- [ ] `--ci` mode with exit codes

**Ship criteria:** Can find and exploit real OWASP Top 10 vulns in intentionally vulnerable apps (DVWA, Juice Shop).

### Phase 3 — CI/CD & Ecosystem (Week 3-4)
**Goal:** PenClaw runs on every PR.

- [ ] GitHub Action (`penclaw/scan-action`)
- [ ] GitHub Issues creation for findings
- [ ] Auto-fix PR generation (branch + commit + PR)
- [ ] PR comment with scan summary
- [ ] Incremental scanning (only scan changed files)
- [ ] Caching (don't re-scan unchanged deps)
- [ ] OpenAPI/Swagger spec ingestion for API testing
- [ ] Custom Semgrep rule authoring guide

### Phase 4 — Negative-Day Monitor (Week 4-5)
**Goal:** `penclaw watch` monitors your deps for stealth patches.

- [ ] Dependency graph extraction (package.json, requirements.txt, go.mod)
- [ ] Git commit monitoring for dependency repos
- [ ] AI diff analysis ("is this a security patch?")
- [ ] Alert system (CLI notification, GitHub Issue, webhook)
- [ ] RSS feed output (per-project)
- [ ] Cron scheduling (`penclaw watch --cron "0 */6 * * *"`)

### Phase 5 — SaaS Layer (Month 2+)
**Goal:** Dashboard for teams, monetization.

- [ ] Web dashboard (scan history, trends, team view)
- [ ] Scheduled scans
- [ ] Slack/email/webhook notifications
- [ ] Team management (roles, permissions)
- [ ] Compliance report templates (SOC2, ISO 27001, PCI DSS)
- [ ] Custom rule marketplace
- [ ] API for programmatic access

---

## 8. Monetization

### Open Core Model

| Tier | Price | Features |
|------|-------|----------|
| **Free** | $0 | CLI, all scan modes, local reports, public repo CI |
| **Pro** | $29/mo | Private repo CI, dashboard, scheduled scans, Slack alerts, priority support |
| **Team** | $99/mo | 5 seats, shared dashboard, compliance reports, custom rules |
| **Enterprise** | Custom | Self-hosted, SSO, audit logs, SLA, unlimited seats |

### Revenue Levers
- **AI API costs** are the main COGS — Pro users offset this
- **GitHub Marketplace** listing drives discovery
- **Negative-day alerts** are high-value (security teams will pay for early warning)
- **Compliance reports** are enterprise upsell (SOC2 report = months of audit work automated)

---

## 9. Competitive Landscape

| Tool | Type | Price | PenClaw Advantage |
|------|------|-------|-------------------|
| Snyk | SaaS scanner | Free-$99/mo | We do dynamic testing + exploitation, not just CVE lookup |
| Trivy | CLI scanner | Free | We orchestrate Trivy + add AI triage + dynamic testing |
| Shannon | AI pentester | Enterprise | We're simple CLI, they're complex platform |
| Redamon | Red team framework | Free/complex | We're `npx penclaw`, they're Docker Compose on Kali |
| Burp Suite Pro | Manual pentester tool | $449/yr | We're automated and AI-native, they're manual-first |
| GitHub CodeQL | Static analysis | Free for public | We add dynamic testing, AI triage, fix generation |

**Positioning:** "Snyk finds CVEs. PenClaw finds *exploits*."

---

## 10. Success Metrics

### MVP (Month 1)
- [ ] 100+ GitHub stars
- [ ] 500+ npm installs
- [ ] < 10% false positive rate on test suite
- [ ] Successfully finds known vulns in DVWA, Juice Shop, WebGoat

### Growth (Month 3)
- [ ] 1,000+ GitHub stars
- [ ] 5,000+ npm installs/month
- [ ] 10+ Pro subscribers
- [ ] GitHub Action in 50+ repos
- [ ] Product Hunt launch

### Scale (Month 6)
- [ ] 5,000+ GitHub stars
- [ ] 25,000+ npm installs/month
- [ ] $1K MRR
- [ ] 3+ conference talks / blog features

---

## 11. Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| AI hallucinated vulnerabilities | Trust destruction | Mandatory PoC verification; no finding without proof |
| Tool installation friction | Low adoption | AI-only fallback mode; Docker image with all tools pre-installed |
| AI API costs too high for free tier | Unsustainable | Rate limiting, caching, local model fallback (Ollama) |
| Legal concerns (automated exploitation) | Liability | Clear ToS: only scan what you own. `--i-own-this` flag for dynamic scans |
| Shannon/Redamon go simple | Competition | Move fast, own the developer experience. They target enterprises, we target devs |
| False sense of security | Reputation | Clear disclaimers: "PenClaw augments, not replaces, professional pentesting" |

---

## 12. Decisions Log

1. **Name:** PenClaw ✅ (decided 2026-03-20)
2. **AI providers:** Multi-provider from day 1 — Anthropic Claude + OpenAI + Ollama/local ✅
3. **Dynamic scanning:** Opt-in (`--dynamic` flag or `scan.dynamic: true` in config). Static is default. ✅
4. **Local model support:** Yes, via Ollama — free tier alternative to cloud AI
5. **Bug bounty angle:** TBD — potential HackerOne/Bugcrowd integration later

---

## 13. References & Inspiration

- [Shannon](https://github.com/KeygraphHQ/shannon) — proven-only findings, 96% exploit rate
- [Redamon](https://github.com/samugit83/redamon) — full kill chain, auto-fix PRs
- [vulnerability-spoiler-alert](https://github.com/spaceraccoon/vulnerability-spoiler-alert) — negative-day commit monitoring
- [Trail of Bits skills](https://github.com/trailofbits/skills) — differential review, FP verification, audit context
- [Trivy](https://github.com/aquasecurity/trivy) — foundation scanner
- [rep+](https://github.com/repplus/rep-chrome) — AI-assisted HTTP replay
- [PinchTab](https://github.com/pinchtab/pinchtab) — token-efficient browser control
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) — methodology reference

---

_PRD authored by Kai | 2026-03-20 | Ready for review._
