# PenClaw Phase 2.5 — Real-World Pentest Parity

## Goal
Close the gap between PenClaw's current fuzzing/scanning and what Kali Linux tools actually find. Ship curated payload packs, blind injection detection, directory bruteforcing, CORS/CSRF/open-redirect checks, SSRF testing, and JWT attacks.

## Constraints
- All new modules slot into existing `ScannerResult` / `RawFinding` types
- No new npm dependencies (use built-in fetch, existing Playwright, existing undici)
- Payload data files go in `data/payloads/*.json` (bundled, not fetched at runtime)
- SecLists content is MIT-licensed — attribute in LICENSE section of README
- Each module is independently testable
- Respect existing `--ci` mode exit codes and SARIF/HTML reporters (they consume `RawFinding[]` generically)

## Modules

### 1. Payload Packs (`data/payloads/`)

Create JSON payload files sourced/curated from SecLists + sqlmap + XSStrike + PortSwigger:

**`data/payloads/sqli.json`** — ~200 payloads organized by technique:
- Error-based (MySQL, PostgreSQL, MSSQL, SQLite, Oracle)
- UNION-based (column count probing, data extraction)
- Time-based blind (`SLEEP()`, `pg_sleep()`, `WAITFOR DELAY`, `RANDOMBLOB`)
- Boolean-based blind (true/false condition pairs)
- Stacked queries
- WAF bypass variants (comments, encoding, case alternation)

**`data/payloads/xss.json`** — ~100 payloads organized by context:
- HTML context (`<script>`, `<img onerror>`, `<svg onload>`, `<details ontoggle>`)
- Attribute context (`" onfocus=`, `' autofocus onfocus=`)
- JavaScript context (template literals, string breaks)
- URL context (`javascript:`, `data:`)
- DOM sinks (document.write, innerHTML, eval patterns)
- WAF bypass variants (encoding, tag mutation, event handlers)

**`data/payloads/ssrf.json`** — ~40 payloads:
- Cloud metadata (`169.254.169.254`, `metadata.google.internal`, Azure IMDS)
- Localhost bypass (`127.0.0.1`, `0.0.0.0`, `[::1]`, `0x7f000001`, `127.1`)
- DNS rebinding patterns
- Protocol smuggling (`file://`, `gopher://`, `dict://`)
- Redirect-based SSRF

**`data/payloads/path-traversal.json`** — ~50 payloads:
- Unix (`../../../etc/passwd`, null byte, double encoding)
- Windows (`..\..\windows\win.ini`)
- Encoding variants (`%2e%2e%2f`, `..%252f`, `%c0%ae`)

**`data/payloads/directories.json`** — ~4,600 paths curated from SecLists `Discovery/Web-Content/common.txt`:
- Admin panels, backup files, config files, API docs, debug endpoints, version control, CI artifacts

**`data/payloads/open-redirect.json`** — ~30 payloads:
- Protocol-relative (`//evil.com`), encoded, parameter-based

### 2. Enhanced Fuzzer (`src/crawl/api-fuzzer.ts` refactor)

Replace hardcoded payloads with loaded payload packs:
- `loadPayloads(category: string): Payload[]` — reads from `data/payloads/`
- Payloads have `{ value, technique, dbms?, context?, description }` structure

Add **blind SQLi detection**:
- `detectTimeBased(endpoint, payload)` — send time-delay payload, measure response time. If response takes >5s vs baseline <1s = confirmed blind SQLi.
- `detectBooleanBased(endpoint)` — send true-condition and false-condition payloads, compare response body length/hash. Significant diff = potential boolean blind.
- Baseline measurement: hit the endpoint 2x normally, record avg response time + body hash.

Add **SSRF testing**:
- `testSsrfParameters(endpoint)` — for any parameter that looks like it takes a URL/path/file (heuristic: param name contains `url`, `uri`, `path`, `file`, `src`, `dest`, `redirect`, `next`, `target`, `link`, `callback`, `return`, `goto`, `ref`), inject SSRF payloads.
- Detection: check for cloud metadata keywords in response (`ami-id`, `instance-id`, `computeMetadata`), or if response contains content from an internal resource.

Add **concurrency control**:
- `maxConcurrentRequests` config option (default: 10)
- `requestDelayMs` config option (default: 0) for stealth mode
- Use a simple semaphore for concurrent fetch

### 3. Directory Scanner (`src/dynamic/directory-scanner.ts` — NEW)

```typescript
export async function runDirectoryScan(
  baseUrl: string,
  config: PenClawConfig
): Promise<ScannerResult>
```

- Load paths from `data/payloads/directories.json`
- Fetch baseline (random path) for SPA detection (reuse existing `isSimilarResponse` logic — extract to shared util)
- Concurrent HEAD/GET requests (10 concurrent, configurable)
- Filter: status 200/403 + NOT similar to baseline + NOT generic HTML error
- Categorize findings: backup files (critical), admin panels (high), config exposure (high), API docs (medium), debug endpoints (high)
- Respect `requestDelayMs` for stealth

### 4. OWASP Expansion (`src/dynamic/owasp-checks.ts` additions)

**CORS Misconfiguration** — `checkCorsMisconfiguration(urlInfo)`:
- Send request with `Origin: https://evil.com` → check if reflected in `Access-Control-Allow-Origin`
- Send with `Origin: null` → check for null origin acceptance
- Send with `Origin: https://target.com.evil.com` → check for subdomain matching bypass
- Severity: high if credentials allowed (`Access-Control-Allow-Credentials: true`), medium otherwise

**CSRF Detection** — `checkCsrfProtection(forms, urlInfo)`:
- For each form with method=POST discovered during crawling:
  - Check for CSRF token input (name contains `csrf`, `token`, `_token`, `authenticity_token`, `__RequestVerificationToken`)
  - Check for `SameSite` cookie + `Origin`/`Referer` validation headers
  - If no CSRF token AND no SameSite=Strict/Lax → finding (medium)
- Skip forms that are search/GET only

**Open Redirect** — `checkOpenRedirect(urlInfo, endpoints)`:
- For endpoints with redirect-like parameters (`redirect`, `url`, `next`, `return`, `goto`, `continue`, `dest`):
  - Inject payloads from `data/payloads/open-redirect.json`
  - Follow redirects manually (max 1 hop), check if final Location points to injected domain
  - Detection: `Location` header contains attacker-controlled domain
- Severity: medium

### 5. JWT Testing (`src/dynamic/jwt-scanner.ts` — NEW)

```typescript
export async function testJwtSecurity(
  crawlResult: CrawlResult,
  config: DynamicScanConfig
): Promise<ScannerResult>
```

Trigger: if any cookie or `Authorization` header contains a JWT (regex: `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`).

Tests:
- **`alg:none` bypass** — decode header, set `alg` to `none`/`None`/`NONE`, empty signature, replay. If server accepts (2xx on protected endpoint) → critical.
- **Expired token acceptance** — decode payload, check `exp`. If already expired AND server accepted it → high.
- **Missing claims** — check for missing `exp`, `iat`, `iss`, `aud` → low/informational.
- **Weak signature** — try signing with common secrets (`secret`, `password`, `key`, `123456`, `jwt_secret`, empty string) using HS256. If any succeeds → critical.
- **Key confusion (RS256→HS256)** — if original `alg` is RS256/RS384/RS512, try changing to HS256 and signing with the server's public key (if discoverable via JWKS endpoint). If accepted → critical.

JWT decode/encode: implement manually (base64url decode, JSON parse — no dependency needed).

### 6. Integration

Wire new modules into `src/cli/scan.ts`:

```
// In dynamic scan flow:
1. Profile URL (existing)
2. Crawl target (existing)  
3. Run Nuclei (existing)
4. Run OWASP checks — expanded with CORS, CSRF, open redirect
5. Run directory scan (NEW)
6. Fuzz endpoints — enhanced with payload packs, blind SQLi, SSRF (ENHANCED)
7. Verify XSS (existing)
8. Test JWT security (NEW)
9. AI triage (existing — already handles arbitrary RawFinding[])
```

Config additions in `.penclaw.yml`:
```yaml
scan:
  # Existing
  excludePaths: []
  excludeVulns: []
  # New
  maxConcurrentRequests: 10  # concurrent HTTP requests for scanning
  requestDelayMs: 0          # delay between requests (stealth mode)
  skipDirectoryScan: false    # skip directory bruteforce
  skipJwtTests: false         # skip JWT testing
  directoryWordlist: null     # custom wordlist path (overrides built-in)
```

### 7. Tests

Add to `test/`:
- `test/payloads.test.ts` — validate all JSON payload files parse correctly, have required fields
- `test/directory-scanner.test.ts` — mock HTTP, verify SPA filtering, categorization
- `test/jwt-scanner.test.ts` — test alg:none encode/decode, weak secret detection with known JWTs
- `test/owasp-cors.test.ts` — test CORS reflection detection
- `test/blind-sqli.test.ts` — test time-based detection logic with mocked response times

## File Manifest (new/modified)

### New files:
- `data/payloads/sqli.json`
- `data/payloads/xss.json`
- `data/payloads/ssrf.json`
- `data/payloads/path-traversal.json`
- `data/payloads/directories.json`
- `data/payloads/open-redirect.json`
- `src/dynamic/directory-scanner.ts`
- `src/dynamic/jwt-scanner.ts`
- `src/utils/payloads.ts` (loader + types)
- `src/utils/http.ts` (shared: concurrency semaphore, SPA baseline, request helpers)
- `test/payloads.test.ts`
- `test/directory-scanner.test.ts`
- `test/jwt-scanner.test.ts`
- `test/owasp-cors.test.ts`
- `test/blind-sqli.test.ts`

### Modified files:
- `src/crawl/api-fuzzer.ts` — replace hardcoded payloads, add blind SQLi + SSRF + concurrency
- `src/dynamic/owasp-checks.ts` — add CORS, CSRF, open redirect checks
- `src/cli/scan.ts` — wire new modules into dynamic scan flow
- `src/types/index.ts` — add new config fields, JWT types, payload types
- `src/config/load-config.ts` — handle new config options with defaults

## Acceptance Criteria
- [ ] `penclaw scan https://juice-shop.herokuapp.com` finds significantly more vulnerabilities than before
- [ ] All payload JSON files load without errors
- [ ] Blind SQLi detects time-based injection on vulnerable targets
- [ ] Directory scan finds exposed paths with SPA false-positive filtering
- [ ] CORS check detects origin reflection
- [ ] CSRF check flags forms without tokens
- [ ] JWT tests detect alg:none and weak secrets
- [ ] `vitest run` passes all new + existing tests
- [ ] `tsc --noEmit` clean
- [ ] No new npm dependencies added

## Attribution
Payload data curated from:
- [SecLists](https://github.com/danielmiessler/SecLists) (MIT License)
- [sqlmap](https://github.com/sqlmapproject/sqlmap) (GPL — payloads only, not code)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) (MIT License)
- [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
