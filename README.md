# rsentinel

A defensive security posture scanner in Rust. Points it at infrastructure **you own or are authorized to test** and reports misconfigurations with CVSS-derived severity, in a format your CI can consume.

Same category as `testssl.sh`, Mozilla Observatory or `ssllabs-scan`, with the checks consolidated behind one CLI and a single machine-readable report.

```bash
rsentinel audit example.com --sarif > results.sarif
```

## Scope

This tool performs **read-only configuration assessment**: it makes ordinary HTTPS and DNS requests and reads what the server volunteers. It does not attempt exploitation, credential guessing, or brute-force enumeration.

> **Authorized use only.** Port scanning and path probing against infrastructure you do not own or have written permission to test is illegal in many jurisdictions. Scan your own systems.

## What it checks

| Module | Coverage |
|---|---|
| **TLS/SSL** | Certificate validity and expiry, chain, protocol versions, cipher suites |
| **HTTP headers** | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| **DNS** | SPF (including over-permissive `+all`), DMARC (including `p=none`), DKIM, DNSSEC, NS/TXT records |
| **CORS** | Origin reflection, wildcard with credentials, null-origin acceptance |
| **Exposure** | 13 commonly-leaked paths: `.env`, `.git/config`, `.aws/credentials`, `backup.sql`, `.DS_Store`, and similar |
| **Tech detect** | Server and framework fingerprinting from response characteristics |
| **Ports** | Optional nmap wrapper (`-Pn --open --version-light`) |
| **CVE lookup** | Correlates detected versions against a CVE database |

Findings are scored on a CVSS-derived scale and bucketed Critical / High / Medium / Low.

## Output formats

Four, because a scanner nobody can pipe anywhere is a scanner nobody runs:

```bash
rsentinel audit example.com              # human-readable terminal report
rsentinel audit example.com --json       # structured JSON
rsentinel audit example.com --markdown   # for PR comments and tickets
rsentinel audit example.com --sarif      # SARIF 2.1.0
```

SARIF is what GitHub code scanning ingests, so the output drops into an existing security pipeline rather than needing a parser written for it.

## Install

```bash
git clone https://github.com/yodablocks/rsentinel-public.git
cd rsentinel-public
cargo build --release
```

Optional: `nmap` for port scanning, a Shodan API key for host intelligence. Every other check works with no key and no account.

## Usage

```bash
# Everything at once
rsentinel audit example.com

# Individual modules
rsentinel ssl-check example.com
rsentinel headers-check example.com
rsentinel dns-check example.com
rsentinel cors-check example.com
rsentinel paths-check example.com
rsentinel tech-check example.com

# Port scan (requires nmap)
rsentinel scan --quick <ip>

# No network calls, sample data
rsentinel demo
```

## Tests

```bash
cargo test
```

161 tests. Network-dependent paths are covered with `wiremock` rather than live requests, so the suite is deterministic and runs offline.

## Design notes

**Severity is derived, not asserted.** Findings carry a CVSS-style score that maps to the severity bucket, so `--json` consumers can threshold on a number instead of string-matching a label.

**External tools are optional, not required.** nmap and Shodan extend coverage; their absence degrades gracefully instead of failing the run.

**Rate limiting is built in.** The `governor` crate bounds outbound API calls so a scan cannot accidentally hammer a third-party service.

## Limitations

- **Unauthenticated, external perspective only.** It sees what any internet client sees. It cannot assess internal network posture, application logic, or anything behind a login.
- **Fingerprinting is heuristic.** Tech detection infers from response characteristics and can be wrong against a server configured to misreport.
- **CVE correlation is version-based.** A detected version matched against a CVE database says nothing about whether a backported patch already fixed it. Treat those findings as leads.
- **Exposure checks are a fixed list**, not a fuzzer. Thirteen well-known paths, deliberately, so a scan is a handful of requests rather than thousands.

## License

MIT
