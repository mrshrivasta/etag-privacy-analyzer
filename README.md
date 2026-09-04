# ETag Privacy Analyzer

A real, no-mock-data security auditing tool that issues a genuine HTTP GET request to a URL you authorize and inspects the **actual live `ETag` response header** to flag privacy and information-disclosure risks — including inode-leaking ETag formats, ETags on cookie-bearing responses missing a proper `Vary` header (a real cross-user cache-leak vector), weak ETags on sensitive pages, and ETag values that resemble opaque tracking tokens.

Available as both a **command-line tool** and a **full multi-page web application**.

Developed by **Karanam Shrivasta**
GitHub: https://github.com/mrshrivasta
LinkedIn: https://www.linkedin.com/in/karanam-shrivasta

---

## ⚠️ Disclaimer (read before use)

This tool sends **real HTTP requests** to whatever URL you provide it. It does not use sample data, fixtures, or simulated responses — every finding is derived from an actual response received from the target server at scan time.

- **Authorized use only.** Only scan URLs and systems that you own, or that you have explicit, contractual, written authorization to test. Sending requests to third-party systems without authorization may violate the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), similar computer-crime laws in other jurisdictions, and the target's Terms of Service — even a single, harmless-looking GET request.
- **No warranty.** This software is provided **"AS IS"**, without warranty of any kind, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, and non-infringement.
- **No liability.** The author, Karanam Shrivasta, accepts no liability for any damage, data loss, downtime, legal consequences, financial loss, or any other harm arising from the use, misuse, or inability to use this software.
- **Not a professional audit.** This tool is an educational and productivity aid. It does not replace a certified penetration test, a compliance audit (PCI-DSS, SOC 2, ISO 27001, etc.), or a professional security assessment performed by a qualified practitioner.
- **You are responsible.** By using this tool you accept full responsibility for how you use it and for obtaining any necessary authorization before scanning a target.

---

## Who should use this project

- Web developers and backend engineers who want to verify their own application's ETag configuration doesn't leak internal server details.
- Privacy engineers and AppSec teams checking whether personalized/authenticated responses risk being served cross-user by shared caches.
- DevOps/SRE teams reviewing web server (Apache/nginx) static-file ETag generation for inode/mtime disclosure.
- Students and educators studying real-world HTTP caching-privacy patterns with a genuine, working tool rather than a slide deck.

## Why use this project

ETags are usually thought of as a harmless caching optimization, but they carry real, under-appreciated risks: classic Apache/nginx inode-based ETags leak internal filesystem metadata to any client; ETags on cookie-bearing personalized responses without a matching `Vary` header can let a shared cache/CDN serve one user's cached body to a different user (a genuine cross-user data leak); and long, opaque ETag values can function as a semi-persistent tracking identifier that survives a user clearing their cookies. This tool automates detection of all of these patterns using a single real HTTP request, with clear severities, a full audit trail (scan logs, alerts, incidents), CSV reporting, and six chart types for trend visibility — all self-hosted, all open, all inspectable.

---

## Detection Rules

Every rule below is evaluated against the **actual `ETag` (and related) response headers** of the one real HTTP GET request made during a scan.

| Rule ID | Name | Severity | What it checks |
|---|---|---|---|
| EPA-001 | ETag Present on Sensitive/Personalized Response | Medium | A sensitive-looking response (session cookie and/or sensitive path segment) returns an ETag, which can act as a semi-persistent tracking token via conditional requests. |
| EPA-002 | Inode-Based ETag Format | High | The ETag value matches the classic Apache/nginx inode-size-mtime hex pattern, disclosing internal filesystem metadata (inode numbers) to any client. |
| EPA-003 | ETag + Cookie Response Missing Vary Header | **Critical** | The response sets a cookie and returns an ETag, but `Vary` doesn't include `Cookie`/`Authorization` — a shared cache could serve one user's cached body to another user. |
| EPA-004 | Weak ETag Validator on Sensitive Response | Medium | A weak (`W/`-prefixed) ETag is used on a sensitive-looking response, increasing the risk of cross-response/cross-user cache confusion. |
| EPA-005 | ETag Present Without Cache-Control Policy | Low | An ETag is present but there is no `Cache-Control` header at all, leaving caching/privacy behavior undefined across intermediaries. |
| EPA-006 | ETag Resembles a Long Opaque Tracking Token | Medium | The ETag contains a long opaque hex sequence (24+ chars) resembling a UUID/session ID rather than a short content hash. |
| EPA-000 | Target Unreachable | Low (informational) | The target could not be reached (DNS failure, connection refused/timeout, TLS error, network policy block). Not a privacy finding — an operational note. |

---

## Architecture

```
etag-privacy-analyzer/
├── Authentication        # app/auth — register/login/logout, Flask-Login sessions, hashed passwords
├── Dashboard              # app/dashboard — run a real scan, view live counters and recent scans
├── Security Engine        # app/security_engine — issues the real HTTP GET request via `requests`
├── Detection Rules        # app/detection_rules — 6 pure functions evaluating the real ETag header
├── Logs                   # app/logs — full scan history / audit trail, per-scan detail view
├── Alerts                 # app/alerts — generated from findings by severity threshold
├── Incident Management    # app/incident_management — track/triage/resolve alert-driven incidents
├── Analytics               # app/analytics — 6 real chart types (pie, bar, line, radar, doughnut, polar area)
├── Reports                 # app/reports — CSV export of findings
├── Settings                 # app/settings — per-user alert threshold and notification preferences
├── Database                 # app/database/models.py — SQLAlchemy models (SQLite by default)
├── CLI                       # cli/main.py — standalone command-line scanner
├── Web Application            # app/ (Flask app factory, blueprints, templates, static assets)
├── Tests                       # tests/ — rule-level unit tests + real local-HTTP-server engine tests
├── Documentation                # this README
└── README.md
```

---

## Setup & Run

### Requirements
- Python 3.9+
- pip

### Install

```bash
cd etag-privacy-analyzer
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Run the web application

```bash
python3 run.py
```

Then open `http://127.0.0.1:5000` in your browser, register an account, and run your first scan from the Dashboard by entering a URL you are authorized to test.

### Run the CLI

```bash
# Basic scan
python3 cli/main.py scan https://your-authorized-target.example.com

# JSON output (for piping into other tools)
python3 cli/main.py scan https://your-authorized-target.example.com --json

# Export findings to CSV
python3 cli/main.py scan https://your-authorized-target.example.com --csv findings.csv

# Skip TLS verification (e.g. internal self-signed hosts you control)
python3 cli/main.py scan https://internal.example.com --no-verify-tls

# List all detection rules
python3 cli/main.py rules
```

The CLI exits with status code `1` if any findings were produced (CI/CD friendly) and `0` on a clean scan.

### Run the tests

```bash
PYTHONPATH=. python3 -m pytest tests/ -v
```

Tests include rule-level unit tests against synthetic-but-realistic response dicts, and genuine end-to-end tests that boot a real local HTTP server on an ephemeral `127.0.0.1` port and perform an actual HTTP request against it via the real Security Engine — no third-party network calls are made during testing.

---

## Frequently Asked Questions

**What does the ETag Privacy Analyzer check?**
It issues one real HTTP GET request to a URL you authorize and inspects the live `ETag` response header, flagging inode-based ETag formats that leak filesystem metadata, ETags on cookie-bearing responses missing a `Vary` header, weak ETags on sensitive pages, and ETag values that resemble opaque tracking tokens — never sample data.

**Who should use the ETag Privacy Analyzer?**
Web developers and security/privacy engineers auditing ETag usage on sites and applications they own or are explicitly authorized to test.

**Is the ETag Privacy Analyzer a replacement for a professional security audit?**
No. It is an educational and productivity aid only. It does not replace a certified penetration test, compliance audit, or professional security assessment.

**Can an ETag really leak server information?**
Yes. On some default Apache/nginx configurations, static-file ETags are generated from the file's inode number, size, and modification time — the inode number is internal server metadata that has no reason to be exposed to clients, and its disclosure has been a recognized, catalogued issue for years.

**Does this tool send more than one request per scan?**
No. Each scan is a single, standard HTTP GET request with redirects followed by the underlying HTTP client — no repeated requests, no brute-forcing, no payload injection.

---

## License & Attribution

Developed by **Karanam Shrivasta**.
GitHub: https://github.com/mrshrivasta · LinkedIn: https://www.linkedin.com/in/karanam-shrivasta

Provided for authorized security auditing and educational use only. See the Disclaimer section above. No warranty of any kind is provided.
