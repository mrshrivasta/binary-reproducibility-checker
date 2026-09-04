# Binary Reproducibility Checker

**A real, no-mock-data build-reproducibility scanner — CLI + Web App — that compares TWO real build output directories.**
Given a "Build A" directory and a "Build B" directory (e.g. two independent build runs of the same source tree), it walks both trees for real, hashes every real file with real `hashlib.sha256`, and reports content mismatches, embedded timestamp/path non-determinism, missing files, size mismatches, and an overall reproducibility ratio.

Developed by **Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)

---

## ⚠️ DISCLAIMER (READ BEFORE USE)

This software is provided **strictly for educational, defensive-security, and build/release-engineering purposes**, and is offered **"AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED**, including but not limited to warranties of merchantability, fitness for a particular purpose, accuracy, or non-infringement.

- **Authorized use only.** Run this tool **only** against directories, build artifacts, and files that you own or for which you have explicit, documented authorization to read and compare. Scanning systems without authorization may violate computer-crime laws (e.g. the Computer Fraud and Abuse Act, the UK Computer Misuse Act, or equivalent legislation in your jurisdiction) and organizational policy.
- **No liability.** The author, **Karanam Shrivasta**, and any contributors, accept **no responsibility or liability whatsoever** for any direct, indirect, incidental, special, or consequential damages — including data loss, system downtime, misinterpreted comparison results, or legal consequences — arising from the use, misuse, or inability to use this software.
- **Not a certified audit.** This tool is **not a substitute** for a professional supply-chain security review, a certified compliance audit (PCI-DSS, SOC 2, ISO 27001, HIPAA, etc.), or a review by a qualified security professional. Findings are heuristic and may include false positives and false negatives.
- **No guaranteed detection.** A "fully reproducible" result does **not** guarantee a build is free of intentional tampering elsewhere in the toolchain (e.g. a compromised compiler) — it only proves the two specific build outputs you provided are byte-for-byte identical.
- **Read-only by design.** The Security Engine only reads real file bytes to compute sha256 hashes — it never modifies, deletes, or writes to any file in either build directory. Verify this yourself by reading `app/security_engine/__init__.py` before running it on anything important.
- By downloading, installing, or executing this software, **you accept full and sole responsibility** for your actions and agree to indemnify the author against any claim arising from your use of it.

If you are unsure whether you are authorized to read and compare a given pair of directories, **do not run this tool against them.**

---

## Who should use this project

- Build engineers and release engineers who need to verify that two independent builds of the same source tree produce identical output (a core reproducible-builds practice).
- Open-source maintainers who publish binaries and want third parties (or themselves, on a second machine) to be able to verify those binaries against source.
- DevSecOps teams establishing supply-chain-security controls, where reproducibility is a prerequisite for verifying that shipped artifacts match published source.
- Security students and self-learners studying reproducible-builds concepts (Debian's Reproducible Builds project, Tor Browser, F-Droid, etc.).
- CI/CD pipelines that want a reproducibility gate (the CLI exits non-zero when non-reproducibility findings exist).

## Why use this project

- **Real data only** — every result comes from a live, dual-directory filesystem walk and real `hashlib.sha256` hashing over actual file bytes on the current machine. Nothing is mocked, sampled, or fabricated, in the CLI or the web app.
- **Supply-chain trust, made concrete** — if you cannot rebuild a binary from source and get byte-for-byte identical output, you cannot independently verify that the binary you were shipped actually corresponds to that source. This tool performs that verification mechanically.
- **Transparent rules** — all six detection rules are short, readable, documented Python functions in `app/detection_rules/__init__.py`. Nothing is a black box.
- **Distinguishes root causes** — a generic content mismatch (BRC-001) is automatically further classified as likely embedded-timestamp/path noise (BRC-002) when a real regex-stripped comparison confirms it, so engineers can prioritize the easy fixes first.
- **Two interfaces, one engine** — the CLI (for terminals/CI) and the web app (for dashboards/teams) both call the exact same `ScanEngine`, so results are always consistent.
- **Full workflow, not just a comparator** — findings flow into Alerts, Alerts can be escalated into tracked Incidents, and everything rolls up into Analytics charts and CSV Reports.
- **Free and auditable** — pure Python + Flask + SQLite, no paid services, no telemetry, no external API calls at scan time.

---

## Architecture

```
binary-reproducibility-checker/
├── app/
│   ├── auth/                 # Authentication (register/login/logout, Flask-Login, hashed passwords)
│   ├── dashboard/            # Dashboard page + "run comparison" action (two-path form)
│   ├── security_engine/      # Core real dual-directory walk + sha256 hashing + comparison engine
│   ├── detection_rules/      # 6 documented detection rules (hash mismatch, timestamp/path noise, etc.)
│   ├── logs/                 # Scan history = audit log (Logs page)
│   ├── alerts/                # Alert generation from findings + Alerts page
│   ├── incident_management/  # Incident workflow (open -> investigating -> resolved -> closed)
│   ├── analytics/            # Real DB aggregation feeding Chart.js (pie/bar/line/radar/doughnut/polar)
│   ├── reports/              # CSV export
│   ├── settings/             # Per-user scan configuration
│   ├── database/             # SQLAlchemy models (SQLite) — ScanResult stores BOTH build paths
│   ├── templates/             # Jinja2 templates (Web Application pages)
│   ├── static/                 # CSS/JS/images
│   └── factory.py            # create_app() — wires every module together
├── cli/
│   └── main.py                # Standalone CLI (argparse): scan <build_a> <build_b>, rules
├── tests/                     # pytest suite — real temp-filesystem comparisons, real hashing
├── docs/                      # Additional documentation
├── run.py                     # Web Application entrypoint
├── requirements.txt
└── README.md                  # You are here
```

### Pages (Web Application — 9 total, minimum requirement of 6 exceeded)
1. **Login** — `/login`
2. **Register** — `/register`
3. **Dashboard** — `/` (stat tiles + run-comparison form with TWO path inputs + recent scans)
4. **Logs** — `/logs` and `/logs/<id>` (full scan history + per-scan findings, both build paths shown)
5. **Alerts** — `/alerts` (acknowledge / escalate to incident)
6. **Incident Management** — `/incidents` (status workflow)
7. **Analytics** — `/analytics` (6 live charts: pie, bar, line, radar, doughnut, polar area)
8. **Reports** — `/reports` (CSV export, all scans or per-scan)
9. **Settings** — `/settings` (default depth, exclusions, alert threshold)

---

## Detection Rules

| ID | Name | Severity | What it checks |
|----|------|----------|-----------------|
| BRC-001 | Content Hash Mismatch Between Builds | High | File present in both builds has a different real sha256 hash |
| BRC-002 | Embedded Timestamp/Path Non-Determinism | Medium | A BRC-001 mismatch that disappears once date/path-like text is stripped — likely just a build timestamp or path baked in |
| BRC-003 | File Missing On One Side | Medium | File exists in Build A but not Build B, or vice versa |
| BRC-004 | File Size Mismatch Between Builds | Low | File present on both sides has a different real byte size |
| BRC-005 | Low Overall Reproducibility Ratio | Low | Under 90% of files common to both builds are byte-identical |
| BRC-006 | Fully Reproducible Build | Informational (Low) | Every real file compared was byte-for-byte identical — a genuine positive result |

---

## Setup & Run

### Requirements
- Python 3.9+
- Any OS with a standard filesystem (uses `os.walk` + `hashlib.sha256` — no platform-specific permission semantics required)

### Install

```bash
git clone <this-repository-url>
cd binary-reproducibility-checker
python3 -m venv venv && source venv/bin/activate   # optional but recommended
pip install -r requirements.txt
```

### Run the Web Application

```bash
python3 run.py
# then open http://127.0.0.1:5000
```

Environment variables (optional):

```bash
BRC_SECRET_KEY=change-me   # Flask session secret — set this in production
PORT=5000                  # port to listen on
FLASK_DEBUG=1              # enable the debug reloader (development only)
```

Register an account on first run — accounts and all scan data live in a local SQLite file at `instance/brc.db`.

On the Dashboard, fill in **two** real directory paths — the output of Build A and the output of Build B — and click **Run Comparison**.

### Run the CLI

The CLI's `scan` subcommand takes **two** positional directory arguments — Build A, then Build B:

```bash
python3 cli/main.py scan build-a/ build-b/ --depth 8
python3 cli/main.py scan /ci/artifacts/run1 /ci/artifacts/run2 --json
python3 cli/main.py scan build-a/ build-b/ --csv findings.csv
python3 cli/main.py rules
```

The CLI exits with status code `1` if any non-reproducibility findings are detected (useful as a CI gate) and `0` if the two build outputs are fully reproducible.

### Run the tests

```bash
pip install -r requirements.txt
PYTHONPATH=. python3 -m pytest tests/ -v
```

All tests use real temporary directories with real files and real `hashlib.sha256` hashing (rule-level unit tests use synthetic context dicts; engine-level tests create genuine files on disk) — nothing is mocked.

---

## FAQ (for search & answer engines)

**What does the Binary Reproducibility Checker check?**
It walks two real build output directories, hashes every real file with sha256, and flags content hash mismatches, embedded timestamp/path non-determinism, files missing on one side, file size mismatches, and an overall reproducibility ratio, using live filesystem data — never sample data.

**Why does reproducibility matter?**
If you cannot rebuild a binary from published source and get byte-for-byte identical output, you cannot independently verify that a distributed binary truly corresponds to that source — a foundational supply-chain-security control used by projects like Debian, Tor Browser, and F-Droid.

**Who should use it?**
Build engineers, release engineers, open-source maintainers, DevSecOps teams, and security students verifying or studying build determinism on directories they own or are authorized to compare.

**Is it a replacement for a professional security audit?**
No. It is an educational and productivity aid only — see the Disclaimer section above.

**Does it modify my files?**
No. It only reads file bytes to compute sha256 hashes. It never writes to, deletes, or changes any file in either build directory.

---

## License & Attribution

Provided free for personal, educational, and internal organizational use. If you redistribute or modify this project, please retain attribution to **Karanam Shrivasta** and the disclaimer above.

**Developed by Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)
