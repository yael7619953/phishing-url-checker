# 🔍 Phishing URL Checker

A tool for detecting structural warning signs in URLs that may indicate phishing attempts — combining static structure analysis, typosquatting detection, and an optional live check against Google Safe Browsing. Available both as a CLI and as a local web interface.

> ⚠️ **This tool is intended for defensive, educational, and research purposes only.** It performs static analysis of the URL string — it does **not** visit the site itself, and it is not a substitute for professional security judgment or tooling.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage — CLI](#usage--cli)
- [Usage — Web Interface](#usage--web-interface)
- [How the Risk Score Is Calculated](#how-the-risk-score-is-calculated)
- [Project Structure](#project-structure)
- [Known Limitations](#known-limitations)
- [License](#license)

---

## Features

**8 static structural checks** (no internet connection required):

| Check                        | What it detects                                                                                                             |
| ---------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| URL length                   | Unusually long URLs (over 75 characters)                                                                                    |
| IP address instead of domain | Direct IP usage (`http://192.168.1.1/...`)                                                                                  |
| Subdomain count              | Suspicious subdomain chains (`login.secure.bank.com`)                                                                       |
| `@` symbol                   | A common technique for hiding the real destination                                                                          |
| Excessive hyphens            | `secure-login-verify.com`                                                                                                   |
| Suspicious keywords          | `secure`, `verify`, `login`, `account`, `update`, etc.                                                                      |
| URL shortener services       | `bit.ly`, `tinyurl.com`, etc.                                                                                               |
| **Typosquatting**            | Similarity to well-known domains, including homoglyph detection (`paypa1.com` ⇄ `paypal.com`) and Levenshtein edit distance |

**Optional external check:**

- Integration with the **Google Safe Browsing API** — checks whether the URL has already been reported as malware/phishing. Requires a free API key; if no key is configured, this check is skipped automatically (graceful degradation) without affecting the rest of the analysis.

**Unified risk score (0–100):**
All checks are combined into a single score with a risk level (Low/Medium/High) and a detailed explanation for every flag raised.

**Two interfaces:**

- **CLI** — single-URL or batch scanning (a file with a list of URLs), with CSV/JSON export
- **Web UI** — a local page with a URL input field, a visual report, and a downloadable detailed CSV report

---

## Installation

Requires **Python 3.9+**.

```bash
git clone https://github.com/<your-username>/phishing-url-checker.git
cd phishing-url-checker
pip install -r requirements.txt
```

### (Optional) Setting up the Google Safe Browsing check

1. Get a free API key: https://developers.google.com/safe-browsing/v4/get-started
2. Create a `.env` file in the project root:
   ```
   SAFE_BROWSING_API_KEY=your-key-here
   ```
   The file is loaded automatically at runtime. Without a key, this check is simply skipped — the rest of the tool keeps working normally.

---

## Usage — CLI

### Scan a single URL

```bash
python main.py "http://paypa1.com/login"
```

```
URL: http://paypa1.com/login
------------------------------------------------------------
[ok]      URL length: 23 characters (threshold: 75)
[ok]      IP address instead of domain: No IP address used as host
[ok]      Subdomain count: 0 subdomain(s) (threshold: 3)
[ok]      '@' symbol in URL: Not found
[ok]      Excessive hyphens in domain: 0 hyphen(s) (threshold: 2)
[FLAGGED] Suspicious keywords: Found: login
[ok]      URL shortener service: Not a known shortener
[FLAGGED] Typosquatting: 'paypa1.com' closely resembles known domain 'paypal.com' (edit distance: 0)
------------------------------------------------------------
Total flags raised: 2 / 8

Risk score: 45 / 100  ->  Medium risk
Why:
  +15 pts - Suspicious keywords: Found: login
  +30 pts - Typosquatting: 'paypa1.com' closely resembles known domain 'paypal.com' (edit distance: 0)
```

### Scan a list of URLs (batch mode)

A plain text file, one URL per line. Blank lines and lines starting with `#` are skipped — lines can also be tagged with `[REAL]` / `[SUSPICIOUS]` for documentation purposes:

```
# Known-safe examples
[REAL] https://www.google.com

# Suspicious examples
[SUSPICIOUS] http://paypa1.com/login
```

```bash
python main.py --file tests/tests.txt
```

Add `--quiet` to print only the summary table, without the detailed per-URL report:

```bash
python main.py --file tests/tests.txt --quiet
```

```
URL                                              SCORE  RISK      FLAGS
-----------------------------------------------------------------------
https://www.google.com                               0  Low         0/8
http://paypa1.com/login                             45  Medium      2/8
http://bank-of-america.com                          40  Medium      2/8

Scanned 3 URL(s): 0 High, 2 Medium, 1 Low risk.
```

### Export results to a file

```bash
python main.py --file tests/tests.txt -o csv    # -> results.csv
python main.py --file tests/tests.txt -o json   # -> results.json
python main.py --file tests/tests.txt -o csv --output-file report.csv
```

### Skip the external Safe Browsing check

```bash
python main.py --no-external "https://example.com"
```

### All CLI options

| Flag                      | Description                                                         |
| ------------------------- | ------------------------------------------------------------------- |
| `url`                     | A single URL to scan (not used together with `--file`)              |
| `-f, --file PATH`         | A file with a list of URLs for batch scanning                       |
| `--no-external`           | Skip the Safe Browsing check even if an API key is configured       |
| `-o, --output {csv,json}` | Export results to a file, in addition to terminal output            |
| `--output-file PATH`      | Custom path for the exported file                                   |
| `-q, --quiet`             | In batch mode: print only the summary table, not the per-URL detail |

---

## Usage — Web Interface

Start the local server:

```bash
python app.py
```

Open your browser at: **http://localhost:5000**

Paste a URL, click "Scan", and get a visual report: a score with a color-coded progress bar (green/orange/red by risk level), and a list of every check with its explanation. A detailed report can be downloaded as a CSV file with one click.

> **Note:** This is a Flask development server intended for local use only. Do not expose it to the open internet as-is.

---

## How the Risk Score Is Calculated

Each check has a fixed weight. The final score is the sum of the weights of every flagged check, capped at 100:

| Check                        | Weight |
| ---------------------------- | ------ |
| IP address instead of domain | 25     |
| Typosquatting                | 30     |
| `@` symbol in URL            | 20     |
| Subdomain count              | 15     |
| Suspicious keywords          | 15     |
| URL shortener service        | 15     |
| Excessive hyphens            | 10     |
| URL length                   | 10     |
| Safe Browsing (if flagged)   | 50     |

**Risk level classification:**

- **Low:** 0–24
- **Medium:** 25–59
- **High:** 60–100

---

## Project Structure

```
├── main.py               # CLI entry point
├── app.py                 # Flask server for the web interface
├── url_checker.py          # URL structure analysis logic (8 checks)
├── typosquatting.py         # Typosquatting detection (Levenshtein + homoglyphs)
├── scoring.py               # Risk score calculation and classification
├── external_lookup.py       # Optional Google Safe Browsing integration
├── reporting.py              # Summary table, CSV/JSON export, batch file reading
├── static/
│   ├── index.html            # Web UI page
│   ├── index.css
│   └── index.js
├── tests/
│   └── tests.txt              # Sample file for batch scanning
└── requirements.txt
```

---

## Known Limitations

- **Static analysis only** (except for Safe Browsing) — the tool does not actually visit the site, so it won't detect malicious content on the page itself, only suspicious patterns in the URL.
- **False positives/negatives are possible** — a high score doesn't necessarily mean phishing, and a low score doesn't guarantee safety. This is a first-pass screening aid, not a final verdict.
- **The known-domains list** in `typosquatting.py` is limited (about 20 common domains) — typosquatting won't be caught for brands not on the list.
- **Safe Browsing depends on an API key and network access** — without an internet connection or a key, this check is silently skipped.
- **The development server (`app.py`)** is intended for local use only and is not hardened for public deployment as-is.

---

## License

MIT
