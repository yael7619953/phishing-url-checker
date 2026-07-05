"""
reporting.py - Stage 5: structured output for single or batch scans.

Turns the raw checks + score for one or more URLs into:
  - a compact summary table for the terminal
  - a CSV file
  - a JSON file

Keeping this separate from url_checker.py / scoring.py mirrors the rest of
the project: each module owns one job and the pieces are combined in
main.py.
"""

import csv
import io
import json
import re

from scoring import CHECK_WEIGHTS

# Matches an optional leading label like "[REAL] " or "[SUSPICIOUS] " at the
# start of a line, so test files can be annotated with ground-truth tags
# without breaking URL parsing.
LEADING_TAG_PATTERN = re.compile(r"^\[[^\]]+\]\s*")


def build_report(url: str, results: list, score_data: dict, error: str = None) -> dict:
    """
    Combine one URL's checks + score into a single flat-ish record that's
    convenient for both the summary table and CSV/JSON export.
    """
    if error:
        return {
            "url": url,
            "error": error,
            "score": None,
            "risk_level": "Error",
            "flags_raised": 0,
            "total_checks": 0,
            "explanations": [],
        }

    flagged = [r for r in results if r["flagged"]]
    return {
        "url": url,
        "error": None,
        "score": score_data["score"],
        "risk_level": score_data["risk_level"],
        "flags_raised": len(flagged),
        "total_checks": len(results),
        "explanations": score_data["explanations"],
    }


def print_summary_table(reports: list) -> None:
    """Print one row per URL: score, risk level, and flag count."""
    if not reports:
        print("No URLs were scanned.")
        return

    url_width = max(len(r["url"]) for r in reports)
    url_width = max(url_width, len("URL"))

    header = f"{'URL':<{url_width}}  {'SCORE':>5}  {'RISK':<8}  {'FLAGS':>5}"
    print(header)
    print("-" * len(header))

    for r in reports:
        if r["error"]:
            print(f"{r['url']:<{url_width}}  {'--':>5}  {'ERROR':<8}  {'--':>5}   ({r['error']})")
            continue
        flags = f"{r['flags_raised']}/{r['total_checks']}"
        print(f"{r['url']:<{url_width}}  {r['score']:>5}  {r['risk_level']:<8}  {flags:>5}")

    print()
    scanned = sum(1 for r in reports if not r["error"])
    errored = len(reports) - scanned
    high = sum(1 for r in reports if r["risk_level"] == "High")
    medium = sum(1 for r in reports if r["risk_level"] == "Medium")
    low = sum(1 for r in reports if r["risk_level"] == "Low")
    summary = f"Scanned {scanned} URL(s): {high} High, {medium} Medium, {low} Low risk."
    if errored:
        summary += f" {errored} could not be scanned."
    print(summary)


def build_detailed_csv(url: str, results: list, score_data: dict) -> str:
    """
    Build a CSV (as a string) with one row per check for a single URL - the
    "detailed report" a person downloads after scanning one link on the web
    frontend. This is intentionally different from export_csv() above, which
    is one row per URL for batch scans.

    Layout: a two-line summary block (url/score/risk), a blank separator
    line, then one row per individual check.
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer)

    writer.writerow(["url", "score", "risk_level"])
    writer.writerow([url, score_data["score"], score_data["risk_level"]])
    writer.writerow([])

    writer.writerow(["check", "flagged", "points", "detail"])
    for r in results:
        points = CHECK_WEIGHTS.get(r["name"], 0) if r["flagged"] else 0
        writer.writerow([r["name"], "Yes" if r["flagged"] else "No", points, r["detail"]])

    return buffer.getvalue()


def export_csv(reports: list, filepath: str) -> None:
    fieldnames = ["url", "score", "risk_level", "flags_raised", "total_checks", "explanations", "error"]
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in reports:
            row = dict(r)
            row["explanations"] = " | ".join(row["explanations"])
            writer.writerow(row)


def export_json(reports: list, filepath: str) -> None:
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(reports, f, indent=2, ensure_ascii=False)


def read_urls_from_file(filepath: str) -> list:
    """
    Read one URL per line from a text file.

    Blank lines and lines starting with '#' (comments) are skipped so the
    input file can be lightly annotated. Never raises for a malformed line -
    only an unreadable file raises, which main.py reports cleanly to the user.
    """
    urls = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            line = LEADING_TAG_PATTERN.sub("", line).strip()
            if not line:
                continue
            urls.append(line)
    return urls
