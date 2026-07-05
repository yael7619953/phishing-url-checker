import argparse
import sys

from url_checker import analyze_url, print_report
from scoring import score_report
from external_lookup import check_safe_browsing
from reporting import (
    build_report,
    print_summary_table,
    export_csv,
    export_json,
    read_urls_from_file,
)


def print_score(report: dict) -> None:
    print(f"Risk score: {report['score']} / 100  ->  {report['risk_level']} risk")
    if report["explanations"]:
        print("Why:")
        for line in report["explanations"]:
            print(f"  {line}")
    else:
        print("Why: no red flags detected.")
    print()


def scan_one(url: str, use_external: bool) -> tuple:
    """
    Run the full check pipeline on a single URL.

    Returns (results, score_data, error). On any unexpected failure the
    error string is set and results/score_data are None, so a single bad
    URL in a batch never crashes the whole run.
    """
    try:
        results = analyze_url(url)
        if use_external:
            results.append(check_safe_browsing(url))
        score_data = score_report(results)
        return results, score_data, None
    except Exception as exc:
        return None, None, f"{exc.__class__.__name__}: {exc}"


def run_batch(urls: list, use_external: bool, verbose: bool) -> list:
    reports = []
    for raw_url in urls:
        url = raw_url.strip()
        if not url:
            continue
        results, score_data, error = scan_one(url, use_external)
        if error:
            print(f"[skipped] {url} - {error}")
            reports.append(build_report(url, [], {}, error=error))
            continue
        if verbose:
            print_report(url, results)
            print_score(score_data)
        reports.append(build_report(url, results, score_data))
    return reports


def main():
    parser = argparse.ArgumentParser(
        description="Analyze one or many URLs for phishing red flags and compute risk scores."
    )
    parser.add_argument(
        "url", nargs="?",
        help="A single URL to analyze (e.g. http://example.com). Omit this if using --file.",
    )
    parser.add_argument(
        "-f", "--file",
        help="Path to a text file with one URL per line (blank lines and '#' comments are skipped) "
             "for batch scanning.",
    )
    parser.add_argument(
        "--no-external",
        action="store_true",
        help="Skip the optional Safe Browsing API lookup, even if a key is configured.",
    )
    parser.add_argument(
        "-o", "--output",
        choices=["csv", "json"],
        help="Export results to a structured file in this format, in addition to the terminal output.",
    )
    parser.add_argument(
        "--output-file",
        default=None,
        help="Path for the exported file (default: results.csv / results.json).",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="In batch mode, only print the summary table (skip the detailed per-URL report).",
    )
    args = parser.parse_args()

    if not args.url and not args.file:
        parser.error("Provide a URL to scan, or --file with a list of URLs.")
    if args.url and args.file:
        parser.error("Provide either a single URL or --file, not both.")

    use_external = not args.no_external

    if args.file:
        try:
            urls = read_urls_from_file(args.file)
        except OSError as exc:
            print(f"Could not read '{args.file}': {exc}")
            sys.exit(1)

        if not urls:
            print(f"No URLs found in '{args.file}' (file is empty or only has comments/blank lines).")
            sys.exit(0)

        reports = run_batch(urls, use_external, verbose=not args.quiet)
        print_summary_table(reports)

    else:
        results, score_data, error = scan_one(args.url, use_external)
        if error:
            print(f"Could not scan '{args.url}': {error}")
            sys.exit(1)
        print_report(args.url, results)
        print_score(score_data)
        reports = [build_report(args.url, results, score_data)]
        print_summary_table(reports)

    if args.output:
        output_path = args.output_file or f"results.{args.output}"
        try:
            if args.output == "csv":
                export_csv(reports, output_path)
            else:
                export_json(reports, output_path)
            print(f"\nResults exported to {output_path}")
        except OSError as exc:
            print(f"\nCould not write output file '{output_path}': {exc}")


if __name__ == "__main__":
    main()
