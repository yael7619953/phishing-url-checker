import argparse

from url_checker import analyze_url, print_report
from scoring import score_report
from external_lookup import check_safe_browsing
 
 
def print_score(report: dict) -> None:
    print(f"Risk score: {report['score']} / 100  ->  {report['risk_level']} risk")
    if report["explanations"]:
        print("Why:")
        for line in report["explanations"]:
            print(f"  {line}")
    else:
        print("Why: no red flags detected.")
    print()
 
 
def main():
    parser = argparse.ArgumentParser(
        description="Analyze a URL's structure for phishing red flags and compute a risk score."
    )
    parser.add_argument(
        "url", help="The URL to analyze (e.g. http://example.com)"
    )
    parser.add_argument(
        "--no-external",
        action="store_true",
        help="Skip the optional Safe Browsing API lookup, even if a key is configured.",
    )
    args = parser.parse_args()
 
    results = analyze_url(args.url)
 
    if not args.no_external:
        results.append(check_safe_browsing(args.url))
 
    print_report(args.url, results)
    print_score(score_report(results))

if __name__ == "__main__":
    main()
