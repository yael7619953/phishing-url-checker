import argparse
from url_checker import

def main():
    parser = argparse.ArgumentParser(
        description="Stage 1: Analyze a URL's structure for phishing red flags."
    )
    parser.add_argument("url", help="The URL to analyze (e.g. http://example.com)")
    args = parser.parse_args()

    results = analyze_url(args.url)
    print_report(args.url, results)


if __name__ == "__main__":
    main()
