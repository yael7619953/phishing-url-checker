"""
app.py - minimal web backend for the URL checker.

Two endpoints, both reusing the exact same pipeline as the CLI (main.py):
  POST /api/scan       -> JSON result, for rendering on the page
  POST /api/scan/csv   -> the same scan, returned as a downloadable CSV

Run with:  python app.py
Then open  http://localhost:5000
"""

from flask import Flask, request, jsonify, Response, send_from_directory

from url_checker import analyze_url
from scoring import score_report
from external_lookup import check_safe_browsing
from reporting import build_detailed_csv

app = Flask(__name__, static_folder="static", static_url_path="")


def run_pipeline(url: str, use_external: bool):
    """Same steps main.py runs for a single URL - kept in one place so the
    CLI and the web endpoints can never drift apart."""
    results = analyze_url(url)
    if use_external:
        results.append(check_safe_browsing(url))
    score_data = score_report(results)
    return results, score_data


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "נא להזין כתובת URL"}), 400

    try:
        results, score_data = run_pipeline(url, use_external=bool(data.get("use_external")))
    except Exception as exc:
        return jsonify({"error": f"לא ניתן היה לסרוק את הכתובת ({exc.__class__.__name__})"}), 500

    return jsonify({
        "url": url,
        "score": score_data["score"],
        "risk_level": score_data["risk_level"],
        "checks": [
            {"name": r["name"], "flagged": r["flagged"], "detail": r["detail"]}
            for r in results
        ],
    })


@app.route("/api/scan/csv", methods=["POST"])
def scan_csv():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "נא להזין כתובת URL"}), 400

    try:
        results, score_data = run_pipeline(url, use_external=bool(data.get("use_external")))
    except Exception as exc:
        return jsonify({"error": f"לא ניתן היה לסרוק את הכתובת ({exc.__class__.__name__})"}), 500

    csv_text = build_detailed_csv(url, results, score_data)
    safe_name = "".join(c for c in url if c.isalnum())[:40] or "scan"
    return Response(
        csv_text,
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="phishing-report-{safe_name}.csv"'},
    )


if __name__ == "__main__":
    app.run(debug=True, port=5000)
