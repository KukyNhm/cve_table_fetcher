#!/usr/bin/env python3
"""cve_table_fetcher.py
=====================================
Fetch **CVSS base scores** (v3.1 → v3.0 → v2 fallback) from the NVD and
**EPSS exploit-probability scores** from FIRST for any set of CVE IDs, then
print the results in TSV/CSV/Markdown or write a self-contained **HTML** file.

Features
--------
* Traffic-light colouring by CVSS; **purple** if EPSS ≥ 70 %.
* Optional **CVSS version tag** (`--show-version` → e.g. `9.8 (v3.1)`).
* Filters `--min-cvss` and `--min-epss`.
* Summary stats: severity breakdown, average EPSS, top-5 EPSS.
* **Examples are baked straight into `--help`.**
* If `--format html` is selected, the script writes `cve_table.html` (or
  what you pass via `-o/--out`). You can tweak its CSS afterwards.

Examples
--------
```bash
# Interactive prompt, default TSV with colours
python cve_table_fetcher.py

# CSV, display CVSS version, only High/Critical + EPSS ≥ 50 %
python cve_table_fetcher.py --format csv --show-version \
                            --min-cvss 7 --min-epss 50

# Markdown table for a GitHub issue
python cve_table_fetcher.py --format md --show-version

# Generate a standalone HTML report
python cve_table_fetcher.py --format html -o report.html
```

Requirements: `pip install requests`  •  License: MIT
"""

from __future__ import annotations

import argparse
import collections
import html as htmllib
import os
import sys
import textwrap
import time
from typing import Dict, List, Optional, Tuple
from dotenv import load_dotenv

import requests

# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
load_dotenv()
NVD_API_KEY = os.getenv("NVD_API_KEY") or sys.exit("Environment variable NVD_API_KEY must be set.")
HTTP_TIMEOUT = 15      # seconds
NVD_SLEEP = 1.8        # polite delay between requests in serial mode
DEFAULT_HTML_FILE = "cve_table.html"

ANSI_RESET = "\033[0m"
COLORS = {
    "none": "\033[38;2;128;128;128m",
    "low": "\033[38;2;0;128;0m",
    "medium": "\033[38;2;200;128;0m",
    "high": "\033[38;2;200;0;0m",
    "critical": "\033[38;2;255;0;0m",
    "epss": "\033[38;2;128;0;128m",
}

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def prompt_cve_ids() -> List[str]:
    """Prompt the user for CVE IDs separated by commas and return a sorted unique list."""
    raw = input("Enter CVE IDs separated by commas: ")
    ids = {c.strip().upper() for c in raw.split(',') if c.strip()}
    if not ids:
        sys.exit("No CVE IDs supplied – quitting.")
    return sorted(ids)


def colour_code(cvss: Optional[float], epss: float, enabled: bool) -> str:
    """Return ANSI colour for the given CVSS/EPSS combination (TSV only)."""
    if not enabled:
        return ""
    if epss >= 70:
        return COLORS["epss"]
    if cvss is None or cvss < 0:
        return COLORS["none"]
    if cvss < 4:
        return COLORS["low"]
    if cvss < 7:
        return COLORS["medium"]
    if cvss < 9:
        return COLORS["high"]
    return COLORS["critical"]


def fetch_epss(cves: List[str]) -> Dict[str, float]:
    """Fetch EPSS scores (percentage) from FIRST as {CVE: float}."""
    url = f"https://api.first.org/data/v1/epss?cve={','.join(cves)}"
    resp = requests.get(url, timeout=HTTP_TIMEOUT)
    resp.raise_for_status()
    data = resp.json().get("data", [])
    return {d["cve"].upper(): round(float(d["epss"]) * 100, 2) for d in data}


def fetch_cvss(cve: str) -> Tuple[Optional[float], Optional[str]]:
    """Return (score, version) where version ∈ {v3.1,v3.0,v2}."""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    resp = requests.get(
        url,
        headers={"apiKey": NVD_API_KEY},
        params={"cveId": cve},
        timeout=HTTP_TIMEOUT,
    )
    resp.raise_for_status()
    metrics = resp.json().get("vulnerabilities", [{}])[0].get("cve", {}).get("metrics", {})
    for key, ver in (("cvssMetricV31", "v3.1"), ("cvssMetricV30", "v3.0"), ("cvssMetricV2", "v2")):
        if key in metrics and metrics[key]:
            return metrics[key][0]["cvssData"]["baseScore"], ver
    return None, None

# --------------------------------------------------------------------------- #
# Output helpers
# --------------------------------------------------------------------------- #


def header_line(fmt: str) -> str:
    if fmt == "csv":
        return "CVE,CVSS,EPSS(%)"
    if fmt == "tsv":
        return "CVE\tCVSS\tEPSS(%)"
    if fmt == "md":
        return "| CVE | CVSS | EPSS(%) |\n| --- | --- | --- |"
    # html handled elsewhere
    return ""


def footer_html() -> str:
    return "</tbody></table></body></html>"


def format_row(values: List[str], fmt: str, colour: str, reset: str) -> str:
    if fmt == "csv":
        return ",".join(values)
    if fmt == "md":
        return "| " + " | ".join(values) + " |"
    if fmt == "html":
        cells = "".join(f"<td>{htmllib.escape(v)}</td>" for v in values)
        return f"  <tr>{cells}</tr>"
    # default tsv with optional colour
    return f"{colour}" + "\t".join(values) + reset


def print_table(rows: List[dict], fmt: str, colors: bool):
    if fmt == "html":
        raise RuntimeError("print_table should not be called for html output – use write_html_file().")
    print(header_line(fmt))
    for r in rows:
        colour = colour_code(r["cvss_num"], r["epss"], colors and fmt == "tsv")
        print(format_row([r["cve"], r["cvss_display"], f"{r['epss']}"] , fmt, colour, ANSI_RESET if colour else ""))

# --------------------------------------------------------------------------- #
# HTML report generation
# --------------------------------------------------------------------------- #

def _css_class(cvss: Optional[float], epss: float) -> str:
    """Return CSS class name based on severity."""
    if epss >= 70:
        return "epss"
    if cvss is None or cvss < 0:
        return "none"
    if cvss < 4:
        return "low"
    if cvss < 7:
        return "medium"
    if cvss < 9:
        return "high"
    return "critical"


def write_html_file(rows: List[dict], out_path: str):
    """Write a standalone HTML file with basic styling."""
    css = textwrap.dedent(
        """
        body{font-family:Arial,Helvetica,sans-serif;margin:0;padding:2rem;background:#fafafe;color:#111}
        table{border-collapse:collapse;margin:0 auto;min-width:420px;width:90%;box-shadow:0 2px 6px rgba(0,0,0,0.1)}
        th,td{border:1px solid #ccc;padding:8px 10px;font-size:0.92rem}
        thead{background:#f0f0f0;font-weight:700}
        tr.low      {background:#b9f6ca}
        tr.medium   {background:#ffe57f}
        tr.high     {background:#ff8a80}
        tr.critical {background:#ff5252;color:#fff}
        tr.epss     {background:#d1c4e9}
        tr.none     {background:#e0e0e0;color:#555}
        caption{caption-side:bottom;padding:1rem;font-size:0.85rem}
        h2{margin-top:3rem;text-align:center;font-size:1.3rem}
        section p{margin:0.4rem 0;max-width:720px;margin-left:auto;margin-right:auto}
        td a{color:inherit;text-decoration:none;font-weight:600}
        td a:hover{border-bottom:2px solid currentColor}
        """
    ).strip()

    html_lines = [
        "<!doctype html>",
        "<html lang=\"en\">",
        "<head>",
        "<meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
        "<title>CVE Report</title>",
        f"<style>{css}</style>",
        "</head>",
        "<body>",
        "<table>",
        "<thead><tr><th>CVE</th><th>CVSS</th><th>EPSS (%)</th></tr></thead>",
        "<tbody>",
    ]

    for r in rows:
        cls = _css_class(r["cvss_num"], r["epss"])
        link = f'<a href="https://nvd.nist.gov/vuln/detail/{r["cve"]}" target="_blank">{r["cve"]}</a>'
        html_lines.append(
            f"<tr class=\"{cls}\"><td>{link}</td><td>{htmllib.escape(r['cvss_display'])}</td><td>{r['epss']}</td></tr>"
        )

    html_lines.extend([
        "</tbody>",
        "</table>",
        "<section>",
        "<h2>Column glossary</h2>",
        "<p><strong>CVE</strong> - <em>Common Vulnerabilities and Exposures</em>. "
        "Each CVE ID (Common Vulnerabilities and Exposures) uniquely identifies a publicly disclosed software or hardware vulnerability. Click the ID to view its entry in the U.S. National Vulnerability Database (NVD).</p>",
        "<p><strong>CVSS</strong> - <em>Common Vulnerability Scoring System</em> "
        "base score (0-10). It expresses the technical severity. Colours follow "
        "the v3.1 thresholds: Low &lt; 4, Medium &lt; 7, High &lt; 9, Critical ≥ 9.</p>",
        "<p><strong>EPSS</strong> - <em>Exploit Prediction Scoring System</em> probability "
        "(0-100 %). It estimates the chance that the vulnerability will be "
        "exploited in the wild within the next 30 days. Rows in purple mark "
        "EPSS ≥ 70 %, indicating high exploitation risk.</p>",
        "</section>",
        "</body>",
        "</html>",
    ])
    
    with open(out_path, "w", encoding="utf-8") as fp:
        fp.write("\n".join(html_lines))

# --------------------------------------------------------------------------- #
# Stats
# --------------------------------------------------------------------------- #

def print_stats(rows: List[dict]):
    if not rows:
        print("[!] No rows to summarise after filtering.", file=sys.stderr)
        return

    sev = collections.Counter()
    epss_vals = [r["epss"] for r in rows]
    for r in rows:
        c = r["cvss_num"]
        if c is None or c < 0:
            sev["N/A"] += 1
        elif c < 4:
            sev["Low"] += 1
        elif c < 7:
            sev["Medium"] += 1
        elif c < 9:
            sev["High"] += 1
        else:
            sev["Critical"] += 1
    print("\n--- Statistics ---", file=sys.stderr)
    for k in ("Critical", "High", "Medium", "Low", "N/A"):
        if k in sev:
            print(f"{k:9}: {sev[k]}", file=sys.stderr)
    print(f"Average EPSS : {sum(epss_vals)/len(epss_vals):.2f}%", file=sys.stderr)
    for r in sorted(rows, key=lambda x: x["epss"], reverse=True)[:5]:
        print(f"Top EPSS     : {r['cve']} {r['epss']}%", file=sys.stderr)

# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def parse_args() -> argparse.Namespace:
    examples = textwrap.dedent(
        """
        Examples:
          python cve_table_fetcher.py                       # interactive prompt → TSV
          python cve_table_fetcher.py --format csv          # CSV on stdout
          python cve_table_fetcher.py --format md -sv       # Markdown + version tag
          python cve_table_fetcher.py --format html -o out.html CVE-2024-1234,CVE-2024-9876
        """
    )

    p = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Fetch CVSS & EPSS for CVE IDs and render a coloured table.",
        epilog=examples,
    )
    p.add_argument("--format", choices=["tsv", "csv", "md", "html"], default="tsv",
                   help="Output format (default: tsv). 'html' writes a file, the others go to stdout.")
    p.add_argument("--min-cvss", type=float, default=0, help="Filter: minimum CVSS score (inclusive)")
    p.add_argument("--min-epss", type=float, default=0, help="Filter: minimum EPSS percentage (inclusive)")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colours in TSV output")
    p.add_argument("--show-version", "-sv", action="store_true", help="Append CVSS version e.g. '9.8 (v3.1)'")
    p.add_argument("-o", "--out", metavar="FILE", help="Write HTML to FILE (default: cve_table.html)")
    return p.parse_args()

# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main():
    args = parse_args()
    cves = prompt_cve_ids()

    print(f"[*] Fetching EPSS for {len(cves)} CVEs…", file=sys.stderr)
    try:
        epss = fetch_epss(cves)
    except requests.HTTPError as e:
        sys.exit(f"[!] EPSS API error: {e}")

    rows = []
    for idx, cve in enumerate(cves, 1):
        print(f"[*] ({idx}/{len(cves)}) Querying NVD for {cve}", file=sys.stderr)
        try:
            score, ver = fetch_cvss(cve)
        except requests.HTTPError as e:
            print(f"[!] NVD error for {cve}: {e}", file=sys.stderr)
            score, ver = None, None
        display = "N/A" if score is None else f"{score:.1f}" + (f" ({ver})" if args.show_version and ver else "")
        rows.append({
            "cve": cve,
            "cvss_num": score if score is not None else -1,
            "cvss_display": display,
            "epss": epss.get(cve, 0.0),
        })
        time.sleep(NVD_SLEEP)

    # filter & sort
    rows = [
        r for r in rows
        if (r["cvss_num"] < 0 or r["cvss_num"] >= args.min_cvss) and r["epss"] >= args.min_epss
    ]
    rows.sort(key=lambda r: (r["cvss_num"], r["epss"]), reverse=True)

    if args.format == "html":
        out_file = args.out or DEFAULT_HTML_FILE
        write_html_file(rows, out_file)
        print(f"[+] HTML report written to {out_file}", file=sys.stderr)
    else:
        print_table(rows, args.format, not args.no_color)

    print_stats(rows)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\n[!] Interrupted by user.")
