# CVE Table Fetcher

Fetch up‑to‑date **CVSS base scores** (v3.1 → v3.0 → v2 fallback) from the NVD and **EPSS exploit‑probability scores** from FIRST for any set of CVE IDs, then render them as a colour‑coded table or a self‑contained HTML report.

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow)

---

## ✨ Features

* **Multi‑source scoring:** automatic CVSS fallback (v3.1 ⇒ v3.0 ⇒ v2).
* **Traffic‑light severity colours** in TSV/HTML; purple rows highlight EPSS ≥ 70 %.
* **Four output formats** – TSV, CSV, GitHub‑friendly Markdown, or standalone HTML.
* **Filtering** by minimum CVSS or EPSS (`--min-cvss`, `--min-epss`).
* **Optional CVSS version tag** (`--show-version`, e.g. `9.8 (v3.1)`).
* **Summary statistics** printed to *stderr* (severity breakdown, average EPSS, top‑5 EPSS).
* **All examples baked into `--help`.**

---

## 🚀 Quick start

```bash
git clone https://github.com/your_username/cve_table_fetcher.git
cd cve_table_fetcher
# CREATE .env with your API key - NVD_API_KEY="YOUR-NVD-KEY"
python cve_table_fetcher.py
```

**Get an NVD API key:** [https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key) (free, instant email).

---

## 🔧 Command‑line usage

```text
usage: cve_table_fetcher.py [-h] [--format {tsv,csv,md,html}] [--min-cvss N]
                            [--min-epss N] [--no-color] [--show-version]
                            [-o FILE]
```

### Common scenarios

| Task                              | Command                                                    |
| --------------------------------- | ---------------------------------------------------------- |
| Interactive TSV with colours      | `python cve_table_fetcher.py`                              |
| CSV to stdout, filter EPSS ≥ 50 % | `python cve_table_fetcher.py --format csv --min-epss 50`   |
| Markdown | `python cve_table_fetcher.py --format md --show-version`   |
| Stand‑alone HTML report           | `python cve_table_fetcher.py --format html -o report.html` |

> **Tip:** pass CVE IDs as a comma‑separated argument *after* the options, e.g. `... CVE-2025-1234,CVE-2024-9876`.

---

## 📄 Output formats

<details>
<summary><strong>TSV / CSV</strong> – plain text</summary>

* Ideal for spreadsheets or further CLI processing (`grep`, `awk`, …).
* TSV adds ANSI colours by default (disable with `--no-color`).

```tsv
CVE            CVSS   EPSS(%)
CVE-2025-1234  9.8    74.20
CVE-2024-9876  5.3    12.77
```

</details>

<details>
<summary><strong>Markdown</strong></summary>

```md
| CVE | CVSS | EPSS(%) |
| --- | ---- | ------- |
| CVE-2025-1234 | 9.8 (v3.1) | 74.20 |
| CVE-2024-9876 | 5.3 (v3.1) | 12.77 |
```

</details>

<details>
<summary><strong>HTML report</strong> – shareable, no dependencies</summary>

* Fully inlined CSS, no external assets.
* Rows are colour‑coded; hover & copy just works.
* Open `report.html` in any browser – or attach it in an email.

</details>

---

## 📊 Statistics block

After the table, the script prints a concise summary to *stderr*, e.g.:

```
--- Statistics ---
Critical : 1
High     : 0
Medium   : 1
Low      : 0
N/A      : 0
Average EPSS : 43.48%
Top EPSS     : CVE-2025-1234 74.20%
```

---

## 🛠️ Configuration & environment

| Variable                 | Purpose                                     |
| ------------------------ | ------------------------------------------- |
| `NVD_API_KEY` (required) | Your personal API key for the NVD REST API. |
| `HTTP_TIMEOUT`           | Global timeout for API calls (seconds).     |
| `NVD_SLEEP`              | Polite delay between serial NVD requests.   |
| `DEFAULT_HTML_FILE`      | Fallback file name for HTML reports.        |

You can override the last three by editing the **Config** section in `cve_table_fetcher.py`.

---

## 📜 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

## 🙋 FAQ

**Q: Why do I need an NVD API key?**
The NVD limits anonymous traffic. A free key lifts the rate‑limit and keeps the service happy.

**Q: How fresh are EPSS scores?**
FIRST updates the data daily. The script always fetches the latest value.

---

Happy patching & stay secure! 🔒
