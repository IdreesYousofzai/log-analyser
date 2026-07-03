"""
log_analyzer.py
----------------
A small SOC-style log analysis tool for Apache/Nginx "combined" access logs.

What it does:
  1. Parses each log line with a regex to pull out IP, timestamp, method,
     URL, status code, and response size.
  2. Flags suspicious activity:
       - Rate abuse: any single IP making 50+ requests within one minute.
       - Brute force: any single IP generating a high number of 401
         (Unauthorized) responses.
       - Scanning: any single IP generating a high number of 404
         (Not Found) responses (probing for pages that don't exist).
  3. Builds a summary: top 10 requesting IPs, top 10 requested URLs,
     overall error rate, and the list of flagged IPs with reasons.
  4. Writes the summary out as both a plain-text report and an HTML report,
     each timestamped with the time the report was generated.

Usage:
    python3 log_analyzer.py sample_logs/access_log_2_bruteforce.log
    python3 log_analyzer.py sample_logs/*.log --outdir reports --prefix combined

Only the Python standard library is used (re, collections, datetime, html,
argparse) so this runs anywhere with Python 3.8+, no pip installs needed.
"""

import re
import sys
import glob
import html
import argparse
from datetime import datetime
from collections import defaultdict, Counter

# ---------------------------------------------------------------------------
# 1. PARSING
# ---------------------------------------------------------------------------

# Matches the standard Apache/Nginx "combined" log format, e.g.:
# 127.0.0.1 - - [10/Oct/2023:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<url>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\d+|-)'
)

# Apache/Nginx default timestamp format: 10/Oct/2023:13:55:36 -0700
TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def parse_line(line):
    """Parse a single access-log line into a dict, or return None if the
    line doesn't match the expected format (malformed/unrecognised lines
    are skipped rather than crashing the whole run)."""
    match = LOG_PATTERN.search(line)
    if not match:
        return None

    data = match.groupdict()

    try:
        dt = datetime.strptime(data["timestamp"], TIMESTAMP_FORMAT)
    except ValueError:
        dt = None

    size = 0 if data["size"] == "-" else int(data["size"])

    return {
        "ip": data["ip"],
        "timestamp": dt,
        "timestamp_raw": data["timestamp"],
        "method": data["method"],
        "url": data["url"],
        "status": int(data["status"]),
        "size": size,
    }


def load_logs(filepaths):
    """Read and parse one or more log files. Returns (entries, skipped_count)."""
    entries = []
    skipped = 0
    for path in filepaths:
        with open(path, "r", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parsed = parse_line(line)
                if parsed:
                    parsed["source_file"] = path
                    entries.append(parsed)
                else:
                    skipped += 1
    return entries, skipped


# ---------------------------------------------------------------------------
# 2. SUSPICIOUS ACTIVITY DETECTION
# ---------------------------------------------------------------------------

RATE_LIMIT_PER_MINUTE = 50   # requests/minute from one IP
BRUTE_FORCE_401_THRESHOLD = 10   # 401 responses from one IP
SCANNING_404_THRESHOLD = 15   # 404 responses from one IP


def detect_rate_abuse(entries):
    """Flag IPs that exceed RATE_LIMIT_PER_MINUTE requests in any single
    calendar minute (bucketed by IP + minute)."""
    buckets = defaultdict(int)
    for e in entries:
        if e["timestamp"] is None:
            continue
        minute_key = e["timestamp"].strftime("%Y-%m-%d %H:%M")
        buckets[(e["ip"], minute_key)] += 1

    flagged = {}
    for (ip, minute_key), count in buckets.items():
        if count > RATE_LIMIT_PER_MINUTE:
            reason = f"Rate abuse: {count} requests in one minute ({minute_key})"
            # keep the worst offending minute per IP
            if ip not in flagged or count > flagged[ip][0]:
                flagged[ip] = (count, reason)
    return {ip: reason for ip, (count, reason) in flagged.items()}


def detect_brute_force(entries):
    """Flag IPs with a high count of 401 Unauthorized responses."""
    counts = Counter(e["ip"] for e in entries if e["status"] == 401)
    return {
        ip: f"Possible brute force: {count} x 401 Unauthorized responses"
        for ip, count in counts.items()
        if count >= BRUTE_FORCE_401_THRESHOLD
    }


def detect_scanning(entries):
    """Flag IPs with a high count of 404 Not Found responses (page/dir
    scanning behaviour)."""
    counts = Counter(e["ip"] for e in entries if e["status"] == 404)
    return {
        ip: f"Possible scanning: {count} x 404 Not Found responses"
        for ip, count in counts.items()
        if count >= SCANNING_404_THRESHOLD
    }


def build_flagged_ips(entries):
    """Merge all detection results into one dict: ip -> [reasons]."""
    detectors = [detect_rate_abuse(entries), detect_brute_force(entries), detect_scanning(entries)]
    flagged = defaultdict(list)
    for result in detectors:
        for ip, reason in result.items():
            flagged[ip].append(reason)
    return dict(flagged)


# ---------------------------------------------------------------------------
# 3. SUMMARY
# ---------------------------------------------------------------------------

def build_summary(entries, skipped_lines, source_files):
    total = len(entries)
    ip_counts = Counter(e["ip"] for e in entries)
    url_counts = Counter(e["url"] for e in entries)
    status_counts = Counter(e["status"] for e in entries)

    error_count = sum(c for status, c in status_counts.items() if status >= 400)
    error_rate = (error_count / total * 100) if total else 0.0

    flagged_ips = build_flagged_ips(entries)

    return {
        "generated_at": datetime.now(),
        "source_files": source_files,
        "total_requests": total,
        "skipped_lines": skipped_lines,
        "unique_ips": len(ip_counts),
        "top_ips": ip_counts.most_common(10),
        "top_urls": url_counts.most_common(10),
        "status_counts": dict(sorted(status_counts.items())),
        "error_count": error_count,
        "error_rate": error_rate,
        "flagged_ips": flagged_ips,
    }


# ---------------------------------------------------------------------------
# 4. REPORT GENERATION
# ---------------------------------------------------------------------------

def generate_txt_report(summary, out_path):
    lines = []
    lines.append("=" * 70)
    lines.append("  LOG ANALYSIS SUMMARY REPORT")
    lines.append("=" * 70)
    lines.append(f"Report generated: {summary['generated_at'].strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Source file(s):   {', '.join(summary['source_files'])}")
    lines.append("")
    lines.append(f"Total requests parsed: {summary['total_requests']}")
    lines.append(f"Lines skipped (unparseable): {summary['skipped_lines']}")
    lines.append(f"Unique IP addresses seen: {summary['unique_ips']}")
    lines.append(f"Overall error rate (4xx/5xx): {summary['error_rate']:.2f}%  "
                 f"({summary['error_count']} of {summary['total_requests']} requests)")
    lines.append("")

    lines.append("-" * 70)
    lines.append("TOP 10 REQUESTING IPs")
    lines.append("-" * 70)
    for ip, count in summary["top_ips"]:
        lines.append(f"  {ip:<20} {count:>6} requests")
    lines.append("")

    lines.append("-" * 70)
    lines.append("TOP 10 MOST VISITED URLs")
    lines.append("-" * 70)
    for url, count in summary["top_urls"]:
        lines.append(f"  {url:<40} {count:>6} requests")
    lines.append("")

    lines.append("-" * 70)
    lines.append("STATUS CODE BREAKDOWN")
    lines.append("-" * 70)
    for status, count in summary["status_counts"].items():
        lines.append(f"  {status}  {count:>6}")
    lines.append("")

    lines.append("-" * 70)
    lines.append("FLAGGED SUSPICIOUS IPs")
    lines.append("-" * 70)
    if summary["flagged_ips"]:
        for ip, reasons in summary["flagged_ips"].items():
            lines.append(f"  {ip}")
            for reason in reasons:
                lines.append(f"      - {reason}")
    else:
        lines.append("  None detected.")
    lines.append("")
    lines.append("=" * 70)

    with open(out_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return out_path


def generate_html_report(summary, out_path):
    def esc(x):
        return html.escape(str(x))

    ip_rows = "\n".join(
        f"<tr><td>{esc(ip)}</td><td>{count}</td></tr>"
        for ip, count in summary["top_ips"]
    )
    url_rows = "\n".join(
        f"<tr><td>{esc(url)}</td><td>{count}</td></tr>"
        for url, count in summary["top_urls"]
    )
    status_rows = "\n".join(
        f"<tr><td>{status}</td><td>{count}</td></tr>"
        for status, count in summary["status_counts"].items()
    )

    if summary["flagged_ips"]:
        flagged_rows = "\n".join(
            f"<tr><td class='flagged-ip'>{esc(ip)}</td>"
            f"<td>{'<br>'.join(esc(r) for r in reasons)}</td></tr>"
            for ip, reasons in summary["flagged_ips"].items()
        )
    else:
        flagged_rows = "<tr><td colspan='2'>None detected.</td></tr>"

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Log Analysis Summary Report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; background:#f4f5f7; color:#1f2328; margin:0; padding:24px; }}
  .container {{ max-width: 900px; margin: 0 auto; background:#fff; border-radius:8px; padding:24px 32px; box-shadow:0 1px 4px rgba(0,0,0,0.08); }}
  h1 {{ font-size:1.4rem; border-bottom:2px solid #2563eb; padding-bottom:10px; }}
  h2 {{ font-size:1.05rem; margin-top:28px; color:#2563eb; }}
  .meta {{ color:#555; font-size:0.9rem; margin-bottom:18px; }}
  .stats {{ display:flex; gap:16px; flex-wrap:wrap; margin:16px 0; }}
  .stat-box {{ background:#eef2ff; border-radius:6px; padding:12px 18px; min-width:150px; }}
  .stat-box .num {{ font-size:1.4rem; font-weight:700; color:#1e3a8a; }}
  .stat-box .label {{ font-size:0.8rem; color:#444; }}
  table {{ width:100%; border-collapse:collapse; margin-top:8px; font-size:0.9rem; }}
  th, td {{ text-align:left; padding:6px 10px; border-bottom:1px solid #e5e7eb; }}
  th {{ background:#f0f2f5; }}
  tr:hover td {{ background:#fafafa; }}
  .flagged-ip {{ color:#b91c1c; font-weight:600; }}
  .error-rate {{ color: {"#b91c1c" if summary["error_rate"] > 10 else "#166534"}; font-weight:700; }}
  footer {{ margin-top:28px; font-size:0.75rem; color:#888; }}
</style>
</head>
<body>
<div class="container">
  <h1>Log Analysis Summary Report</h1>
  <div class="meta">
    Report generated: {esc(summary['generated_at'].strftime('%Y-%m-%d %H:%M:%S'))}<br>
    Source file(s): {esc(', '.join(summary['source_files']))}
  </div>

  <div class="stats">
    <div class="stat-box"><div class="num">{summary['total_requests']}</div><div class="label">Total requests</div></div>
    <div class="stat-box"><div class="num">{summary['unique_ips']}</div><div class="label">Unique IPs</div></div>
    <div class="stat-box"><div class="num error-rate">{summary['error_rate']:.2f}%</div><div class="label">Error rate (4xx/5xx)</div></div>
    <div class="stat-box"><div class="num">{len(summary['flagged_ips'])}</div><div class="label">Flagged suspicious IPs</div></div>
  </div>

  <h2>Top 10 Requesting IPs</h2>
  <table><tr><th>IP Address</th><th>Requests</th></tr>{ip_rows}</table>

  <h2>Top 10 Most Visited URLs</h2>
  <table><tr><th>URL</th><th>Requests</th></tr>{url_rows}</table>

  <h2>Status Code Breakdown</h2>
  <table><tr><th>Status Code</th><th>Count</th></tr>{status_rows}</table>

  <h2>Flagged Suspicious IPs</h2>
  <table><tr><th>IP Address</th><th>Reason(s)</th></tr>{flagged_rows}</table>

  <footer>Generated by log_analyzer.py &mdash; {esc(summary['generated_at'].strftime('%Y-%m-%d %H:%M:%S'))}</footer>
</div>
</body>
</html>"""

    with open(out_path, "w") as f:
        f.write(html_doc)
    return out_path


# ---------------------------------------------------------------------------
# 5. CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Analyse Apache/Nginx access logs for suspicious activity.")
    parser.add_argument("logfiles", nargs="*", help="Path(s) to log file(s). Glob patterns are supported. "
                         "If omitted, defaults to sample_logs/*.log so the script has something to run on.")
    parser.add_argument("--outdir", default="reports", help="Directory to write reports into (default: reports)")
    parser.add_argument("--prefix", default=None, help="Filename prefix for reports (default: derived from first log file)")
    args = parser.parse_args()

    logfile_args = args.logfiles
    if not logfile_args:
        default_pattern = "sample_logs/*.log"
        print(f"No log files given on the command line — defaulting to '{default_pattern}'.\n"
              f"To analyse specific files, run e.g.:\n"
              f"  python3 log_analyzer.py sample_logs/access_log_2_bruteforce.log\n"
              f"  python3 log_analyzer.py sample_logs/*.log --outdir reports --prefix combined\n")
        logfile_args = [default_pattern]

    # Expand any glob patterns passed by the shell-unaware caller
    import os
    filepaths = []
    missing_patterns = []
    for pattern in logfile_args:
        matches = glob.glob(pattern)
        if matches:
            filepaths.extend(matches)
        elif os.path.exists(pattern):
            # A literal filename (no glob wildcard) that exists as-is
            filepaths.append(pattern)
        else:
            missing_patterns.append(pattern)

    if missing_patterns:
        print("Could not find any files matching:", file=sys.stderr)
        for p in missing_patterns:
            print(f"  {p}  (looked in: {os.path.abspath(p)})", file=sys.stderr)
        print(f"\nCurrent working directory: {os.getcwd()}", file=sys.stderr)
        print("Check the path is correct, or cd into the folder containing your log files.", file=sys.stderr)

    if not filepaths:
        sys.exit(1)

    entries, skipped = load_logs(filepaths)
    if not entries:
        print("No valid log lines could be parsed from the given file(s).", file=sys.stderr)
        sys.exit(1)

    summary = build_summary(entries, skipped, filepaths)

    import os
    os.makedirs(args.outdir, exist_ok=True)
    prefix = args.prefix or os.path.splitext(os.path.basename(filepaths[0]))[0]

    txt_path = os.path.join(args.outdir, f"{prefix}_report.txt")
    html_path = os.path.join(args.outdir, f"{prefix}_report.html")

    generate_txt_report(summary, txt_path)
    generate_html_report(summary, html_path)

    print(f"Parsed {summary['total_requests']} requests from {len(filepaths)} file(s) "
          f"({skipped} lines skipped).")
    print(f"Flagged {len(summary['flagged_ips'])} suspicious IP(s).")
    print(f"Reports written:\n  {txt_path}\n  {html_path}")


if __name__ == "__main__":
    main()
