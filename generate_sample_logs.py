"""
generate_sample_logs.py
------------------------
Creates 4 synthetic Apache/Nginx "combined" style access.log files for testing
log_analyzer.py. All IPs are fake (RFC 5737 / private test ranges), no real
data is used. Each file is built to exercise a different detection path:

  access_log_1_normal.log      -> ordinary browsing traffic, nothing suspicious
  access_log_2_bruteforce.log  -> normal traffic + one IP hammering /login with 401s
  access_log_3_scanning.log    -> normal traffic + one IP probing many URLs -> 404s
  access_log_4_rateflood.log   -> normal traffic + one IP sending 60+ req/minute

Run: python3 generate_sample_logs.py
"""
import random
from datetime import datetime, timedelta

OUT_DIR = "sample_logs"

METHODS = ["GET", "GET", "GET", "POST"]
PAGES = ["/", "/index.html", "/about.html", "/contact.html", "/products.html",
         "/blog/post-1", "/blog/post-2", "/images/logo.png", "/css/style.css",
         "/js/app.js", "/api/products", "/api/cart"]
STATUS_OK = [200, 200, 200, 200, 304, 301]
UA = '"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"'
REF = '"-"'


def fmt_time(dt):
    return dt.strftime("%d/%b/%Y:%H:%M:%S -0000")


def normal_line(ip, dt):
    method = random.choice(METHODS)
    page = random.choice(PAGES)
    status = random.choice(STATUS_OK)
    size = random.randint(200, 15000)
    return f'{ip} - - [{fmt_time(dt)}] "{method} {page} HTTP/1.1" {status} {size} {REF} {UA}'

def random_ip(base_pool):
    return random.choice(base_pool)

def write_log(filename, lines):
    with open(f"{OUT_DIR}/{filename}", "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"wrote {filename}: {len(lines)} lines")

def build_normal_traffic(start, count, ip_pool):
    lines = []
    t = start
    for _ in range(count):
        ip = random_ip(ip_pool)
        t += timedelta(seconds=random.randint(1, 20))
        lines.append(normal_line(ip, t))
    return lines, t

NORMAL_IPS = [f"198.51.100.{i}" for i in range(2, 30)]


def main():
    random.seed(42)
    start = datetime(2026, 6, 15, 8, 0, 0)

    # ---------- 1. Normal traffic only ----------
    lines, _ = build_normal_traffic(start, 300, NORMAL_IPS)
    lines.sort(key=lambda l: l.split("[")[1])  # already roughly ordered
    write_log("access_log_1_normal.log", lines)

    # ---------- 2. Brute-force attempt ----------
    lines, t = build_normal_traffic(start, 150, NORMAL_IPS)
    attacker = "203.0.113.66"
    t2 = start + timedelta(minutes=5)
    for _ in range(45):
        t2 += timedelta(seconds=random.randint(1, 3))
        line = f'{attacker} - - [{fmt_time(t2)}] "POST /login HTTP/1.1" 401 512 {REF} {UA}'
        lines.append(line)
    # attacker eventually "succeeds"
    t2 += timedelta(seconds=2)
    lines.append(f'{attacker} - - [{fmt_time(t2)}] "POST /login HTTP/1.1" 200 1024 {REF} {UA}')
    more, _ = build_normal_traffic(t, 100, NORMAL_IPS)
    lines.extend(more)
    write_log("access_log_2_bruteforce.log", lines)

    # ---------- 3. Directory / page scanning ----------
    lines, t = build_normal_traffic(start, 150, NORMAL_IPS)
    scanner = "203.0.113.77"
    scan_paths = ["/wp-admin", "/phpmyadmin", "/.env", "/admin.php", "/config.php",
                  "/backup.zip", "/.git/config", "/shell.php", "/test.php",
                  "/old/login.php", "/db.sql", "/xmlrpc.php", "/wp-login.php",
                  "/api/v1/secret", "/console", "/uploads/../../etc/passwd"]
    t3 = start + timedelta(minutes=10)
    for p in scan_paths * 2:  # hit each twice-ish -> plenty of 404s
        t3 += timedelta(seconds=random.randint(1, 2))
        lines.append(f'{scanner} - - [{fmt_time(t3)}] "GET {p} HTTP/1.1" 404 210 {REF} {UA}')
    more, _ = build_normal_traffic(t, 100, NORMAL_IPS)
    lines.extend(more)
    write_log("access_log_3_scanning.log", lines)

    # ---------- 4. Rate flood (>50 requests in one minute from one IP) ----------
    lines, t = build_normal_traffic(start, 150, NORMAL_IPS)
    flooder = "203.0.113.88"
    t4 = start + timedelta(minutes=20, seconds=0)
    for _ in range(70):  # 70 requests inside the same minute window
        t4 += timedelta(milliseconds=random.randint(300, 800))
        lines.append(f'{flooder} - - [{fmt_time(t4)}] "GET /api/products HTTP/1.1" 200 3000 {REF} {UA}')
    more, _ = build_normal_traffic(t, 100, NORMAL_IPS)
    lines.extend(more)
    write_log("access_log_4_rateflood.log", lines)

if __name__ == "__main__":
    main()
