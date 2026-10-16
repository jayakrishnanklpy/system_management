#!/usr/bin/env python3
"""
logstats.py - summarize nginx access logs across many domains (compact tables).

Usage:
  python3 logstats.py                       # reads /home/nginx/domains/*/log/access.log
  python3 logstats.py --top 15 --per-domain 5
  python3 logstats.py --status 404          # only count 404s (also 200, 5xx ...)
  python3 logstats.py --domain pharmacy     # only domains matching this text
  python3 logstats.py --keep-query          # don't strip ?query from URLs
  tail -n 5000 /home/nginx/domains/*/log/access.log | python3 logstats.py
"""
import argparse
import glob
import gzip
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from functools import lru_cache

RED = '\033[1;31m'
RESET = '\033[0m'


@lru_cache(maxsize=4096)
def parse_ts(s):
    try:
        return datetime.strptime(s, '%d/%b/%Y:%H:%M:%S %z')
    except ValueError:
        return None

LINE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+)[^"]*" (?P<status>\d{3}) (?P<bytes>\S+) '
    r'"(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
)
HEADER_RE = re.compile(r'^==> (?P<path>.+) <==$')
DOMAIN_RE = re.compile(r'/domains/([^/]+)/')


def domain_from_path(path):
    m = DOMAIN_RE.search(path)
    return m.group(1) if m else os.path.basename(os.path.dirname(path)) or path


def open_any(path):
    if path.endswith('.gz'):
        return gzip.open(path, 'rt', errors='replace')
    return open(path, 'rt', errors='replace')


def iter_files(pattern):
    for path in sorted(glob.glob(pattern)):
        domain = domain_from_path(path)
        try:
            with open_any(path) as f:
                for line in f:
                    yield domain, line
        except OSError as e:
            print(f'skip {path}: {e}', file=sys.stderr)


def iter_stdin():
    domain = 'unknown'
    for line in sys.stdin:
        line = line.rstrip('\n')
        h = HEADER_RE.match(line)
        if h:
            domain = domain_from_path(h.group('path'))
            continue
        yield domain, line


def status_match(status, wanted):
    if not wanted:
        return True
    if wanted.lower().endswith('xx'):
        return status[0] == wanted[0]
    return status == wanted


def clip(s, n):
    s = str(s)
    return s if len(s) <= n else s[:n - 1] + '…'


def table(title, headers, rows, right=(), color=''):
    """Bordered table. `right` = indexes of right-aligned (numeric) columns.
    `color` = ANSI escape applied to the whole table (e.g. RED)."""
    end = RESET if color else ''
    print(f'\n{color}{title}{end}')
    if not rows:
        print(f'{color}  (none){end}')
        return
    rows = [[str(c) for c in r] for r in rows]
    w = [max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(headers)]
    sep = '+' + '+'.join('-' * (x + 2) for x in w) + '+'

    def fmt(cells):
        out = []
        for i, c in enumerate(cells):
            out.append(c.rjust(w[i]) if i in right else c.ljust(w[i]))
        return '| ' + ' | '.join(out) + ' |'

    print(f'{color}{sep}{end}')
    print(f'{color}{fmt(headers)}{end}')
    print(f'{color}{sep}{end}')
    for r in rows:
        print(f'{color}{fmt(r)}{end}')
    print(f'{color}{sep}{end}')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--glob', default='/home/nginx/domains/*/log/access.log')
    ap.add_argument('--top', type=int, default=10, help='rows in overall tables')
    ap.add_argument('--per-domain', type=int, default=3, help='top URLs listed per domain')
    ap.add_argument('--keep-query', action='store_true')
    ap.add_argument('--status', default=None)
    ap.add_argument('--domain', default=None)
    ap.add_argument('--recent', type=int, default=5,
                    help='minutes for the "recent activity" section at the bottom (default 5)')
    ap.add_argument('--no-color', action='store_true', help='disable red highlighting')
    args = ap.parse_args()
    use_color = not args.no_color and (sys.stdout.isatty() or os.environ.get('FORCE_COLOR'))
    red = RED if use_color else ''
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=args.recent)
    recent = Counter()        # (domain, ip, method, url, status) -> hits
    recent_last = {}          # same key -> last timestamp string
    recent_ip = Counter()
    recent_domain = Counter()
    recent_total = 0

    source = iter_stdin() if not sys.stdin.isatty() else iter_files(args.glob)

    total = bad = 0
    by_domain = Counter()
    by_domain_bytes = Counter()
    by_domain_cls = defaultdict(Counter)   # 2xx/3xx/4xx/5xx
    by_domain_url = defaultdict(Counter)
    by_domain_ip = defaultdict(Counter)
    url_all = Counter()
    ip_all = Counter()
    ip_404 = Counter()
    ip_domains = defaultdict(set)
    ua_all = Counter()
    status_all = Counter()
    first_ts = last_ts = None

    for domain, line in source:
        m = LINE_RE.match(line)
        if not m:
            if line.strip():
                bad += 1
            continue
        if args.domain and args.domain not in domain:
            continue
        status = m.group('status')
        if not status_match(status, args.status):
            continue

        url = m.group('url')
        if not args.keep_query:
            url = url.split('?', 1)[0]
        ip = m.group('ip')
        size = int(m.group('bytes')) if m.group('bytes').isdigit() else 0

        total += 1
        by_domain[domain] += 1
        by_domain_bytes[domain] += size
        by_domain_cls[domain][status[0] + 'xx'] += 1
        by_domain_url[domain][url] += 1
        by_domain_ip[domain][ip] += 1
        url_all[(domain, url)] += 1
        ip_all[ip] += 1
        ip_domains[ip].add(domain)
        ua_all[m.group('ua')[:60]] += 1
        status_all[status] += 1
        if status == '404':
            ip_404[ip] += 1

        ts = m.group('time')
        first_ts = first_ts or ts
        last_ts = ts

        dt = parse_ts(ts)
        if dt is not None and dt >= cutoff:
            key = (domain, ip, m.group('method'), m.group('url'), status)
            recent[key] += 1
            recent_last[key] = dt.strftime('%H:%M:%S')
            recent_ip[ip] += 1
            recent_domain[domain] += 1
            recent_total += 1

    if not total:
        print('No log lines parsed. Check --glob / filters / input.')
        return

    n = args.top
    print(f'Requests: {total}   Unparsable lines: {bad}')
    print(f'Range:    {first_ts}  ->  {last_ts}')

    # 1. one row per domain, everything at a glance
    rows = []
    for d, c in by_domain.most_common():
        cls = by_domain_cls[d]
        top_ip, top_ip_n = by_domain_ip[d].most_common(1)[0]
        rows.append([
            d, c, f'{c * 100 / total:.1f}%',
            cls['2xx'], cls['3xx'], cls['4xx'], cls['5xx'],
            f'{by_domain_bytes[d] / 1048576:.1f}',
            top_ip, top_ip_n,
        ])
    table('HITS PER DOMAIN',
          ['domain', 'hits', 'share', '2xx', '3xx', '4xx', '5xx', 'MB', 'top IP', 'IP hits'],
          rows, right=(1, 2, 3, 4, 5, 6, 7, 9))

    # 2. top URLs per domain in a single grouped table
    rows = []
    for d, c in by_domain.most_common():
        for i, (u, cnt) in enumerate(by_domain_url[d].most_common(args.per_domain)):
            rows.append([d if i == 0 else '', clip(u, 70), cnt, f'{cnt * 100 / c:.0f}%'])
    table(f'TOP {args.per_domain} URLs PER DOMAIN',
          ['domain', 'url', 'hits', '% of domain'], rows, right=(2, 3))

    # 3. top URLs overall
    table(f'TOP {n} URLs OVERALL',
          ['hits', 'domain', 'url'],
          [[c, d, clip(u, 70)] for (d, u), c in url_all.most_common(n)], right=(0,))

    # 4. top IPs with 404 count and domains touched
    table(f'TOP {n} CLIENT IPs',
          ['ip', 'hits', '404s', 'domains hit'],
          [[ip, c, ip_404[ip], len(ip_domains[ip])] for ip, c in ip_all.most_common(n)],
          right=(1, 2, 3))

    # 5. likely scanners: most 404s
    table(f'TOP {n} IPs BY 404s (likely scanners)',
          ['ip', '404s', 'total hits', '404 ratio', 'domains hit'],
          [[ip, c, ip_all[ip], f'{c * 100 / ip_all[ip]:.0f}%', len(ip_domains[ip])]
           for ip, c in ip_404.most_common(n)],
          right=(1, 2, 3, 4))

    # 6. status codes + user agents side by side would be wide; keep two small tables
    table('STATUS CODES',
          ['status', 'hits', 'share'],
          [[s, c, f'{c * 100 / total:.1f}%'] for s, c in sorted(status_all.items())],
          right=(1, 2))

    table(f'TOP {n} USER AGENTS',
          ['hits', 'user agent'],
          [[c, ua] for ua, c in ua_all.most_common(n)], right=(0,))

    # ---- recent activity, highlighted in red, always last ----
    m_ = args.recent
    print(f'\n{red}{"#" * 70}\nRECENT ACTIVITY: last {m_} min  ({recent_total} requests)\n{"#" * 70}{RESET if red else ""}')
    if recent_total:
        table(f'Last {m_} min: hits per domain',
              ['domain', 'hits'],
              [[d, c] for d, c in recent_domain.most_common()],
              right=(1,), color=red)
        table(f'Last {m_} min: top IPs',
              ['ip', 'hits', 'domains hit'],
              [[ip, c, len({k[0] for k in recent if k[1] == ip})]
               for ip, c in recent_ip.most_common(n)],
              right=(1, 2), color=red)
        table(f'Last {m_} min: who hit what (most hits first)',
              ['last seen', 'domain', 'ip', 'method', 'status', 'hits', 'url'],
              [[recent_last[k], k[0], k[1], k[2], k[4], c, clip(k[3], 80)]
               for k, c in recent.most_common(max(n * 3, 30))],
              right=(5,), color=red)
    else:
        print(f'{red}No requests in the last {m_} minutes.{RESET if red else ""}')


if __name__ == '__main__':
    main()
