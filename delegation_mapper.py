"""
delegation-mapper
=================

"Who can act in your name — and are they still trustworthy?"

Supply-chain security covers the code you import. Nothing covers the
authority you *lend*: contractors authorized to file notices, transmit
data, or speak as your company. delegation-mapper keeps a delegation
inventory and watches every delegate's public security posture —
unauthenticated, with nothing but the Python standard library.

Checks per delegate domain:
  * TLS certificate validity (expiry date + hostname match, via ssl)
  * security.txt presence at /.well-known/security.txt (via urllib)
  * DNS resolvability (via socket)

Flags:
  * stale review        — last_review_date more than 180 days ago
  * missing security.txt
  * TLS cert expired or expiring within 30 days
  * DNS resolution failure

Usage:
    python3 delegation_mapper.py --inventory fixtures/sample-inventory.yaml
    python3 delegation_mapper.py --inventory inv.yaml --markdown report.md --json report.json
    python3 delegation_mapper.py --inventory inv.yaml --json - | jq .

The inventory file is a small subset of YAML (documented below under
"Inventory format") so the parser stays stdlib-only.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import socket
import ssl
import sys
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple

STALE_REVIEW_DAYS = 180
CERT_EXPIRY_WARN_DAYS = 30
NET_TIMEOUT_SECONDS = 5

# ---------------------------------------------------------------------------
# Minimal YAML-subset parser (stdlib only)
# ---------------------------------------------------------------------------
#
# Supports exactly what the inventory format needs:
#   * mapping: key: value  (string values, optionally single/double quoted)
#   * sequences of mappings under a key, with "- key: value" items
#   * sequences of plain scalars under a key, with "- value" items
#   * comments (# ...) and blank lines
#   * two-space indentation
# Anything else raises ValueError. Keep inventories simple.

def _strip_comment(line: str) -> str:
    in_single = in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            return line[:i].rstrip()
    return line.rstrip()


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def parse_inventory_yaml(text: str) -> Dict[str, Any]:
    """Parse the supported YAML subset into a dict."""
    root: Dict[str, Any] = {}
    # stack of (indent, container) where container is dict or list
    stack: List[Tuple[int, Any]] = [(-1, root)]
    # stack of (indent, dict) for "- key: value" list items; nested scalar
    # lists never touch this, so the parent item context survives them
    item_stack: List[Tuple[int, Dict[str, Any]]] = []

    def current_container(indent: int) -> Any:
        while stack and stack[-1][0] >= indent:
            stack.pop()
        if not stack:
            raise ValueError("Bad indentation in inventory YAML")
        return stack[-1][1]

    for lineno, raw in enumerate(text.splitlines(), 1):
        line = _strip_comment(raw)
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        body = line.strip()

        if body.startswith("- "):
            parent = current_container(indent)
            if not isinstance(parent, list):
                raise ValueError(f"Line {lineno}: '-' outside a sequence")
            item_text = body[2:].strip()
            if item_text and ":" in item_text:
                key, _, val = item_text.partition(":")
                item: Dict[str, Any] = {key.strip(): _unquote(val)}
                parent.append(item)
                while item_stack and item_stack[-1][0] >= indent:
                    item_stack.pop()
                item_stack.append((indent, item))
            else:
                parent.append(_unquote(item_text))
            continue

        if body == "-":
            parent = current_container(indent)
            if not isinstance(parent, list):
                raise ValueError(f"Line {lineno}: '-' outside a sequence")
            item = {}
            parent.append(item)
            while item_stack and item_stack[-1][0] >= indent:
                item_stack.pop()
            item_stack.append((indent, item))
            continue

        if ":" in body:
            key, _, val = body.partition(":")
            key = key.strip()
            val = val.strip()
            if item_stack and indent > item_stack[-1][0]:
                container = item_stack[-1][1]
            else:
                container = current_container(indent)
                if isinstance(container, list):
                    raise ValueError(f"Line {lineno}: mapping key inside a list")
            if val == "":
                # Nested block follows; decide dict vs list by peeking at the
                # next non-blank, non-comment line.
                peek: Optional[str] = None
                for nxt in text.splitlines()[lineno:]:
                    stripped = _strip_comment(nxt).strip()
                    if stripped:
                        peek = stripped
                        break
                child: Any = [] if (peek and peek.startswith("-")) else {}
                container[key] = child
                stack.append((indent, child))
            else:
                container[key] = _unquote(val)
            continue

        raise ValueError(f"Line {lineno}: cannot parse {raw!r}")

    return root


def load_inventory(path: str) -> List[Dict[str, Any]]:
    """Load and validate a delegation inventory YAML file."""
    with open(path, "r", encoding="utf-8") as fh:
        data = parse_inventory_yaml(fh.read())
    delegates = data.get("delegates", [])
    if not isinstance(delegates, list):
        raise ValueError("Top-level 'delegates' must be a list")
    required = ("name", "authority", "last_review_date")
    for entry in delegates:
        for field in required:
            if field not in entry or not str(entry[field]).strip():
                raise ValueError(
                    f"Delegate {entry.get('name', '?')!r} is missing required field {field!r}"
                )
    return delegates


# ---------------------------------------------------------------------------
# Posture checks (stdlib only, no authentication)
# ---------------------------------------------------------------------------

CheckResult = Dict[str, Any]


def check_dns(domain: str, timeout: float = NET_TIMEOUT_SECONDS) -> CheckResult:
    """Resolve a domain. Returns {ok, detail}."""
    try:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            infos = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
        finally:
            socket.setdefaulttimeout(old_timeout)
        ips = sorted({info[4][0] for info in infos})
        return {"ok": True, "detail": "resolves to " + ", ".join(ips[:3])}
    except (socket.gaierror, socket.timeout, OSError) as exc:
        return {"ok": False, "detail": f"DNS resolution failed: {exc}"}


def check_tls(
    domain: str, timeout: float = NET_TIMEOUT_SECONDS
) -> CheckResult:
    """Fetch the TLS certificate: validity window + hostname match."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls:
                cert = tls.getpeercert()
    except (socket.gaierror, socket.timeout, OSError, ssl.SSLError) as exc:
        return {
            "ok": False,
            "detail": f"TLS handshake failed: {exc}",
            "expired": True,
            "expiry": None,
        }

    not_after = cert.get("notAfter")
    not_before = cert.get("notBefore")
    expiry: Optional[dt.datetime] = None
    if not_after:
        expiry = dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=dt.timezone.utc
        )
    now = dt.datetime.now(dt.timezone.utc)
    days_left = (expiry - now).days if expiry else None

    try:
        ssl.match_hostname(cert, domain)
        hostname_ok = True
        hostname_detail = "hostname matches"
    except ssl.CertificateError as exc:
        hostname_ok = False
        hostname_detail = f"hostname mismatch: {exc}"

    ok = hostname_ok and days_left is not None and days_left > 0
    if days_left is None:
        detail = f"no expiry in certificate; {hostname_detail}"
    elif days_left <= 0:
        detail = f"certificate EXPIRED {abs(days_left)} days ago; {hostname_detail}"
    else:
        detail = f"certificate valid, expires in {days_left} days; {hostname_detail}"

    return {
        "ok": ok,
        "detail": detail,
        "expired": days_left is not None and days_left <= 0,
        "expiry": expiry.isoformat() if expiry else None,
        "days_left": days_left,
    }


def check_security_txt(
    domain: str, timeout: float = NET_TIMEOUT_SECONDS
) -> CheckResult:
    """Fetch https://<domain>/.well-known/security.txt."""
    url = f"https://{domain}/.well-known/security.txt"
    request = urllib.request.Request(url, headers={"User-Agent": "delegation-mapper/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status == 200:
                body = response.read(4096).decode("utf-8", errors="replace")
                has_contact = "Contact:" in body
                return {
                    "ok": True,
                    "detail": (
                        "security.txt present"
                        + ("" if has_contact else " (no Contact: field)")
                    ),
                }
            return {"ok": False, "detail": f"HTTP {response.status}"}
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, TimeoutError) as exc:
        return {"ok": False, "detail": f"fetch failed: {exc}"}


# ---------------------------------------------------------------------------
# Flag evaluation
# ---------------------------------------------------------------------------

Flag = Dict[str, str]  # {"severity": ..., "flag": ..., "detail": ...}


def evaluate_staleness(entry: Dict[str, Any], today: dt.date) -> Optional[Flag]:
    raw = str(entry.get("last_review_date", "")).strip()
    try:
        reviewed = dt.date.fromisoformat(raw)
    except ValueError:
        return {
            "severity": "HIGH",
            "flag": "stale-review",
            "detail": f"last_review_date {raw!r} is not a valid ISO date — review state unknown",
        }
    age = (today - reviewed).days
    if age > STALE_REVIEW_DAYS:
        return {
            "severity": "MEDIUM",
            "flag": "stale-review",
            "detail": f"last reviewed {raw} ({age} days ago, limit is {STALE_REVIEW_DAYS})",
        }
    return None


def evaluate_domain_posture(
    domain: str,
    dns_fn: Optional[Callable[[str], CheckResult]] = None,
    tls_fn: Optional[Callable[[str], CheckResult]] = None,
    sectxt_fn: Optional[Callable[[str], CheckResult]] = None,
) -> Tuple[List[Flag], Dict[str, CheckResult]]:
    """Run all posture checks for one domain. Returns (flags, raw results).

    Check functions default at call time (not def time) so tests and
    embedders can substitute them by patching the module attributes.
    """
    dns_fn = dns_fn or check_dns
    tls_fn = tls_fn or check_tls
    sectxt_fn = sectxt_fn or check_security_txt
    flags: List[Flag] = []
    dns = dns_fn(domain)
    tls = tls_fn(domain)
    sectxt = sectxt_fn(domain)

    if not dns["ok"]:
        flags.append(
            {
                "severity": "HIGH",
                "flag": "dns-failure",
                "detail": f"{domain}: {dns['detail']}",
            }
        )
    if tls.get("expired"):
        flags.append(
            {
                "severity": "HIGH",
                "flag": "tls-expired",
                "detail": f"{domain}: {tls['detail']}",
            }
        )
    elif (
        tls.get("days_left") is not None
        and tls["days_left"] <= CERT_EXPIRY_WARN_DAYS
        and tls.get("ok")
    ):
        flags.append(
            {
                "severity": "MEDIUM",
                "flag": "tls-expiring-soon",
                "detail": f"{domain}: {tls['detail']}",
            }
        )
    if not tls["ok"] and not tls.get("expired"):
        # Handshake/hostname problem that is not plain expiry.
        flags.append(
            {
                "severity": "MEDIUM",
                "flag": "tls-error",
                "detail": f"{domain}: {tls['detail']}",
            }
        )
    if not sectxt["ok"]:
        flags.append(
            {
                "severity": "LOW",
                "flag": "missing-security-txt",
                "detail": f"{domain}: {sectxt['detail']}",
            }
        )
    return flags, {"dns": dns, "tls": tls, "security_txt": sectxt}


def assess_delegate(
    entry: Dict[str, Any],
    today: Optional[dt.date] = None,
    dns_fn: Optional[Callable[[str], CheckResult]] = None,
    tls_fn: Optional[Callable[[str], CheckResult]] = None,
    sectxt_fn: Optional[Callable[[str], CheckResult]] = None,
) -> Dict[str, Any]:
    """Assess one delegate: staleness + per-domain posture. Returns a report dict."""
    today = today or dt.date.today()
    dns_fn = dns_fn or check_dns
    tls_fn = tls_fn or check_tls
    sectxt_fn = sectxt_fn or check_security_txt
    flags: List[Flag] = []

    stale = evaluate_staleness(entry, today)
    if stale:
        flags.append(stale)

    domains = entry.get("domains") or []
    if isinstance(domains, str):
        domains = [domains]
    domain_results: Dict[str, Dict[str, CheckResult]] = {}
    for domain in domains:
        domain_flags, results = evaluate_domain_posture(
            str(domain), dns_fn=dns_fn, tls_fn=tls_fn, sectxt_fn=sectxt_fn
        )
        flags.extend(domain_flags)
        domain_results[str(domain)] = results

    severities = [f["severity"] for f in flags]
    if "HIGH" in severities:
        risk = "HIGH"
    elif "MEDIUM" in severities:
        risk = "MEDIUM"
    elif "LOW" in severities:
        risk = "LOW"
    else:
        risk = "NONE"

    return {
        "name": entry.get("name"),
        "authority": entry.get("authority"),
        "scopes": entry.get("scopes") or [],
        "domains": [str(d) for d in domains],
        "contact": entry.get("contact"),
        "last_review_date": entry.get("last_review_date"),
        "risk": risk,
        "flags": flags,
        "domain_posture": domain_results,
    }


def build_risk_map(
    delegates: List[Dict[str, Any]],
    today: Optional[dt.date] = None,
    **check_fns: Callable[[str], CheckResult],
) -> Dict[str, Any]:
    """Assess every delegate and return the full risk-map structure."""
    today = today or dt.date.today()
    assessed = [assess_delegate(d, today=today, **check_fns) for d in delegates]
    summary = {
        "total_delegates": len(assessed),
        "by_risk": {
            level: sum(1 for a in assessed if a["risk"] == level)
            for level in ("HIGH", "MEDIUM", "LOW", "NONE")
        },
        "flag_counts": {},
    }
    for a in assessed:
        for f in a["flags"]:
            summary["flag_counts"][f["flag"]] = summary["flag_counts"].get(f["flag"], 0) + 1
    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "stale_review_days": STALE_REVIEW_DAYS,
        "cert_expiry_warn_days": CERT_EXPIRY_WARN_DAYS,
        "summary": summary,
        "delegates": assessed,
    }


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------

def render_markdown(risk_map: Dict[str, Any]) -> str:
    lines = [
        "# Delegation Risk Map",
        "",
        f"Generated: {risk_map['generated_at']}",
        "",
        "## Summary",
        "",
        f"- Delegates assessed: {risk_map['summary']['total_delegates']}",
    ]
    for level in ("HIGH", "MEDIUM", "LOW", "NONE"):
        lines.append(f"- Risk {level}: {risk_map['summary']['by_risk'][level]}")
    if risk_map["summary"]["flag_counts"]:
        lines.append("")
        lines.append("### Flags raised")
        lines.append("")
        for flag, count in sorted(risk_map["summary"]["flag_counts"].items()):
            lines.append(f"- {flag}: {count}")
    lines.append("")
    lines.append("## Delegates")
    lines.append("")
    for d in risk_map["delegates"]:
        lines.append(f"### {d['name']} — risk: {d['risk']}")
        lines.append("")
        lines.append(f"- Authority granted: {d['authority']}")
        if d["scopes"]:
            lines.append(f"- Scopes: {', '.join(str(s) for s in d['scopes'])}")
        if d["domains"]:
            lines.append(f"- Domains: {', '.join(d['domains'])}")
        if d.get("contact"):
            lines.append(f"- Contact: {d['contact']}")
        lines.append(f"- Last reviewed: {d['last_review_date']}")
        if d["flags"]:
            lines.append("- Flags:")
            for f in d["flags"]:
                lines.append(f"  - **{f['severity']}** `{f['flag']}` — {f['detail']}")
        else:
            lines.append("- Flags: none ✅")
        lines.append("")
    return "\n".join(lines)


def render_json(risk_map: Dict[str, Any]) -> str:
    return json.dumps(risk_map, indent=2, sort_keys=False) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Map delegated authorities and watch delegates' public security posture."
    )
    parser.add_argument(
        "--inventory",
        required=True,
        help="Path to the delegation inventory YAML file.",
    )
    parser.add_argument(
        "--markdown",
        default="-",
        help="Where to write the Markdown report ('-' for stdout).",
    )
    parser.add_argument(
        "--json",
        default=None,
        help="Where to write the JSON report ('-' for stdout).",
    )
    args = parser.parse_args(argv)

    try:
        delegates = load_inventory(args.inventory)
    except (OSError, ValueError) as exc:
        print(f"error: cannot load inventory: {exc}", file=sys.stderr)
        return 2

    risk_map = build_risk_map(delegates)
    markdown = render_markdown(risk_map)

    if args.markdown == "-":
        print(markdown)
    else:
        with open(args.markdown, "w", encoding="utf-8") as fh:
            fh.write(markdown)
        print(f"wrote Markdown report to {args.markdown}", file=sys.stderr)

    if args.json:
        payload = render_json(risk_map)
        if args.json == "-":
            print(payload)
        else:
            with open(args.json, "w", encoding="utf-8") as fh:
                fh.write(payload)
            print(f"wrote JSON report to {args.json}", file=sys.stderr)

    high = risk_map["summary"]["by_risk"]["HIGH"]
    return 1 if high else 0


if __name__ == "__main__":
    sys.exit(main())
