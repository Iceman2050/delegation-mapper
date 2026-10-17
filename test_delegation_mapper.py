"""Tests for delegation_mapper.py — no real network is ever touched.

Network-facing functions (check_dns, check_tls, check_security_txt) are
replaced with deterministic stubs via monkeypatch / explicit injection.
"""

import datetime as dt
import json
from pathlib import Path

import pytest

import delegation_mapper as dm

HERE = Path(__file__).resolve().parent

TODAY = dt.date(2026, 10, 16)

HEALTHY_DNS = {"ok": True, "detail": "resolves to 93.184.216.34"}
HEALTHY_TLS = {
    "ok": True,
    "detail": "certificate valid, expires in 300 days; hostname matches",
    "expired": False,
    "expiry": "2027-08-12T00:00:00+00:00",
    "days_left": 300,
}
HEALTHY_SECTXT = {"ok": True, "detail": "security.txt present"}


def healthy_checks():
    return {
        "dns_fn": lambda domain: HEALTHY_DNS,
        "tls_fn": lambda domain: HEALTHY_TLS,
        "sectxt_fn": lambda domain: HEALTHY_SECTXT,
    }


def make_delegate(**overrides):
    entry = {
        "name": "Meridian Filing Services",
        "authority": "files bankruptcy notices on our behalf",
        "scopes": ["US bankruptcy courts"],
        "domains": ["meridian-filings.example"],
        "contact": "security@meridian-filings.example",
        "last_review_date": "2026-09-20",
    }
    entry.update(overrides)
    return entry


# ---------------------------------------------------------------------------
# Required behaviours
# ---------------------------------------------------------------------------

def test_stale_review_is_flagged():
    result = dm.assess_delegate(
        make_delegate(last_review_date="2025-11-02"),  # 348 days before TODAY
        today=TODAY,
        **healthy_checks(),
    )
    flags = [f["flag"] for f in result["flags"]]
    assert "stale-review" in flags
    assert result["risk"] in ("MEDIUM", "HIGH")


def test_missing_security_txt_is_flagged():
    checks = healthy_checks()
    checks["sectxt_fn"] = lambda domain: {"ok": False, "detail": "HTTP 404"}
    result = dm.assess_delegate(make_delegate(), today=TODAY, **checks)
    flags = [f["flag"] for f in result["flags"]]
    assert "missing-security-txt" in flags


def test_expired_tls_cert_is_flagged():
    checks = healthy_checks()
    checks["tls_fn"] = lambda domain: {
        "ok": False,
        "detail": "certificate EXPIRED 12 days ago; hostname matches",
        "expired": True,
        "expiry": "2026-10-04T00:00:00+00:00",
        "days_left": -12,
    }
    result = dm.assess_delegate(make_delegate(), today=TODAY, **checks)
    flags = [f["flag"] for f in result["flags"]]
    assert "tls-expired" in flags
    assert result["risk"] == "HIGH"


def test_healthy_delegate_produces_no_flags():
    result = dm.assess_delegate(make_delegate(), today=TODAY, **healthy_checks())
    assert result["flags"] == []
    assert result["risk"] == "NONE"


def test_json_and_markdown_contain_all_delegates(tmp_path):
    delegates = [
        make_delegate(name="Delegate One"),
        make_delegate(name="Delegate Two", last_review_date="2024-01-01"),
        make_delegate(name="Delegate Three", domains=["a.example", "b.example"]),
    ]
    risk_map = dm.build_risk_map(delegates, today=TODAY, **healthy_checks())

    payload = json.loads(dm.render_json(risk_map))
    names_json = [d["name"] for d in payload["delegates"]]
    assert names_json == ["Delegate One", "Delegate Two", "Delegate Three"]

    markdown = dm.render_markdown(risk_map)
    for name in ("Delegate One", "Delegate Two", "Delegate Three"):
        assert name in markdown
    # The stale one must surface in both formats too.
    assert "stale-review" in markdown
    assert any(
        f["flag"] == "stale-review"
        for d in payload["delegates"]
        for f in d["flags"]
    )


# ---------------------------------------------------------------------------
# Additional posture-flag coverage
# ---------------------------------------------------------------------------

def test_expiring_soon_tls_is_flagged():
    checks = healthy_checks()
    checks["tls_fn"] = lambda domain: {
        "ok": True,
        "detail": "certificate valid, expires in 9 days; hostname matches",
        "expired": False,
        "expiry": "2026-10-25T00:00:00+00:00",
        "days_left": 9,
    }
    result = dm.assess_delegate(make_delegate(), today=TODAY, **checks)
    flags = [f["flag"] for f in result["flags"]]
    assert "tls-expiring-soon" in flags
    assert result["risk"] == "MEDIUM"


def test_dns_failure_is_flagged():
    checks = healthy_checks()
    checks["dns_fn"] = lambda domain: {"ok": False, "detail": "DNS resolution failed"}
    result = dm.assess_delegate(make_delegate(), today=TODAY, **checks)
    flags = [f["flag"] for f in result["flags"]]
    assert "dns-failure" in flags
    assert result["risk"] == "HIGH"


def test_tls_handshake_error_is_flagged():
    checks = healthy_checks()
    checks["tls_fn"] = lambda domain: {
        "ok": False,
        "detail": "TLS handshake failed: connection refused",
        "expired": False,
        "expiry": None,
    }
    result = dm.assess_delegate(make_delegate(), today=TODAY, **checks)
    flags = [f["flag"] for f in result["flags"]]
    assert "tls-error" in flags


def test_tls_hostname_mismatch_not_flagged_as_expired():
    checks = healthy_checks()
    checks["tls_fn"] = lambda domain: {
        "ok": False,
        "detail": "certificate valid, expires in 300 days; hostname mismatch",
        "expired": False,
        "expiry": "2027-08-12T00:00:00+00:00",
        "days_left": 300,
    }
    result = dm.assess_delegate(make_delegate(), today=TODAY, **checks)
    flags = [f["flag"] for f in result["flags"]]
    assert "tls-error" in flags
    assert "tls-expired" not in flags


def test_invalid_review_date_is_flagged():
    result = dm.assess_delegate(
        make_delegate(last_review_date="not-a-date"), today=TODAY, **healthy_checks()
    )
    flags = [f["flag"] for f in result["flags"]]
    assert "stale-review" in flags
    assert result["flags"][0]["severity"] == "HIGH"


def test_exactly_180_days_is_not_stale():
    review = (TODAY - dt.timedelta(days=180)).isoformat()
    result = dm.assess_delegate(
        make_delegate(last_review_date=review), today=TODAY, **healthy_checks()
    )
    assert [f["flag"] for f in result["flags"]] == []


def test_delegate_without_domains_skips_posture_checks():
    result = dm.assess_delegate(
        make_delegate(domains=[]), today=TODAY, **healthy_checks()
    )
    assert result["flags"] == []
    assert result["risk"] == "NONE"


def test_flag_counts_and_risk_buckets_in_summary():
    stale = make_delegate(name="Stale", last_review_date="2024-01-01")
    fine = make_delegate(name="Fine")
    risk_map = dm.build_risk_map([stale, fine], today=TODAY, **healthy_checks())
    assert risk_map["summary"]["total_delegates"] == 2
    assert risk_map["summary"]["by_risk"]["MEDIUM"] == 1
    assert risk_map["summary"]["by_risk"]["NONE"] == 1
    assert risk_map["summary"]["flag_counts"]["stale-review"] == 1


# ---------------------------------------------------------------------------
# Inventory parsing / validation
# ---------------------------------------------------------------------------

def test_yaml_subset_parser_reads_fixture():
    path = HERE / "fixtures" / "sample-inventory.yaml"
    delegates = dm.load_inventory(str(path))
    assert len(delegates) == 6
    names = [d["name"] for d in delegates]
    assert "Meridian Filing Services" in names
    meridian = next(d for d in delegates if d["name"] == "Meridian Filing Services")
    assert meridian["authority"] == "files bankruptcy notices on our behalf"
    assert meridian["scopes"] == ["US bankruptcy courts", "notices.ourcompany.internal"]
    assert meridian["domains"] == ["meridian-filings.example"]
    assert meridian["last_review_date"] == "2026-09-20"


def test_yaml_parser_rejects_garbage():
    with pytest.raises(ValueError):
        dm.parse_inventory_yaml("just some random text\nwith no colons at all")


def test_load_inventory_requires_fields(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("delegates:\n  - name: \"No Authority\"\n    last_review_date: \"2026-01-01\"\n")
    with pytest.raises(ValueError, match="authority"):
        dm.load_inventory(str(bad))


# ---------------------------------------------------------------------------
# CLI end-to-end (checks stubbed, files on disk)
# ---------------------------------------------------------------------------

def test_cli_end_to_end_with_stubbed_checks(tmp_path, monkeypatch):
    inv = tmp_path / "inv.yaml"
    inv.write_text(
        "delegates:\n"
        "  - name: \"Stubbed Delegate\"\n"
        "    authority: \"files notices\"\n"
        "    domains:\n"
        "      - \"stubbed.example\"\n"
        "    last_review_date: \"2026-09-20\"\n"
    )
    monkeypatch.setattr(dm, "check_dns", lambda domain: HEALTHY_DNS)
    monkeypatch.setattr(dm, "check_tls", lambda domain: HEALTHY_TLS)
    monkeypatch.setattr(dm, "check_security_txt", lambda domain: HEALTHY_SECTXT)

    md_out = tmp_path / "report.md"
    json_out = tmp_path / "report.json"
    rc = dm.main(
        ["--inventory", str(inv), "--markdown", str(md_out), "--json", str(json_out)]
    )
    assert rc == 0
    md_text = md_out.read_text()
    assert "Stubbed Delegate" in md_text
    assert "Delegation Risk Map" in md_text
    payload = json.loads(json_out.read_text())
    assert payload["summary"]["total_delegates"] == 1
    assert payload["delegates"][0]["name"] == "Stubbed Delegate"
    assert payload["delegates"][0]["risk"] == "NONE"


def test_cli_returns_nonzero_when_high_risk(tmp_path, monkeypatch):
    inv = tmp_path / "inv.yaml"
    inv.write_text(
        "delegates:\n"
        "  - name: \"Bad Delegate\"\n"
        "    authority: \"sends email\"\n"
        "    domains:\n"
        "      - \"bad.example\"\n"
        "    last_review_date: \"2026-09-20\"\n"
    )
    monkeypatch.setattr(dm, "check_dns", lambda domain: HEALTHY_DNS)
    monkeypatch.setattr(
        dm, "check_tls",
        lambda domain: {"ok": False, "detail": "expired", "expired": True,
                        "expiry": None, "days_left": -3},
    )
    monkeypatch.setattr(dm, "check_security_txt", lambda domain: HEALTHY_SECTXT)
    rc = dm.main(["--inventory", str(inv), "--markdown", "-"])
    assert rc == 1


def test_cli_errors_on_missing_inventory(capsys):
    rc = dm.main(["--inventory", "/nonexistent/inv.yaml", "--markdown", "-"])
    assert rc == 2
    assert "error" in capsys.readouterr().err.lower()
