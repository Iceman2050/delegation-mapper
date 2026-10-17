# delegation-mapper

**Who can act in your name — and are they still trustworthy?**

Breaches increasingly come through contractors **authorized to act in your
name**: firms that file notices, transmit your data, or speak as your
company. Supply-chain security covers the code you *import*. Nothing
covers the authority you *lend*.

`delegation-mapper` closes that gap. You keep a **delegation inventory**
— every delegate, the authority granted, the systems/domains in scope,
the contact on file, and the last review date — and the tool watches each
delegate's public security posture, continuously and without any
authentication, using only the Python standard library.

## What it checks (per delegate domain)

- **TLS certificate validity** — expiry date and hostname match (via `ssl`)
- **security.txt presence** — `https://<domain>/.well-known/security.txt` (via `urllib`, short timeout)
- **DNS resolvability** — (via `socket`)

## What it flags

| Flag | Meaning |
|------|---------|
| `stale-review` | `last_review_date` is more than 180 days ago (or not a valid date) |
| `missing-security-txt` | no `security.txt` published on the delegate's domain |
| `tls-expired` | certificate expired — HIGH severity |
| `tls-expiring-soon` | certificate expires within 30 days |
| `tls-error` | handshake or hostname problem that is not plain expiry |
| `dns-failure` | domain does not resolve — HIGH severity |

Each delegate gets a risk rating (`NONE` / `LOW` / `MEDIUM` / `HIGH`).
The CLI exits non-zero (`1`) when any delegate is `HIGH` risk, so it drops
straight into CI or a cron.

## Install

Zero third-party dependencies — Python 3.9+ only.

```bash
git clone https://github.com/Iceman2050/delegation-mapper.git
cd delegation-mapper
pip install -e .
```

Or just run the single file directly: `python3 delegation_mapper.py ...`

## Usage

1. Write your delegation inventory (see
   [`fixtures/sample-inventory.yaml`](fixtures/sample-inventory.yaml)):

```yaml
delegates:
  - name: "Meridian Filing Services"
    authority: "files bankruptcy notices on our behalf"
    scopes:
      - "US bankruptcy courts"
      - "notices.ourcompany.internal"
    domains:
      - "meridian-filings.example"
    contact: "security@meridian-filings.example"
    last_review_date: "2026-09-20"
```

2. Run the mapper:

```bash
# Markdown report to stdout
python3 delegation_mapper.py --inventory fixtures/sample-inventory.yaml

# Markdown + JSON to files
python3 delegation_mapper.py --inventory inventory.yaml \
    --markdown delegation-risk-map.md --json delegation-risk-map.json
```

`--markdown -` / `--json -` write to stdout explicitly. `pip install -e .`
also installs a `delegation-mapper` console entry point with the same flags.

## Example output

```
# Delegation Risk Map

Generated: 2026-10-16T20:50:00+00:00

## Summary

- Delegates assessed: 6
- Risk HIGH: 1
- Risk MEDIUM: 3
- Risk LOW: 1
- Risk NONE: 1

### Flags raised

- dns-failure: 1
- missing-security-txt: 4
- stale-review: 3
- tls-expired: 1

## Delegates

### Meridian Filing Services — risk: NONE

- Authority granted: files bankruptcy notices on our behalf
- Scopes: US bankruptcy courts, notices.ourcompany.internal
- Domains: meridian-filings.example
- Contact: security@meridian-filings.example
- Last reviewed: 2026-09-20
- Flags: none ✅

### Northbridge Mail Relay — risk: MEDIUM

- Authority granted: sends email as @ourcompany
- Scopes: marketing.ourcompany, support.ourcompany
- Domains: mail.northbridge-relay.example
- Contact: postmaster@northbridge-relay.example
- Last reviewed: 2025-11-02
- Flags:
  - **MEDIUM** `stale-review` — last reviewed 2025-11-02 (348 days ago, limit is 180)
  ...
```

The JSON report mirrors the same structure (`summary` + per-delegate
`risk`, `flags`, and raw `domain_posture` results) for piping into
dashboards or alerting.

## Tests

```bash
python3 -m pytest -q
```

All network access is mocked — the suite never touches the real network.
It covers: stale-review flagging, missing `security.txt` flagging, expired
TLS flagging, expiring-soon and handshake-error cases, DNS failures, the
healthy-delegate no-flag case, YAML inventory parsing/validation, CLI
exit codes, and JSON + Markdown completeness.

## Library use

The check functions are substitutable: `assess_delegate(entry,
dns_fn=..., tls_fn=..., sectxt_fn=...)` — pass your own implementations
(e.g. backed by a scanner or cache) without forking the tool.

## License

MIT — see [LICENSE](LICENSE).

## Built by Ingenious AI

This tool is built and maintained by **Ingenious AI**. Get early access to our AI security platforms:

- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DisclosureGuard
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ModelMinder
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20TermsWatch
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Vibe-Code%20Audit
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20BreachHunter
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ChatBreaker
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DomainGuard
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ContentCraft%20AI


> Built by Ingenious AI with Muse — get free tokens with invite code `2HCQH1`
