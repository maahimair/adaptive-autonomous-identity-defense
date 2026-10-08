# Adaptive Autonomous Identity Defense & Deception Framework (AAIDD)

A next-generation autonomous security gateway for identity-based attacks. It
intercepts authentication events, models distributed "low and slow" credential
stuffing behaviour, and responds by behavioural blocking, adaptive deception
(tarpitting), and collaborative threat-intelligence sync.

![Python](https://img.shields.io/badge/python-3.x-blue)
![Status](https://img.shields.io/badge/status-prototype-orange)

---

## Problem

Traditional intrusion detection and prevention systems rely on static
thresholds that sophisticated threat actors bypass easily using distributed,
low-rate credential stuffing across many source addresses. No single IP ever
crosses the alert threshold, so the attack proceeds unnoticed.

AAIDD correlates authentication failures **by source over a sliding time
window** instead of evaluating each IP in isolation, which is what makes
"low and slow" distributed patterns visible.

---

## System Architecture & Data Flow

```text
                 [ Incoming SSH / Web Auth Connection ]
                                   │
                                   ▼
                 [ Python Real-Time Log Interceptor ]
                                   │
                    ├──► [ Standard Login ] ──► (Allow User In)
                                   │
                                   ▼ (If Failed)
                     [ Behavioral ML Extraction ]
             (Tracks velocity, sliding-window correlation)
                                   │
              ┌────────────────────┴────────────────────┐
              ▼ (Below Threat Threshold)                 ▼ (Threshold Met)
      [ Log Event & Wait ]                 [ Autonomous Response Engine ]
                                                             │
                    ┌────────────────────────────────────────┼───────────────────────────────────────┐
                    ▼                                        ▼                                       ▼
    [ Module 1: Behavioural Block ]      [ Module 2: Adaptive Deception ]          [ Module 3: Swarm Sync ]
     Flags "low and slow" multi-IP        Routes traffic into an isolated            Broadcasts the bad IP
     attacks across long windows.          fake Python shell terminal.               to the internal blocklist
                    │                                        │                          registry.
                    └────────────────────────────────────────┼───────────────────────────────────────┘
                                                             ▼
                                                [ Output to SIEM Dashboard ]
                                       (Real-time attack profiles & metrics)
```

---

## Components

| Module | Path | Purpose |
| --- | --- | --- |
| Behavioural detection | `defender_engine/log_sentinel.py` | Tails auth logs, correlates failures per source IP inside a sliding window, emits SIEM-schema alerts |
| Adaptive deception | `deception_tarpit/mock_shell.py` | Fake interactive shell that logs attacker commands without executing anything |
| Threat swarm sync | `threat_swarm/swarm_sync.py` | Signs and broadcasts indicators of compromise to the shared blocklist registry |
| Attack simulator | `attacker_engine/auth_flood.py` | Lab-only generator of the failed-login telemetry the defender detects |

---

## Repository Structure

```text
adaptive-autonomous-identity-defense/
├── README.md
├── requirements.txt
├── .gitignore
├── attacker_engine/
│   └── auth_flood.py                 # Lab SSH authentication flood simulator
├── defender_engine/
│   └── log_sentinel.py               # Real-time auth.log interceptor & event parser
├── deception_tarpit/
│   └── mock_shell.py                 # Isolated interactive terminal
├── threat_swarm/
│   └── swarm_sync.py                 # Signed IoC broadcast client
├── telemetry_siem/
│   └── sample_alerts.json            # SIEM ingestion schema fixture
└── tests/
    └── test_defender_and_deception.py
```

---

## Installation

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

The defender and deception modules need **only the Python standard library**.
`paramiko` is required for the lab attack simulator and `requests` for live
swarm transmission; both degrade gracefully with a clear message when absent.

---

## Usage

### Behavioural detection

```bash
python defender_engine/log_sentinel.py
```

Tails `auth.log` (override with `AAIDD_LOG_PATH`) and appends JSONL alerts to
`telemetry_siem/alert_live.json`. The tail loop buffers partial lines and
reopens the file automatically on rotation.

Trigger defaults: **3 failures from one source within 10 seconds**.

### Adaptive deception tarpit

```bash
python deception_tarpit/mock_shell.py
```

Presents a fake `ubuntu@prod-db-server` shell. Nothing touches the real
filesystem — the entire host is an in-memory tree. Destructive commands
(`rm`) report success without doing anything, and `sudo`/`su` fail
indefinitely so the attacker believes escalation is progressing.

### Threat swarm sync

```bash
export AAIDD_SWARM_SECRET="$(openssl rand -hex 32)"
python threat_swarm/swarm_sync.py          # dry run: signs and prints only
python threat_swarm/swarm_sync.py --live   # transmit to AAIDD_REGISTRY_URL
```

### Lab attack simulator

```bash
python attacker_engine/auth_flood.py
```

Targets loopback only by default. See "Safety rails" below.

---

## Configuration

| Variable | Used by | Purpose |
| --- | --- | --- |
| `AAIDD_LOG_PATH` | defender | Auth log to tail |
| `AAIDD_SWARM_SECRET` | swarm | Per-node HMAC signing key (required) |
| `AAIDD_NODE_ID` | swarm | Node identity sent with every broadcast |
| `AAIDD_REGISTRY_URL` | swarm | Blocklist registry endpoint |

---

## SIEM Alert Schema

Behavioural alerts (`AAIDD-IDENTITY-ANOMALY-01`):

```json
{
  "event_id": "AAIDD-IDENTITY-ANOMALY-01",
  "alert_timestamp": "2026-06-14T10:31:00Z",
  "source_incident_time": "Jun 15 12:00:02",
  "indicators": {
    "attacker_ip": "198.51.100.42",
    "targeted_identity": "root"
  },
  "risk_assessment": {
    "confidence_rating": "High",
    "classification": "Distributed Authentication Velocity Exploit"
  }
}
```

Deception events (`AAIDD-DECEPTION-ENGAGEMENT-02`) carry `captured_input` and a
snapshot of `environment_state`.

---

## Tests

```bash
python -m pytest tests -q
```

31 tests covering log parsing, sliding-window alerting, burst de-duplication,
alert re-arming, path-traversal containment in the fake shell, telemetry
failure handling, and HMAC signing/verification. Runs fully offline — no SSH,
no network.

---

## Safety Rails

This is a defensive research prototype. The attack simulator is fenced in:

* **Loopback only by default.** Targeting any other host raises
  `LabTargetNotAllowedError` unless `allow_remote=True` is passed explicitly.
* **Never trusts host keys.** `RejectPolicy` is always set, so a MITM cannot
  silently intercept even lab traffic.
* **Never logs passwords.** Only the username, attempt count and outcome are
  printed, so terminal scrollback and CI logs never contain usable credentials.
* **Short timeouts.** 2-second connect, banner and auth timeouts.
* **Documentation-range IPs.** Sample indicators use RFC 5737 reserved ranges
  (`198.51.100.0/24`, `203.0.113.0/24`), which cannot resolve to a real host.

`threat_swarm/swarm_sync.py` refuses to run with an empty HMAC key, because an
empty key still produces a valid signature that anyone could forge.

---

## Tech Stack

* Core automation: Python 3.x, Linux systems engineering
* Simulation: Paramiko (SSH automation)
* Log processing: Regular expressions, structured JSON schema
* Analytics / SIEM: Splunk, ELK stack

---

## Roadmap

- [x] System architecture design and flow mapping
- [x] Phase 1 — Core authentication interceptor and regex log processing engine
- [x] Phase 2 — Low and slow behavioural feature extraction pipeline
- [x] Phase 3 — Adaptive deception socket router and tarpit engine
- [x] Phase 4 — Swarm API registry client and SIEM schema output
- [ ] Phase 5 — Live Socket/IP routing into the tarpit (currently simulated)
- [ ] Phase 6 — Splunk / ELK dashboard integration
- [ ] Phase 7 — Password-entropy and breach-dictionary correlation

## Limitations

* The sliding window is evaluated per source IP only; true distributed
  correlation across many low-volume IPs needs shared state or clustering.
* The shield `Failed password` regex covers the common `auth.log` formats but
  not journald output. A `journalctl -f` adapter would broaden coverage.
* `threat_swarm` transport is functional but the registry API contract is
  internal and undocumented.
* The "low and slow" detection window and threshold are static constants and
  have not been tuned against production traffic.