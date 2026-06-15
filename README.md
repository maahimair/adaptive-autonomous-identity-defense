# Adaptive Autonomous Identity Defense & Deception Framework (AAIDD)

![Status](https://shields.io)
![Language](https://shields.io)
![Field](https://shields.io)

Traditional intrusion detection and prevention systems rely on static thresholds that sophisticated threat actors easily bypass using distributed "low and slow" credential stuffing. AAIDD is a next-generation, autonomous security gateway designed to intercept, analyze, and neutralize identity-based attacks using behavioral modeling, adaptive deception (tarpitting), and crowdsourced threat intelligence synchronization.

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
             (Tracks entropy, password leaks, low-slow rates)
                                   │
            ┌──────────────────────┴──────────────────────┐
            ▼ (Below Threat Threshold)                    ▼ (Threat Threshold Met)
    [ Log Event & Wait ]                           [ Autonomous Response Engine ]
                                                          │
                    ┌─────────────────────────────────────┴─────────────────────────────────────┐
                    ▼                                     ▼                                     ▼
        [ Module 1: Behavioral Block ]       [ Module 2: Adaptive Deception ]       [ Module 3: Swarm Sync ]
         Flags "Low & Slow" multi-IP          Routes traffic into an isolated        Broadcasts bad IP to 
         attacks across long windows.        fake Python Shell terminal.            local API blocklist registry.
                    │                                     │                                     │
                    └─────────────────────────────────────┼─────────────────────────────────────┘
                                                          ▼
                                            [ Output to SIEM Dashboard ]
                                       (Real-time attack profiles & metrics)
```

---

## Key Features & Future-Facing Enhancements

### 1. AI-Driven "Low and Slow" Behavioral Detection
*   The Problem: Attackers switch IPs or slow down brute-force attacks to stay under traditional rate limits.
*   The AAIDD Solution: Monitors authentication event logs using sequential time-delta evaluations and checks semantic password entropy against known leaked credential dictionaries to spot highly coordinated distributed attacks.

### 2. Adaptive Deception Gateway (The "Infinite Maze" Tarpit)
*   The Problem: Outright blocking an IP notifies the attacker they have been caught, prompting them to pivot to another target asset.
*   The AAIDD Solution: Instead of severing the TCP pipe, malicious sockets are transparently routed into a simulated, text-based interactive environment. The attacker believes they have succeeded, allowing security teams to safely profile post-exploitation behavior while consuming the attacker's computing resources.

### 3. Automated Collaborative Threat Swarm Sync
*   The Problem: Defending infrastructures operate in silos, leaving individual nodes vulnerable until manual security logs are updated.
*   The AAIDD Solution: Incorporates a lightweight automated API broker system. Once an endpoint dynamically flags a high-confidence threat signature, the malicious IP metadata is instantaneously pushed to an internal distributed blocklist registry to immunize adjacent services.

---

## Tech Stack & Core Engineering Components
*   Core Systems Automation: Python 3.x, Linux Systems Engineering
*   Packet Manipulation & Simulation: Paramiko (SSH Automation Framework)
*   Log Processing Data Wrangling: Regular Expressions (RegEx), Structured JSON Object Schema
*   Security Analytics / Visualization: Splunk Enterprise / ELK Stack (Elasticsearch, Logstash, Kibana)

---

## Development Roadmap (4-1 Semester Milestones)
- [x] Comprehensive System Architecture Design & Flow Mapping
- [ ] Phase 1: Core Authentication Interceptor & RegEx Log Processing Engine
- [ ] Phase 2: Low & Slow Behavioral Feature Extraction Pipeline
- [ ] Phase 3: Adaptive Network Socket Router (Deception Tarpit Engine)
- [ ] Phase 4: Swarm API Registry Integration & Splunk Monitoring Dashboards

---

## Repository Structure (Target Layout)
```text
├── adaptive-autonomous-identity-defense/
│   ├── README.md               # System design documentation & roadmap
│   ├── attacker_engine/
│   │   └── auth_flood.py       # Paramiko-driven multi-threaded attack simulation
│   ├── defender_engine/
│   │   └── log_sentinel.py     # Real-time text interceptor & event parser
│   ├── deception_tarpit/
│   │   └── mock_shell.py       # Isolated interactive terminal router 
│   └── telemetry_siem/
│       └── sample_alerts.json  # Schema logs formatted for SIEM ingestion
```
