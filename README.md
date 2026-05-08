# 🔴 Hemo-Lock — ICS/OT Attack & Defense Lab

> **⚠️ Authorized use only. All testing conducted on an isolated, air-gapped lab network. Do not replicate on any network you do not own.**

Hemo-Lock is a full red team attack chain targeting a simulated hospital ICU infusion pump control system built on real industrial hardware. The lab demonstrates how a misconfigured OT network can be exploited end-to-end — from WiFi entry to physical impact on a peristaltic pump — and how defense-in-depth controls detect and block it.

---

## 🏗️ Network Architecture

```
[Attacker — Kali Linux]
    │  WiFi crack (WPA2)
    ▼
[Enterprise Zone — 192.168.10.0/24]
    │  Cisco WLC 3500 + C9120AXI AP
    │  Windows 10 Workstation (192.168.10.10)
    │
    ▼ FortiGate Rugged 60D
[IDMZ — 10.10.10.0/24]
    │  OT Historian RPi5 (10.10.10.20) — Grafana, InfluxDB, rsyslog, pycomm3
    │  Cowrie SSH Honeypot RPi5 (10.10.10.50)
    │
    ▼
[ICS/OT Zone — 10.20.20.0/24]
    │  IDS RPi5 (10.20.20.5) — Zeek, Suricata
    │  Allen Bradley PLC (10.20.20.100)
    └  MasterFlex Peristaltic Pump (physical)
```

---

## ⚔️ Attack Chain

| Phase | Action | Tool |
|---|---|---|
| 1 | Crack WiFi AP (WPA2 handshake) | aircrack-ng |
| 2 | Scan IDMZ, find Historian | nmap |
| 3 | SSH brute force Historian | Hydra |
| 4 | Pivot via Historian, confirm OT route via syslog | paramiko |
| 5 | CIP Write Tag — `Dosage_Rate` 8 → 32 (4x) | pycomm3 |
| 6 | Pump physically changes behavior | — |

---

## 🛡️ Defense Layers

| Layer | Control |
|---|---|
| 1 | Suricata DPI drops unauthorized CIP Write Tag commands |
| 2 | PLC firmware IP allowlist — only 10.20.20.5 on port 44818 |
| 3 | Ladder logic value clamp — max 50 mL/hr rate of change |
| + | Cowrie honeypot detects lateral movement |

---

## 🚀 Usage

```bash
pip install pycomm3 paramiko rich

# Full chain
python3 redteam_chain.py

# Specific phases
python3 redteam_chain.py --phases 2 3 4

# Skip confirmations
python3 redteam_chain.py --auto
```

---

## 🛠️ Stack

**Attack:** Kali Linux, aircrack-ng, Hydra, nmap, pycomm3, Wireshark

**Defense:** Suricata, Zeek, Grafana, InfluxDB, rsyslog, Cowrie

**Hardware:** Allen Bradley PLC, Raspberry Pi 5 ×3, FortiGate Rugged 60D, Cisco IE-2000 ×2, Cisco WLC 3500, C9120AXI AP, MasterFlex Peristaltic Pump
