# 🔴 Hemo-Lock — ICS/OT Attack & Defense Lab
 
> **Authorized use only.** All actions performed by this tool are confined to the isolated BCIT INCS 4810 lab network. Unauthorized use outside this environment is strictly prohibited.
 
---
 
## Overview
 
`redteam_chain.py` is a guided, interactive red-team automation script built for the **BCIT INCS 4810** course (ISA/IEC 62443). It simulates a full attack chain against an IT/OT lab environment — from initial Wi-Fi compromise all the way through to a PLC process-value injection — and finishes with a defense validation step.
 
The script is written in Python 3 and uses a rich terminal UI with color-coded output, phase-by-phase confirmation prompts, and a final JSON report.
 
---
 
## Lab Topology
 
| Zone | Host | IP | Role |
|------|------|----|------|
| Wi-Fi | Target AP | `HemoLock` (SSID) | WPA2 access point |
| IDMZ | Historian | `10.10.10.20` | Jump host / SSH target |
| IDMZ | Honeypot | `10.10.10.50` | Cowrie — automatically avoided |
| OT | IDS (RPi5) | `10.20.20.5` | Zeek / Suricata sensor |
| OT | PLC | `10.20.20.111` | Allen-Bradley / EtherNet/IP |
 
> All IPs and credentials are pre-configured in the `CFG` dictionary at the top of the script. Update these if your lab topology differs.
 
---
 
## Attack Chain Phases
 
| # | Phase | Description |
|---|-------|-------------|
| 1 | **WiFi AP Crack** | Puts `wlan0` into monitor mode, captures a WPA2 handshake with `besside-ng`, and cracks it with `aircrack-ng` + `rockyou.txt`. Reconnects via NetworkManager on success. |
| 2 | **IDMZ Recon** | Injects routing to the IDMZ and OT subnets, then runs an `nmap` SYN scan. Automatically detects and skips the Cowrie honeypot. Operator selects the Historian from discovered hosts. |
| 3 | **SSH Brute Force** | Paramiko-based sequential SSH brute forcer against the Historian. Tries a priority list (common/username-derived passwords) before falling back to `rockyou.txt`. |
| 4 | **SSH Pivot / OT Recon** | SSHes into the Historian, reads OT syslog, hops to the IDS via an SSH tunnel, and enumerates OT zone hosts and open industrial ports (EtherNet/IP 44818, S7 102). Optionally steals the IDS SSH private key. |
| 5 | **PLC CIP Write Attack** | Opens an EtherNet/IP connection to the Allen-Bradley PLC (via pycomm3). Reads the current `Dosage_Rate` tag value and writes the configured attack value. Supports stealth mode (periodic writes with random jitter) and manual tag writes. |
| 6 | **Defense Validation** | SSHes back through Historian → IDS and tails Suricata's `fast.log` for CIP Write alerts, confirming whether the IDS detected the attack. Performs anti-forensics (clears bash history and `auth.log`) on both hosts. |
 
---
 
## Requirements
 
### System Tools
 
These must be present on the attacker machine (Kali Linux recommended):
 
- `aircrack-ng` / `besside-ng` / `airodump-ng`
- `nmap`
- `macchanger`
- `nmcli` (NetworkManager)
- A wireless interface that supports monitor mode (default: `wlan0`)
### Python Dependencies
 
Installed automatically on first run via `pip`:
 
- `rich` — terminal UI
- `paramiko` — SSH client / pivot
- `pycomm3` — EtherNet/IP / CIP communication
Python **3.10+** is required (uses `str | None` union syntax).
 
---
 
## Usage
 
```bash
# Run the full chain interactively (confirms each phase before running)
sudo python3 redteam_chain.py
 
# Run specific phases only
sudo python3 redteam_chain.py --phases 2 3 4
 
# Skip per-phase confirmation prompts (auto mode)
sudo python3 redteam_chain.py --auto
 
# Combine: run phases 4 and 5 without prompts
sudo python3 redteam_chain.py --phases 4 5 --auto
```
 
> `sudo` is required for raw socket operations (nmap, monitor mode, route injection).
 
---
 
## Output
 
- **Live terminal output** — color-coded by severity (green = success, yellow = warning, red = error/failure).
- **Phase summary table** — printed at the end of the run showing status and key findings for each phase.
- **JSON report** — saved to `/tmp/incs4810_report_<timestamp>.json` with full per-phase output.
---
 
## OPSEC Features
 
- MAC address randomization on `wlan0` before Phase 1
- Route injection bound to the Wi-Fi interface (never falls back to `eth0`/VMware NAT)
- Honeypot detection — Cowrie at `10.10.10.50` is automatically excluded from targeting
- Anti-forensics in Phase 6 — clears `~/.bash_history` and `/var/log/auth.log` on the Historian and IDS
- Stealth mode in Phase 5 — periodic PLC writes with randomized timing and jitter
---
 
## Instructor / Course Info
 
| Field | Value |
|-------|-------|
| Course | INCS 4810 |
| Instructor | Victor Mendez |
| Location | BCIT SW01-3550 |
| Framework | ISA/IEC 62443 |
 
---
 
## Disclaimer
 
This tool was developed exclusively for use in the BCIT INCS 4810 authorized lab environment. It must not be used against any systems, networks, or devices without explicit written authorization. The authors assume no liability for misuse.

**Attack:** Kali Linux, aircrack-ng, Hydra, nmap, pycomm3, Wireshark

**Defense:** Suricata, Zeek, Grafana, InfluxDB, rsyslog, Cowrie

**Hardware:** Allen Bradley PLC, Raspberry Pi 5 ×4, FortiGate Rugged 60D, Cisco IE-2000 ×2, Cisco WLC 3500, C9120AXI AP, MasterFlex Peristaltic Pump
