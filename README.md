# 🔴 Hemo-Lock — ICS/OT Attack & Defense Lab

---
 
> [!CAUTION]
> ## ⚠ AUTHORIZED USE ONLY — READ BEFORE PROCEEDING
>
> This framework is a **weapons-grade offensive security tool** developed exclusively for the **BCIT INCS 4810 Industrial Cybersecurity** course. It is designed to operate solely within a **physically isolated, air-gapped lab environment** under explicit instructor authorization.
>
> **Deployment of this tool against any network, system, or device that you do not own or have written authorization to test constitutes a criminal offence** under the *Criminal Code of Canada*, the *Computer Fraud and Abuse Act (US)*, and equivalent legislation in all other jurisdictions.
>
> By executing this framework, you affirm that:
> - You are operating within the designated BCIT INCS 4810 lab topology
> - You hold explicit, written authorization from the lab instructor
> - All traffic is confined to the isolated lab network segment
> - You accept full legal and ethical responsibility for your actions
>
> **The authors, BCIT, and affiliated instructors assume no liability for misuse.**
 
---
 
## Overview
 
`redteam_chain.py` is a fully automated, seven-phase offensive kill chain purpose-built for Operational Technology (OT) / Industrial Control System (ICS) red team simulation. It demonstrates a complete adversarial lifecycle — from unauthenticated wireless perimeter compromise through deep lateral movement into a live PLC — with zero manual tooling hand-off between phases.
 
The framework chains the following capability classes into a single, operator-driven pipeline:
 
- **802.11 Wireless Exploitation** — Targeted WPA2 deauthentication, offline handshake capture, and autonomous dictionary cracking via `besside-ng` and `aircrack-ng`.
- **Dynamic Network Routing** — Gateway discovery, RFC-1918 subnet probing, and kernel route injection bound to the wireless interface to prevent fallback through NAT adapters.
- **Active Honeypot Fingerprinting** — Behavioural Cowrie detection using garbage-credential probing to avoid deception infrastructure before committing to a target.
- **SSH Pivoting & Credential Reuse** — Multi-hop tunnelling through an Industrial DMZ Historian into a restricted OT zone, with automatic private key theft to achieve passwordless lateral movement.
- **CIP/EtherNet-IP Protocol Abuse** — Native `pycomm3` LogixDriver sessions proxied over an SSH tunnel to enumerate, read, and write Allen-Bradley PLC data tables.
- **HMI Stealth Mode** — Asynchronous, jitter-driven tag freezing that exploits the PLC scan cycle to mask operator-visible process values during concurrent tag manipulation.
- **Defense Validation** — Jump-host access to the OT zone's Suricata IDS to validate Layer-1 CIP write detection and alert generation.
All phase results are logged to a structured JSON report at `/tmp/incs4810_report_<timestamp>.json`.
 
---
 
## Target Topology
 
The framework targets a three-tier ISA/IEC 62443-aligned lab architecture:
 
```
[ ATTACKER ]
  Kali Linux
  wlan0 (monitor/managed)
       |
       |  802.11 WPA2 Enterprise
       |  SSID: HemoLock
       |
  [ PERIMETER ]
  FortiGate Firewall / AP
       |
       |  10.10.10.0/24  (Industrial DMZ)
       |
  ┌────┴──────────────────────────────────┐
  │            IDMZ Segment               │
  │                                       │
  │  10.10.10.20  — Historian Server      │  ← SSH target (Phase 3)
  │  10.10.10.50  — Cowrie Honeypot       │  ← Fingerprinted and avoided (Phase 2)
  └────┬──────────────────────────────────┘
       |
       |  FortiGate OT Firewall
       |  10.20.20.0/24  (Restricted OT Zone)
       |
  ┌────┴──────────────────────────────────┐
  │           OT Zone Segment             │
  │                                       │
  │  10.20.20.5   — RPi5 IDS             │  ← Zeek / Suricata (SSH pivot target)
  │  10.20.20.111 — Allen-Bradley PLC    │  ← EtherNet/IP target (Phases 5 & 6)
  └───────────────────────────────────────┘
```
 
**Protocol fingerprints hunted in OT zone:**
 
| Port  | Protocol         | Vendor                         |
|-------|------------------|--------------------------------|
| 44818 | EtherNet/IP CIP  | Allen-Bradley / Rockwell       |
| 502   | Modbus TCP       | Generic PLC / RTU              |
| 102   | ISO-TSAP (S7)    | Siemens                        |
 
---
 
## Prerequisites & Setup
 
### Operating System
 
Kali Linux (2023.x or later) running on hardware with a monitor-mode capable wireless adapter.
 
### System Packages
 
```bash
sudo apt update
sudo apt install -y aircrack-ng besside-ng macchanger nmap sshpass
```
 
> `sshpass` is required for the SSH tunnel ProxyCommand used in Phases 5 and 6. The framework will fail to open CIP tunnels without it.
 
### Python Version
 
Python 3.11 or later (required for `str | None` union syntax and `list[PhaseResult]` generics).
 
```bash
python3 --version
```
 
### Python Libraries
 
The framework bootstraps its own dependencies at startup using `pip` into the active environment. You may also pre-install them:
 
```bash
pip install rich paramiko pycomm3
```
 
| Library    | Role                                                                 |
|------------|----------------------------------------------------------------------|
| `rich`     | Terminal UI — progress bars, live tables, panels, styled output      |
| `paramiko` | SSH client — brute force, pivoting, remote command execution, key theft |
| `pycomm3`  | Rockwell CIP/EtherNet-IP driver — PLC enumeration and tag writes     |
 
### Wordlist
 
The framework defaults to `/usr/share/wordlists/rockyou.txt`. On stock Kali this file ships gzipped; the framework auto-extracts it. To manually prepare:
 
```bash
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
```
 
---
 
## The Attack Chain — Phases 1–7
 
---
 
### Phase 1 — 802.11 Deauth & Offline Cracking
 
**Objective:** Crack the WPA2 pre-shared key for the target SSID and associate the attacker's `wlan0` to the target network.
 
The interface is placed into monitor mode via `macchanger` and `airmon-ng`. The framework executes an active scan to enumerate visible BSSIDs, then presents the operator with a live table of discovered APs filtered to the target SSID (`HemoLock`). Once a BSSID is selected, `besside-ng` is launched with the `-b` flag to restrict deauthentication bursts to the exact target AP — avoiding unintended disruption to adjacent stations.
 
The resulting WPA2 handshake capture (`wpa.cap`) is cracked offline using `aircrack-ng` against `rockyou.txt`, with results written to `cracked.txt`. On success, the framework restores managed mode, injects a NetworkManager WPA-PSK profile, and reconnects `wlan0` — acquiring a DHCP lease on the target's `10.10.10.x` segment autonomously.
 
```
besside-ng -b <BSSID> wlan0
aircrack-ng ./wpa.cap -w /usr/share/wordlists/rockyou.txt -l cracked.txt
```
 
---
 
### Phase 2 — Autonomous IDMZ Routing & Honeypot Fingerprinting
 
**Objective:** Discover reachable IDMZ subnets, inject kernel routes via the wireless gateway, and identify legitimate targets while actively avoiding Cowrie honeypot traps.
 
The framework interrogates the wireless interface's routing table to extract the default gateway, then executes a fast `nmap -T5 -PS` sweep across RFC-1918 private address space to fingerprint which subnets the gateway routes. Each discovered subnet receives a kernel route injected with `ip route add ... dev wlan0`, explicitly binding traffic to the wireless interface to prevent fallback through any VMware NAT or Ethernet adapter.
 
A targeted `nmap -T4 -sS -Pn` port sweep enumerates live hosts across discovered subnets on ports `22, 80, 443, 3000, 8086, 102, 44818`. Every host presenting port 22 is then subjected to **active Cowrie fingerprinting**: a paramiko connection attempt using randomised garbage credentials (`fake_hunter99` / `FakePassw0rd!@#88`). A legitimate SSH daemon raises `AuthenticationException`; Cowrie silently accepts any credential pair and grants a session. Hosts that accept the garbage login are flagged `[TRAP: Cowrie Honeypot]` and excluded from subsequent targeting, while real servers are promoted as Historian candidates.
 
---
 
### Phase 3 — Initial Access via SSH Dictionary Attack
 
**Objective:** Establish authenticated shell access to the Historian server (`10.10.10.20`) by brute-forcing SSH credentials.
 
The framework implements a native paramiko SSH brute forcer with intelligent error handling — distinguishing between clean `AuthenticationException` rejections, `SSHException` rate-limit signals (which trigger a 1-second backoff and retry on the same password), and network-level timeouts (which abort after three consecutive failures to avoid burning the connection).
 
A priority candidate list (`""`, `admin`, reversed username, `admin123`, `password`) is prepended to the full `rockyou.txt` wordlist before iteration, maximising hit probability on weak default credentials. A live `rich` progress bar tracks attempt count, elapsed time, and the current password being tested. On success, the recovered credential is persisted into `CFG["historian"]` and reused by all subsequent phases without re-prompting.
 
---
 
### Phase 4 — SSH Pivoting & OT Zone Reconnaissance
 
**Objective:** Land on the Historian, steal any available SSH private keys, tunnel into the IDS inside the OT zone, and sweep the `10.20.20.x` segment for industrial device fingerprints.
 
The framework opens a paramiko session to the Historian and immediately hunts `~/.ssh/` for RSA and Ed25519 private keys. If a PEM block is found, it is parsed in-memory via `paramiko.RSAKey.from_private_key()` / `paramiko.Ed25519Key.from_private_key()` and stored as a live `PKey` object — a stolen credential that will authenticate the pivot to the IDS without ever requiring a password.
 
Using paramiko's `Transport.open_channel("direct-tcpip")`, the framework constructs an in-process SSH hop from the attacker → Historian → IDS (`10.20.20.5`). The stolen key is tried against a candidate list of usernames before falling back to a password list. On successful hop, the framework runs a concurrent bash port sweep from the IDS (source IP `10.20.20.5`) across the full `10.20.20.1–254` range on ports `44818`, `502`, and `102`, inferring PLC vendor from the responding port. The confirmed PLC IP and type are auto-corrected in `CFG["plc"]` for downstream phases.
 
Anti-forensic cleanup (`cat /dev/null > ~/.bash_history` and `truncate /var/log/auth.log`) is executed on both the Historian and IDS before disconnecting.
 
---
 
### Phase 5 — CIP Memory Map Enumeration
 
**Objective:** Dump the Allen-Bradley PLC's internal data table over an SSH-tunnelled CIP connection and enumerate all user-defined tags with live values.
 
The framework spawns a native `ssh -L 44818:PLC:44818` process using a double-hop ProxyCommand — first through the Historian (via `sshpass`), then authenticating to the IDS using either the stolen private key or a password. This binds `localhost:44818` to the PLC's EtherNet/IP port without any direct attacker-to-OT-zone routing.
 
A `pycomm3.LogixDriver` session is opened over the local tunnel endpoint, attempting CIP slot paths `["", "/0", "/1", "/2", "/3"]` until a successful connection is established. The driver calls `get_tag_list()` to retrieve the PLC's full data table, filtering out system noise (`__`, `Program:`, `Routine:`, `Task:`, `Trend:` prefixes) to surface only user-defined tags. Each tag is then polled with `plc_conn.read()` to retrieve its live value, and the full memory map is presented in a rich table with tag name, data type, current value, and any access denial indicators.
 
---
 
### Phase 6 — Interactive CIP Attack Console
 
**Objective:** Conduct live, operator-controlled tag writes against the PLC, with optional HMI Stealth Mode to mask the attack from process operators.
 
Phase 6 reuses the same double-hop `ssh -L` tunnel infrastructure as Phase 5, maintaining the `pycomm3` LogixDriver connection open across the entire interactive session. A dynamically rendered tag table is presented, and the operator selects both a target tag and an injection value for each write cycle.
 
**HMI Stealth Mode** is the centrepiece capability of this phase. When enabled, the operator selects a separate "decoy" tag to freeze at a safe, operator-plausible value. A background daemon thread writes the freeze value to that tag at a randomised interval of **3–8 ms** — a jitter window calculated to interleave with the PLC's scan cycle and prevent the HMI display from reflecting the true process state. The PLC's program logic sees the actual manipulated value; the operator console sees only the frozen decoy. The freeze thread serialises all writes through a `threading.Lock()` shared with the main injection loop to prevent concurrent CIP session corruption.
 
**Relay Chatter / Denial-of-Control** mode drives the attack tag into continuous 50 ms write bursts using a tight `while True` loop, overwhelming the tag's update queue to prevent legitimate SCADA writes from taking effect. This constitutes a denial-of-control condition against the process. A raw CIP Assembly Object fallback — using `generic_message()` with service code `0x10` (Set Attribute Single) against Class `0x04` (Assembly) instances — is automatically attempted if no named tag write succeeds.
 
---
 
### Phase 7 — Defense Validation
 
**Objective:** Reconnect through the Historian jump host to the OT zone's Suricata IDS and verify that Layer-1 CIP write activity was detected and alerted on.
 
The framework opens a fresh double-hop SSH session (Historian → IDS) using the credentials established in Phase 4, then executes:
 
```bash
tail -50 /var/log/suricata/fast.log | grep -i 'cip\|write\|plc'
```
 
Any matching Suricata alert entries are printed to the console and flagged as confirmation that the IDS successfully detected the EtherNet/IP CIP write traffic generated during Phase 6. A clean (empty) log indicates a detection gap in the deployed ruleset and is reported separately. Anti-forensic cleanup runs on both hop nodes before the session closes.
 
This phase closes the red team loop — demonstrating not only the ability to compromise the OT zone and manipulate live PLC state, but also validating whether the blue team's detection instrumentation is capable of observing the attack.
 
---
 
## Usage
 
### Full Automated Chain (no per-phase confirmation prompts)
 
```bash
sudo python3 redteam_chain.py --auto
```
 
### Interactive Chain (prompts before each phase)
 
```bash
sudo python3 redteam_chain.py
```
 
### Run Specific Phases Only
 
```bash
# Run only IDMZ recon, SSH brute force, and pivot
sudo python3 redteam_chain.py --phases 2 3 4
 
# Run CIP enumeration and attack console only
sudo python3 redteam_chain.py --phases 5 6
 
# Run defense validation only
sudo python3 redteam_chain.py --phases 7
```
 
### On Phase Failure
 
When running in interactive mode (without `--auto`), a failed phase presents three operator choices:
 
```
r = retry   |   c = continue to next phase   |   q = quit
```
 
### JSON Report Output
 
Upon completion, a full structured report is written to:
 
```
/tmp/incs4810_report_YYYYMMDD_HHMMSS.json
```
 
The report contains per-phase status (`success` / `failed` / `skipped`), findings, timestamps, and raw output — suitable for inclusion in a lab assessment or post-engagement debrief.
 
---
 
## Lab Configuration
 
The static topology configuration is defined in the `CFG` dictionary at the top of the script. Update these values if your lab's IP assignments differ from the defaults:
 
```python
CFG = {
    "wifi":      { "interface": "wlan0", "ssid": "HemoLock", ... },
    "historian": { "ip": "10.10.10.20",  "port": 22, ... },
    "honeypot":  { "ip": "10.10.10.50" },
    "ids":       { "ip": "10.20.20.5",   "port": 22, ... },
    "plc":       { "ip": "10.20.20.111", "tag": "Dosage_Rate", ... },
}
```
 
Phase 4 will auto-correct the PLC IP if the OT sweep discovers a different address — no manual update required.
 
---
 
## References & Standards
 
- **ISA/IEC 62443** — Industrial Automation and Control Systems Security
- **MITRE ATT&CK for ICS** — [https://attack.mitre.org/matrices/ics/](https://attack.mitre.org/matrices/ics/)
- **Purdue Model / Industrial Network Segmentation** — IDMZ / OT Zone isolation
- **pycomm3 Documentation** — [https://github.com/ottowayi/pycomm3](https://github.com/ottowayi/pycomm3)
- **Aircrack-ng Suite** — [https://www.aircrack-ng.org/](https://www.aircrack-ng.org/)
---
 
*BCIT INCS 4810 — Industrial Cybersecurity | Instructor: Victor Mendez | ISA/IEC 62443*
