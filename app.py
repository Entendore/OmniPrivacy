#!/usr/bin/env python3
"""
PrivacyGuard — Cross-Platform Privacy Toolkit v1.2.0
=====================================================
Install:  pip install PySide6 cryptography psutil Pillow
Run:      python privacyguard.py
"""

import sys, os, random, string, secrets, json, base64, hashlib, math
import platform, time, socket, subprocess, struct, re
from pathlib import Path
from datetime import datetime
from collections import OrderedDict

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QTextEdit, QFileDialog,
    QComboBox, QCheckBox, QSlider, QSpinBox, QProgressBar,
    QFrame, QStackedWidget, QGroupBox, QMessageBox, QListWidget,
    QListWidgetItem, QGridLayout, QScrollArea, QSizePolicy,
    QStatusBar, QTableWidget, QTableWidgetItem, QHeaderView,
    QSplitter, QTabWidget, QAbstractItemView
)
from PySide6.QtCore import Qt, QThread, Signal, QSize, QRectF, QTimer
from PySide6.QtGui import (
    QFont, QColor, QPixmap, QPainter, QLinearGradient, QBrush, QPen,
    QClipboard, QPalette, QIcon
)

# Optional Dependencies
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    HAS_CRYPTO = True
except ImportError: HAS_CRYPTO = False

try:
    import psutil
    HAS_PSUTIL = True
except ImportError: HAS_PSUTIL = False

try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    HAS_PIL = True
except ImportError: HAS_PIL = False

# ═══════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════

APP_NAME   = "PrivacyGuard"
APP_VER    = "1.2.0"
C_BG       = "#0d1117"
C_SURFACE  = "#161b22"
C_CARD     = "#21262d"
C_BORDER   = "#30363d"
C_ACCENT   = "#58a6ff"
C_ACCENT2  = "#79b8ff"
C_TEXT     = "#c9d1d9"
C_TEXT2    = "#8b949e"
C_SUCCESS  = "#3fb950"
C_WARN     = "#d29922"
C_ERROR    = "#f85149"
C_PURPLE   = "#bc8cff"

SIDEBAR_PAGES = [
    ("⬡", "Dashboard"),
    ("⇌", "Proxy Manager"),
    ("◎", "Network Monitor"),
    ("🖼", "EXIF Scrubber"),
    ("🔐", "File Encryptor"),
    ("✂", "File Shredder"),
    ("⚙", "Password Gen"),
    ("࿇", "Vault"),
    ("◎", "Privacy Scan"),
    ("⎘", "Clipboard"),
]

# ═══════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════

def app_data_dir():
    s = platform.system()
    if s == "Windows": base = Path(os.environ.get("APPDATA", Path.home()))
    elif s == "Darwin": base = Path.home() / "Library" / "Application Support"
    else: base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    d = base / APP_NAME; d.mkdir(parents=True, exist_ok=True); return d

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480_000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_str(data: str, password: str) -> str:
    salt = os.urandom(16); key = derive_key(password, salt)
    return base64.urlsafe_b64encode(salt + Fernet(key).encrypt(data.encode())).decode()

def decrypt_str(token: str, password: str) -> str:
    raw = base64.urlsafe_b64decode(token.encode()); salt, enc = raw[:16], raw[16:]
    return Fernet(derive_key(password, salt)).decrypt(enc).decode()

def encrypt_bytes(data: bytes, password: str) -> bytes:
    salt = os.urandom(16); key = derive_key(password, salt)
    return salt + Fernet(key).encrypt(data)

def decrypt_bytes(token: bytes, password: str) -> bytes:
    salt, enc = token[:16], token[16:]
    return Fernet(derive_key(password, salt)).decrypt(enc)

def calc_strength(pw):
    if not pw: return 0, "None", C_ERROR
    pool = sum([26 if any(c.islower() for c in pw) else 0, 26 if any(c.isupper() for c in pw) else 0,
                10 if any(c.isdigit() for c in pw) else 0, 32 if any(c in string.punctuation for c in pw) else 0])
    if pool == 0: return 0, "None", C_ERROR
    ent = len(pw) * math.log2(pool)
    if ent < 28: return ent, "Very Weak", C_ERROR
    elif ent < 36: return ent, "Weak", "#ff7b72"
    elif ent < 60: return ent, "Fair", C_WARN
    elif ent < 80: return ent, "Strong", C_SUCCESS
    else: return ent, "Very Strong", "#56d364"

def make_card(parent=None):
    f = QFrame(parent); f.setObjectName("card"); return f

def styled_heading(text, size=20):
    lbl = QLabel(text); lbl.setStyleSheet(f"font-size:{size}px; font-weight:700; color:{C_TEXT};"); return lbl

def styled_subheading(text):
    lbl = QLabel(text); lbl.setStyleSheet(f"font-size:13px; color:{C_TEXT2};"); lbl.setWordWrap(True); return lbl

# ═══════════════════════════════════════════════════════════
# System Proxy Manager
# ═══════════════════════════════════════════════════════════

class SystemProxyManager:
    @staticmethod
    def get_network_services_macos():
        try:
            r = subprocess.run(["networksetup", "-listallnetworkservices"], capture_output=True, text=True, timeout=5)
            return [l.strip() for l in r.stdout.strip().split("\n")[1:] if l.strip() and "An asterisk" not in l]
        except: return ["Wi-Fi", "Ethernet"]

    @staticmethod
    def set_proxy(host, port, proxy_type="http", username="", password=""):
        s = platform.system()
        try:
            if s == "Windows": return SystemProxyManager._set_windows(host, port, proxy_type, username, password)
            elif s == "Darwin": return SystemProxyManager._set_macos(host, port, proxy_type, username, password)
            elif s == "Linux": return SystemProxyManager._set_linux(host, port, proxy_type, username, password)
            return False, "Unsupported OS"
        except Exception as e: return False, str(e)

    @staticmethod
    def disable_proxy():
        s = platform.system()
        try:
            if s == "Windows": return SystemProxyManager._disable_windows()
            elif s == "Darwin": return SystemProxyManager._disable_macos()
            elif s == "Linux": return SystemProxyManager._disable_linux()
            return False, "Unsupported OS"
        except Exception as e: return False, str(e)

    @staticmethod
    def get_current():
        s = platform.system()
        try:
            if s == "Windows": return SystemProxyManager._get_windows()
            elif s == "Darwin": return SystemProxyManager._get_macos()
            elif s == "Linux": return SystemProxyManager._get_linux()
        except: pass
        return {"enabled": False, "server": ""}

    # Windows
    @staticmethod
    def _set_windows(h, p, pt, u, pw):
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        server = f"{h}:{p}"
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"socks={server}" if pt in ("socks4","socks5") else server)
        winreg.CloseKey(key)
        try:
            from ctypes import windll
            windll.wininet.InternetSetOptionW(0, 39, 0, 0); windll.wininet.InternetSetOptionW(0, 37, 0, 0)
        except: pass
        return True, f"System proxy set to {h}:{p}"

    @staticmethod
    def _disable_windows():
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0); winreg.CloseKey(key)
        try:
            from ctypes import windll; windll.wininet.InternetSetOptionW(0, 39, 0, 0); windll.wininet.InternetSetOptionW(0, 37, 0, 0)
        except: pass
        return True, "System proxy disabled"

    @staticmethod
    def _get_windows():
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
            enabled, _ = winreg.QueryValueEx(key, "ProxyEnable"); server, _ = winreg.QueryValueEx(key, "ProxyServer"); winreg.CloseKey(key)
            return {"enabled": bool(enabled), "server": server or ""}
        except: return {"enabled": False, "server": ""}

    # macOS
    @staticmethod
    def _set_macos(h, p, pt, u, pw):
        svcs = SystemProxyManager.get_network_services_macos()
        for svc in svcs:
            if pt in ("http", "https"):
                subprocess.run(["networksetup", "-setwebproxy", svc, h, str(p), u, pw], timeout=5)
                subprocess.run(["networksetup", "-setsecurewebproxy", svc, h, str(p), u, pw], timeout=5)
                subprocess.run(["networksetup", "-setwebproxystate", svc, "on"], timeout=5)
                subprocess.run(["networksetup", "-setsecurewebproxystate", svc, "on"], timeout=5)
            elif pt in ("socks4", "socks5"):
                subprocess.run(["networksetup", "-setsocksfirewallproxy", svc, h, str(p), u, pw], timeout=5)
                subprocess.run(["networksetup", "-setsocksfirewallproxystate", svc, "on"], timeout=5)
        return True, f"Proxy set for {len(svcs)} service(s)"

    @staticmethod
    def _disable_macos():
        svcs = SystemProxyManager.get_network_services_macos()
        for svc in svcs:
            subprocess.run(["networksetup", "-setwebproxystate", svc, "off"], timeout=5)
            subprocess.run(["networksetup", "-setsecurewebproxystate", svc, "off"], timeout=5)
            subprocess.run(["networksetup", "-setsocksfirewallproxystate", svc, "off"], timeout=5)
        return True, "Proxy disabled"

    @staticmethod
    def _get_macos():
        for svc in SystemProxyManager.get_network_services_macos():
            try:
                r = subprocess.run(["networksetup", "-getwebproxy", svc], capture_output=True, text=True, timeout=5)
                if "Enabled: Yes" in r.stdout:
                    lines = r.stdout.strip().split("\n")
                    return {"enabled": True, "server": f"{lines[0].split(':')[1].strip()}:{lines[1].split(':')[1].strip()}"}
            except: pass
        return {"enabled": False, "server": ""}

    # Linux
    @staticmethod
    def _set_linux(h, p, pt, u, pw):
        try:
            subprocess.run(["gsettings", "set", "org.gnome.system.proxy", "mode", "manual"], timeout=5)
            if pt in ("http", "https"):
                subprocess.run(["gsettings", "set", "org.gnome.system.proxy.http", "host", h], timeout=5)
                subprocess.run(["gsettings", "set", "org.gnome.system.proxy.http", "port", str(p)], timeout=5)
            elif pt in ("socks4", "socks5"):
                subprocess.run(["gsettings", "set", "org.gnome.system.proxy.socks", "host", h], timeout=5)
                subprocess.run(["gsettings", "set", "org.gnome.system.proxy.socks", "port", str(p)], timeout=5)
            return True, f"GNOME proxy set to {h}:{p}"
        except: return False, "Set env vars manually:\nexport http_proxy=http://{}:{}".format(h, p)

    @staticmethod
    def _disable_linux():
        try: subprocess.run(["gsettings", "set", "org.gnome.system.proxy", "mode", "none"], timeout=5); return True, "Proxy disabled"
        except: return False, "Could not disable proxy automatically."

    @staticmethod
    def _get_linux():
        try:
            r = subprocess.run(["gsettings", "get", "org.gnome.system.proxy", "mode"], capture_output=True, text=True, timeout=5)
            if "manual" in r.stdout:
                r2 = subprocess.run(["gsettings", "get", "org.gnome.system.proxy.http", "host"], capture_output=True, text=True, timeout=5)
                r3 = subprocess.run(["gsettings", "get", "org.gnome.system.proxy.http", "port"], capture_output=True, text=True, timeout=5)
                return {"enabled": True, "server": f"{r2.stdout.strip().strip("'')}:{r3.stdout.strip()}"}
        except: pass
        hp = os.environ.get("http_proxy", os.environ.get("HTTP_PROXY", ""))
        return {"enabled": bool(hp), "server": hp} if hp else {"enabled": False, "server": ""}


# ═══════════════════════════════════════════════════════════
# Worker Threads
# ═══════════════════════════════════════════════════════════

class ProxyTestWorker(QThread):
    result = Signal(dict)
    def __init__(self, host, port, ptype, username="", password=""):
        super().__init__(); self.host, self.port, self.ptype = host, int(port), ptype
        self.username, self.password = username, password

    def run(self):
        r = {"reachable": False, "proxy_ip": None, "direct_ip": None, "latency": 0, "error": None, "anon_level": "Unknown"}
        start = time.time()
        try:
            sock = socket.create_connection((self.host, self.port), timeout=8); sock.close()
            r["reachable"] = True; r["latency"] = int((time.time() - start) * 1000)
        except Exception as e: r["error"] = f"Connection failed: {e}"; self.result.emit(r); return

        try:
            import urllib.request
            r["direct_ip"] = urllib.request.urlopen("https://api.ipify.org", timeout=8).read().decode().strip()
        except: r["direct_ip"] = "Unknown"

        try:
            import urllib.request
            scheme = {"http":"http","https":"https","socks4":"socks4","socks5":"socks5"}.get(self.ptype,"http")
            proxy_url = f"{scheme}://"
            if self.username and self.password: proxy_url += f"{self.username}:{self.password}@"
            proxy_url += f"{self.host}:{self.port}"
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({'http': proxy_url, 'https': proxy_url}))
            r["proxy_ip"] = opener.open("https://api.ipify.org", timeout=12).read().decode().strip()
            if r["proxy_ip"] and r["direct_ip"] and r["proxy_ip"] != r["direct_ip"]:
                try:
                    headers = json.loads(opener.open("https://httpbin.org/headers", timeout=10).read())
                    r["anon_level"] = "Transparent" if headers.get("headers",{}).get("X-Forwarded-For") else "Anonymous"
                except: r["anon_level"] = "Likely Anonymous"
            elif r["proxy_ip"]: r["anon_level"] = "Not Anonymous (IP leaked)"
        except Exception as e: r["error"] = f"Proxy test failed: {e}"; r["proxy_ip"] = "Error"
        self.result.emit(r)

class IpCheckWorker(QThread):
    result = Signal(dict)
    def run(self):
        r = {"ip": None, "country": None, "city": None, "isp": None, "error": None}
        for url in ["https://ipapi.co/json/", "https://ipwho.is/"]:
            try:
                import urllib.request; data = json.loads(urllib.request.urlopen(url, timeout=10).read().decode())
                r["ip"] = data.get("ip") or data.get("query",""); r["country"] = data.get("country_name") or data.get("country","")
                r["city"] = data.get("city",""); r["isp"] = data.get("org") or data.get("connection",{}).get("org",""); break
            except: continue
        if not r["ip"]:
            try: r["ip"] = __import__("urllib.request", fromlist=["urlopen"]).urlopen("https://api.ipify.org", timeout=8).read().decode().strip()
            except Exception as e: r["error"] = str(e)
        self.result.emit(r)

class DnsLeakWorker(QThread):
    result = Signal(dict)
    def run(self):
        r = {"dns_servers": [], "leak": False, "error": None}; s = platform.system()
        try:
            cmd = ["ipconfig", "/all"] if s == "Windows" else (["cat", "/etc/resolv.conf"] if s == "Linux" else ["scutil", "--dns"])
            output = subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
            if s == "Windows":
                for l in output.split("\n"):
                    if "DNS Servers" in l:
                        ip = l.split(":")[-1].strip()
                        if ip and ip[0].isdigit(): r["dns_servers"].append(ip)
            elif s == "Linux":
                for l in output.split("\n"):
                    if l.startswith("nameserver"): r["dns_servers"].append(l.split()[1].strip())
            else:
                for l in output.split("\n"):
                    m = re.search(r'(\d+\.\d+\.\d+\.\d+)', l)
                    if "nameserver" in l and m: r["dns_servers"].append(m.group(1))
            r["dns_servers"] = list(OrderedDict.fromkeys(r["dns_servers"]))
            privacy_dns = {"1.1.1.1","1.0.0.1","8.8.8.8","8.8.4.4","9.9.9.9","149.112.112.112"}
            public = [d for d in r["dns_servers"] if not any(d.startswith(p) for p in ("192.168.","10.","172.16.","127.","0."))]
            if public and not any(d in privacy_dns for d in public): r["leak"] = True
        except Exception as e: r["error"] = str(e)
        self.result.emit(r)

class ConnectionWorker(QThread):
    result = Signal(list)
    def run(self):
        conns = []
        if HAS_PSUTIL:
            try:
                for c in psutil.net_connections(kind='inet'):
                    pname = ""
                    try: pname = psutil.Process(c.pid).name() if c.pid else ""
                    except: pass
                    conns.append({"proto":"TCP" if c.type==socket.SOCK_STREAM else "UDP",
                        "local":f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                        "remote":f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                        "state":c.status or "","pid":c.pid or 0,"process":pname})
            except: pass
        else:
            try:
                cmd = ["netstat", "-ano"] if platform.system()=="Windows" else ["netstat", "-tunap"]
                for l in subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout.split("\n"):
                    l=l.strip()
                    if l and (l.startswith("TCP") or l.startswith("UDP")):
                        p=l.split()
                        if len(p)>=4: conns.append({"proto":p[0].upper(),"local":p[1],"remote":p[2],"state":p[3] if p[0]=="TCP" else "","pid":int(p[-1]) if p[-1].isdigit() else 0,"process":""})
            except: pass
        self.result.emit(conns)

class ShredderWorker(QThread):
    progress = Signal(int, int); file_progress = Signal(str); done = Signal(bool, str)
    def __init__(self, files, passes, method):
        super().__init__(); self.files, self.passes, self.method = files, passes, method; self._cancel = False
    def cancel(self): self._cancel = True
    def run(self):
        total = len(self.files)
        for i, fp in enumerate(self.files):
            if self._cancel: self.done.emit(False, "Cancelled."); return
            self.file_progress.emit(os.path.basename(fp))
            try: self._shred(fp)
            except Exception as e: self.done.emit(False, f"Error: {e}"); return
            self.progress.emit(i+1, total)
        self.done.emit(True, f"Shredded {total} file(s) successfully.")
    def _shred(self, filepath):
        p = Path(filepath); sz = p.stat().st_size
        for _ in range(self.passes):
            if self._cancel: return
            with open(filepath, "r+b") as f:
                rem = sz
                while rem > 0:
                    ch = min(rem, 1<<20)
                    d = os.urandom(ch) if self.method in ("Random","DoD 5220") else (b"\x00"*ch if self.method=="Zeros" else b"\xff"*ch)
                    f.write(d); rem -= ch
                f.flush(); os.fsync(f.fileno())
        with open(filepath, "r+b") as f: f.truncate(0); f.flush(); os.fsync(f.fileno())
        try: new = p.parent / secrets.token_hex(8); p.rename(new); new.unlink()
        except: p.unlink()

class ScannerWorker(QThread):
    progress = Signal(int, int); result = Signal(dict); done = Signal(list)
    def __init__(self): super().__init__(); self._cancel = False
    def cancel(self): self._cancel = True
    def run(self):
        results = []; checks = [self._ssh, self._shell_hist, self._downloads, self._temp, self._browsers, self._env, self._hosts, self._dns_check]
        total = len(checks)
        for i, chk in enumerate(checks):
            if self._cancel: return
            self.progress.emit(i+1, total)
            try:
                r = chk()
                if r: results.append(r); self.result.emit(r)
            except Exception as e: results.append(dict(name=chk.__name__, severity="info", message=str(e), fix="N/A"))
        self.done.emit(results)

    def _ssh(self):
        d = Path.home() / ".ssh"
        if not d.exists(): return dict(name="SSH Keys", severity="good", message="No .ssh directory.", fix="N/A")
        unenc = [k.name for k in d.glob("id_*") if k.is_file() and not k.name.endswith(".pub") and "ENCRYPTED" not in k.read_text()]
        return dict(name="SSH Keys", severity="warning", message=f"Unencrypted: {', '.join(unenc)}", fix="ssh-keygen -p -f <keyfile>") if unenc else dict(name="SSH Keys", severity="good", message="All keys encrypted.", fix="N/A")

    def _shell_hist(self):
        n = sum(len(Path(f).read_text().splitlines()) for f in [Path.home()/".bash_history", Path.home()/".zsh_history"] if Path(f).exists())
        return dict(name="Shell History", severity="info", message=f"{n} commands in history.", fix="history -c && history -w") if n else dict(name="Shell History", severity="good", message="No history found.", fix="N/A")

    def _downloads(self):
        dl = Path.home() / "Downloads"
        if not dl.exists(): return None
        sens = {".pdf",".doc",".docx",".xls",".xlsx",".key",".pem",".p12",".pfx",".ovpn",".zip",".7z",".rar"}
        cnt = sum(1 for f in dl.iterdir() if f.is_file() and f.suffix.lower() in sens)
        return dict(name="Downloads", severity="info", message=f"{cnt} potentially sensitive files.", fix="Review downloads.") if cnt else dict(name="Downloads", severity="good", message="Downloads look clean.", fix="N/A")

    def _temp(self):
        dirs = [Path(os.environ.get("TEMP",""))] if platform.system()=="Windows" else [Path("/tmp"), Path.home()/".cache"]
        total = sum(f.stat().st_size for d in dirs if d.exists() for f in d.rglob("*") if f.is_file())
        mb = total/(1<<20)
        return dict(name="Temp Files", severity="warning", message=f"Temp/cache uses {mb:.0f} MB.", fix="Run disk cleanup.") if mb > 100 else dict(name="Temp Files", severity="good", message=f"Temp/cache uses {mb:.1f} MB.", fix="N/A")

    def _browsers(self):
        h = Path.home(); s = platform.system(); found = []
        cp = Path(os.environ.get("LOCALAPPDATA",""))/"Google"/"Chrome"/"User Data" if s=="Windows" else (h/"Library"/"Application Support"/"Google"/"Chrome" if s=="Darwin" else h/".config"/"google-chrome")
        if cp.exists(): found.append("Chrome")
        fp = Path(os.environ.get("APPDATA",""))/"Mozilla"/"Firefox" if s=="Windows" else (h/"Library"/"Application Support"/"Firefox" if s=="Darwin" else h/".mozilla"/"firefox")
        if fp.exists(): found.append("Firefox")
        return dict(name="Browser Data", severity="info", message=f"Profiles: {', '.join(found)}", fix="Clear browser data.") if found else dict(name="Browser Data", severity="good", message="No major profiles.", fix="N/A")

    def _env(self):
        keys = [k for k in os.environ if any(w in k.upper() for w in ["PASSWORD","SECRET","TOKEN","API_KEY","CREDENTIAL"])]
        return dict(name="Env Variables", severity="warning", message=f"Suspicious: {', '.join(keys[:5])}", fix="Remove from profile.") if keys else dict(name="Env Variables", severity="good", message="No sensitive env vars.", fix="N/A")

    def _hosts(self):
        hp = Path("/etc/hosts") if platform.system()!="Windows" else Path(r"C:\Windows\System32\drivers\etc\hosts")
        if not hp.exists(): return None
        try:
            custom = [l.strip() for l in hp.read_text().splitlines() if l.strip() and not l.startswith("#") and "localhost" not in l.lower()]
            return dict(name="Hosts File", severity="info", message=f"{len(custom)} custom entries.", fix="Review for redirects.") if custom else dict(name="Hosts File", severity="good", message="Standard hosts file.", fix="N/A")
        except: return dict(name="Hosts File", severity="info", message="Cannot read.", fix="N/A")

    def _dns_check(self):
        privacy_dns = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112"}
        try:
            s = platform.system(); cmd = ["ipconfig", "/all"] if s=="Windows" else (["cat", "/etc/resolv.conf"] if s=="Linux" else ["scutil", "--dns"])
            output = subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
            if any(dns in output for dns in privacy_dns): return dict(name="DNS Privacy", severity="good", message="Using privacy DNS.", fix="N/A")
            return dict(name="DNS Privacy", severity="warning", message="Not using privacy DNS.", fix="Set DNS to 1.1.1.1 or 9.9.9.9")
        except: return None

class EncryptWorker(QThread):
    progress = Signal(int, int); status = Signal(str); done = Signal(bool, str)
    def __init__(self, files, password, shred_original):
        super().__init__(); self.files, self.password, self.shred_original = files, password, shred_original; self._cancel = False
    def cancel(self): self._cancel = True
    def run(self):
        total = len(self.files); success = 0
        for i, fpath in enumerate(self.files):
            if self._cancel: self.done.emit(False, "Cancelled."); return
            p = Path(fpath); self.status.emit(f"Encrypting: {p.name}...")
            try:
                enc_data = encrypt_bytes(p.read_bytes(), self.password)
                Path(str(p) + ".enc").write_bytes(enc_data)
                if self.shred_original:
                    sz = p.stat().st_size
                    with open(fpath, "r+b") as f: f.write(os.urandom(sz)); f.flush(); os.fsync(f.fileno())
                    p.unlink()
                success += 1
            except Exception as e: self.done.emit(False, f"Error on {p.name}: {e}"); return
            self.progress.emit(i+1, total)
        self.done.emit(True, f"Encrypted {success}/{total} files.")

class DecryptWorker(QThread):
    progress = Signal(int, int); status = Signal(str); done = Signal(bool, str)
    def __init__(self, files, password):
        super().__init__(); self.files, self.password = files, password; self._cancel = False
    def cancel(self): self._cancel = False
    def run(self):
        total = len(self.files); success = 0
        for i, fpath in enumerate(self.files):
            if self._cancel: self.done.emit(False, "Cancelled."); return
            p = Path(fpath); self.status.emit(f"Decrypting: {p.name}...")
            try:
                dec_data = decrypt_bytes(p.read_bytes(), self.password)
                Path(str(p)[:-4]).write_bytes(dec_data); success += 1
            except Exception as e: self.done.emit(False, f"Error on {p.name} (Wrong password?): {e}"); return
            self.progress.emit(i+1, total)
        self.done.emit(True, f"Decrypted {success}/{total} files.")


# ═══════════════════════════════════════════════════════════
# Page Widgets
# ═══════════════════════════════════════════════════════════

class DashboardPage(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self); lay.setSpacing(16); lay.setContentsMargins(24,24,24,24)
        lay.addWidget(styled_heading("Dashboard"))
        lay.addWidget(styled_subheading("Welcome to PrivacyGuard — your cross-platform privacy toolkit."))
        grid = QGridLayout(); grid.setSpacing(12)
        cur = SystemProxyManager.get_current()
        cards = [
            ("🖥", "Platform", f"{platform.system()} {platform.release()}"),
            ("🌐", "System Proxy", f"{'ON → ' + cur.get('server','') if cur.get('enabled') else 'OFF'}"),
            ("🔐", "Encryption", "Available ✓" if HAS_CRYPTO else "Not installed ✗"),
            ("📊", "Network Lib", "psutil ✓" if HAS_PSUTIL else "psutil ✗"),
            ("🖼", "Image Lib", "Pillow ✓" if HAS_PIL else "Pillow ✗"),
            ("👤", "User", os.environ.get("USER", os.environ.get("USERNAME","—"))),
        ]
        for i,(icon,title,val) in enumerate(cards):
            c = make_card(); cl = QVBoxLayout(c)
            il = QLabel(icon); il.setStyleSheet("font-size:28px;"); tl = QLabel(title); tl.setStyleSheet(f"color:{C_TEXT2};font-size:12px;")
            vl = QLabel(val); vl.setStyleSheet(f"color:{C_TEXT};font-size:14px;font-weight:600;"); vl.setWordWrap(True)
            cl.addWidget(il); cl.addWidget(tl); cl.addWidget(vl); grid.addWidget(c, i//3, i%3)
        lay.addLayout(grid)
        qa = QLabel("Quick Actions"); qa.setStyleSheet(f"color:{C_TEXT2};font-size:13px;font-weight:600;"); lay.addWidget(qa)
        btn_row = QHBoxLayout()
        for label, slot in [("🧹 Clear Clipboard", self._clear_clip), ("🔑 Generate Password", self._gen_pw), ("🔍 Run Privacy Scan", self._scan)]:
            b = QPushButton(label); b.setObjectName("accentBtn"); b.setCursor(Qt.PointingHandCursor); b.clicked.connect(slot); btn_row.addWidget(b)
        lay.addLayout(btn_row); lay.addStretch()
    def _clear_clip(self): QApplication.clipboard().clear(); QMessageBox.information(self, "Done", "Clipboard cleared.")
    def _gen_pw(self):
        QApplication.clipboard().setText(''.join(secrets.choice(string.ascii_letters+string.digits+string.punctuation) for _ in range(20)))
        QMessageBox.information(self, "Generated", "20-char password copied.")
    def _scan(self):
        p = self.window()
        if hasattr(p, 'sidebar'): p.sidebar.btns[8].click()


class ProxyManagerPage(QWidget):
    def __init__(self):
        super().__init__()
        self.profiles = []; self.profiles_path = app_data_dir() / "proxy_profiles.json"
        self.test_worker = None; self._load_profiles()
        lay = QVBoxLayout(self); lay.setSpacing(10); lay.setContentsMargins(24,24,24,24)
        lay.addWidget(styled_heading("Proxy Manager"))
        lay.addWidget(styled_subheading("Configure proxies, set system-wide, test connectivity and anonymity."))
        splitter = QSplitter(Qt.Horizontal); splitter.setStyleSheet(f"QSplitter::handle{{background:{C_BORDER};}}")
        
        # Profiles
        left = make_card(); ll = QVBoxLayout(left); ll.addWidget(QLabel("Proxy Profiles"))
        self.profile_list = QListWidget(); self.profile_list.setMinimumWidth(200)
        self.profile_list.currentRowChanged.connect(self._select_profile); ll.addWidget(self.profile_list)
        pb = QHBoxLayout()
        for label, slot in [("➕", self._add_profile), ("🗑", self._del_profile), ("💾", self._save_profiles_btn)]:
            b = QPushButton(label); b.setFixedWidth(40); b.setCursor(Qt.PointingHandCursor); b.clicked.connect(slot); pb.addWidget(b)
        pb.addStretch(); ll.addLayout(pb)
        io_row = QHBoxLayout()
        imp_btn = QPushButton("Import"); imp_btn.setCursor(Qt.PointingHandCursor); imp_btn.clicked.connect(self._import_profiles); io_row.addWidget(imp_btn)
        exp_btn = QPushButton("Export"); exp_btn.setCursor(Qt.PointingHandCursor); exp_btn.clicked.connect(self._export_profiles); io_row.addWidget(exp_btn)
        ll.addLayout(io_row); splitter.addWidget(left)

        # Editor
        right_w = QWidget(); rl = QVBoxLayout(right_w); rl.setSpacing(10)
        editor_card = make_card(); el = QVBoxLayout(editor_card); el.addWidget(QLabel("Profile Configuration"))
        form = QGridLayout(); form.setSpacing(8)
        self.name_edit = QLineEdit(); self.name_edit.setPlaceholderText("My Proxy"); form.addWidget(QLabel("Name:"), 0, 0); form.addWidget(self.name_edit, 0, 1)
        self.type_cb = QComboBox(); self.type_cb.addItems(["http", "https", "socks4", "socks5"]); form.addWidget(QLabel("Type:"), 1, 0); form.addWidget(self.type_cb, 1, 1)
        self.host_edit = QLineEdit(); self.host_edit.setPlaceholderText("proxy.example.com"); form.addWidget(QLabel("Host:"), 2, 0); form.addWidget(self.host_edit, 2, 1)
        self.port_spin = QSpinBox(); self.port_spin.setRange(1, 65535); self.port_spin.setValue(1080); form.addWidget(QLabel("Port:"), 3, 0); form.addWidget(self.port_spin, 3, 1)
        self.user_edit = QLineEdit(); self.user_edit.setPlaceholderText("(optional)"); form.addWidget(QLabel("Username:"), 4, 0); form.addWidget(self.user_edit, 4, 1)
        self.pass_edit = QLineEdit(); self.pass_edit.setEchoMode(QLineEdit.Password); self.pass_edit.setPlaceholderText("(optional)"); form.addWidget(QLabel("Password:"), 5, 0); form.addWidget(self.pass_edit, 5, 1)
        el.addLayout(form)
        save_btn = QPushButton("💾  Save Profile"); save_btn.setObjectName("accentBtn"); save_btn.setCursor(Qt.PointingHandCursor); save_btn.clicked.connect(self._save_current_profile); el.addWidget(save_btn)
        rl.addWidget(editor_card)

        actions_card = make_card(); al = QVBoxLayout(actions_card)
        sys_row = QHBoxLayout()
        sys_set = QPushButton("🌐  Set System Proxy"); sys_set.setObjectName("accentBtn"); sys_set.setCursor(Qt.PointingHandCursor); sys_set.clicked.connect(self._set_system_proxy); sys_row.addWidget(sys_set)
        sys_disable = QPushButton("🚫  Disable System Proxy"); sys_disable.setCursor(Qt.PointingHandCursor); sys_disable.clicked.connect(self._disable_system_proxy); sys_row.addWidget(sys_disable)
        al.addLayout(sys_row)
        self.sys_proxy_lbl = QLabel(""); self.sys_proxy_lbl.setStyleSheet(f"color:{C_TEXT2};font-size:11px;"); al.addWidget(self.sys_proxy_lbl)
        test_row = QHBoxLayout()
        test_btn = QPushButton("🔍  Test Proxy"); test_btn.setObjectName("accentBtn"); test_btn.setCursor(Qt.PointingHandCursor); test_btn.clicked.connect(self._test_proxy); test_row.addWidget(test_btn)
        tor_btn = QPushButton("🧅  Check Tor"); tor_btn.setCursor(Qt.PointingHandCursor); tor_btn.clicked.connect(self._check_tor); test_row.addWidget(tor_btn)
        al.addLayout(test_row)
        self.test_results = QTextEdit(); self.test_results.setReadOnly(True); self.test_results.setMaximumHeight(130)
        self.test_results.setStyleSheet(f"background:{C_BG};color:{C_TEXT};border:1px solid {C_BORDER};border-radius:6px;font-family:monospace;font-size:12px;")
        al.addWidget(self.test_results); rl.addWidget(actions_card); rl.addStretch()
        splitter.addWidget(right_w); splitter.setSizes([220, 500]); lay.addWidget(splitter, 1)
        self._refresh_profiles(); self._update_sys_proxy_lbl()

    def _load_profiles(self):
        try:
            if self.profiles_path.exists(): self.profiles = json.loads(self.profiles_path.read_text())
        except: self.profiles = []
    def _save_profiles(self):
        try: self.profiles_path.write_text(json.dumps(self.profiles, indent=2))
        except: pass
    def _save_profiles_btn(self): self._save_profiles(); QMessageBox.information(self, "Saved", "Profiles saved.")
    def _refresh_profiles(self):
        self.profile_list.clear()
        for p in self.profiles: self.profile_list.addItem(f'{ {"http":"🌐","https":"🔒","socks4":"🧦","socks5":"🧦"}.get(p.get("type","http"),"🌐") } {p.get("name","Unnamed")}')
    def _select_profile(self, row):
        if 0 <= row < len(self.profiles):
            p = self.profiles[row]; self.name_edit.setText(p.get("name",""))
            idx = self.type_cb.findText(p.get("type","http"))
            if idx >= 0: self.type_cb.setCurrentIndex(idx)
            self.host_edit.setText(p.get("host","")); self.port_spin.setValue(p.get("port",1080))
            self.user_edit.setText(p.get("username","")); self.pass_edit.setText(p.get("password",""))
    def _add_profile(self): self.profiles.append(dict(name="New Proxy", type="http", host="", port=1080, username="", password="")); self._save_profiles(); self._refresh_profiles(); self.profile_list.setCurrentRow(len(self.profiles)-1)
    def _del_profile(self):
        row = self.profile_list.currentRow()
        if 0 <= row < len(self.profiles): self.profiles.pop(row); self._save_profiles(); self._refresh_profiles()
    def _save_current_profile(self):
        profile = dict(name=self.name_edit.text() or "Unnamed", type=self.type_cb.currentText(), host=self.host_edit.text(), port=self.port_spin.value(), username=self.user_edit.text(), password=self.pass_edit.text())
        row = self.profile_list.currentRow()
        if 0 <= row < len(self.profiles): self.profiles[row] = profile
        else: self.profiles.append(profile)
        self._save_profiles(); self._refresh_profiles()
    def _get_current_profile(self):
        row = self.profile_list.currentRow()
        return self.profiles[row] if 0 <= row < len(self.profiles) else None
    def _import_profiles(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import Profiles", "", "JSON (*.json)")
        if path:
            try: data = json.loads(Path(path).read_text()); self.profiles.extend(data); self._save_profiles(); self._refresh_profiles()
            except Exception as e: QMessageBox.critical(self, "Error", str(e))
    def _export_profiles(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export Profiles", "profiles.json", "JSON (*.json)")
        if path:
            try: Path(path).write_text(json.dumps(self.profiles, indent=2))
            except Exception as e: QMessageBox.critical(self, "Error", str(e))
    def _set_system_proxy(self):
        p = self._get_current_profile()
        if not p or not p.get("host"): QMessageBox.warning(self, "No Profile", "Select a profile with a host."); return
        ok, msg = SystemProxyManager.set_proxy(p["host"], p["port"], p.get("type","http"), p.get("username",""), p.get("password",""))
        (QMessageBox.information if ok else QMessageBox.critical)(self, "Success" if ok else "Failed", msg); self._update_sys_proxy_lbl()
    def _disable_system_proxy(self):
        ok, msg = SystemProxyManager.disable_proxy(); (QMessageBox.information if ok else QMessageBox.critical)(self, "Done" if ok else "Failed", msg); self._update_sys_proxy_lbl()
    def _update_sys_proxy_lbl(self):
        cur = SystemProxyManager.get_current()
        self.sys_proxy_lbl.setText(f"System proxy: {'ON → ' + cur.get('server','') if cur.get('enabled') else 'OFF'}")
        self.sys_proxy_lbl.setStyleSheet(f"color:{C_SUCCESS if cur.get('enabled') else C_TEXT2};font-size:11px;")
    def _test_proxy(self):
        p = self._get_current_profile()
        if not p or not p.get("host"): QMessageBox.warning(self, "No Profile", "Select a profile."); return
        self.test_results.setPlainText("Testing proxy connection...")
        self.test_worker = ProxyTestWorker(p["host"], p["port"], p.get("type","http"), p.get("username",""), p.get("password",""))
        self.test_worker.result.connect(self._on_test_result); self.test_worker.start()
    def _on_test_result(self, r):
        lines = []
        lines.append(f"✅ Reachable (latency: {r['latency']}ms)" if r["reachable"] else f"❌ Unreachable: {r.get('error','')}")
        if r.get("direct_ip"): lines.append(f"📡 Direct IP:  {r['direct_ip']}")
        if r.get("proxy_ip"): lines.append(f"📡 Proxy IP:   {r['proxy_ip']}")
        if r.get("anon_level"): lines.append(f"🔒 Anonymity:  {r['anon_level']}")
        self.test_results.setPlainText("\n".join(lines))
    def _check_tor(self):
        try: socket.create_connection(("127.0.0.1", 9050), timeout=3).close(); self.test_results.setPlainText("🧅 Tor detected on 127.0.0.1:9050\nSetup SOCKS5 proxy to 127.0.0.1:9050")
        except: self.test_results.setPlainText("❌ Tor not detected on port 9050.\nInstall Tor or start Tor Browser (port 9150).")


class NetworkMonitorPage(QWidget):
    def __init__(self):
        super().__init__()
        self.conn_worker = None; self.dns_worker = None; self.ip_worker = None
        self.refresh_timer = QTimer(); self.refresh_timer.setInterval(3000); self.refresh_timer.timeout.connect(self._refresh_connections)
        lay = QVBoxLayout(self); lay.setSpacing(10); lay.setContentsMargins(24,24,24,24)
        lay.addWidget(styled_heading("Network Monitor"))
        top_grid = QGridLayout(); top_grid.setSpacing(10)
        
        ip_card = make_card(); ip_l = QVBoxLayout(ip_card); ip_h = QHBoxLayout(); ip_h.addWidget(QLabel("🌐  Public IP"))
        ip_btn = QPushButton("Refresh"); ip_btn.setFixedWidth(70); ip_btn.setCursor(Qt.PointingHandCursor); ip_btn.clicked.connect(self._check_ip); ip_h.addWidget(ip_btn); ip_l.addLayout(ip_h)
        self.ip_lbl = QLabel("Checking..."); self.ip_lbl.setStyleSheet(f"font-size:16px;font-weight:700;color:{C_ACCENT};"); ip_l.addWidget(self.ip_lbl)
        self.ip_details = QLabel(""); self.ip_details.setStyleSheet(f"color:{C_TEXT2};font-size:11px;"); self.ip_details.setWordWrap(True); ip_l.addWidget(self.ip_details)
        top_grid.addWidget(ip_card, 0, 0)

        dns_card = make_card(); dns_l = QVBoxLayout(dns_card); dns_h = QHBoxLayout(); dns_h.addWidget(QLabel("🔒  DNS Check"))
        dns_btn = QPushButton("Test"); dns_btn.setFixedWidth(70); dns_btn.setCursor(Qt.PointingHandCursor); dns_btn.clicked.connect(self._check_dns); dns_h.addWidget(dns_btn); dns_l.addLayout(dns_h)
        self.dns_lbl = QLabel("Not tested"); self.dns_lbl.setWordWrap(True); self.dns_lbl.setStyleSheet("font-size:12px;"); dns_l.addWidget(self.dns_lbl)
        self.dns_status = QLabel(""); self.dns_status.setWordWrap(True); self.dns_status.setStyleSheet("font-size:11px;"); dns_l.addWidget(self.dns_status)
        top_grid.addWidget(dns_card, 0, 1)

        stats_card = make_card(); stats_l = QVBoxLayout(stats_card); stats_l.addWidget(QLabel("📊  Connections"))
        self.stats_lbl = QLabel("Not scanned"); self.stats_lbl.setStyleSheet("font-size:13px;"); stats_l.addWidget(self.stats_lbl)
        self.auto_cb = QCheckBox("Auto-refresh (3s)"); self.auto_cb.toggled.connect(lambda on: self.refresh_timer.start() if on else self.refresh_timer.stop()); stats_l.addWidget(self.auto_cb)
        top_grid.addWidget(stats_card, 0, 2)
        lay.addLayout(top_grid)

        tbl_card = make_card(); tbl_l = QVBoxLayout(tbl_card); tbl_h = QHBoxLayout(); tbl_h.addWidget(QLabel("Active Connections"))
        tbl_h.addWidget(QLabel("Filter:")); self.filter_edit = QLineEdit(); self.filter_edit.setMaximumWidth(250); self.filter_edit.setPlaceholderText("Search...")
        self.filter_edit.textChanged.connect(self._filter_table); tbl_h.addWidget(self.filter_edit); tbl_l.addLayout(tbl_h)
        self.conn_table = QTableWidget(); self.conn_table.setColumnCount(6)
        self.conn_table.setHorizontalHeaderLabels(["Proto", "Local", "Remote", "State", "PID", "Process"])
        self.conn_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.conn_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.conn_table.setSelectionBehavior(QAbstractItemView.SelectRows); self.conn_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.conn_table.setAlternatingRowColors(True)
        self.conn_table.setStyleSheet(f"QTableWidget{{background:{C_BG};color:{C_TEXT};border:1px solid {C_BORDER};gridline-color:{C_BORDER};font-size:12px;}}QHeaderView::section{{background:{C_CARD};color:{C_TEXT2};border:1px solid {C_BORDER};padding:4px;}}")
        tbl_l.addWidget(self.conn_table); lay.addWidget(tbl_card, 1)
        self._check_ip(); self._refresh_connections()

    def _check_ip(self): self.ip_lbl.setText("Checking..."); self.ip_worker = IpCheckWorker(); self.ip_worker.result.connect(self._on_ip_result); self.ip_worker.start()
    def _on_ip_result(self, r):
        if r.get("ip"): self.ip_lbl.setText(r["ip"]); self.ip_details.setText("  ".join(filter(None, [f"📍 {r['city']}" if r.get("city") else "", f"🏳 {r['country']}" if r.get("country") else "", f"🏢 {r['isp']}" if r.get("isp") else ""])))
        else: self.ip_lbl.setText("Unavailable")
    def _check_dns(self): self.dns_lbl.setText("Checking..."); self.dns_status.setText(""); self.dns_worker = DnsLeakWorker(); self.dns_worker.result.connect(self._on_dns_result); self.dns_worker.start()
    def _on_dns_result(self, r):
        if r.get("dns_servers"): self.dns_lbl.setText("DNS Servers:\n" + "\n".join(f"  • {d}" for d in r["dns_servers"])); self.dns_status.setText("⚠ Potential DNS leak!" if r.get("leak") else "✅ No obvious leak detected."); self.dns_status.setStyleSheet(f"color:{C_WARN if r.get('leak') else C_SUCCESS};font-size:11px;")
        else: self.dns_lbl.setText("Could not detect.")
    def _refresh_connections(self): self.conn_worker = ConnectionWorker(); self.conn_worker.result.connect(self._on_connections); self.conn_worker.start()
    def _on_connections(self, conns):
        self.all_connections = conns; tcp = sum(1 for c in conns if c["proto"]=="TCP"); udp = sum(1 for c in conns if c["proto"]=="UDP")
        est = sum(1 for c in conns if c["state"]=="ESTABLISHED"); lst = sum(1 for c in conns if c["state"]=="LISTEN")
        self.stats_lbl.setText(f"Total: {len(conns)}\nTCP: {tcp}  UDP: {udp}\nEstablished: {est}\nListening: {lst}"); self._populate_table(conns)
    def _populate_table(self, conns):
        colors = {"ESTABLISHED":C_SUCCESS,"LISTEN":C_ACCENT,"TIME_WAIT":C_WARN,"CLOSE_WAIT":C_WARN,"CLOSED":C_ERROR}
        self.conn_table.setRowCount(len(conns))
        for i, c in enumerate(conns):
            for j, key in enumerate(["proto","local","remote","state","pid","process"]):
                item = QTableWidgetItem(str(c.get(key, "")))
                if key == "state" and str(c.get(key,"")) in colors: item.setForeground(QColor(colors[str(c.get(key,""))]))
                self.conn_table.setItem(i, j, item)
    def _filter_table(self, text):
        if not hasattr(self, 'all_connections'): return
        text = text.lower(); self._populate_table(self.all_connections if not text else [c for c in self.all_connections if any(text in str(v).lower() for v in c.values())])


class ExifScrubberPage(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self); lay.setSpacing(12); lay.setContentsMargins(24,24,24,24)
        lay.addWidget(styled_heading("Metadata & EXIF Scrubber"))
        lay.addWidget(styled_subheading("Strip hidden GPS and camera metadata from images before sharing."))
        c = make_card(); cl = QVBoxLayout(c); cl.addWidget(QLabel("Select Image:"))
        file_row = QHBoxLayout(); self.file_edit = QLineEdit(); self.file_edit.setReadOnly(True); self.file_edit.setPlaceholderText("No file selected..."); file_row.addWidget(self.file_edit)
        browse_btn = QPushButton("📂 Browse"); browse_btn.setCursor(Qt.PointingHandCursor); browse_btn.clicked.connect(self._browse); file_row.addWidget(browse_btn); cl.addLayout(file_row); lay.addWidget(c)
        c2 = make_card(); cl2 = QVBoxLayout(c2); cl2.addWidget(QLabel("Current Metadata:"))
        self.meta_table = QTableWidget(0, 2); self.meta_table.setHorizontalHeaderLabels(["Tag", "Value"])
        self.meta_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents); self.meta_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.meta_table.setEditTriggers(QAbstractItemView.NoEditTriggers); self.meta_table.setAlternatingRowColors(True)
        self.meta_table.setStyleSheet(f"QTableWidget{{background:{C_BG};color:{C_TEXT};border:1px solid {C_BORDER};gridline-color:{C_BORDER};font-size:12px;}}QHeaderView::section{{background:{C_CARD};color:{C_TEXT2};border:1px solid {C_BORDER};padding:4px;}}")
        cl2.addWidget(self.meta_table); lay.addWidget(c2, 1)
        btn_row = QHBoxLayout()
        self.extract_btn = QPushButton("🔍  Extract Metadata"); self.extract_btn.setObjectName("accentBtn"); self.extract_btn.setCursor(Qt.PointingHandCursor); self.extract_btn.setMinimumHeight(40); self.extract_btn.clicked.connect(self._extract); btn_row.addWidget(self.extract_btn)
        self.scrub_btn = QPushButton("🧹  Strip & Save Clean Copy"); self.scrub_btn.setObjectName("dangerBtn"); self.scrub_btn.setCursor(Qt.PointingHandCursor); self.scrub_btn.setMinimumHeight(40); self.scrub_btn.clicked.connect(self._scrub); btn_row.addWidget(self.scrub_btn)
        lay.addLayout(btn_row); self.status_lbl = QLabel(""); self.status_lbl.setStyleSheet(f"color:{C_TEXT2};font-size:12px;"); lay.addWidget(self.status_lbl)
        if not HAS_PIL: self.status_lbl.setText("⚠ Install Pillow to use this feature: pip install Pillow"); self.status_lbl.setStyleSheet(f"color:{C_WARN};")

    def _browse(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Image", "", "Images (*.jpg *.jpeg *.png *.tiff *.bmp *.webp);;All Files (*)")
        if path: self.file_edit.setText(path); self.meta_table.setRowCount(0); self.status_lbl.setText("")
    def _extract(self):
        if not HAS_PIL: QMessageBox.critical(self, "Missing", "pip install Pillow"); return
        path = self.file_edit.text()
        if not path or not Path(path).exists(): QMessageBox.warning(self, "Error", "Select a valid image."); return
        try:
            img = Image.open(path); exif_data = img._getexif(); self.meta_table.setRowCount(0)
            if not exif_data: self.status_lbl.setText("✅ No EXIF data found."); return
            gps_tags = set()
            for tag_id, value in exif_data.items():
                tag = TAGS.get(tag_id, tag_id)
                if "GPS" in str(tag): gps_tags.add(tag)
                row = self.meta_table.rowCount(); self.meta_table.insertRow(row)
                self.meta_table.setItem(row, 0, QTableWidgetItem(str(tag))); self.meta_table.setItem(row, 1, QTableWidgetItem(str(value)[:100]))
            if gps_tags: self.status_lbl.setText(f"⚠️ WARNING: GPS Data detected! Tags: {', '.join(gps_tags)}"); self.status_lbl.setStyleSheet(f"color:{C_ERROR};font-size:12px;")
            else: self.status_lbl.setText(f"ℹ️ Found {self.meta_table.rowCount()} metadata entries."); self.status_lbl.setStyleSheet(f"color:{C_TEXT2};font-size:12px;")
        except Exception as e: QMessageBox.critical(self, "Error", str(e))
    def _scrub(self):
        if not HAS_PIL: return
        path = self.file_edit.text()
        if not path or not Path(path).exists(): return
        save_path, _ = QFileDialog.getSaveFileName(self, "Save Clean Image", Path(path).stem + "_clean" + Path(path).suffix, "Images (*.jpg *.jpeg *.png *.bmp *.webp)")
        if not save_path: return
        try:
            img = Image.open(path); data = list(img.getdata()); clean_img = Image.new(img.mode, img.size); clean_img.putdata(data); clean_img.save(save_path, format=img.format or "PNG")
            self.status_lbl.setText(f"✅ Saved clean image."); self.status_lbl.setStyleSheet(f"color:{C_SUCCESS};font-size:12px;"); self.meta_table.setRowCount(0)
        except Exception as e: QMessageBox.critical(self, "Error", str(e))


class FileEncryptorPage(QWidget):
    def __init__(self):
        super().__init__()
        self.files = []; self.worker = None
        lay = QVBoxLayout(self); lay.setSpacing(12); lay.setContentsMargins(24,24,24,24)
        lay.addWidget(styled_heading("File & Folder Encryptor"))
        lay.addWidget(styled_subheading("AES-256 encrypt files. Protects files locally or before cloud upload."))
        c = make_card(); cl = QVBoxLayout(c); cl.addWidget(QLabel("Files/Folders:"))
        self.file_list = QListWidget(); self.file_list.setMinimumHeight(100); self.file_list.setStyleSheet(f"background:{C_BG};border:1px solid {C_BORDER};border-radius:6px;color:{C_TEXT};padding:4px;"); cl.addWidget(self.file_list)
        br = QHBoxLayout()
        for label, slot in [("Add Files", self._add_files), ("Add Folder", self._add_folder), ("Remove", self._remove_sel), ("Clear", self._clear_all)]:
            b = QPushButton(label); b.clicked.connect(slot); br.addWidget(b)
        cl.addLayout(br); lay.addWidget(c)
        c2 = make_card(); cl2 = QVBoxLayout(c2); pw_grid = QGridLayout(); pw_grid.setSpacing(8)
        self.pw_input = QLineEdit(); self.pw_input.setEchoMode(QLineEdit.Password); self.pw_input.setMinimumHeight(36); pw_grid.addWidget(QLabel("Password:"), 0, 0); pw_grid.addWidget(self.pw_input, 0, 1)
        self.pw_confirm = QLineEdit(); self.pw_confirm.setEchoMode(QLineEdit.Password); self.pw_confirm.setMinimumHeight(36); pw_grid.addWidget(QLabel("Confirm:"), 1, 0); pw_grid.addWidget(self.pw_confirm, 1, 1)
        cl2.addLayout(pw_grid); self.shred_cb = QCheckBox("Securely shred original files after encryption"); self.shred_cb.setStyleSheet(f"color:{C_WARN};font-weight:bold;"); cl2.addWidget(self.shred_cb); lay.addWidget(c2)
        self.progress = QProgressBar(); lay.addWidget(self.progress); self.status_lbl = QLabel(""); self.status_lbl.setStyleSheet(f"color:{C_TEXT2};font-size:12px;"); lay.addWidget(self.status_lbl)
        action_row = QHBoxLayout()
        enc_btn = QPushButton("🔒  ENCRYPT"); enc_btn.setObjectName("accentBtn"); enc_btn.setCursor(Qt.PointingHandCursor); enc_btn.setMinimumHeight(44); enc_btn.clicked.connect(self._encrypt); action_row.addWidget(enc_btn)
        dec_btn = QPushButton("🔓  DECRYPT .enc FILES"); dec_btn.setObjectName("dangerBtn"); dec_btn.setCursor(Qt.PointingHandCursor); dec_btn.setMinimumHeight(44); dec_btn.clicked.connect(self._decrypt); action_row.addWidget(dec_btn)
        lay.addLayout(action_row); lay.addStretch()
        if not HAS_CRYPTO: self.status_lbl.setText("⚠ pip install cryptography"); self.status_lbl.setStyleSheet(f"color:{C_WARN};")

    def _add_files(self):
        for p, _ in [QFileDialog.getOpenFileNames(self, "Select Files")]:
            if p and p not in self.files: self.files.append(p); self.file_list.addItem(os.path.basename(p))
    def _add_folder(self):
        p = QFileDialog.getExistingDirectory(self, "Select Folder")
        if p and p not in self.files: self.files.append(p); self.file_list.addItem("📁 " + os.path.basename(p))
    def _remove_sel(self):
        for item in self.file_list.selectedItems(): idx = self.file_list.row(item); self.file_list.takeItem(idx); self.files.pop(idx)
    def _clear_all(self): self.files.clear(); self.file_list.clear()
    def _validate_pw(self):
        if not HAS_CRYPTO: QMessageBox.critical(self, "Error", "pip install cryptography"); return False
        pw = self.pw_input.text()
        if len(pw) < 8: QMessageBox.warning(self, "Weak", "Min 8 chars."); return False
        if pw != self.pw_confirm.text(): QMessageBox.warning(self, "Mismatch", "Passwords don't match."); return False
        return True
    def _encrypt(self):
        if not self.files: QMessageBox.warning(self, "Empty", "Add files."); return
        if not self._validate_pw(): return
        self.progress.setValue(0); pw = self.pw_input.text()
        self.worker = EncryptWorker(self.files[:], pw, self.shred_cb.isChecked())
        self.worker.progress.connect(lambda c,t: self.progress.setValue(int(c/t*100)))
        self.worker.status.connect(lambda s: self.status_lbl.setText(s))
        self.worker.done.connect(self._on_done); self.worker.start()
    def _decrypt(self):
        if not self._validate_pw(): return
        enc_files = [f for f in self.files if f.endswith(".enc")]
        if not enc_files: QMessageBox.information(self, "Info", "Add .enc files."); return
        self.progress.setValue(0); pw = self.pw_input.text()
        self.worker = DecryptWorker(enc_files, pw)
        self.worker.progress.connect(lambda c,t: self.progress.setValue(int(c/t*100)))
        self.worker.status.connect(lambda s: self.status_lbl.setText(s))
        self.worker.done.connect(self._on_done); self.worker.start()
    def _on_done(self, ok, msg):
        self.status_lbl.setText(msg); self.files.clear(); self.file_list.clear()
        if not ok: QMessageBox.critical(self, "Error", msg)


class ShredderPage(QWidget):
    def __init__(self):
        super().__init__()
        self.files = []; self.worker = None
        lay = QVBoxLayout(self); lay.setSpacing(12); lay.setContentsMargins(24,24,24,24)
        lay.addWidget(styled_heading("File Shredder")); lay.addWidget(styled_subheading("Securely delete files by overwriting contents before removal."))
        c = make_card(); cl = QVBoxLayout(c); cl.addWidget(QLabel("Files to shred:"))
        self.file_list = QListWidget(); self.file_list.setMinimumHeight(100); self.file_list.setStyleSheet(f"background:{C_BG};border:1px solid {C_BORDER};border-radius:6px;color:{C_TEXT};padding:4px;"); cl.addWidget(self.file_list)
        br = QHBoxLayout()
        for label, slot in [("Add Files", self._add_files), ("Add Folder", self._add_folder), ("Remove", self._remove_sel), ("Clear", self._clear_all)]:
            b = QPushButton(label); b.clicked.connect(slot); br.addWidget(b)
        cl.addLayout(br); lay.addWidget(c)
        c2 = make_card(); cl2 = QVBoxLayout(c2); or2 = QHBoxLayout(); or2.addWidget(QLabel("Passes:"))
        self.pass_spin = QSpinBox(); self.pass_spin.setRange(1,35); self.pass_spin.setValue(3); or2.addWidget(self.pass_spin); or2.addStretch(); or2.addWidget(QLabel("Method:"))
        self.method_cb = QComboBox(); self.method_cb.addItems(["Random","Zeros","Ones","DoD 5220"]); or2.addWidget(self.method_cb); cl2.addLayout(or2); lay.addWidget(c2)
        self.progress = QProgressBar(); lay.addWidget(self.progress); self.status_lbl = QLabel(""); self.status_lbl.setStyleSheet(f"color:{C_TEXT2};font-size:12px;"); lay.addWidget(self.status_lbl)
        self.shred_btn = QPushButton("⚠  SHRED FILES"); self.shred_btn.setObjectName("dangerBtn"); self.shred_btn.setCursor(Qt.PointingHandCursor); self.shred_btn.setMinimumHeight(40); self.shred_btn.clicked.connect(self._shred); lay.addWidget(self.shred_btn); lay.addStretch()
    def _add_files(self):
        for p, _ in [QFileDialog.getOpenFileNames(self, "Select Files")]:
            if p and p not in self.files: self.files.append(p); self.file_list.addItem(os.path.basename(p))
    def _add_folder(self):
        p = QFileDialog.getExistingDirectory(self, "Select Folder")
        if p and p not in self.files: self.files.append(p); self.file_list.addItem(os.path.basename(p))
    def _remove_sel(self):
        for item in self.file_list.selectedItems(): idx = self.file_list.row(item); self.file_list.takeItem(idx); self.files.pop(idx)
    def _clear_all(self): self.files.clear(); self.file_list.clear()
    def _shred(self):
        if not self.files: return
        if QMessageBox.warning(self, "Confirm", f"IRREVERSIBLY destroy {len(self.files)} file(s)?", QMessageBox.Yes|QMessageBox.No) != QMessageBox.Yes: return
        self.shred_btn.setEnabled(False); self.progress.setValue(0)
        self.worker = ShredderWorker(self.files[:], self.pass_spin.value(), self.method_cb.currentText())
        self.worker.progress.connect(lambda c,t: self.progress.setValue(int(c/t*100)))
        self.worker.file_progress.connect(lambda n: self.status_lbl.setText(f"Shredding: {n}"))
        self.worker.done.connect(self._on_done); self.worker.start()
    def _on_done(self, ok, msg):
        self.shred_btn.setEnabled(True); self.status_lbl.setText(msg)
        if ok: self.files.clear(); self.file_list.clear(); self.progress.setValue(100)
        QMessageBox.information(self, "Done" if ok else "Error", msg)


class PasswordPage(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self); lay.setSpacing(12); lay.setContentsMargins(24,24,24,24)
        lay.addWidget(styled_heading("Password Generator"))
        c = make_card(); cl = QVBoxLayout(c)
        self.pw_display = QLineEdit(); self.pw_display.setReadOnly(True); self.pw_display.setMinimumHeight(44)
        self.pw_display.setStyleSheet(f"font-size:20px;font-family:monospace;background:{C_BG};color:{C_TEXT};border:1px solid {C_BORDER};border-radius:8px;padding:8px;"); cl.addWidget(self.pw_display)
        self.strength_bar = QProgressBar(); self.strength_bar.setRange(0,100); self.strength_bar.setTextVisible(False); self.strength_bar.setFixedHeight(8); cl.addWidget(self.strength_bar)
        self.strength_lbl = QLabel("—"); self.strength_lbl.setStyleSheet(f"color:{C_TEXT2};font-size:12px;"); cl.addWidget(self.strength_lbl); lay.addWidget(c)
        c2 = make_card(); cl2 = QVBoxLayout(c2); lr = QHBoxLayout(); lr.addWidget(QLabel("Length:"))
        self.len_slider = QSlider(Qt.Horizontal); self.len_slider.setRange(4,128); self.len_slider.setValue(20); self.len_slider.valueChanged.connect(lambda v: self.len_lbl.setText(str(v))); lr.addWidget(self.len_slider)
        self.len_lbl = QLabel("20"); self.len_lbl.setMinimumWidth(30); lr.addWidget(self.len_lbl); cl2.addLayout(lr)
        self.cb_upper = QCheckBox("Uppercase"); self.cb_upper.setChecked(True); self.cb_lower = QCheckBox("Lowercase"); self.cb_lower.setChecked(True)
        self.cb_digit = QCheckBox("Digits"); self.cb_digit.setChecked(True); self.cb_sym = QCheckBox("Symbols"); self.cb_sym.setChecked(True)
        self.cb_ambig = QCheckBox("Exclude ambiguous (0O1lI|)")
        for cb in [self.cb_upper, self.cb_lower, self.cb_digit, self.cb_sym, self.cb_ambig]: cl2.addWidget(cb)
        lay.addWidget(c2); br = QHBoxLayout()
        gen = QPushButton("🔑  Generate"); gen.setObjectName("accentBtn"); gen.setMinimumHeight(40); gen.setCursor(Qt.PointingHandCursor); gen.clicked.connect(self._generate); br.addWidget(gen)
        copy = QPushButton("📋  Copy"); copy.setMinimumHeight(40); copy.setCursor(Qt.PointingHandCursor); copy.clicked.connect(self._copy); br.addWidget(copy)
        lay.addLayout(br); lay.addStretch()
    def _charset(self):
        cs = ""
        if self.cb_upper.isChecked(): cs += string.ascii_uppercase
        if self.cb_lower.isChecked(): cs += string.ascii_lowercase
        if self.cb_digit.isChecked(): cs += string.digits
        if self.cb_sym.isChecked(): cs += string.punctuation
        if self.cb_ambig.isChecked(): cs = cs.translate(str.maketrans("","","0O1lI|"))
        return cs or string.ascii_letters
    def _generate(self):
        cs = self._charset(); pw = ''.join(secrets.choice(cs) for _ in range(self.len_slider.value())); self.pw_display.setText(pw)
        ent, label, color = calc_strength(pw); self.strength_bar.setValue(min(int(ent),100))
        self.strength_bar.setStyleSheet(f"QProgressBar::chunk{{background:{color};border-radius:4px;}}QProgressBar{{background:{C_BORDER};border-radius:4px;border:none;}}")
        self.strength_lbl.setText(f"{label} ({ent:.0f} bits)")
    def _copy(self):
        pw = self.pw_display.text()
        if pw: QApplication.clipboard().setText(pw); self.strength_lbl.setText("Copied! ✓")


class VaultPage(QWidget):
    def __init__(self):
        super().__init__()
        self.vault_path = app_data_dir() / "vault.dat"; self.notes = []; self.master_pw = None
        self.lock_timer = QTimer(); self.lock_timer.setInterval(300000); self.lock_timer.timeout.connect(self._lock)
        lay = QVBoxLayout(self); lay.setSpacing(12); lay.setContentsMargins(24,24,24,24)
        self.stack = QStackedWidget(); lay.addWidget(self.stack)
        lw = QWidget(); ll = QVBoxLayout(lw); ll.setSpacing(12); ll.addWidget(styled_heading("Encrypted Vault"))
        ll.addWidget(styled_subheading("AES-256 encrypted notes. All data stored locally."))
        if not HAS_CRYPTO: ll.addWidget(QLabel("⚠ pip install cryptography"))
        self.new_vault_lbl = QLabel(""); self.new_vault_lbl.setStyleSheet(f"color:{C_WARN};"); ll.addWidget(self.new_vault_lbl)
        ll.addWidget(QLabel("Master Password:")); self.pw_input = QLineEdit(); self.pw_input.setEchoMode(QLineEdit.Password); self.pw_input.setMinimumHeight(36); self.pw_input.returnPressed.connect(self._unlock); ll.addWidget(self.pw_input)
        ll.addWidget(QLabel("Confirm Password:")); self.pw_confirm = QLineEdit(); self.pw_confirm.setEchoMode(QLineEdit.Password); self.pw_confirm.setMinimumHeight(36); ll.addWidget(self.pw_confirm)
        ub = QPushButton("🔓  Unlock / Create"); ub.setObjectName("accentBtn"); ub.setMinimumHeight(40); ub.setCursor(Qt.PointingHandCursor); ub.clicked.connect(self._unlock); ll.addWidget(ub); ll.addStretch(); self.stack.addWidget(lw)
        mw = QWidget(); ml = QVBoxLayout(mw); ml.setSpacing(12); ml.addWidget(styled_heading("🔐  Encrypted Vault"))
        tr = QHBoxLayout(); self.note_list = QListWidget(); self.note_list.setMinimumWidth(160)
        self.note_list.setStyleSheet(f"background:{C_BG};border:1px solid {C_BORDER};border-radius:6px;color:{C_TEXT};"); self.note_list.currentRowChanged.connect(self._select_note); tr.addWidget(self.note_list, 1)
        ed = QVBoxLayout(); self.title_edit = QLineEdit(); self.title_edit.setPlaceholderText("Title..."); self.title_edit.setMinimumHeight(36); ed.addWidget(self.title_edit)
        self.content_edit = QTextEdit(); self.content_edit.setStyleSheet(f"background:{C_BG};color:{C_TEXT};border:1px solid {C_BORDER};border-radius:6px;"); ed.addWidget(self.content_edit, 1); tr.addLayout(ed, 3); ml.addLayout(tr)
        br = QHBoxLayout()
        for l, s in [("➕ New", self._new_note),("💾 Save", self._save_note),("🗑 Delete", self._del_note),("🔒 Lock", self._lock)]:
            b = QPushButton(l); b.setCursor(Qt.PointingHandCursor); b.clicked.connect(s); br.addWidget(b)
        ml.addLayout(br); self.stack.addWidget(mw); self._check_vault()

    def _check_vault(self):
        e = self.vault_path.exists(); self.pw_confirm.setVisible(not e)
        self.new_vault_lbl.setText("Create new vault." if not e else "Enter password to unlock."); self.pw_input.clear(); self.pw_confirm.clear()
    def _unlock(self):
        if not HAS_CRYPTO: QMessageBox.critical(self,"Error","pip install cryptography"); return
        pw = self.pw_input.text()
        if not pw: return
        if not self.vault_path.exists():
            if pw != self.pw_confirm.text() or len(pw)<8: QMessageBox.warning(self,"Error","Passwords don't match or too short."); return
            self.master_pw = pw; self.notes = []; self._save_vault()
        else:
            try: self.notes = json.loads(decrypt_str(self.vault_path.read_text(), pw)); self.master_pw = pw
            except: QMessageBox.critical(self,"Failed","Wrong password."); return
        self._refresh(); self.stack.setCurrentIndex(1); self.lock_timer.start()
    def _lock(self):
        self.master_pw = None; self.notes = []; self.note_list.clear(); self.title_edit.clear(); self.content_edit.clear()
        self.stack.setCurrentIndex(0); self._check_vault(); self.lock_timer.stop()
    def _refresh(self):
        self.note_list.clear()
        for n in self.notes: self.note_list.addItem(n.get("title","Untitled"))
    def _select_note(self, row):
        if 0<=row<len(self.notes): self.title_edit.setText(self.notes[row].get("title","")); self.content_edit.setPlainText(self.notes[row].get("content",""))
    def _new_note(self):
        self.notes.append(dict(title="New Note",content="",created=datetime.now().isoformat())); self._refresh(); self.note_list.setCurrentRow(len(self.notes)-1)
    def _save_note(self):
        row = self.note_list.currentRow()
        if 0<=row<len(self.notes):
            self.notes[row]["title"]=self.title_edit.text() or "Untitled"; self.notes[row]["content"]=self.content_edit.toPlainText()
            self.notes[row]["modified"]=datetime.now().isoformat(); self._save_vault(); self._refresh(); self.note_list.setCurrentRow(row)
    def _del_note(self):
        row = self.note_list.currentRow()
        if 0<=row<len(self.notes): self.notes.pop(row); self._save_vault(); self._refresh()
    def _save_vault(self):
        if self.master_pw: self.vault_path.write_text(encrypt_str(json.dumps(self.notes),self.master_pw))


class ScannerPage(QWidget):
    def __init__(self):
        super().__init__()
        self.worker = None
        lay = QVBoxLayout(self); lay.setSpacing(12); lay.setContentsMargins(24,24,24,24)
        lay.addWidget(styled_heading("Privacy Scanner")); lay.addWidget(styled_subheading("Scan for common privacy risks and recommendations."))
        self.scan_btn = QPushButton("🔍  Run Privacy Scan"); self.scan_btn.setObjectName("accentBtn"); self.scan_btn.setMinimumHeight(44); self.scan_btn.setCursor(Qt.PointingHandCursor); self.scan_btn.clicked.connect(self._scan); lay.addWidget(self.scan_btn)
        self.progress = QProgressBar(); lay.addWidget(self.progress)
        self.score_lbl = QLabel(""); self.score_lbl.setStyleSheet(f"font-size:16px;font-weight:700;"); lay.addWidget(self.score_lbl)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); scroll.setStyleSheet("border:none;")
        self.results_w = QWidget(); self.results_lay = QVBoxLayout(self.results_w); self.results_lay.setSpacing(8); self.results_lay.addStretch(); scroll.setWidget(self.results_w); lay.addWidget(scroll, 1)
    def _scan(self):
        while self.results_lay.count()>1: item=self.results_lay.takeAt(0); 
        if item.widget(): item.widget().deleteLater()
        self.progress.setValue(0); self.scan_btn.setEnabled(False); self.worker = ScannerWorker()
        self.worker.progress.connect(lambda c,t: self.progress.setValue(int(c/t*100))); self.worker.result.connect(self._add_result); self.worker.done.connect(self._scan_done); self.worker.start()
    def _add_result(self, r):
        colors={"good":C_SUCCESS,"info":C_ACCENT,"warning":C_WARN,"error":C_ERROR}; c=make_card(); cl=QVBoxLayout(c)
        h=QLabel(f'<span style="color:{colors.get(r["severity"],C_TEXT2)};font-weight:700;">[{r["severity"].upper()}]</span>  {r["name"]}')
        h.setStyleSheet("font-size:14px;"); cl.addWidget(h); m=QLabel(r["message"]); m.setStyleSheet(f"color:{C_TEXT};font-size:13px;"); m.setWordWrap(True); cl.addWidget(m)
        if r["fix"]!="N/A": f2=QLabel(f'💡 <i>{r["fix"]}</i>'); f2.setStyleSheet(f"color:{C_TEXT2};font-size:12px;"); f2.setWordWrap(True); cl.addWidget(f2)
        self.results_lay.insertWidget(self.results_lay.count()-1, c)
    def _scan_done(self, results):
        self.scan_btn.setEnabled(True); self.progress.setValue(100); good=sum(1 for r in results if r["severity"]=="good")
        score=int(good/len(results)*100) if results else 0; color=C_SUCCESS if score>=80 else (C_WARN if score>=50 else C_ERROR)
        self.score_lbl.setText(f'Privacy Score: <span style="color:{color}">{score}/100</span>')


class ClipboardPage(QWidget):
    def __init__(self):
        super().__init__()
        self.auto_timer = QTimer(); self.auto_timer.timeout.connect(self._clear)
        self._monitor_timer = QTimer(); self._monitor_timer.setInterval(500); self._monitor_timer.timeout.connect(self._check_clipboard); self._last_clip = ""
        lay = QVBoxLayout(self); lay.setSpacing(12); lay.setContentsMargins(24,24,24,24)
        lay.addWidget(styled_heading("Clipboard Guard"))
        c = make_card(); cl = QVBoxLayout(c); cl.addWidget(QLabel("Current Clipboard:"))
        self.preview = QTextEdit(); self.preview.setReadOnly(True); self.preview.setMaximumHeight(120)
        self.preview.setStyleSheet(f"background:{C_BG};color:{C_TEXT};border:1px solid {C_BORDER};border-radius:6px;font-family:monospace;"); cl.addWidget(self.preview); lay.addWidget(c)
        c2 = make_card(); cl2 = QVBoxLayout(c2); br = QHBoxLayout()
        cb = QPushButton("🧹 Clear"); cb.setObjectName("accentBtn"); cb.setMinimumHeight(36); cb.setCursor(Qt.PointingHandCursor); cb.clicked.connect(self._clear); br.addWidget(cb)
        rb = QPushButton("🔄 Refresh"); rb.setMinimumHeight(36); rb.setCursor(Qt.PointingHandCursor); rb.clicked.connect(self._refresh); br.addWidget(rb); cl2.addLayout(br)
        ar = QHBoxLayout(); self.auto_cb = QCheckBox("Auto-clear after"); self.auto_cb.toggled.connect(self._toggle_auto); ar.addWidget(self.auto_cb)
        self.auto_spin = QSpinBox(); self.auto_spin.setRange(5,300); self.auto_spin.setValue(30); self.auto_spin.setSuffix(" sec"); self.auto_spin.valueChanged.connect(self._update_interval); ar.addWidget(self.auto_spin); cl2.addLayout(ar)
        self.auto_status = QLabel("Auto-clear: OFF"); self.auto_status.setStyleSheet(f"color:{C_TEXT2};font-size:12px;"); cl2.addWidget(self.auto_status); lay.addWidget(c2)
        c3 = make_card(); cl3 = QVBoxLayout(c3)
        self.monitor_cb = QCheckBox("Monitor clipboard changes"); self.monitor_cb.toggled.connect(self._toggle_monitor); cl3.addWidget(self.monitor_cb)
        self.log = QTextEdit(); self.log.setReadOnly(True); self.log.setMaximumHeight(120)
        self.log.setStyleSheet(f"background:{C_BG};color:{C_TEXT2};border:1px solid {C_BORDER};border-radius:6px;font-size:12px;"); cl3.addWidget(self.log); lay.addWidget(c3); lay.addStretch()
    def _refresh(self): txt=QApplication.clipboard().text(); self.preview.setPlainText(txt or "(empty)"); self._last_clip=txt
    def _clear(self): QApplication.clipboard().clear(); self.preview.setPlainText("(cleared)"); self.log.append(f"[{datetime.now().strftime('%H:%M:%S')}] Cleared")
    def _toggle_auto(self, on):
        if on: self.auto_timer.start(self.auto_spin.value()*1000); self.auto_status.setText(f"Auto-clear: ON ({self.auto_spin.value()}s)"); self.auto_status.setStyleSheet(f"color:{C_SUCCESS};font-size:12px;")
        else: self.auto_timer.stop(); self.auto_status.setText("Auto-clear: OFF"); self.auto_status.setStyleSheet(f"color:{C_TEXT2};font-size:12px;")
    def _update_interval(self, v):
        if self.auto_cb.isChecked(): self.auto_timer.setInterval(v*1000); self.auto_status.setText(f"Auto-clear: ON ({v}s)")
    def _toggle_monitor(self, on):
        if on: self._monitor_timer.start(); self._last_clip=QApplication.clipboard().text(); self.log.append(f"[{datetime.now().strftime('%H:%M:%S')}] Monitoring started")
        else: self._monitor_timer.stop()
    def _check_clipboard(self):
        txt=QApplication.clipboard().text()
        if txt!=self._last_clip:
            self._last_clip=txt; p=txt[:80].replace("\n","↵")+("..." if len(txt)>80 else "")
            self.log.append(f"[{datetime.now().strftime('%H:%M:%S')}] Changed: \"{p}\""); self.preview.setPlainText(txt)


# ═══════════════════════════════════════════════════════════
# Sidebar & MainWindow
# ═══════════════════════════════════════════════════════════

class Sidebar(QWidget):
    page_changed = Signal(int)
    def __init__(self):
        super().__init__()
        self.setFixedWidth(210); self.setObjectName("sidebar")
        lay = QVBoxLayout(self); lay.setContentsMargins(0,0,0,0); lay.setSpacing(0)
        logo_w = QWidget(); logo_l = QVBoxLayout(logo_w); logo_l.setContentsMargins(16,20,16,12)
        name = QLabel("PrivacyGuard"); name.setStyleSheet(f"font-size:17px;font-weight:700;color:{C_ACCENT};")
        ver = QLabel(f"v{APP_VER}"); ver.setStyleSheet(f"font-size:11px;color:{C_TEXT2};")
        logo_l.addWidget(name); logo_l.addWidget(ver); lay.addWidget(logo_w)
        sep = QFrame(); sep.setFrameShape(QFrame.HLine); sep.setStyleSheet(f"color:{C_BORDER};"); lay.addWidget(sep)
        self.btns = []
        for i, (icon, label) in enumerate(SIDEBAR_PAGES):
            b = QPushButton(f"  {icon}   {label}"); b.setObjectName("sidebarBtn"); b.setCursor(Qt.PointingHandCursor); b.setCheckable(True); b.setMinimumHeight(42)
            b.clicked.connect(lambda checked, idx=i: self._on_click(idx)); lay.addWidget(b); self.btns.append(b)
        if self.btns: self.btns[0].setChecked(True)
        lay.addStretch(); plat = QLabel(f"  {platform.system()} {platform.machine()}"); plat.setStyleSheet(f"color:{C_TEXT2};font-size:10px;padding:8px;"); lay.addWidget(plat)
    def _on_click(self, idx):
        for b in self.btns: b.setChecked(False)
        self.btns[idx].setChecked(True); self.page_changed.emit(idx)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} — Privacy Toolkit"); self.setMinimumSize(900, 620); self.resize(1080, 720)
        central = QWidget(); self.setCentralWidget(central); hlay = QHBoxLayout(central); hlay.setContentsMargins(0,0,0,0); hlay.setSpacing(0)
        self.sidebar = Sidebar(); hlay.addWidget(self.sidebar); self.stack = QStackedWidget()
        self.stack.addWidget(DashboardPage())      # 0
        self.stack.addWidget(ProxyManagerPage())    # 1
        self.stack.addWidget(NetworkMonitorPage())  # 2
        self.stack.addWidget(ExifScrubberPage())    # 3
        self.stack.addWidget(FileEncryptorPage())   # 4
        self.stack.addWidget(ShredderPage())        # 5
        self.stack.addWidget(PasswordPage())        # 6
        self.stack.addWidget(VaultPage())           # 7
        self.stack.addWidget(ScannerPage())         # 8
        self.stack.addWidget(ClipboardPage())       # 9
        hlay.addWidget(self.stack, 1); self.sidebar.page_changed.connect(self.stack.setCurrentIndex)
        sb = QStatusBar(); sb.setStyleSheet(f"background:{C_SURFACE};color:{C_TEXT2};font-size:11px;border:none;")
        sb.showMessage(f"  {APP_NAME} v{APP_VER}  •  Ready  •  Data: {app_data_dir()}"); self.setStatusBar(sb)


# ═══════════════════════════════════════════════════════════
# Stylesheet
# ═══════════════════════════════════════════════════════════

STYLESHEET = f"""
QMainWindow, QWidget {{ background: {C_BG}; color: {C_TEXT}; font-family: 'Segoe UI','Helvetica Neue','Ubuntu',sans-serif; }}
#sidebar {{ background: {C_SURFACE}; border-right: 1px solid {C_BORDER}; }}
#sidebarBtn {{ background: transparent; color: {C_TEXT2}; border: none; text-align: left; padding: 8px 16px; font-size: 13px; border-left: 3px solid transparent; }}
#sidebarBtn:hover {{ background: {C_CARD}; color: {C_TEXT}; }}
#sidebarBtn:checked {{ background: {C_CARD}; color: {C_ACCENT}; border-left: 3px solid {C_ACCENT}; font-weight: 600; }}
#card {{ background: {C_CARD}; border: 1px solid {C_BORDER}; border-radius: 10px; padding: 14px; }}
#accentBtn {{ background: {C_ACCENT}; color: #fff; border: none; border-radius: 8px; font-size: 14px; font-weight: 600; padding: 8px 18px; }}
#accentBtn:hover {{ background: {C_ACCENT2}; }}
#accentBtn:pressed {{ background: #388bfd; }}
#dangerBtn {{ background: {C_ERROR}; color: #fff; border: none; border-radius: 8px; font-size: 14px; font-weight: 700; padding: 8px 18px; }}
#dangerBtn:hover {{ background: #ff6e76; }}
QPushButton {{ background: {C_SURFACE}; color: {C_TEXT}; border: 1px solid {C_BORDER}; border-radius: 6px; padding: 6px 14px; font-size: 13px; }}
QPushButton:hover {{ background: {C_CARD}; border-color: {C_TEXT2}; }}
QPushButton:pressed {{ background: {C_BORDER}; }}
QPushButton:disabled {{ color: {C_BORDER}; }}
QLineEdit {{ background: {C_BG}; color: {C_TEXT}; border: 1px solid {C_BORDER}; border-radius: 6px; padding: 6px 10px; font-size: 13px; }}
QLineEdit:focus {{ border-color: {C_ACCENT}; }}
QTextEdit {{ background: {C_BG}; color: {C_TEXT}; border: 1px solid {C_BORDER}; border-radius: 6px; padding: 6px; font-size: 13px; }}
QComboBox {{ background: {C_BG}; color: {C_TEXT}; border: 1px solid {C_BORDER}; border-radius: 6px; padding: 6px 10px; font-size: 13px; }}
QComboBox::drop-down {{ border: none; }}
QComboBox QAbstractItemView {{ background: {C_CARD}; color: {C_TEXT}; border: 1px solid {C_BORDER}; selection-background-color: {C_ACCENT}; }}
QSpinBox {{ background: {C_BG}; color: {C_TEXT}; border: 1px solid {C_BORDER}; border-radius: 6px; padding: 4px 8px; font-size: 13px; }}
QSlider::groove:horizontal {{ background: {C_BORDER}; height: 6px; border-radius: 3px; }}
QSlider::handle:horizontal {{ background: {C_ACCENT}; width: 16px; height: 16px; margin: -5px 0; border-radius: 8px; }}
QSlider::sub-page:horizontal {{ background: {C_ACCENT}; border-radius: 3px; }}
QCheckBox {{ color: {C_TEXT}; spacing: 8px; font-size: 13px; }}
QCheckBox::indicator {{ width: 18px; height: 18px; border: 2px solid {C_BORDER}; border-radius: 4px; background: {C_BG}; }}
QCheckBox::indicator:checked {{ background: {C_ACCENT}; border-color: {C_ACCENT}; }}
QProgressBar {{ background: {C_BORDER}; border: none; border-radius: 6px; height: 8px; }}
QProgressBar::chunk {{ background: {C_ACCENT}; border-radius: 6px; }}
QListWidget {{ background: {C_BG}; color: {C_TEXT}; border: 1px solid {C_BORDER}; border-radius: 6px; padding: 4px; font-size: 13px; outline: none; }}
QListWidget::item {{ padding: 6px; border-radius: 4px; }}
QListWidget::item:selected {{ background: {C_ACCENT}; color: #fff; }}
QListWidget::item:hover {{ background: {C_CARD}; }}
QLabel {{ color: {C_TEXT}; }}
QSplitter::handle {{ background: {C_BORDER}; }}
QTableWidget {{ background: {C_BG}; color: {C_TEXT}; border: 1px solid {C_BORDER}; border-radius: 6px; gridline-color: {C_BORDER}; font-size: 12px; }}
QHeaderView::section {{ background: {C_CARD}; color: {C_TEXT2}; border: 1px solid {C_BORDER}; padding: 4px; font-size: 11px; }}
QScrollBar:vertical {{ background: {C_BG}; width: 10px; border: none; }}
QScrollBar::handle:vertical {{ background: {C_BORDER}; border-radius: 5px; min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background: {C_TEXT2}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{ background: {C_BG}; height: 10px; border: none; }}
QScrollBar::handle:horizontal {{ background: {C_BORDER}; border-radius: 5px; min-width: 30px; }}
QScrollArea {{ border: none; }}
QStatusBar {{ border-top: 1px solid {C_BORDER}; }}
"""

# ═══════════════════════════════════════════════════════════
# Entry Point
# ═══════════════════════════════════════════════════════════

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion"); app.setStyleSheet(STYLESHEET)
    pal = QPalette()
    pal.setColor(QPalette.Window, QColor(C_BG)); pal.setColor(QPalette.WindowText, QColor(C_TEXT))
    pal.setColor(QPalette.Base, QColor(C_BG)); pal.setColor(QPalette.AlternateBase, QColor(C_CARD))
    pal.setColor(QPalette.ToolTipBase, QColor(C_CARD)); pal.setColor(QPalette.ToolTipText, QColor(C_TEXT))
    pal.setColor(QPalette.Text, QColor(C_TEXT)); pal.setColor(QPalette.Button, QColor(C_SURFACE))
    pal.setColor(QPalette.ButtonText, QColor(C_TEXT)); pal.setColor(QPalette.Highlight, QColor(C_ACCENT))
    pal.setColor(QPalette.HighlightedText, QColor("#ffffff")); app.setPalette(pal)
    win = MainWindow(); win.show(); sys.exit(app.exec())

if __name__ == "__main__":
    main()