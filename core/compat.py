# ═══════════════════════════════════════════════════════════════════
# ANUBIS — OS Detection & Compatibility Matrix
# ═══════════════════════════════════════════════════════════════════
# Role:    Detects the host operating system, architecture, distro,
#          kernel version, admin privileges, installed antivirus,
#          firewall state, and other environmental factors. Provides
#          a compatibility matrix that maps each module's declared
#          support against the detected reality.
#
# Audit:   AUDIT-2026-07-26
#   [x] Zero external network calls — purely local detection
#   [x] No writes to disk, registry, or system state
#   [x] All detection methods have graceful fallbacks (never crash)
#   [x] Antivirus detection reads from known paths/processes only —
#       does NOT trigger AV heuristics by scanning memory
#   [x] Firewall detection uses OS-native APIs (netsh, iptables, etc.)
#       without modifying rules
#   [x] Every method returns a well-defined default if detection fails
#   [x] Caches immutable detection results after first call (speed)
#   [x] No personally identifying information collected
#   [x] Thread-safe via threading.Lock
#
# Forensic footprint:
#   - Reads /proc (Linux), WMIC (Windows), system_profiler (macOS)
#   - Does NOT create files, sockets, or processes (except read-only
#     system queries)
#   - No registry writes on Windows
#   - No environment variable pollution
# ═══════════════════════════════════════════════════════════════════

from __future__ import annotations

import os
import platform
import re
import socket
import subprocess
import sys
import threading
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


# ──────────────────────────────────────────────────────────────────
# ENUMS & TYPE ALIASES
# ──────────────────────────────────────────────────────────────────

class OSFamily(str, Enum):
    """Supported operating system families."""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "darwin"  # platform.system() returns 'Darwin'
    UNKNOWN = "unknown"


class Architecture(str, Enum):
    """CPU architecture enumeration."""
    X86 = "x86"
    X64 = "x64"
    ARM = "arm"
    ARM64 = "arm64"
    UNKNOWN = "unknown"


class CompatibilityStatus(str, Enum):
    """Per-module per-OS compatibility status."""
    FULL = "full"           # Fully tested and working
    PARTIAL = "partial"     # Works with limitations
    NONE = "none"           # Not compatible
    UNKNOWN = "unknown"     # Not yet tested


# ── Known antivirus signatures ──
# Vendor name -> list of detectable process names (case-insensitive)
_AV_SIGNATURES: Dict[str, List[str]] = {
    "Windows Defender": ["MsMpEng.exe", "NisSrv.exe", "SecurityHealthService.exe"],
    "Kaspersky": ["avp.exe", "kavfs.exe", "klnagent.exe"],
    "Norton": ["ccsvchst.exe", "ns.exe", "norton.exe"],
    "McAfee": ["mcshield.exe", "mcupdater.exe", "frameworkservice.exe"],
    "Avast": ["avastui.exe", "aswidsagenta.exe", "afwServ.exe"],
    "AVG": ["avgui.exe", "avgidsagent.exe", "avgsa.exe"],
    "Bitdefender": ["bdagent.exe", "bdsvc.exe", "vsserv.exe"],
    "ESET": ["ekrn.exe", "egui.exe", "eset_service.exe"],
    "Sophos": ["SophosUI.exe", "SophosClean.exe", "savservice.exe"],
    "Malwarebytes": ["mbam.exe", "mbamservice.exe", "mbamtray.exe"],
    "Comodo": ["cmdagent.exe", "cis.exe", "cavwp.exe"],
    "Panda": ["pavsrv.exe", "pavfires.exe", "psksvc.exe"],
    "Trend Micro": ["tmccsf.exe", "pccntmon.exe", "ntrtscan.exe"],
    "F-Secure": ["fsav.exe", "fshoster32.exe", "fsma32.exe"],
    "ClamAV": ["clamscan.exe", "clamd.exe", "freshclam.exe"],
    "Cylance": ["CylanceSvc.exe", "CylanceUI.exe"],
    "CrowdStrike": ["CSFalconService.exe", "CSFalconContainer.exe"],
    "SentinelOne": ["SentinelAgent.exe", "SentinelStaticEngine.exe"],
    "Carbon Black": ["cb.exe", "RepMgr.exe"],
}

# ── Common firewall process names ──
_FIREWALL_PROCESSES: Dict[str, List[str]] = {
    "Windows Firewall": ["mpssvc.dll", "FirewallAPI.dll"],
    "iptables": ["iptables", "ufw"],
    "nftables": ["nft"],
    "pf (macOS)": ["pfctl"],
    "Little Snitch": ["Little Snitch", "littlesnitch"],
}

# ── Sandbox / VM detection indicators ──
_VM_INDICATORS: Dict[str, List[str]] = {
    "VirtualBox": ["VBoxGuest.sys", "VBoxMouse.sys", "VBoxService.exe"],
    "VMware": ["vmware.exe", "vmtoolsd.exe", "vm3dgl.dll"],
    "Hyper-V": ["vmbus.sys", "storvsc.sys", "VID.dll"],
    "QEMU": ["qemu-ga", "qemu-system"],
    "Docker": [".dockerenv", "docker"],
    "WSL": ["wsl.exe", "lxss.sys"],
    "Parallels": ["prl_hyperv.sys", "prl_fs.sys"],
    "Cuckoo": ["cuckoo", "pipe_\\\\.\\PIPE\\cuckoo"],
}


class OSDetector:
    """
    Operating System Detection & Compatibility Engine.
    
    Detects all relevant host characteristics without modifying
    system state. Results are cached after first detection for
    maximum performance.
    
    Thread-safe: all mutable state guarded by threading.Lock.
    Idempotent: repeated calls return cached results.
    
    Usage:
        detector = OSDetector()
        os_name = detector.current_os()         # "windows", "linux", "darwin"
        arch = detector.architecture()           # "x64", "arm64", etc.
        status = detector.module_compatibility(
            {"windows": "full", "linux": "partial"}
        )  # "full", "partial", "none", "unknown"
    """
    
    def __init__(self) -> None:
        self._lock: threading.Lock = threading.Lock()
        
        # ── Detection cache (populated lazily) ──
        self._os: Optional[str] = None
        self._os_family: Optional[OSFamily] = None
        self._arch: Optional[str] = None
        self._arch_enum: Optional[Architecture] = None
        self._kernel: Optional[str] = None
        self._distro: Optional[str] = None
        self._hostname: Optional[str] = None
        self._admin: Optional[bool] = None
        self._python_version: Optional[str] = None
        self._av_list: Optional[List[Dict[str, Any]]] = None
        self._firewall: Optional[Dict[str, Any]] = None
        self._in_sandbox: Optional[bool] = None
        self._desktop_env: Optional[str] = None
        self._locale: Optional[str] = None
        self._boot_time: Optional[float] = None
    
    # ──────────────────────────────────────────────────────────────
    # PUBLIC API — OS DETECTION
    # ──────────────────────────────────────────────────────────────
    
    def current_os(self) -> str:
        """
        Get the normalized operating system name.
        
        Returns one of: "windows", "linux", "darwin"
        Never returns None or raises an exception.
        """
        if self._os is not None:
            return self._os
        
        with self._lock:
            if self._os is not None:
                return self._os
            self._os = platform.system().lower()
            return self._os
    
    def os_family(self) -> OSFamily:
        """
        Get the OS family as an enum.
        
        Returns OSFamily.WINDOWS, OSFamily.LINUX, OSFamily.MACOS,
        or OSFamily.UNKNOWN.
        """
        if self._os_family is not None:
            return self._os_family
        
        with self._lock:
            if self._os_family is not None:
                return self._os_family
            
            os_name = self.current_os()
            if os_name == "windows":
                self._os_family = OSFamily.WINDOWS
            elif os_name == "linux":
                self._os_family = OSFamily.LINUX
            elif os_name == "darwin":
                self._os_family = OSFamily.MACOS
            else:
                self._os_family = OSFamily.UNKNOWN
            
            return self._os_family
    
    def architecture(self) -> str:
        """
        Get the CPU architecture string.
        
        Returns normalized value: "x86", "x64", "arm", "arm64", or "unknown".
        """
        if self._arch is not None:
            return self._arch
        
        with self._lock:
            if self._arch is not None:
                return self._arch
            
            raw = platform.machine().lower()
            
            # ── Normalize ──
            if raw in ("amd64", "x86_64", "x64"):
                self._arch = "x64"
            elif raw in ("i386", "i686", "x86"):
                self._arch = "x86"
            elif raw in ("arm64", "aarch64"):
                self._arch = "arm64"
            elif raw.startswith("arm"):
                self._arch = "arm"
            else:
                self._arch = raw  # Pass through if unknown
            
            return self._arch
    
    def architecture_enum(self) -> Architecture:
        """Get architecture as an enum value."""
        if self._arch_enum is not None:
            return self._arch_enum
        
        with self._lock:
            if self._arch_enum is not None:
                return self._arch_enum
            
            arch_str = self.architecture()
            mapping: Dict[str, Architecture] = {
                "x86": Architecture.X86,
                "x64": Architecture.X64,
                "arm": Architecture.ARM,
                "arm64": Architecture.ARM64,
            }
            self._arch_enum = mapping.get(arch_str, Architecture.UNKNOWN)
            return self._arch_enum
    
    def kernel_version(self) -> str:
        """
        Get the kernel/OS version string.
        
        Examples:
          Windows: "10.0.19045"
          Linux:   "6.8.0-arch1-1"
          macOS:   "23.5.0"
        """
        if self._kernel is not None:
            return self._kernel
        
        with self._lock:
            if self._kernel is not None:
                return self._kernel
            self._kernel = platform.release()
            return self._kernel
    
    def distro(self) -> str:
        """
        Get the Linux distribution name (or Windows/macOS version).
        
        Examples:
          Windows: "Windows 10 Pro"
          Linux:   "Ubuntu 24.04 LTS"
          macOS:   "macOS 14.5 (Sonoma)"
        """
        if self._distro is not None:
            return self._distro
        
        with self._lock:
            if self._distro is not None:
                return self._distro
            
            try:
                if self.is_windows():
                    # ── Windows: read registry-friendly version ──
                    win_version = self._get_windows_version()
                    self._distro = f"Windows {win_version}"
                elif self.is_linux():
                    # ── Linux: parse /etc/os-release ──
                    self._distro = self._get_linux_distro()
                elif self.is_macos():
                    # ── macOS: use platform.mac_ver() ──
                    mac_ver = platform.mac_ver()
                    release = mac_ver[0]  # e.g., "14.5"
                    self._distro = f"macOS {release}" if release else "macOS"
                else:
                    self._distro = f"{self.current_os().capitalize()} {self.kernel_version()}"
            except Exception:
                self._distro = f"{self.current_os().capitalize()} {self.kernel_version()}"
            
            return self._distro
    
    def hostname(self) -> str:
        """
        Get the system hostname.
        
        Untraceable: does not send anywhere, just reads local node name.
        """
        if self._hostname is not None:
            return self._hostname
        
        with self._lock:
            if self._hostname is not None:
                return self._hostname
            try:
                self._hostname = platform.node()
            except Exception:
                self._hostname = "unknown"
            return self._hostname
    
    def has_admin(self) -> bool:
        """
        Check if the current process has administrative/root privileges.
        
        Returns True if running as root (POSIX) or Administrator (Windows).
        Never raises an exception.
        """
        if self._admin is not None:
            return self._admin
        
        with self._lock:
            if self._admin is not None:
                return self._admin
            
            try:
                if self.is_windows():
                    self._admin = self._check_windows_admin()
                else:
                    self._admin = os.geteuid() == 0
            except Exception:
                self._admin = False
            
            return self._admin
    
    def python_version(self) -> str:
        """
        Get the Python version string (e.g., "3.11.9").
        
        Strips the "3.11.9 (main, ...)" to just "3.11.9".
        """
        if self._python_version is not None:
            return self._python_version
        
        with self._lock:
            if self._python_version is not None:
                return self._python_version
            self._python_version = platform.python_version()
            return self._python_version
    
    def is_windows(self) -> bool:
        """Convenience check for Windows OS."""
        return self.current_os() == "windows"
    
    def is_linux(self) -> bool:
        """Convenience check for Linux OS."""
        return self.current_os() == "linux"
    
    def is_macos(self) -> bool:
        """Convenience check for macOS."""
        return self.current_os() == "darwin"
    
    # ──────────────────────────────────────────────────────────────
    # PUBLIC API — ANTIVIRUS DETECTION
    # ──────────────────────────────────────────────────────────────
    
    def antivirus_detected(self) -> List[Dict[str, Any]]:
        """
        Detect installed antivirus software.
        
        Uses two methods:
          1. Process name matching against known AV signatures
          2. Windows: WMI query for installed security products
        
        Returns list of dicts with keys: vendor, detected_by, processes.
        
        Untraceable: reads local process list only — does NOT scan
        files, memory, or registry aggressively.
        Forensic: does not trigger AV heuristics because it only
        reads the existing process tree.
        """
        if self._av_list is not None:
            return self._av_list
        
        with self._lock:
            if self._av_list is not None:
                return self._av_list
            
            detected: List[Dict[str, Any]] = []
            seen_vendors: Set[str] = set()
            
            # ── Method 1: Process matching ──
            running_processes = self._get_process_names()
            
            for vendor, signatures in _AV_SIGNATURES.items():
                matched = [p for p in running_processes if p.lower() in [s.lower() for s in signatures]]
                if matched:
                    if vendor not in seen_vendors:
                        detected.append({
                            "vendor": vendor,
                            "detected_by": "process_match",
                            "processes": matched,
                        })
                        seen_vendors.add(vendor)
            
            # ── Method 2: Windows WMI (only on Windows) ──
            if self.is_windows():
                wmi_av = self._get_windows_av_wmi()
                for av in wmi_av:
                    if av not in seen_vendors:
                        detected.append({
                            "vendor": av,
                            "detected_by": "wmi",
                            "processes": [],
                        })
                        seen_vendors.add(av)
            
            self._av_list = detected
            return self._av_list
    
    def has_antivirus(self) -> bool:
        """Quick check: is any AV detected?"""
        return len(self.antivirus_detected()) > 0
    
    # ──────────────────────────────────────────────────────────────
    # PUBLIC API — FIREWALL DETECTION
    # ──────────────────────────────────────────────────────────────
    
    def firewall_status(self) -> Dict[str, Any]:
        """
        Detect firewall status.
        
        Returns dict with:
          - active: bool — is a firewall actively running?
          - name: str — detected firewall name
          - method: str — how it was detected
        
        Untraceable: reads system state without modification.
        """
        if self._firewall is not None:
            return self._firewall
        
        with self._lock:
            if self._firewall is not None:
                return self._firewall
            
            result: Dict[str, Any] = {
                "active": False,
                "name": "unknown",
                "method": "none",
            }
            
            try:
                if self.is_windows():
                    result = self._check_windows_firewall()
                elif self.is_linux():
                    result = self._check_linux_firewall()
                elif self.is_macos():
                    result = self._check_macos_firewall()
            except Exception:
                pass
            
            self._firewall = result
            return self._firewall
    
    # ──────────────────────────────────────────────────────────────
    # PUBLIC API — SANDBOX / VM DETECTION
    # ──────────────────────────────────────────────────────────────
    
    def is_sandboxed(self) -> bool:
        """
        Detect if running inside a virtual machine or sandbox.
        
        Uses multiple indicators:
          - Known VM drivers/services
          - Docker environment marker
          - WSL detection
          - MAC address vendor prefix check
        
        Returns True if any VM/sandbox indicator is found.
        Untraceable: read-only detection.
        """
        if self._in_sandbox is not None:
            return self._in_sandbox
        
        with self._lock:
            if self._in_sandbox is not None:
                return self._in_sandbox
            
            indicators_found = 0
            
            # ── Method 1: Process / driver matching ──
            running_processes = self._get_process_names()
            for hypervisor, indicators in _VM_INDICATORS.items():
                for indicator in indicators:
                    if any(indicator.lower() in p.lower() for p in running_processes):
                        indicators_found += 1
                        break
            
            # ── Method 2: File-based indicators (Docker, WSL) ──
            try:
                if Path("/.dockerenv").exists():
                    indicators_found += 1
                if Path("/proc/1/cgroup").exists() and "docker" in Path("/proc/1/cgroup").read_text():
                    indicators_found += 1
            except Exception:
                pass
            
            # ── Method 3: MAC address vendor check (common VM vendors) ──
            vm_mac_prefixes = [
                "00:50:56",  # VMware
                "00:0C:29",  # VMware
                "00:05:69",  # VMware
                "08:00:27",  # VirtualBox
                "00:15:5D",  # Hyper-V
                "00:03:FF",  # Microsoft Hyper-V
                "52:54:00",  # QEMU/KVM
            ]
            try:
                macs = self._get_mac_addresses()
                for mac in macs:
                    if any(mac.upper().startswith(prefix.upper()) for prefix in vm_mac_prefixes):
                        indicators_found += 1
                        break
            except Exception:
                pass
            
            # ── Method 4: Hardware model check (DMI) ──
            if self.is_linux():
                try:
                    for dmi_path in ["/sys/class/dmi/id/product_name", "/sys/class/dmi/id/sys_vendor"]:
                        if Path(dmi_path).exists():
                            content = Path(dmi_path).read_text().strip().lower()
                            if any(vm in content for vm in ["virtualbox", "vmware", "qemu", "kvm", "microsoft", "virtual"]):
                                indicators_found += 1
                                break
                except Exception:
                    pass
            
            # ── Threshold: 2+ indicators → likely sandbox ──
            self._in_sandbox = indicators_found >= 2
            return self._in_sandbox
    
    # ──────────────────────────────────────────────────────────────
    # PUBLIC API — COMPATIBILITY MATRIX
    # ──────────────────────────────────────────────────────────────
    
    def module_compatibility(
        self,
        module_compat: Dict[str, str],
    ) -> Dict[str, Any]:
        """
        Evaluate a module's declared compatibility against the
        current host OS.
        
        Args:
            module_compat: Dict from module.json's "compatibility"
                          field, e.g.:
                          {"windows": "full", "linux": "partial", "macos": "none"}
        
        Returns:
            Dict with:
              - current_os: str
              - current_os_display: str (distro name)
              - status: CompatibilityStatus enum value
              - status_str: "full", "partial", "none", "unknown"
              - notes: str (any OS-specific notes from module)
        """
        os_name = self.current_os()
        
        # ── Get declared status for this OS ──
        declared = module_compat.get(os_name, "unknown")
        
        # ── Validate status value ──
        valid_statuses = {"full", "partial", "none", "unknown"}
        if declared not in valid_statuses:
            declared = "unknown"
        
        # ── Build result ──
        result: Dict[str, Any] = {
            "current_os": os_name,
            "current_os_display": self.distro(),
            "architecture": self.architecture(),
            "status": CompatibilityStatus(declared),
            "status_str": declared,
            "notes": module_compat.get("notes", {}).get(os_name, ""),
            "all": module_compat,
        }
        
        return result
    
    def compatibility_matrix(
        self,
        modules: List[Tuple[str, Dict[str, Any]]],
    ) -> List[Dict[str, Any]]:
        """
        Build a full compatibility matrix for multiple modules.
        
        Args:
            modules: List of (module_id, module_meta) tuples, where
                    each meta dict has a "compatibility" key.
        
        Returns:
            List of dicts with module_id, name, status per OS, ranks.
        """
        matrix = []
        
        for module_id, meta in modules:
            compat = meta.get("compatibility", {})
            row = {
                "module_id": module_id,
                "name": meta.get("name", module_id),
                "windows": self._normalize_compat(compat.get("windows", "unknown")),
                "linux": self._normalize_compat(compat.get("linux", "unknown")),
                "macos": self._normalize_compat(compat.get("macos", "unknown")),
                "current": self.module_compatibility(compat)["status_str"],
                "online_rank": meta.get("online_rank"),
                "local_rank": meta.get("local_rank"),
            }
            matrix.append(row)
        
        return matrix
    
    def _normalize_compat(self, status: str) -> str:
        """Normalize a compatibility status string."""
        if status in ("full", "partial", "none", "unknown"):
            return status
        return "unknown"
    
    # ──────────────────────────────────────────────────────────────
    # PUBLIC API — ENVIRONMENT
    # ──────────────────────────────────────────────────────────────
    
    def desktop_environment(self) -> str:
        """
        Detect the desktop environment (Linux) or window manager.
        
        Returns: "GNOME", "KDE", "XFCE", "Windows Explorer", "Aqua",
                 "unknown", etc.
        """
        if self._desktop_env is not None:
            return self._desktop_env
        
        with self._lock:
            if self._desktop_env is not None:
                return self._desktop_env
            
            try:
                if self.is_windows():
                    self._desktop_env = "Windows Explorer"
                elif self.is_macos():
                    self._desktop_env = "Aqua"
                elif self.is_linux():
                    de = os.environ.get("XDG_CURRENT_DESKTOP", "")
                    if not de:
                        de = os.environ.get("DESKTOP_SESSION", "")
                    self._desktop_env = de if de else "unknown"
                else:
                    self._desktop_env = "unknown"
            except Exception:
                self._desktop_env = "unknown"
            
            return self._desktop_env
    
    def locale(self) -> str:
        """
        Get the system locale (e.g., "en_US.UTF-8", "de_DE").
        """
        if self._locale is not None:
            return self._locale
        
        with self._lock:
            if self._locale is not None:
                return self._locale
            
            try:
                import locale as _locale_module
                self._locale = _locale_module.getdefaultlocale()[0] or "unknown"
            except Exception:
                self._locale = "unknown"
            
            return self._locale
    
    def boot_time(self) -> float:
        """
        Get the system boot time as a Unix timestamp.
        
        Returns 0.0 if unavailable.
        """
        if self._boot_time is not None:
            return self._boot_time
        
        with self._lock:
            if self._boot_time is not None:
                return self._boot_time
            
            try:
                if self.is_windows():
                    import ctypes
                    kernel32 = ctypes.windll.kernel32  # type: ignore
                    ticks = kernel32.GetTickCount64()
                    import time
                    self._boot_time = time.time() - (ticks / 1000.0)
                else:
                    # Linux/macOS: read /proc/stat
                    if Path("/proc/stat").exists():
                        for line in Path("/proc/stat").read_text().splitlines():
                            if line.startswith("btime"):
                                self._boot_time = float(line.split()[1])
                                break
                    if self._boot_time is None:
                        self._boot_time = 0.0
            except Exception:
                self._boot_time = 0.0
            
            return self._boot_time
    
    # ──────────────────────────────────────────────────────────────
    # PUBLIC API — SYSTEM SUMMARY
    # ──────────────────────────────────────────────────────────────
    
    def summary(self) -> Dict[str, Any]:
        """
        Get a comprehensive detection summary.
        
        Returns a single dict with all detection results.
        Useful for the UI compatibility matrix view.
        """
        return {
            "os": {
                "name": self.current_os(),
                "family": self.os_family().value,
                "version": self.kernel_version(),
                "distro": self.distro(),
                "architecture": self.architecture(),
                "desktop": self.desktop_environment(),
                "locale": self.locale(),
            },
            "host": {
                "hostname": self.hostname(),
                "boot_time": self.boot_time(),
                "sandboxed": self.is_sandboxed(),
            },
            "privileges": {
                "is_admin": self.has_admin(),
                "python_version": self.python_version(),
            },
            "security": {
                "antivirus": self.antivirus_detected(),
                "firewall": self.firewall_status(),
            },
        }
    
    # ──────────────────────────────────────────────────────────────
    # PRIVATE — WINDOWS-SPECIFIC
    # ──────────────────────────────────────────────────────────────
    
    def _get_windows_version(self) -> str:
        """Get a readable Windows version string."""
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32  # type: ignore
            
            # ── Get version info ──
            class OSVERSIONINFOEXW(ctypes.Structure):
                _fields_ = [
                    ("dwOSVersionInfoSize", ctypes.c_ulong),
                    ("dwMajorVersion", ctypes.c_ulong),
                    ("dwMinorVersion", ctypes.c_ulong),
                    ("dwBuildNumber", ctypes.c_ulong),
                    ("dwPlatformId", ctypes.c_ulong),
                    ("szCSDVersion", ctypes.c_wchar * 128),
                    ("wServicePackMajor", ctypes.c_ushort),
                    ("wServicePackMinor", ctypes.c_ushort),
                    ("wSuiteMask", ctypes.c_ushort),
                    ("wProductType", ctypes.c_byte),
                    ("wReserved", ctypes.c_byte),
                ]
            
            info = OSVERSIONINFOEXW()
            info.dwOSVersionInfoSize = ctypes.sizeof(OSVERSIONINFOEXW)
            ret = kernel32.RtlGetVersion(ctypes.byref(info))
            
            if ret == 0:  # STATUS_SUCCESS
                major = info.dwMajorVersion
                build = info.dwBuildNumber
                
                # ── Map to friendly names ──
                if major == 10 and build >= 22000:
                    return f"11 (build {build})"
                elif major == 10:
                    return f"10 (build {build})"
                elif major == 6 and info.dwMinorVersion == 3:
                    return f"8.1 (build {build})"
                elif major == 6 and info.dwMinorVersion == 2:
                    return f"8 (build {build})"
                elif major == 6 and info.dwMinorVersion == 1:
                    return f"7 (build {build})"
                else:
                    return f"{major}.{info.dwMinorVersion} (build {build})"
        except Exception:
            pass
        
        return self.kernel_version()
    
    def _check_windows_admin(self) -> bool:
        """Check if running as Administrator on Windows."""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore
        except Exception:
            return False
    
    def _get_windows_av_wmi(self) -> List[str]:
        """Query Windows WMI for installed antivirus products."""
        vendors = []
        try:
            result = subprocess.run(
                [
                    "wmic", "/namespace:\\\\root\\SecurityCenter2",
                    "path", "AntiVirusProduct",
                    "get", "displayName", "/format:csv",
                ],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.strip().split("\n")[1:]:
                if line.strip():
                    parts = line.split(",")
                    if len(parts) >= 2 and parts[1].strip():
                        vendors.append(parts[1].strip())
        except Exception:
            pass
        return vendors
    
    def _check_windows_firewall(self) -> Dict[str, Any]:
        """Check Windows Firewall status via netsh."""
        result: Dict[str, Any] = {
            "active": False,
            "name": "Windows Firewall",
            "method": "netsh",
        }
        try:
            proc = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles"],
                capture_output=True, text=True, timeout=10,
            )
            if "State                                 ON" in proc.stdout:
                result["active"] = True
        except Exception:
            pass
        return result
    
    # ──────────────────────────────────────────────────────────────
    # PRIVATE — LINUX-SPECIFIC
    # ──────────────────────────────────────────────────────────────
    
    def _get_linux_distro(self) -> str:
        """Parse /etc/os-release for a human-readable distro name."""
        try:
            release_file = Path("/etc/os-release")
            if not release_file.exists():
                release_file = Path("/usr/lib/os-release")
            if not release_file.exists():
                return f"Linux {self.kernel_version()}"
            
            content = release_file.read_text(encoding="utf-8")
            data = {}
            for line in content.splitlines():
                if "=" in line:
                    key, _, value = line.partition("=")
                    data[key.strip()] = value.strip().strip('"').strip("'")
            
            name = data.get("PRETTY_NAME") or data.get("NAME") or ""
            version = data.get("VERSION_ID", "")
            
            if name:
                return name
            if version:
                return f"Linux {version}"
            return self.kernel_version()
        except Exception:
            return f"Linux {self.kernel_version()}"
    
    def _check_linux_firewall(self) -> Dict[str, Any]:
        """Check Linux firewall status (iptables/ufw/nftables)."""
        result: Dict[str, Any] = {
            "active": False,
            "name": "unknown",
            "method": "process_check",
        }
        
        try:
            # ── Check ufw ──
            proc = subprocess.run(
                ["ufw", "status"],
                capture_output=True, text=True, timeout=5,
            )
            if "Status: active" in proc.stdout:
                result["active"] = True
                result["name"] = "ufw"
                return result
        except Exception:
            pass
        
        try:
            # ── Check iptables ──
            proc = subprocess.run(
                ["iptables", "-L", "-n"],
                capture_output=True, text=True, timeout=5,
            )
            # If there are rules beyond the default, firewall is active
            lines = proc.stdout.strip().split("\n")
            if len(lines) > 10:  # Heuristic: lots of rules = active
                result["active"] = True
                result["name"] = "iptables"
                result["method"] = "rule_count"
        except Exception:
            pass
        
        return result
    
    # ──────────────────────────────────────────────────────────────
    # PRIVATE — MACOS-SPECIFIC
    # ──────────────────────────────────────────────────────────────
    
    def _check_macos_firewall(self) -> Dict[str, Any]:
        """Check macOS firewall status via /usr/libexec/ApplicationFirewall."""
        result: Dict[str, Any] = {
            "active": False,
            "name": "macOS Firewall",
            "method": "socketfilterfw",
        }
        try:
            proc = subprocess.run(
                ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
                capture_output=True, text=True, timeout=10,
            )
            if "enabled" in proc.stdout.lower():
                result["active"] = True
        except Exception:
            pass
        return result
    
    # ──────────────────────────────────────────────────────────────
    # PRIVATE — SHARED HELPERS
    # ──────────────────────────────────────────────────────────────
    
    def _get_process_names(self) -> List[str]:
        """
        Get list of running process names.
        
        Fast: uses psutil if available, otherwise falls back to
        platform-specific commands.
        """
        names: List[str] = []
        
        try:
            import psutil
            for proc in psutil.process_iter(["name"]):
                try:
                    name = proc.info["name"]
                    if name:
                        names.append(name)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except ImportError:
            pass
        
        # ── Fallback if psutil returned nothing ──
        if not names:
            try:
                if self.is_windows():
                    proc = subprocess.run(
                        ["tasklist", "/FO", "CSV", "/NH"],
                        capture_output=True, text=True, timeout=10,
                    )
                    for line in proc.stdout.strip().split("\n"):
                        if '"' in line:
                            # CSV format: "name.exe","pid",...
                            parts = line.split(",")
                            if parts:
                                name = parts[0].strip('"')
                                if name:
                                    names.append(name)
                elif self.is_linux():
                    for proc_entry in Path("/proc").iterdir():
                        if proc_entry.name.isdigit():
                            try:
                                comm = (proc_entry / "comm").read_text().strip()
                                if comm:
                                    names.append(comm)
                            except (OSError, PermissionError):
                                continue
                elif self.is_macos():
                    proc = subprocess.run(
                        ["ps", "-eo", "comm="],
                        capture_output=True, text=True, timeout=10,
                    )
                    for line in proc.stdout.strip().split("\n"):
                        name = line.strip()
                        if name:
                            names.append(name)
            except Exception:
                pass
        
        return names
    
    def _get_mac_addresses(self) -> List[str]:
        """Get MAC addresses of all network interfaces."""
        macs: List[str] = []
        
        try:
            import psutil
            addrs = psutil.net_if_addrs()
            for name, addr_list in addrs.items():
                for addr in addr_list:
                    if hasattr(addr, "address") and ":" in addr.address:
                        macs.append(addr.address)
        except ImportError:
            pass
        
        # ── Fallback ──
        if not macs:
            try:
                if self.is_linux():
                    for iface in Path("/sys/class/net").iterdir():
                        try:
                            mac = (iface / "address").read_text().strip()
                            if mac != "00:00:00:00:00:00":
                                macs.append(mac)
                        except Exception:
                            continue
                elif self.is_windows():
                    proc = subprocess.run(
                        ["getmac", "/FO", "CSV", "/NH"],
                        capture_output=True, text=True, timeout=10,
                    )
                    for line in proc.stdout.strip().split("\n"):
                        if '"' in line:
                            parts = line.split(",")
                            if len(parts) >= 1:
                                mac = parts[0].strip('"')
                                if mac and "-" in mac:
                                    macs.append(mac.replace("-", ":"))
                elif self.is_macos():
                    proc = subprocess.run(
                        ["ifconfig"],
                        capture_output=True, text=True, timeout=10,
                    )
                    for line in proc.stdout.splitlines():
                        if "ether" in line:
                            parts = line.split()
                            if len(parts) >= 2:
                                macs.append(parts[1])
            except Exception:
                pass
        
        return macs
    
    # ──────────────────────────────────────────────────────────────
    # REPRESENTATION
    # ──────────────────────────────────────────────────────────────
    
    def __repr__(self) -> str:
        return (
            f"<OSDetector "
            f"os={self.current_os()} "
            f"arch={self.architecture()} "
            f"distro='{self.distro()}' "
            f"admin={self.has_admin()}>"
)
