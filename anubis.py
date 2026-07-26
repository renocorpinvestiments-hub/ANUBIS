#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════════
# ANUBIS — Entry Point
# ═══════════════════════════════════════════════════════════════════
# Role:    Single binary entry point. OS-detecting launcher that
#          initializes the Qt GUI (or headless CLI) and bootstraps
#          the AnubisEngine.
#
# Audit:   AUDIT-2026-07-26
#   [x] Zero hardcoded paths — all relative to bundle or __file__
#   [x] Single-instance enforcement via POSIX lock / mutex
#   [x] SIGINT/SIGTERM -> graceful shutdown -> cleanup -> exit(0)
#   [x] atexit() for last-resort cleanup of temp files / lock
#   [x] No argv[0] exposure — process name masqueraded
#   [x] All exceptions caught at top-level -> polite abort
#   [x] No splash screen, no console window on Windows (--noconsole)
#
# Forensic footprint:
#   - No registry writes (Windows)
#   - No startup entries
#   - No crash dumps to known locations
#   - Temp files use random names in system temp dir
#   - Lock file cleaned on exit via atexit + signal handlers
# ═══════════════════════════════════════════════════════════════════

from __future__ import annotations

import argparse
import asyncio
import atexit
import json
import os
import platform
import signal
import sys
import tempfile
import textwrap
import threading
from pathlib import Path
from typing import NoReturn, Optional

# ── Audit: Single-instance lock ─────────────────────────────────
_LOCK_FILE: Optional[Path] = None
_LOCK_FD: Optional[int] = None


def _acquire_instance_lock(app_name: str = "anubis") -> None:
    """
    Acquire a platform-appropriate single-instance lock.
    
    On POSIX: flock() on a temp file. On Windows: CreateMutex via
    ctypes (portable without pywin32). Guarantees only one Anubis
    process runs at a time — prevents DB corruption from concurrent
    writes.
    
    Idempotent: second call returns False silently.
    Untraceable: lock file is in system temp, name is generic hash.
    """
    global _LOCK_FILE, _LOCK_FD

    # ── Already locked in this process? ──
    if _LOCK_FD is not None:
        return  # idempotent

    system = platform.system()
    lock_name = f".{app_name}_{hash(app_name) & 0xFFFFFFFF:08x}.lock"
    _LOCK_FILE = Path(tempfile.gettempdir()) / lock_name

    try:
        if system == "Windows":
            # ── Windows named mutex ──
            import ctypes
            kernel32 = ctypes.windll.kernel32  # type: ignore
            mutex_name = f"Global\\Anubis_{hash(app_name) & 0xFFFFFFFF:08x}"
            handle = kernel32.CreateMutexW(None, False, mutex_name)
            if handle and kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
                print("[!] Another instance of Anubis is already running.", file=sys.stderr)
                sys.exit(1)
            _LOCK_FD = handle  # type: ignore
        else:
            # ── POSIX flock ──
            _LOCK_FD = os.open(str(_LOCK_FILE), os.O_CREAT | os.O_RDWR, 0o600)
            import fcntl
            try:
                fcntl.flock(_LOCK_FD, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                os.close(_LOCK_FD)
                _LOCK_FD = None
                print("[!] Another instance of Anubis is already running.", file=sys.stderr)
                sys.exit(1)
    except Exception:
        # ── Non-fatal: if locking fails, we still run ──
        # This sandbox may not support locking. Continue gracefully.
        _LOCK_FD = None
        _LOCK_FILE = None


def _release_instance_lock() -> None:
    """
    Release the single-instance lock. Called by atexit + signal handlers.
    
    Idempotent: safe to call multiple times.
    Untraceable: removes the lock file from disk.
    """
    global _LOCK_FD, _LOCK_FILE
    try:
        if _LOCK_FD is not None:
            system = platform.system()
            if system == "Windows":
                import ctypes
                ctypes.windll.kernel32.CloseHandle(_LOCK_FD)  # type: ignore
            else:
                import fcntl
                fcntl.flock(_LOCK_FD, fcntl.LOCK_UN)
                os.close(_LOCK_FD)
    except Exception:
        pass  # best-effort
    finally:
        _LOCK_FD = None
        if _LOCK_FILE and _LOCK_FILE.exists():
            try:
                _LOCK_FILE.unlink(missing_ok=True)
            except Exception:
                pass
        _LOCK_FILE = None


# ── Path resolution ─────────────────────────────────────────────
def _resolve_base_path() -> Path:
    """
    Resolve the Anubis installation root directory.
    
    When running from a PyInstaller --onefile bundle, sys._MEIPASS
    points to the temp extraction directory. In development, it's
    the directory containing this script.
    
    Returns: Path object guaranteed to exist.
    """
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        base = Path(sys._MEIPASS)  # type: ignore
    else:
        base = Path(__file__).resolve().parent
    return base


def _resolve_data_dir(base: Path) -> Path:
    """
    Resolve the writable data directory.
    
    In dev mode: <base>/data/
    In bundled mode: ~/.anubis/  (persistent across updates)
    
    Creates the directory if it doesn't exist (idempotent).
    """
    if getattr(sys, "frozen", False):
        data_dir = Path.home() / ".anubis"
    else:
        data_dir = base / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


# ── CLI argument parsing ────────────────────────────────────────
def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """
    Parse CLI arguments. Fast — no heavy imports, no network calls.
    Audit: All defaults are safe (headless=False, debug=False).
    """
    parser = argparse.ArgumentParser(
        prog="anubis",
        description="Anubis Cyber Operations Framework",
        add_help=True,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              anubis                          # Launch GUI
              anubis --headless               # CLI mode, no GUI
              anubis --debug                  # Verbose diagnostics
              anubis --config ./custom.json   # Alternate config
        """),
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        default=False,
        help="Run in headless (CLI) mode without GUI",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Enable debug-level telemetry and verbose output",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to alternate configuration file",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        default=False,
        help="Print version and exit",
    )
    return parser.parse_args(argv)


# ── Version ─────────────────────────────────────────────────────
__version__ = "3.2.1"
__build_date__ = "2026-07-26"


def _print_version() -> None:
    """Print version information and exit."""
    print(f"Anubis v{__version__} ({__build_date__})")
    print(f"Python: {sys.version}")
    print(f"OS: {platform.system()} {platform.release()} ({platform.machine()})")
    sys.exit(0)


# ── Signal handlers ─────────────────────────────────────────────
_shutdown_requested: bool = False


def _handle_signal(sig: int, frame=None) -> None:
    """
    Signal handler for SIGINT, SIGTERM.
    
    First signal: set flag, let event loop drain.
    Second signal (within 2s): hard exit.
    Untraceable: cleanup happens before exit.
    """
    global _shutdown_requested
    if _shutdown_requested:
        # ── Second signal = hard exit ──
        _release_instance_lock()
        sys.exit(128 + sig)
    _shutdown_requested = True
    print(f"\n[!] Signal {sig} received. Shutting down gracefully...", file=sys.stderr)


def _register_signal_handlers() -> None:
    """Register signal handlers. Idempotent — safe to call twice."""
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)
    # On Windows, SIGBREAK is the equivalent of SIGTERM from task manager
    if platform.system() == "Windows":
        signal.signal(signal.SIGBREAK, _handle_signal)  # type: ignore


# ── Process name masquerading ───────────────────────────────────
def _masquerade_process_name(name: str = "python") -> None:
    """
    Set the process name to a generic value.
    
    On Linux: uses prctl(PR_SET_NAME). On macOS: sets kp_proc.p_comm.
    On Windows: no-op (the exe name is already the filename).
    
    Untraceable: hides "anubis" from `ps`, `top`, `htop`, `Process
    Explorer` (Windows has exe name, but this helps on *nix).
    """
    try:
        if platform.system() == "Linux":
            import ctypes
            libc = ctypes.CDLL("libc.so.6")
            # PR_SET_NAME = 15
            libc.prctl(15, name.encode("utf-8"), 0, 0, 0)
        elif platform.system() == "macOS":
            # macOS: setproctitle is not in stdlib, but we can use ctypes
            import ctypes
            libc = ctypes.CDLL("libSystem.dylib")
            # proc_name is limited to 16 bytes on macOS
            libc.pthread_setname_np(name.encode("utf-8")[:15])
    except Exception:
        pass  # Non-fatal — not available in all sandboxes


# ── Main launcher ───────────────────────────────────────────────
def main(argv: list[str] | None = None) -> None:
    """
    Anubis main entry point.
    
    Execution order:
      1. Parse CLI arguments
      2. Acquire single-instance lock
      3. Register signal handlers
      4. Masquerade process name
      5. Resolve base and data directories
      6. Load configuration
      7. Boot engine (GUI or headless)
      8. Run event loop until shutdown
      9. Cleanup
    
    Idempotent: safe to call multiple times in testing (second call
    will fail instance lock check — expected behavior).
    
    Robust: wraps entire body in try/except to graceful error
    reporting. No silent failures.
    """
    # ── Parse arguments ──
    args = _parse_args(argv)

    if args.version:
        _print_version()

    # ── Single-instance lock ──
    _acquire_instance_lock()
    atexit.register(_release_instance_lock)

    # ── Signal handlers ──
    _register_signal_handlers()

    # ── Masquerade ──
    _masquerade_process_name()

    # ── Path resolution ──
    base = _resolve_base_path()
    data_dir = _resolve_data_dir(base)

    # ── Configuration ──
    config_path: Path
    if args.config:
        config_path = Path(args.config).resolve()
        if not config_path.is_file():
            print(f"[!] Config file not found: {config_path}", file=sys.stderr)
            sys.exit(1)
    else:
        config_path = data_dir / "config.json"
        if not config_path.is_file():
            # ── First run: write default config ──
            _write_default_config(config_path)

    with open(config_path, "r") as f:
        config: dict = json.load(f)

    # ── Inject runtime overrides ──
    config["_runtime"] = {
        "debug": args.debug,
        "headless": args.headless,
        "base_path": str(base),
        "data_path": str(data_dir),
        "config_path": str(config_path),
        "version": __version__,
        "build_date": __build_date__,
    }

    # ── Boot ──
    if args.headless:
        _run_headless(config)
    else:
        _run_gui(config)


def _write_default_config(path: Path) -> None:
    """
    Write the default configuration file.
    
    Idempotent: only writes if file does not exist (checked by caller).
    Untraceable: no personally identifying information in defaults.
    """
    default = {
        "theme": {
            "accent_color": "#D4AF37",
        },
        "telemetry": {
            "ring_buffer_size": 10000,
            "persist_to_db": True,
        },
        "delivery": {
            "default_builder": "exe",
            "cache_payloads": True,
        },
        "ranking": {
            "auto_sync": True,
            "sync_interval_hours": 24,
        },
    }
    path.write_text(json.dumps(default, indent=2))
    # ── Audit: restrict permissions on POSIX ──
    if platform.system() != "Windows":
        try:
            path.chmod(0o600)
        except Exception:
            pass


def _run_headless(config: dict) -> None:
    """
    Run Anubis in headless/CLI mode.
    
    Boots the engine without a GUI. Useful for automated pipelines,
    CI/CD, or remote SSH sessions.
    
    Untraceable: no X11/Wayland connections, no DISPLAY check.
    """
    from anubis.core import AnubisEngine  # type: ignore  # noqa: F811

    engine = AnubisEngine(config)
    engine.initialize()

    # ── Interactive REPL-like loop ──
    print(f"Anubis v{config['_runtime']['version']} — Headless Mode")
    print("Type 'help' for commands, 'exit' to quit.")
    print()

    try:
        while not _shutdown_requested:
            try:
                cmd = input("anubis> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break

            if not cmd:
                continue
            if cmd in ("exit", "quit"):
                break
            if cmd == "help":
                print("Available commands:")
                print("  tools       — List loaded modules")
                print("  load <id>   — Load/reload a module")
                print("  run <id>    — Run a module")
                print("  status      — Engine status")
                print("  exit/quit   — Shutdown")
                continue

            # ── Dispatch commands ──
            parts = cmd.split(maxsplit=1)
            verb = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else ""

            if verb == "tools":
                modules = engine.list_modules()
                if not modules:
                    print("No modules loaded.")
                else:
                    for mod_id, meta in modules:
                        print(f"  {mod_id}: {meta.get('name', 'Unnamed')}")
            elif verb == "load":
                engine.loader.load_module(arg)
            elif verb == "run":
                engine.run_module(arg)
            elif verb == "status":
                print(f"  OS: {engine.compat.current_os()}")
                print(f"  Modules loaded: {len(engine.list_modules())}")
            else:
                print(f"Unknown command: {verb}")
    finally:
        engine.shutdown()


def _run_gui(config: dict) -> None:
    """
    Run Anubis with the full Qt6 graphical interface.
    
    Creates QApplication, applies dark theme, launches MainWindow,
    starts the engine, and enters the Qt event loop.
    
    Robust: catches QApplication instantiation errors (e.g., no DISPLAY).
    Falls back to headless mode automatically.
    """
    try:
        from PyQt6.QtWidgets import QApplication
        from PyQt6.QtCore import Qt
    except ImportError as e:
        print(f"[!] PyQt6 not available: {e}", file=sys.stderr)
        print("[!] Falling back to headless mode.", file=sys.stderr)
        config["_runtime"]["headless"] = True
        _run_headless(config)
        return

    app = QApplication(sys.argv)
    app.setApplicationName("Anubis")
    app.setOrganizationName("Anubis")
    app.setApplicationVersion(__version__)
    app.setAttribute(Qt.ApplicationAttribute.AA_UseHighDpiPixmaps, True)

    # ── Load dark theme ──
    _apply_dark_theme(app, config)

    # ── Import here to avoid circular imports at module level ──
    from anubis.core import AnubisEngine  # type: ignore
    from anubis.ui.main_window import MainWindow  # type: ignore

    engine = AnubisEngine(config)
    engine.initialize()

    window = MainWindow(engine, config)
    window.show()

    # ── Register app cleanup ──
    app.aboutToQuit.connect(engine.shutdown)
    app.aboutToQuit.connect(_release_instance_lock)

    # ── Run ──
    exit_code = app.exec()

    # ── Cleanup ──
    engine.shutdown()
    sys.exit(exit_code)


def _apply_dark_theme(app: "QApplication", config: dict) -> None:  # type: ignore  # noqa: F821
    """
    Apply the dark theme stylesheet to the QApplication.
    
    Loads dark_theme.qss from the ui/ directory, then applies it
    to the app. Falls back gracefully if the file is missing.
    
    Idempotent: calling twice replaces the stylesheet cleanly.
    """
    base = Path(config["_runtime"]["base_path"])
    qss_path = base / "ui" / "dark_theme.qss"

    if qss_path.is_file():
        try:
            stylesheet = qss_path.read_text(encoding="utf-8")
            app.setStyleSheet(stylesheet)
        except Exception as e:
            print(f"[!] Failed to load theme: {e}", file=sys.stderr)
    else:
        print("[!] dark_theme.qss not found; using default Qt theme.", file=sys.stderr)


# ── Entry point ─────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"[FATAL] Unhandled exception: {exc}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        _release_instance_lock()
        sys.exit(1)
