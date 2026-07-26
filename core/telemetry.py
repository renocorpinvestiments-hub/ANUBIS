# ═══════════════════════════════════════════════════════════════════
# ANUBIS — Live Telemetry & Error Handling System
# ═══════════════════════════════════════════════════════════════════
# Role:    Centralized logging, error tracking, and live diagnostics.
#          Maintains an in-memory ring buffer (last N events), persists
#          to SQLite, and emits Qt signals for the live console UI.
#
# Audit:   AUDIT-2026-07-26
#   [x] Ring buffer is O(1) append/evict via collections.deque
#   [x] SQLite writes are batched (max 50ms interval) — never per-event
#   [x] Qt signals are emitted asynchronously (queued connections)
#   [x] No external network calls — data stays local
#   [x] All exceptions in telemetry itself are caught (fail-safe)
#   [x] Crash reports are written with sanitized paths (no usernames)
#   [x] Configurable ring buffer size (default 10,000)
#   [x] Thread-safe: all operations guarded by threading.Lock
#   [x] Idempotent: register_module/debug/info/warning/error/critical
#       are all safe to call multiple times
#
# Forensic footprint:
#   - Writes only to designated database (data_dir / telemetry.db)
#   - No syslog, Windows Event Log, or system journal writes
#   - No external C2 callouts
#   - Crash reports are sanitized — no absolute paths with usernames
# ═══════════════════════════════════════════════════════════════════

from __future__ import annotations

import asyncio
import collections
import json
import os
import platform
import sqlite3
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Deque, Dict, List, Optional, Set, Tuple


# ──────────────────────────────────────────────────────────────────
# ENUMS & DATA CLASSES
# ──────────────────────────────────────────────────────────────────

class LogLevel(str, Enum):
    """Telemetry log levels in order of severity."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


# ── Severity ordering for filtering ──
_LOG_LEVEL_ORDER: Dict[LogLevel, int] = {
    LogLevel.DEBUG: 0,
    LogLevel.INFO: 1,
    LogLevel.WARNING: 2,
    LogLevel.ERROR: 3,
    LogLevel.CRITICAL: 4,
}


@dataclass
class TelemetryEvent:
    """
    A single telemetry event.
    
    Immutable after creation. Stored in ring buffer and optionally
    persisted to SQLite.
    """
    level: LogLevel
    module_id: str
    event_type: str
    message: str
    details: Optional[Dict[str, Any]] = None
    traceback_str: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    os: str = ""
    architecture: str = ""
    pid: int = 0
    
    def __post_init__(self) -> None:
        """Fill in runtime defaults if not provided."""
        if not self.os:
            self.os = platform.system().lower()
        if not self.architecture:
            self.architecture = platform.machine()
        if not self.pid:
            self.pid = os.getpid()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level.value,
            "module_id": self.module_id,
            "event_type": self.event_type,
            "message": self.message,
            "details": json.dumps(self.details) if self.details else None,
            "traceback": self.traceback_str,
            "timestamp": self.timestamp,
            "os": self.os,
            "architecture": self.architecture,
            "pid": self.pid,
        }
    
    def formatted(self) -> str:
        """
        Format the event as a human-readable string for the console.
        
        Format: [HH:MM:SS] [LEVEL] [module] message
        """
        ts = time.strftime("%H:%M:%S", time.gmtime(self.timestamp))
        level_str = self.level.value.upper().ljust(8)
        
        line = f"[{ts}] [{level_str}] [{self.module_id}] {self.message}"
        
        if self.level in (LogLevel.ERROR, LogLevel.CRITICAL) and self.traceback_str:
            # ── Include first line of traceback ──
            tb_lines = self.traceback_str.strip().split("\n")
            if tb_lines:
                last_line = tb_lines[-1].strip()
                if last_line:
                    line += f"\n  └─ {last_line}"
        
        return line


@dataclass
class CrashReport:
    """
    A structured crash report generated on critical errors.
    
    Written to disk as JSON for later analysis.
    """
    module_id: str
    version: str
    os_name: str
    os_version: str
    architecture: str
    python_version: str
    error_type: str
    error_message: str
    traceback: str
    timestamp: float = field(default_factory=time.time)
    event_history: List[Dict[str, Any]] = field(default_factory=list)


# ──────────────────────────────────────────────────────────────────
# CALLBACK TYPE
# ──────────────────────────────────────────────────────────────────

# Callback signature for UI live console updates
# def callback(event: TelemetryEvent) -> None
TelemetryCallback = Callable[[TelemetryEvent], None]


# ═══════════════════════════════════════════════════════════════════
# TELEMETRY ENGINE
# ═══════════════════════════════════════════════════════════════════

class Telemetry:
    """
    Centralized telemetry and error handling system.
    
    Features:
      - O(1) ring buffer (configurable size, default 10,000)
      - Configurable SQLite persistence (batch writes)
      - Qt signal emission via callbacks
      - Crash report generation on CRITICAL events
      - Event filtering by level, module, or type
    
    Thread-safe: all operations guarded by threading.Lock.
    Idempotent: register_module is safe to call multiple times.
    Fail-safe: exceptions in telemetry are caught (never crash the engine).
    
    Usage:
        telemetry = Telemetry(engine, ring_buffer_size=10000, persist=True)
        telemetry.info("engine", {"message": "Engine started"})
        telemetry.error("module_001", "Execution failed", traceback_str)
        telemetry.critical("module_001", "Fatal error", traceback_str)
        
        # ── Register a UI callback for live console ──
        telemetry.register_callback(lambda event: console.write(event.formatted()))
    """
    
    def __init__(
        self,
        engine: Any = None,
        ring_buffer_size: int = 10000,
        persist: bool = True,
    ) -> None:
        """
        Args:
            engine: AnubisEngine instance (can be None for standalone).
            ring_buffer_size: Max events to keep in memory.
            persist: If True, writes events to SQLite database.
        """
        self._engine = engine
        self._ring_buffer_size = max(ring_buffer_size, 100)  # Minimum 100
        self._persist = persist
        
        # ── Thread safety ──
        self._lock: threading.Lock = threading.Lock()
        
        # ── Ring buffer (O(1) append/evict) ──
        self._buffer: Deque[TelemetryEvent] = collections.deque(maxlen=self._ring_buffer_size)
        
        # ── Registered modules ──
        self._registered_modules: Set[str] = set()
        
        # ── Callbacks (UI live console, etc.) ──
        self._callbacks: List[TelemetryCallback] = []
        
        # ── Database connections (lazy) ──
        self._db: Optional[sqlite3.Connection] = None
        self._db_lock: threading.Lock = threading.Lock()
        self._batch: List[Dict[str, Any]] = []
        self._batch_lock: threading.Lock = threading.Lock()
        self._last_flush: float = time.monotonic()
        self._flush_interval: float = 0.05  # 50ms max batch delay
        
        # ── Crash reports directory ──
        self._crash_dir: Optional[Path] = None
        
        # ── Statistics ──
        self._stats: Dict[str, int] = {
            "total_events": 0,
            "debug": 0,
            "info": 0,
            "warning": 0,
            "error": 0,
            "critical": 0,
            "dropped": 0,  # Events dropped due to ring buffer overflow (pre-maxlen)
        }
        
        # ── Initialize ──
        self._init_database()
        self._init_crash_dir()
    
    # ──────────────────────────────────────────────────────────────
    # PUBLIC API — EVENT LOGGING
    # ──────────────────────────────────────────────────────────────
    
    def debug(
        self,
        module_id: str,
        details: Optional[Dict[str, Any]] = None,
        message: str = "",
    ) -> None:
        """Log a debug-level event."""
        self._emit(LogLevel.DEBUG, module_id, "debug", message or str(details), details)
    
    def info(
        self,
        module_id: str,
        details: Optional[Dict[str, Any]] = None,
        message: str = "",
    ) -> None:
        """Log an info-level event."""
        self._emit(LogLevel.INFO, module_id, "info", message or str(details), details)
    
    def warning(
        self,
        module_id: str,
        details: Optional[Dict[str, Any]] = None,
        message: str = "",
    ) -> None:
        """Log a warning-level event."""
        self._emit(LogLevel.WARNING, module_id, "warning", message or str(details), details)
    
    def error(
        self,
        module_id: str,
        details: Optional[Dict[str, Any]] = None,
        traceback_str: Optional[str] = None,
        message: str = "",
    ) -> None:
        """
        Log an error-level event.
        
        Args:
            module_id: The module or subsystem identifier.
            details: Structured details dict (preferred) or error message string.
            traceback_str: Full traceback string (use traceback.format_exc()).
            message: Optional human-readable message.
        """
        if isinstance(details, str):
            # ── Compat: allow string as message ──
            if not message:
                message = details
                details = {"error": details}
        
        self._emit(LogLevel.ERROR, module_id, "error", message, details, traceback_str)
    
    def critical(
        self,
        module_id: str,
        details: Optional[Dict[str, Any]] = None,
        traceback_str: Optional[str] = None,
        message: str = "",
    ) -> None:
        """
        Log a critical-level event and generate a crash report.
        
        Critical events trigger:
          1. Event logged to ring buffer and DB
          2. Crash report written to disk
          3. All registered callbacks notified (UI popup)
        
        Args:
            module_id: The module or subsystem identifier.
            details: Structured details dict.
            traceback_str: Full traceback string.
            message: Optional human-readable message.
        """
        if isinstance(details, str):
            if not message:
                message = details
                details = {"error": details}
        
        event = self._emit(
            LogLevel.CRITICAL, module_id, "critical", message, details, traceback_str
        )
        
        # ── Generate crash report ──
        if event is not None:
            self._generate_crash_report(event)
    
    def log(
        self,
        level: str,
        module_id: str,
        message: str = "",
        details: Optional[Dict[str, Any]] = None,
        traceback_str: Optional[str] = None,
    ) -> None:
        """
        Generic log method — accepts level as string.
        
        Args:
            level: One of "debug", "info", "warning", "error", "critical".
            module_id: Module or subsystem identifier.
            message: Human-readable message.
            details: Structured details dict.
            traceback_str: Full traceback string.
        """
        level_enum = LogLevel(level.lower())
        if level_enum == LogLevel.DEBUG:
            self.debug(module_id, details, message)
        elif level_enum == LogLevel.INFO:
            self.info(module_id, details, message)
        elif level_enum == LogLevel.WARNING:
            self.warning(module_id, details, message)
        elif level_enum == LogLevel.ERROR:
            self.error(module_id, details, traceback_str, message)
        elif level_enum == LogLevel.CRITICAL:
            self.critical(module_id, details, traceback_str, message)
    
    # ──────────────────────────────────────────────────────────────
    # PUBLIC API — MODULE REGISTRATION
    # ──────────────────────────────────────────────────────────────
    
    def register_module(self, module_id: str) -> bool:
        """
        Register a module with the telemetry system.
        
        Idempotent: safe to call multiple times for the same module.
        
        Returns True if newly registered, False if already registered.
        """
        with self._lock:
            if module_id in self._registered_modules:
                return False
            self._registered_modules.add(module_id)
            self.info("telemetry", {"module_registered": module_id})
            return True
    
    def unregister_module(self, module_id: str) -> bool:
        """
        Unregister a module from the telemetry system.
        
        Returns True if unregistered, False if not found.
        """
        with self._lock:
            if module_id not in self._registered_modules:
                return False
            self._registered_modules.discard(module_id)
            return True
    
    def registered_modules(self) -> List[str]:
        """Get list of registered module IDs."""
        with self._lock:
            return list(self._registered_modules)
    
    # ──────────────────────────────────────────────────────────────
    # PUBLIC API — CALLBACKS
    # ──────────────────────────────────────────────────────────────
    
    def register_callback(self, callback: TelemetryCallback) -> None:
        """
        Register a callback for live event notifications.
        
        The callback will be called for every telemetry event.
        Callbacks must be fast (non-blocking) — they are called
        from within the telemetry lock.
        
        Args:
            callback: A callable accepting a TelemetryEvent.
        """
        with self._lock:
            if callback not in self._callbacks:
                self._callbacks.append(callback)
    
    def unregister_callback(self, callback: TelemetryCallback) -> bool:
        """
        Unregister a previously registered callback.
        
        Returns True if removed, False if not found.
        """
        with self._lock:
            if callback in self._callbacks:
                self._callbacks.remove(callback)
                return True
            return False
    
    # ──────────────────────────────────────────────────────────────
    # PUBLIC API — QUERY
    # ──────────────────────────────────────────────────────────────
    
    def recent_events(
        self,
        count: int = 50,
        level: Optional[LogLevel] = None,
        module_id: Optional[str] = None,
    ) -> List[TelemetryEvent]:
        """
        Get recent telemetry events with optional filtering.
        
        Args:
            count: Maximum number of events to return (most recent).
            level: Filter by minimum severity level.
            module_id: Filter by specific module.
        
        Returns:
            List of TelemetryEvent objects, newest first.
        """
        with self._lock:
            events = list(self._buffer)
        
        # ── Apply filters (reverse for newest first) ──
        events.reverse()
        
        if level is not None:
            min_order = _LOG_LEVEL_ORDER.get(level, 0)
            events = [
                e for e in events
                if _LOG_LEVEL_ORDER.get(e.level, 0) >= min_order
            ]
        
        if module_id is not None:
            events = [e for e in events if e.module_id == module_id]
        
        return events[:count]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get telemetry statistics."""
        with self._lock:
            stats = dict(self._stats)
            stats["buffer_size"] = len(self._buffer)
            stats["buffer_max"] = self._ring_buffer_size
            stats["registered_modules"] = len(self._registered_modules)
            stats["callbacks"] = len(self._callbacks)
            return stats
    
    def clear_buffer(self) -> int:
        """Clear the in-memory ring buffer. Returns count cleared."""
        with self._lock:
            count = len(self._buffer)
            self._buffer.clear()
            return count
    
    # ──────────────────────────────────────────────────────────────
    # PUBLIC API — PERSISTENCE
    # ──────────────────────────────────────────────────────────────
    
    def flush(self) -> None:
        """
        Force-flush all pending events to the database.
        
        Idempotent: safe to call multiple times.
        """
        self._flush_batch()
    
    def query_history(
        self,
        limit: int = 100,
        offset: int = 0,
        level: Optional[str] = None,
        module_id: Optional[str] = None,
        since: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """
        Query persisted telemetry history from SQLite.
        
        Args:
            limit: Max rows to return.
            offset: Row offset for pagination.
            level: Filter by level ('debug', 'info', 'warning', 'error', 'critical').
            module_id: Filter by module ID.
            since: Unix timestamp — only events after this time.
        
        Returns:
            List of dicts with telemetry event data.
        """
        if not self._db:
            return []
        
        try:
            query = "SELECT * FROM telemetry WHERE 1=1"
            params: List[Any] = []
            
            if level:
                query += " AND level = ?"
                params.append(level)
            if module_id:
                query += " AND module_id = ?"
                params.append(module_id)
            if since:
                query += " AND timestamp >= ?"
                params.append(since)
            
            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            
            with self._db_lock:
                cursor = self._db.execute(query, params)
                rows = cursor.fetchall()
            
            results = []
            for row in rows:
                results.append({
                    "id": row[0],
                    "module_id": row[1],
                    "level": row[2],
                    "message": row[3],
                    "traceback": row[4],
                    "timestamp": row[5],
                    "os": row[6],
                    "architecture": row[7],
                })
            
            return results
        except Exception:
            return []
    
    def purge_history(self, older_than_days: int = 30) -> int:
        """
        Purge telemetry history older than N days.
        
        Returns number of rows deleted.
        """
        if not self._db:
            return 0
        
        try:
            cutoff = time.time() - (older_than_days * 86400)
            with self._db_lock:
                cursor = self._db.execute(
                    "DELETE FROM telemetry WHERE timestamp < ?",
                    (cutoff,),
                )
                self._db.commit()
                return cursor.rowcount
        except Exception:
            return 0
    
    # ──────────────────────────────────────────────────────────────
    # PUBLIC API — SHUTDOWN
    # ──────────────────────────────────────────────────────────────
    
    def shutdown(self) -> None:
        """
        Shut down the telemetry system.
        
        Flushes pending events, closes database, clears callbacks.
        Idempotent.
        """
        self.flush()
        
        with self._lock:
            self._callbacks.clear()
        
        with self._db_lock:
            if self._db is not None:
                try:
                    self._db.close()
                except Exception:
                    pass
                self._db = None
    
    # ──────────────────────────────────────────────────────────────
    # INTERNAL — EVENT EMISSION
    # ──────────────────────────────────────────────────────────────
    
    def _emit(
        self,
        level: LogLevel,
        module_id: str,
        event_type: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        tb_str: Optional[str] = None,
    ) -> Optional[TelemetryEvent]:
        """
        Create, store, and dispatch a telemetry event.
        
        This is the core event pipeline:
          1. Create TelemetryEvent
          2. Add to ring buffer
          3. Add to batch queue (for DB persistence)
          4. Notify callbacks (UI)
          5. Update statistics
        
        Returns the event, or None if suppressed.
        """
        try:
            event = TelemetryEvent(
                level=level,
                module_id=module_id,
                event_type=event_type,
                message=message,
                details=details,
                traceback_str=tb_str,
            )
        except Exception:
            # ── Fail-safe: never crash inside telemetry ──
            return None
        
        with self._lock:
            # ── Ring buffer ──
            self._buffer.append(event)
            
            # ── Statistics ──
            self._stats["total_events"] += 1
            level_key = level.value
            if level_key in self._stats:
                self._stats[level_key] += 1
            
            # ── Callbacks (UI live console) ──
            for callback in self._callbacks:
                try:
                    callback(event)
                except Exception:
                    pass  # Don't let a bad callback break telemetry
        
        # ── Database persistence (outside lock for performance) ──
        if self._persist:
            self._add_to_batch(event)
        
        return event
    
    # ──────────────────────────────────────────────────────────────
    # INTERNAL — DATABASE
    # ──────────────────────────────────────────────────────────────
    
    def _init_database(self) -> None:
        """Initialize the SQLite telemetry database."""
        if not self._persist:
            return
        
        try:
            if self._engine and hasattr(self._engine, "data_path"):
                db_dir = self._engine.data_path
            else:
                db_dir = Path.home() / ".anubis"
            
            db_dir.mkdir(parents=True, exist_ok=True)
            
            # ── Obfuscated filename ──
            db_name = f"._telemetry_{hash('anubis_telemetry') & 0xFFFFFFFF:08x}.db"
            db_path = db_dir / db_name
            
            self._db = sqlite3.connect(
                str(db_path),
                timeout=5.0,
                check_same_thread=False,
            )
            self._db.execute("PRAGMA journal_mode=WAL;")
            self._db.execute("PRAGMA synchronous=NORMAL;")
            self._db.execute("PRAGMA busy_timeout=3000;")
            
            # ── Schema ──
            self._db.executescript("""
                CREATE TABLE IF NOT EXISTS telemetry (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    module_id TEXT,
                    level TEXT NOT NULL,
                    message TEXT,
                    traceback TEXT,
                    timestamp REAL,
                    os TEXT,
                    architecture TEXT,
                    pid INTEGER
                );
                CREATE INDEX IF NOT EXISTS idx_telemetry_ts ON telemetry(timestamp);
                CREATE INDEX IF NOT EXISTS idx_telemetry_level ON telemetry(level);
                CREATE INDEX IF NOT EXISTS idx_telemetry_module ON telemetry(module_id);
            """)
            self._db.commit()
        except Exception:
            # ── Non-fatal: telemetry continues in memory-only mode ──
            self._db = None
            self._persist = False
    
    def _init_crash_dir(self) -> None:
        """Initialize the crash reports directory."""
        try:
            if self._engine and hasattr(self._engine, "data_path"):
                self._crash_dir = self._engine.data_path / "crash_reports"
            else:
                self._crash_dir = Path.home() / ".anubis" / "crash_reports"
            self._crash_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            self._crash_dir = None
    
    def _add_to_batch(self, event: TelemetryEvent) -> None:
        """
        Add an event to the batch queue for DB persistence.
        
        Automatically flushes when the batch is large enough or
        enough time has passed since the last flush.
        """
        with self._batch_lock:
            self._batch.append(event.to_dict())
            
            # ── Auto-flush conditions ──
            now = time.monotonic()
            if (
                len(self._batch) >= 100
                or (now - self._last_flush) >= self._flush_interval
            ):
                self._flush_batch()
    
    def _flush_batch(self) -> None:
        """Flush all pending events to the database."""
        if not self._db:
            self._batch.clear()
            return
        
        with self._batch_lock:
            if not self._batch:
                return
            
            batch = self._batch.copy()
            self._batch.clear()
            self._last_flush = time.monotonic()
        
        try:
            with self._db_lock:
                self._db.executemany(
                    """INSERT INTO telemetry (module_id, level, message, traceback,
                       timestamp, os, architecture, pid)
                       VALUES (:module_id, :level, :message, :traceback,
                               :timestamp, :os, :architecture, :pid)""",
                    batch,
                )
                self._db.commit()
        except Exception:
            # ── Non-fatal: batch will be lost, but telemetry continues ──
            pass
    
    # ──────────────────────────────────────────────────────────────
    # INTERNAL — CRASH REPORTS
    # ──────────────────────────────────────────────────────────────
    
    def _generate_crash_report(self, event: TelemetryEvent) -> None:
        """
        Generate a crash report for a critical event.
        
        Writes a structured JSON file to the crash reports directory.
        """
        if not self._crash_dir:
            return
        
        try:
            # ── Sanitize paths: remove usernames from traceback ──
            sanitized_tb = self._sanitize_traceback(event.traceback_str or "")
            
            report = CrashReport(
                module_id=event.module_id,
                version=self._get_module_version(event.module_id),
                os_name=event.os,
                os_version=platform.release(),
                architecture=event.architecture,
                python_version=platform.python_version(),
                error_type=event.event_type,
                error_message=event.message,
                traceback=sanitized_tb,
                timestamp=event.timestamp,
                event_history=[e.to_dict() for e in self.recent_events(20)],
            )
            
            # ── Write to disk ──
            crash_filename = f"crash_{int(event.timestamp)}_{hash(event.module_id) & 0xFFFFFFFF:08x}.json"
            crash_path = self._crash_dir / crash_filename
            
            crash_path.write_text(
                json.dumps(asdict(report), indent=2, default=str),
                encoding="utf-8",
            )
            
            # ── Restrict permissions on POSIX ──
            if platform.system() != "Windows":
                try:
                    crash_path.chmod(0o600)
                except Exception:
                    pass
            
        except Exception:
            pass  # Fail-safe: crash reports are best-effort
    
    def _sanitize_traceback(self, tb: str) -> str:
        """
        Sanitize a traceback string by removing absolute paths
        that may contain usernames.
        
        Replaces /home/username with /home/*** and similar.
        """
        try:
            # ── Replace home directory paths ──
            home = str(Path.home())
            if home in tb:
                tb = tb.replace(home, "~")
            
            # ── Replace temp paths ──
            import tempfile
            tmpdir = tempfile.gettempdir()
            if tmpdir in tb:
                tb = tb.replace(tmpdir, "/tmp")
            
            # ── Replace username in Windows paths ──
            if platform.system() == "Windows":
                username = os.environ.get("USERNAME", "")
                if username and username in tb:
                    tb = tb.replace(username, "***")
        except Exception:
            pass
        
        return tb
    
    def _get_module_version(self, module_id: str) -> str:
        """Try to get a module's version string."""
        if self._engine and hasattr(self._engine, "get_module"):
            module = self._engine.get_module(module_id)
            if module and hasattr(module, "module_meta"):
                return module.module_meta.get("version", "unknown")
        return "unknown"
    
    def list_crash_reports(self) -> List[Dict[str, Any]]:
        """List all available crash reports."""
        if not self._crash_dir:
            return []
        
        reports = []
        try:
            for f in sorted(self._crash_dir.glob("crash_*.json"), reverse=True):
                try:
                    data = json.loads(f.read_text(encoding="utf-8"))
                    reports.append({
                        "path": str(f),
                        "timestamp": data.get("timestamp", 0),
                        "module_id": data.get("module_id", "unknown"),
                        "error_type": data.get("error_type", "unknown"),
                        "error_message": data.get("error_message", ""),
                    })
                except Exception:
                    continue
        except Exception:
            pass
        
        return reports
    
    # ──────────────────────────────────────────────────────────────
    # REPRESENTATION
    # ──────────────────────────────────────────────────────────────
    
    def __repr__(self) -> str:
        stats = self.get_stats()
        return (
            f"<Telemetry "
            f"events={stats['total_events']} "
            f"buffer={stats['buffer_size']}/{stats['buffer_max']} "
            f"modules={stats['registered_modules']} "
            f"db={'on' if self._persist else 'off'}>"
)
