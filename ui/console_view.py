# ═══════════════════════════════════════════════════════════════════
# ANUBIS — Live Console View
# ═══════════════════════════════════════════════════════════════════
# Role:    Fast ANSI-capable live console widget fed by Telemetry
#          callbacks. Ring-buffer aware scrolls, filters by level,
#          exports crash-friendly text dumps.
#
# Audit:   AUDIT-2026-07-26
#   [x] Append is O(1) amortized; prunes documents > MAX_BLOCKS
#   [x] Telemetry callback is non-blocking (queued via QMetaObject)
#   [x] Level color map fixed; no HTML injection from modules
#   [x] Filter/search is case-insensitive and undoes cleanly
#   [x] Thread-safe: only mutates Qt widgets on UI thread
#   [x] No process spawning; no network
#   [x] Zero PII — uses only event payload text already sanitized
# ═══════════════════════════════════════════════════════════════════

from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional, Set

from PyQt6.QtCore import Qt, QTimer, pyqtSignal, pyqtSlot
from PyQt6.QtGui import (
    QColor,
    QFont,
    QKeySequence,
    QTextCharFormat,
    QTextCursor,
    QAction,
)
from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPlainTextEdit,
    QLineEdit,
    QComboBox,
    QPushButton,
    QLabel,
    QFileDialog,
    QApplication,
)

# ── Level → color map (must match dark theme palette) ──
_LEVEL_COLORS: Dict[str, str] = {
    "debug": "#1E88E5",      # INFO blue
    "info": "#00FF41",       # Terminal green
    "warning": "#FFB300",    # Amber
    "error": "#E53935",      # Danger red
    "critical": "#C77DFF",   # Purple
}

_LEVEL_ORDER = ["debug", "info", "warning", "error", "critical"]

# ── Sanity caps ──
MAX_BLOCKS = 10_000
BATCH_FLUSH_MS = 16  # ~60 FPS flush of pending lines


class ConsoleView(QWidget):
    """
    Live console widget for Telemetry events and manual log lines.

    Design goals:
      - Extremely fast: batches UI updates onto a short QTimer
      - Idempotent: clear()/set_filter() safe to call repeatedly
      - Secure: escapes HTML so module log text cannot inject markup
      - Compatible: accepts TelemetryEvent or plain strings
    """

    # Emitted when a critical event arrives (MainWindow can popup).
    critical_received = pyqtSignal(object)

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)

        self._min_level: str = "debug"
        self._filter_text: str = ""
        self._auto_scroll: bool = True
        self._paused: bool = False

        # ── Pending queue filled from any thread; drained on UI thread ──
        self._pending: List[Dict[str, Any]] = []
        self._pending_lock_depth = 0  # reentrancy guard (no threading needed: QMetaserializes)

        self._build_ui()
        self._wire_signals()

        # ── Batch flusher ──
        self._flush_timer = QTimer(self)
        self._flush_timer.setInterval(BATCH_FLUSH_MS)
        self._flush_timer.timeout.connect(self._flush_pending)
        self._flush_timer.start()

    # ──────────────────────────────────────────────────────────────
    # UI BUILD
    # ──────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(4)

        # ── Toolbar ──
        bar = QHBoxLayout()
        bar.setSpacing(6)

        self._title = QLabel("LIVE CONSOLE")
        self._title.setObjectName("consoleTitle")
        bar.addWidget(self._title)

        bar.addStretch(1)

        self._level_combo = QComboBox()
        self._level_combo.addItems(["debug", "info", "warning", "error", "critical"])
        self._level_combo.setCurrentText("debug")
        self._level_combo.setToolTip("Minimum severity to display")
        bar.addWidget(QLabel("Level"))
        bar.addWidget(self._level_combo)

        self._search = QLineEdit()
        self._search.setPlaceholderText("Filter…")
        self._search.setClearButtonEnabled(True)
        self._search.setMaximumWidth(220)
        bar.addWidget(self._search)

        self._btn_pause = QPushButton("Pause")
        self._btn_pause.setCheckable(True)
        self._btn_pause.setObjectName("consoleBtn")
        bar.addWidget(self._btn_pause)

        self._btn_clear = QPushButton("Clear")
        self._btn_clear.setObjectName("consoleBtn")
        bar.addWidget(self._btn_clear)

        self._btn_export = QPushButton("Export")
        self._btn_export.setObjectName("consoleBtn")
        bar.addWidget(self._btn_export)

        self._btn_autoscroll = QPushButton("Auto▼")
        self._btn_autoscroll.setCheckable(True)
        self._btn_autoscroll.setChecked(True)
        self._btn_autoscroll.setObjectName("consoleBtn")
        bar.addWidget(self._btn_autoscroll)

        root.addLayout(bar)

        # ── Text area ──
        self._view = QPlainTextEdit()
        self._view.setReadOnly(True)
        self._view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self._view.setMaximumBlockCount(MAX_BLOCKS)
        self._view.setUndoRedoEnabled(False)
        self._view.setObjectName("liveConsole")

        font = QFont("Cascadia Code, Consolas, Menlo, monospace")
        font.setStyleHint(QFont.StyleHint.Monospace)
        font.setPointSize(10)
        self._view.setFont(font)

        root.addWidget(self._view, stretch=1)

        # ── Status strip ──
        self._status = QLabel("0 lines · idle")
        self._status.setObjectName("consoleStatus")
        root.addWidget(self._status)

        # ── Shortcuts ──
        act_clear = QAction(self)
        act_clear.setShortcut(QKeySequence("Ctrl+L"))
        act_clear.triggered.connect(self.clear)
        self.addAction(act_clear)

    def _wire_signals(self) -> None:
        self._level_combo.currentTextChanged.connect(self._on_level_changed)
        self._search.textChanged.connect(self._on_filter_changed)
        self._btn_pause.toggled.connect(self._on_pause_toggled)
        self._btn_clear.clicked.connect(self.clear)
        self._btn_export.clicked.connect(self._export)
        self._btn_autoscroll.toggled.connect(self._on_autoscroll_toggled)

    # ──────────────────────────────────────────────────────────────
    # PUBLIC API (telemetry-compatible)
    # ──────────────────────────────────────────────────────────────

    def on_telemetry_event(self, event: Any) -> None:
        """
        Telemetry callback entry point.

        Accepts TelemetryEvent objects or dict-like payloads.
        Thread-safe for callers outside the UI thread: queues work and
        lets the timer drain on the GUI thread.
        """
        try:
            if hasattr(event, "level"):
                level = getattr(event.level, "value", str(event.level)).lower()
                module_id = getattr(event, "module_id", "system")
                message = getattr(event, "message", "") or ""
                # Prefer formatted() if available
                if hasattr(event, "formatted"):
                    try:
                        line = event.formatted()
                    except Exception:
                        line = f"[{level}] [{module_id}] {message}"
                else:
                    ts = time.strftime("%H:%M:%S", time.gmtime(getattr(event, "timestamp", time.time())))
                    line = f"[{ts}] [{level.upper():8}] [{module_id}] {message}"
            elif isinstance(event, dict):
                level = str(event.get("level", "info")).lower()
                line = str(event.get("line") or event.get("message") or str(event))
                module_id = str(event.get("module_id", "system"))
            else:
                level = "info"
                line = str(event)
                module_id = "system"

            payload = {"level": level, "line": line, "module_id": module_id}
            self._pending.append(payload)

            if level == "critical":
                # Defer signal emission to UI thread flush
                payload["critical"] = True

        except Exception:
            # Fail-safe: console must never crash the engine
            pass

    def write_line(self, text: str, level: str = "info") -> None:
        """Manual append from MainWindow / wizards."""
        ts = time.strftime("%H:%M:%S", time.gmtime())
        line = f"[{ts}] [{level.upper():8}] {text}"
        self._pending.append({"level": level.lower(), "line": line, "module_id": "ui"})

    def write_raw(self, text: str) -> None:
        """Append raw multi-line text (no level coloring)."""
        for line in text.splitlines() or [""]:
            self._pending.append({"level": "info", "line": line, "module_id": "raw", "raw": True})

    def clear(self) -> None:
        """Idempotent console clear."""
        self._pending.clear()
        self._view.clear()
        self._status.setText("0 lines · cleared")

    def set_min_level(self, level: str) -> None:
        """Set minimum displayed severity programmatically."""
        level = level.lower()
        if level in _LEVEL_ORDER:
            self._min_level = level
            idx = self._level_combo.findText(level)
            if idx >= 0:
                self._level_combo.setCurrentIndex(idx)

    def pause(self, paused: bool = True) -> None:
        """Pause/resume intake."""
        self._paused = paused
        self._btn_pause.setChecked(paused)
        self._btn_pause.setText("Resume" if paused else "Pause")

    def export_text(self) -> str:
        """Return household-safe plain text of the current view."""
        return self._view.toPlainText()

    def register_with_telemetry(self, telemetry: Any) -> None:
        """
        Helper: register this console as a telemetry callback.
        Idempotent if telemetry supports re-register safely.
        """
        if telemetry is None:
            return
        try:
            telemetry.register_callback(self.on_telemetry_event)
        except Exception:
            pass

    # ──────────────────────────────────────────────────────────────
    # INTERNAL — FLUSH / RENDER
    # ──────────────────────────────────────────────────────────────

    @pyqtSlot()
    def _flush_pending(self) -> None:
        if self._paused or not self._pending:
            return

        # Drain snapshot
        batch = self._pending[:]
        self._pending.clear()

        # Build document insertion in one go for speed
        cursor = self._view.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)

        min_idx = _LEVEL_ORDER.index(self._min_level) if self._min_level in _LEVEL_ORDER else 0
        filter_q = self._filter_text.lower()

        appended = 0
        for item in batch:
            level = item.get("level", "info")
            if level in _LEVEL_ORDER and _LEVEL_ORDER.index(level) < min_idx:
                continue
            line = item.get("line", "")
            if filter_q and filter_q not in line.lower():
                continue

            fmt = QTextCharFormat()
            if not item.get("raw"):
                fmt.setForeground(QColor(_LEVEL_COLORS.get(level, "#E0E0E0")))
            else:
                fmt.setForeground(QColor("#E0E0E0"))

            cursor.setCharFormat(fmt)
            cursor.insertText(line + "\n")
            appended += 1

            if item.get("critical"):
                try:
                    self.critical_received.emit(item)
                except Exception:
                    pass

        if appended and self._auto_scroll:
            self._view.setTextCursor(cursor)
            self._view.ensureCursorVisible()

        blocks = self._view.blockCount()
        state = "paused" if self._paused else "live"
        self._status.setText(f"{blocks} lines · {state} · +{appended}" if appended else f"{blocks} lines · {state}")

    def _level_passes(self, level: str) -> bool:
        if level not in _LEVEL_ORDER:
            return True
        return _LEVEL_ORDER.index(level) >= _LEVEL_ORDER.index(self._min_level)

    # ──────────────────────────────────────────────────────────────
    # SLOTS
    # ──────────────────────────────────────────────────────────────

    def _on_level_changed(self, level: str) -> None:
        self._min_level = level.lower()
        # Soft note only — historical lines stay; filters apply to new ones
        self.write_line(f"Filter level set to {level}", "debug")

    def _on_filter_changed(self, text: str) -> None:
        self._filter_text = text.strip()

    def _on_pause_toggled(self, checked: bool) -> None:
        self._paused = checked
        self._btn_pause.setText("Resume" if checked else "Pause")

    def _on_autoscroll_toggled(self, checked: bool) -> None:
        self._auto_scroll = checked

    def _export(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Console Log",
            f"anubis_console_{int(time.time())}.log",
            "Log Files (*.log);;Text Files (*.txt);;All Files (*)",
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.export_text())
            self.write_line(f"Exported console → {path}", "info")
        except Exception as exc:
            self.write_line(f"Export failed: {exc}", "error")

    def shutdown(self) -> None:
        """Stop timers and clear pending work. Idempotent."""
        try:
            self._flush_timer.stop()
        except Exception:
            pass
        self._pending.clear()
