# ═══════════════════════════════════════════════════════════════════
# ANUBIS — Main Window
# ═══════════════════════════════════════════════════════════════════
# Role:    Primary OS-like shell: sidebar navigation, dynamic tool
#          control panels (from control.json), delivery actions,
#          rankings table, live console, status bar.
#
# Audit:   AUDIT-2026-07-26
#   [x] Control panels rendered dynamically from control.json
#   [x] Module run is async via engine loop (UI never blocks)
#   [x] Telemetry callbackregistered once; console is the sink
#   [x] All file dialogs default to engine data/base paths
#   [x] No shell=True, no eval on control field values
#   [x] Theme/accent from config; re-apply safe
#   [x] Shutdown tears down wizard workers + console timers
#   [x] Sidebar selection is O(1); tool widgets created lazy
#   [x] Scalable: QStackedWidget pages created only when needed
# ═══════════════════════════════════════════════════════════════════

from __future__ import annotations

import json
import platform
import time
import traceback
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from PyQt6.QtCore import Qt, QTimer, QSize, pyqtSlot
from PyQt6.QtGui import QAction, QColor, QFont, QIcon, QKeySequence, QCloseEvent
from PyQt6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QSplitter,
    QTreeWidget,
    QTreeWidgetItem,
    QStackedWidget,
    QLabel,
    QPushButton,
    QLineEdit,
    QSpinBox,
    QComboBox,
    QCheckBox,
    QSlider,
    QPlainTextEdit,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QScrollArea,
    QFrame,
    QStatusBar,
    QMessageBox,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QTabWidget,
    QApplication,
    QSizePolicy,
)

from anubis.ui.console_view import ConsoleView
from anubis.ui.add_tool_wizard import AddToolWizard
from anubis.ui import load_dark_theme, apply_accent_color


class MainWindow(QMainWindow):
    """
    Anubis primary GUI shell.

    Usage:
        window = MainWindow(engine, config)
        window.show()
    """

    NAV = [
        ("tools", "📦  Tools"),
        ("rank", "📊  Rankings"),
        ("add", "➕  Add Tool"),
        ("delivery", "🚚  Delivery"),
        ("scan", "🔬  Scan"),
        ("logs", "📁  Logs"),
        ("config", "⚙️  Settings"),
    ]

    def __init__(self, engine: Any, config: Dict[str, Any], parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.engine = engine
        self.config = config or {}
        self._runtime = self.config.get("_runtime", {})

        self.setWindowTitle(f"ANUBIS  v{self._runtime.get('version', '3.2.1')}")
        self.setMinimumSize(1180, 720)
        self.resize(1400, 880)
        self.setObjectName("anubisMain")

        # ── State ──
        self._tool_pages: Dict[str, QWidget] = {}
        self._control_widgets: Dict[str, Dict[str, Any]] = {}  # module_id -> {field_id: widget}
        self._active_module_id: Optional[str] = None
        self._delivery_jobs: int = 0

        # ── Theme ──
        app = QApplication.instance()
        if app is not None:
            load_dark_theme(app, self._runtime.get("base_path"))
            accent = self.config.get("theme", {}).get("accent_color", "#D4AF37")
            apply_accent_color(app, accent)

        self._build_ui()
        self._build_menu()
        self._wire_engine()
        self._refresh_tools()
        self._start_status_timer()

        self.console.write_line("Anubis UI ready", "info")

    # ════════════════════════════════════════════════════════════
    # BUILD
    # ════════════════════════════════════════════════════════════

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Header ──
        header = QFrame()
        header.setObjectName("appHeader")
        header.setFixedHeight(48)
        h = QHBoxLayout(header)
        h.setContentsMargins(16, 0, 16, 0)

        brand = QLabel("☰  ANUBIS")
        brand.setObjectName("brandLabel")
        h.addWidget(brand)

        ver = QLabel(f"v{self._runtime.get('version', '3.2.1')}")
        ver.setObjectName("versionLabel")
        h.addWidget(ver)
        h.addStretch(1)

        self._online_dot = QLabel("● ONLINE")
        self._online_dot.setObjectName("onlineDot")
        h.addWidget(self._online_dot)

        self._delivering_lbl = QLabel("⚡ 0 Delivering")
        self._delivering_lbl.setObjectName("headerMeta")
        h.addWidget(self._delivering_lbl)

        root.addWidget(header)

        # ── Body splitter: sidebar | workspace ──
        body = QSplitter(Qt.Orientation.Horizontal)
        body.setObjectName("bodySplitter")
        body.setChildrenCollapsible(False)

        # Sidebar
        self.sidebar = QTreeWidget()
        self.sidebar.setObjectName("sidebar")
        self.sidebar.setHeaderHidden(True)
        self.sidebar.setFixedWidth(200)
        self.sidebar.setIndentation(12)
        self.sidebar.setAnimated(True)
        self._populate_sidebar()
        body.addWidget(self.sidebar)

        # Right side: workspace stack + console
        right = QSplitter(Qt.Orientation.Vertical)
        right.setObjectName("rightSplitter")

        self.stack = QStackedWidget()
        self.stack.setObjectName("mainStack")

        # Pages
        self.page_tools_host = QStackedWidget()  # nested stack per tool
        self.page_tools_empty = self._make_empty_tools_page()
        self.page_tools_host.addWidget(self.page_tools_empty)

        self.page_rank = self._make_rank_page()
        self.page_delivery = self._make_delivery_page()
        self.page_scan = self._make_scan_page()
        self.page_logs = self._make_logs_page()
        self.page_config = self._make_config_page()

        # Map indexes
        self._page_index = {
            "tools": self.stack.addWidget(self.page_tools_host),
            "rank": self.stack.addWidget(self.page_rank),
            "delivery": self.stack.addWidget(self.page_delivery),
            "scan": self.stack.addWidget(self.page_scan),
            "logs": self.stack.addWidget(self.page_logs),
            "config": self.stack.addWidget(self.page_config),
        }

        right.addWidget(self.stack)

        # Console
        self.console = ConsoleView()
        self.console.setMinimumHeight(160)
        right.addWidget(self.console)
        right.setStretchFactor(0, 3)
        right.setStretchFactor(1, 1)

        body.addWidget(right)
        body.setStretchFactor(0, 0)
        body.setStretchFactor(1, 1)
        root.addWidget(body, stretch=1)

        # Status bar
        sb = QStatusBar()
        sb.setObjectName("appStatusBar")
        self.setStatusBar(sb)
        self._sb_rec = QLabel("🔴 Rec: OFF")
        self._sb_net = QLabel("📶 —")
        self._sb_active = QLabel("⚡ 0 Active")
        self._sb_health = QLabel("🟢 All OK")
        for w in (self._sb_rec, self._sb_net, self._sb_active, self._sb_health):
            sb.addPermanentWidget(w)
            sb.addPermanentWidget(self._sep())

        # Signals
        self.sidebar.itemClicked.connect(self._on_sidebar_clicked)
        self.console.critical_received.connect(self._on_critical)

    def _sep(self) -> QLabel:
        s = QLabel("│")
        s.setObjectName("statusSep")
        return s

    def _populate_sidebar(self) -> None:
        self.sidebar.clear()
        self._nav_items: Dict[str, QTreeWidgetItem] = {}
        self._tools_root = QTreeWidgetItem(["📦  Tools"])
        self._tools_root.setData(0, Qt.ItemDataRole.UserRole, "tools")
        self.sidebar.addTopLevelItem(self._tools_root)

        for key, label in self.NAV:
            if key == "tools":
                continue
            item = QTreeWidgetItem([label])
            item.setData(0, Qt.ItemDataRole.UserRole, key)
            self.sidebar.addTopLevelItem(item)
            self._nav_items[key] = item

        self._tools_root.setExpanded(True)
        self.sidebar.setCurrentItem(self._tools_root)

    def _build_menu(self) -> None:
        menubar = self.menuBar()
        menubar.setObjectName("appMenuBar")

        file_m = menubar.addMenu("&File")
        act_add = QAction("Add Tool…", self)
        act_add.setShortcut(QKeySequence("Ctrl+N"))
        act_add.triggered.connect(self._open_add_wizard)
        file_m.addAction(act_add)

        act_refresh = QAction("Refresh Modules", self)
        act_refresh.setShortcut(QKeySequence("F5"))
        act_refresh.triggered.connect(self._refresh_tools)
        file_m.addAction(act_refresh)

        file_m.addSeparator()
        act_quit = QAction("Quit", self)
        act_quit.setShortcut(QKeySequence("Ctrl+Q"))
        act_quit.triggered.connect(self.close)
        file_m.addAction(act_quit)

        view_m = menubar.addMenu("&View")
        act_console = QAction("Focus Console", self)
        act_console.setShortcut(QKeySequence("Ctrl+`"))
        act_console.triggered.connect(lambda: self.console.setFocus())
        view_m.addAction(act_console)

        help_m = menubar.addMenu("&Help")
        act_about = QAction("About Anubis", self)
        act_about.triggered.connect(self._about)
        help_m.addAction(act_about)

    def _wire_engine(self) -> None:
        tel = getattr(self.engine, "telemetry", None)
        if tel is not None:
            self.console.register_with_telemetry(tel)
            try:
                tel.register_module("ui")
            except Exception:
                pass

    # ════════════════════════════════════════════════════════════
    # PAGES
    # ════════════════════════════════════════════════════════════

    def _make_empty_tools_page(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title = QLabel("No tool selected")
        title.setObjectName("emptyTitle")
        sub = QLabel("Pick a module from the sidebar or use
