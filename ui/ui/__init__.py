# ═══════════════════════════════════════════════════════════════════
# ANUBIS — UI Package
# ═══════════════════════════════════════════════════════════════════
# Role:    UI package entry point. Exports MainWindow and theme
#          loading helpers. Lazy-imports heavy Qt widgets so that
#          `import anubis.ui` stays fast in headless mode.
#
# Audit:   AUDIT-2026-07-26
#   [x] Lazy Qt imports — no PyQt6 load unless GUI path is taken
#   [x] Theme load is idempotent (safe to re-apply)
#   [x] Falls back cleanly if QSS missing
#   [x] Zero network I/O
#   [x] No writes outside engine data_dir
# ═══════════════════════════════════════════════════════════════════

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication

__all__ = [
    "MainWindow",
    "load_dark_theme",
    "apply_accent_color",
    "get_ui_resource_path",
]


def get_ui_resource_path(filename: str, base_path: Optional[str] = None) -> Path:
    """
    Resolve a UI resource path (QSS, icons, etc.).

    Preference order:
      1. base_path/ui/<filename> if base_path provided
      2. package-relative ui/<filename>
    """
    if base_path:
        candidate = Path(base_path) / "ui" / filename
        if candidate.is_file():
            return candidate

    package_dir = Path(__file__).resolve().parent
    return package_dir / filename


def load_dark_theme(app: "QApplication", base_path: Optional[str] = None) -> bool:
    """
    Load and apply dark_theme.qss to the QApplication.

    Idempotent: re-applying replaces the previous stylesheet cleanly.
    Returns True if applied, False if QSS missing/unreadable.
    """
    try:
        qss_path = get_ui_resource_path("dark_theme.qss", base_path)
        if not qss_path.is_file():
            return False
        app.setStyleSheet(qss_path.read_text(encoding="utf-8"))
        return True
    except Exception:
        return False


def apply_accent_color(app: "QApplication", hex_color: str = "#D4AF37") -> None:
    """
    Inject a runtime accent color override without rewriting the QSS file.

    Robust: validates hex before injection.
    """
    try:
        color = hex_color.strip()
        if not color.startswith("#") or len(color) not in (4, 7):
            color = "#D4AF37"

        extra = f"""
        QPushButton[role="primary"] {{
            background-color: {color};
            border: 1px solid {color};
            color: #0A0A0F;
        }}
        QPushButton[role="primary"]:hover {{
            background-color: #E5C555;
        }}
        QProgressBar::chunk {{
            background-color: {color};
        }}
        QTreeWidget::item:selected,
        QListWidget::item:selected,
        QTableWidget::item:selected {{
            background-color: {color};
            color: #0A0A0F;
        }}
        """
        current = app.styleSheet() or ""
        app.setStyleSheet(current + "\n" + extra)
    except Exception:
        pass


def MainWindow(*args: Any, **kwargs: Any) -> Any:
    """
    Lazy export of MainWindow.

    Keeping the real import behind a function avoids loading PyQt6
    when only theme helpers are needed (e.g. tests / headless).
    """
    from anubis.ui.main_window import MainWindow as _MainWindow
    return _MainWindow(*args, **kwargs)
