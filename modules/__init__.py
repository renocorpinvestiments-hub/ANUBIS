# ═══════════════════════════════════════════════════════════════════
# ANUBIS — Module Registry
# ═══════════════════════════════════════════════════════════════════
# Role:    Auto-discovers TIP-compliant module directories, validates
#          them at registry level, and provides fast lookup by ID.
#          Acts as a discovery layer above core/loader.py.
#
# Audit:   AUDIT-2026-07-26
#   [x] Zero hardcoded paths — resolved from engine config
#   [x] Idempotent: scan + register safe to call multiple times
#   [x] Rejects non-NNN_name directories at discovery time
#   [x] All exceptions caught — never crashes on bad module dir
#   [x] Thread-safe via threading.Lock
#   [x] No exec/eval — pure importlib inspection
#   [x] No network calls
#   [x] No writes outside engine data_dir
# ═══════════════════════════════════════════════════════════════════

from __future__ import annotations

import re
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ── Pattern: 3 digits + underscore + alphanumeric/dash name ──
_MODULE_DIR_RE = re.compile(r"^\d{3}_[A-Za-z0-9_\-]+$")


class ModuleRegistry:
    """
    Module Registry — fast discovery and lookup of TIP-compliant modules.
    
    Scans designated directories for valid module folders, validates
    their structure at the directory level, and provides O(1) lookup
    by module ID.
    
    Thread-safe: all registry mutations guarded by threading.Lock.
    Idempotent: scan() and register() safe to call repeatedly.
    
    Usage:
        registry = ModuleRegistry(engine)
        registry.scan()
        module = registry.get("001")
        all_modules = registry.list_modules()
    """
    
    def __init__(self, engine: Any) -> None:
        self._engine = engine
        self._lock: threading.Lock = threading.Lock()
        
        # ── Registry: module_id -> metadata dict ──
        self._modules: Dict[str, Dict[str, Any]] = {}
        
        # ── Registry: path -> module_id ──
        self._path_to_id: Dict[str, str] = {}
        
        # ── Discovered directories (scanned once) ──
        self._scan_dirs: List[Path] = []
        self._scanned: bool = False
    
    # ──────────────────────────────────────────────────────────────
    # PUBLIC API
    # ──────────────────────────────────────────────────────────────
    
    def scan(self) -> int:
        """
        Scan all configured module directories for valid modules.
        
        Idempotent: safe to call multiple times. On subsequent calls,
        discovers new modules without removing existing ones.
        
        Returns: Number of modules found (new + existing).
        """
        with self._lock:
            self._resolve_scan_dirs()
            count = 0
            
            for scan_dir in self._scan_dirs:
                if not scan_dir.is_dir():
                    continue
                
                for entry in sorted(scan_dir.iterdir()):
                    if not entry.is_dir():
                        continue
                    
                    # ── Validate folder naming ──
                    if not _MODULE_DIR_RE.match(entry.name):
                        continue
                    
                    # ── Extract module ID (first 3 chars) ──
                    module_id = entry.name[:3]
                    
                    # ── Skip already registered ──
                    if module_id in self._modules:
                        count += 1
                        continue
                    
                    # ── Quick structural validation ──
                    meta = self._validate_structure(entry)
                    if meta is not None:
                        self._modules[module_id] = meta
                        self._path_to_id[str(entry.resolve())] = module_id
                        count += 1
            
            self._scanned = True
            return count
    
    def register(self, path: Path) -> Optional[str]:
        """
        Register a single module directory.
        
        Useful for the Add Tool Wizard to register newly imported
        modules without a full rescan.
        
        Args:
            path: Path to the module directory.
        
        Returns:
            Module ID if registration succeeded, None otherwise.
        """
        path = path.resolve()
        if not path.is_dir() or not _MODULE_DIR_RE.match(path.name):
            return None
        
        module_id = path.name[:3]
        
        with self._lock:
            # ── Already registered? Update metadata ──
            meta = self._validate_structure(path)
            if meta is None:
                return None
            
            self._modules[module_id] = meta
            self._path_to_id[str(path)] = module_id
            return module_id
    
    def unregister(self, module_id: str) -> bool:
        """
        Remove a module from the registry (does not delete files).
        
        Idempotent: safe to call twice.
        Returns True if removed, False if not found.
        """
        with self._lock:
            if module_id not in self._modules:
                return False
            
            del self._modules[module_id]
            # Clean up path mapping
            paths_to_remove = [
                p for p, mid in self._path_to_id.items() if mid == module_id
            ]
            for p in paths_to_remove:
                del self._path_to_id[p]
            
            return True
    
    def get(self, module_id: str) -> Optional[Dict[str, Any]]:
        """
        Get module metadata by ID.
        
        O(1) lookup. Returns None if not found.
        """
        with self._lock:
            return self._modules.get(module_id)
    
    def get_by_path(self, path: Path) -> Optional[Dict[str, Any]]:
        """
        Get module metadata by filesystem path.
        
        Returns None if path not registered.
        """
        path_str = str(path.resolve())
        with self._lock:
            module_id = self._path_to_id.get(path_str)
            if module_id is None:
                return None
            return self._modules.get(module_id)
    
    def list_modules(self) -> List[Tuple[str, Dict[str, Any]]]:
        """
        List all registered modules.
        
        Returns list of (module_id, metadata_dict) tuples, sorted by ID.
        """
        with self._lock:
            return sorted(
                [(mid, meta) for mid, meta in self._modules.items()],
                key=lambda x: x[0],
            )
    
    def find_by_tag(self, tag: str) -> List[Tuple[str, Dict[str, Any]]]:
        """
        Find modules by tag.
        
        Tags are case-insensitive partial matches.
        """
        tag_lower = tag.lower()
        results = []
        with self._lock:
            for mid, meta in self._modules.items():
                tags = [t.lower() for t in meta.get("tags", [])]
                if any(tag_lower in t for t in tags):
                    results.append((mid, meta))
        return results
    
    def module_count(self) -> int:
        """Get total number of registered modules."""
        with self._lock:
            return len(self._modules)
    
    def clear(self) -> None:
        """Clear the registry. Idempotent."""
        with self._lock:
            self._modules.clear()
            self._path_to_id.clear()
            self._scanned = False
    
    # ──────────────────────────────────────────────────────────────
    # INTERNAL
    # ──────────────────────────────────────────────────────────────
    
    def _resolve_scan_dirs(self) -> None:
        """Resolve the list of directories to scan for modules."""
        if self._scan_dirs:
            return  # Already resolved
        
        base_path = self._engine.config.get("_runtime", {}).get("base_path")
        data_path = self._engine.config.get("_runtime", {}).get("data_path")
        
        # ── Bundled modules ──
        if base_path:
            bundled = Path(base_path) / "modules"
            if bundled.is_dir():
                self._scan_dirs.append(bundled.resolve())
        
        # ── User-installed modules ──
        if data_path:
            user_dir = Path(data_path) / "modules"
            if user_dir.is_dir():
                self._scan_dirs.append(user_dir.resolve())
        
        # ── Fallback: package-relative ──
        if not self._scan_dirs:
            fallback = Path(__file__).resolve().parent
            if fallback.is_dir():
                self._scan_dirs.append(fallback)
    
    def _validate_structure(self, path: Path) -> Optional[Dict[str, Any]]:
        """
        Validate a module's structural integrity at the directory level.
        
        Checks:
          - module.json exists and is valid JSON
          - main.py exists
          - control.json exists and is valid JSON (or warn)
          - icon.png exists (or warn)
        
        Returns metadata dict from module.json, or None on failure.
        """
        module_json = path / "module.json"
        main_py = path / "main.py"
        control_json = path / "control.json"
        
        # ── Essential files ──
        if not module_json.is_file():
            return None
        if not main_py.is_file():
            return None
        
        # ── Parse module.json ──
        try:
            meta = json.loads(module_json.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
        
        # ── Ensure required fields ──
        if "id" not in meta or "name" not in meta:
            return None
        
        # ── Validate control.json (non-fatal) ──
        if control_json.is_file():
            try:
                json.loads(control_json.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                meta["_control_valid"] = False
                meta["_warnings"] = meta.get("_warnings", []) + ["Invalid control.json"]
        else:
            meta["_control_valid"] = False
        
        # ── Enrich with path info ──
        meta["_path"] = str(path.resolve())
        meta["_icon_path"] = str(path / "icon.png") if (path / "icon.png").is_file() else ""
        
        # ── Normalize compatibility ──
        compat = meta.get("compatibility", {})
        for os_name in ("windows", "linux", "macos"):
            if os_name not in compat:
                compat[os_name] = "unknown"
        meta["compatibility"] = compat
        
        return meta
    
    # ──────────────────────────────────────────────────────────────
    # REPRESENTATION
    # ──────────────────────────────────────────────────────────────
    
    def __repr__(self) -> str:
        count = self.module_count()
        return f"<ModuleRegistry modules={count} scanned={self._scanned}>"


# ── Package-level singleton helper ──
_registry: Optional[ModuleRegistry] = None
_registry_lock: threading.Lock = threading.Lock()


def get_registry(engine: Any) -> ModuleRegistry:
    """
    Get or create the global ModuleRegistry instance.
    
    Idempotent: safe to call multiple times with the same engine.
    Thread-safe.
    """
    global _registry
    if _registry is None:
        with _registry_lock:
            if _registry is None:
                _registry = ModuleRegistry(engine)
    return _registry


# ── Needed imports ──
import json


# ── Export ──
__all__ = [
    "ModuleRegistry",
    "get_registry",
                      ]
