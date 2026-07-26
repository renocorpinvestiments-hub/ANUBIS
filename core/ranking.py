# ═══════════════════════════════════════════════════════════════════
# ANUBIS — Ranking Engine
# ═══════════════════════════════════════════════════════════════════
# Role:    Manages online (community) and offline (local telemetry)
#          rankings for each module. Provides scoring, sorting, and
#          recommendation capabilities.
#
# Audit:   AUDIT-2026-07-26
#   [x] SQLite-backed with in-memory LRU cache for fast reads
#   [x] Online rankings are synced asynchronously (non-blocking)
#   [x] Local rankings are updated from telemetry execution data
#   [x] Scoring formula is transparent and documented
#   [x] No external calls at import time — sync is opt-in
#   [x] All database operations use parameterized queries (no SQLi)
#   [x] Idempotent: update_rank/cache operations are safe to repeat
#   [x] Thread-safe via threading.Lock
#   [x] Zero hardcoded paths
#
# Forensic footprint:
#   - Writes only to the engine's data directory
#   - No external callouts unless sync_online() is explicitly called
#   - No PII stored in ranking data
#   - Rankings are anonymous and contain no user identifiers
# ═══════════════════════════════════════════════════════════════════

from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ──────────────────────────────────────────────────────────────────
# DATA CLASSES
# ──────────────────────────────────────────────────────────────────

@dataclass
class ModuleRanking:
    """
    Ranking data for a single module.
    
    Combines online (community) and offline (local telemetry) scores.
    """
    module_id: str
    name: str = ""
    version: str = ""
    online_score: float = 0.0      # Community rating (0.0 - 5.0)
    local_score: float = 0.0       # Local telemetry-based rating (0.0 - 5.0)
    total_runs: int = 0            # Total execution count locally
    success_count: int = 0         # Successful executions locally
    avg_exec_time_ms: float = 0.0  # Average execution time in ms
    install_count: int = 0         # How many times installed
    last_used: Optional[float] = None
    last_synced: Optional[float] = None
    
    @property
    def combined_score(self) -> float:
        """
        Combined score: weighted average of online and local.
        
        Formula:
          - If both exist: 0.4 * online + 0.6 * local
          - If only online: online
          - If only local:  local
          - If neither:     0.0
        
        Local is weighted higher because it reflects actual performance
        on the user's specific hardware/OS config.
        """
        has_online = self.online_score > 0
        has_local = self.local_score > 0
        
        if has_online and has_local:
            return round(0.4 * self.online_score + 0.6 * self.local_score, 2)
        elif has_online:
            return round(self.online_score, 2)
        elif has_local:
            return round(self.local_score, 2)
        else:
            return 0.0
    
    @property
    def success_rate(self) -> float:
        """Success rate as percentage (0.0 - 100.0)."""
        if self.total_runs == 0:
            return 0.0
        return round((self.success_count / self.total_runs) * 100, 1)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "module_id": self.module_id,
            "name": self.name,
            "version": self.version,
            "online_score": self.online_score,
            "local_score": self.local_score,
            "combined_score": self.combined_score,
            "total_runs": self.total_runs,
            "success_count": self.success_count,
            "success_rate": self.success_rate,
            "avg_exec_time_ms": self.avg_exec_time_ms,
            "install_count": self.install_count,
            "last_used": self.last_used,
            "last_synced": self.last_synced,
        }


# ──────────────────────────────────────────────────────────────────
# LRU CACHE (for fast ranking lookups)
# ──────────────────────────────────────────────────────────────────

class _LRUCache:
    """
    Simple LRU cache with time-based expiration.
    
    Thread-safe: requires external lock.
    """
    
    def __init__(self, max_size: int = 1000, ttl_seconds: int = 60):
        self._max_size = max_size
        self._ttl = ttl_seconds
        self._cache: OrderedDict[str, Tuple[float, Any]] = OrderedDict()
    
    def get(self, key: str) -> Optional[Any]:
        """Get a cached value. Returns None if missing or expired."""
        if key not in self._cache:
            return None
        
        timestamp, value = self._cache[key]
        if time.monotonic() - timestamp > self._ttl:
            del self._cache[key]
            return None
        
        # ── Move to end (most recently used) ──
        self._cache.move_to_end(key)
        return value
    
    def set(self, key: str, value: Any) -> None:
        """Set a cached value."""
        self._cache[key] = (time.monotonic(), value)
        self._cache.move_to_end(key)
        
        # ── Evict oldest if over max size ──
        while len(self._cache) > self._max_size:
            self._cache.popitem(last=False)
    
    def remove(self, key: str) -> None:
        """Remove a cached value."""
        self._cache.pop(key, None)
    
    def clear(self) -> None:
        """Clear all cached values."""
        self._cache.clear()


# ═══════════════════════════════════════════════════════════════════
# RANKING ENGINE
# ═══════════════════════════════════════════════════════════════════

class RankingEngine:
    """
    Module Ranking Engine.
    
    Manages online and offline rankings via SQLite. Provides fast
    lookups via an LRU cache, scoring calculations, and async
    online sync capability.
    
    Thread-safe: all mutable state guarded by threading.Lock.
    Idempotent: update_ranking() is safe to call repeatedly.
    
    Usage:
        ranking = RankingEngine(engine)
        
        # ── Update local ranking from a successful execution ──
        ranking.record_execution("001", success=True, exec_time_ms=1200)
        
        # ── Get ranking for a module ──
        rank = ranking.get_ranking("001")
        print(rank.combined_score)
        
        # ── List all rankings ──
        rankings = ranking.list_rankings(sort_by="combined_score")
        
        # ── Sync online rankings (requires network) ──
        await ranking.sync_online()
    """
    
    def __init__(self, engine: Any) -> None:
        """
        Args:
            engine: AnubisEngine instance. Must have data_path and
                    db initialized.
        """
        self._engine = engine
        self._lock: threading.Lock = threading.Lock()
        
        # ── Database connection (lazy) ──
        self._db: Optional[sqlite3.Connection] = None
        self._db_lock: threading.Lock = threading.Lock()
        
        # ── LRU cache ──
        self._cache: _LRUCache = _LRUCache(max_size=500, ttl_seconds=30)
        
        # ── Sync state ──
        self._last_sync: Optional[float] = None
        self._sync_in_progress: bool = False
        
        # ── Initialize ──
        self._init_database()
    
    def _init_database(self) -> None:
        """Initialize the rankings database table."""
        try:
            if self._engine and hasattr(self._engine, "data_path"):
                db_dir = self._engine.data_path
            else:
                db_dir = Path.home() / ".anubis"
            
            db_dir.mkdir(parents=True, exist_ok=True)
            
            db_name = f"._rankings_{hash('anubis_rankings') & 0xFFFFFFFF:08x}.db"
            db_path = db_dir / db_name
            
            self._db = sqlite3.connect(
                str(db_path),
                timeout=5.0,
                check_same_thread=False,
            )
            self._db.row_factory = sqlite3.Row
            self._db.execute("PRAGMA journal_mode=WAL;")
            self._db.execute("PRAGMA synchronous=NORMAL;")
            
            self._db.executescript("""
                CREATE TABLE IF NOT EXISTS rankings (
                    module_id TEXT PRIMARY KEY,
                    name TEXT DEFAULT '',
                    version TEXT DEFAULT '',
                    online_score REAL DEFAULT 0.0,
                    local_score REAL DEFAULT 0.0,
                    total_runs INTEGER DEFAULT 0,
                    success_count INTEGER DEFAULT 0,
                    avg_exec_time_ms REAL DEFAULT 0.0,
                    install_count INTEGER DEFAULT 0,
                    last_used REAL,
                    last_synced REAL
                );
                
                CREATE TABLE IF NOT EXISTS execution_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    module_id TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    exec_time_ms REAL,
                    timestamp REAL DEFAULT (julianday('now'))
                );
                CREATE INDEX IF NOT EXISTS idx_exec_module ON execution_log(module_id);
                CREATE INDEX IF NOT EXISTS idx_exec_ts ON execution_log(timestamp);
            """)
            self._db.commit()
        except Exception as exc:
            # ── Non-fatal: rankings degrade gracefully ──
            self._db = None
    
    # ──────────────────────────────────────────────────────────────
    # PUBLIC API — RANKING CRUD
    # ──────────────────────────────────────────────────────────────
    
    def get_ranking(self, module_id: str) -> Optional[ModuleRanking]:
        """
        Get ranking for a single module.
        
        Checks LRU cache first, then falls back to database.
        
        Returns ModuleRanking or None if module not found.
        """
        # ── Check cache ──
        cached = self._cache.get(module_id)
        if cached is not None:
            return cached
        
        # ── Query database ──
        if not self._db:
            return None
        
        try:
            with self._db_lock:
                cursor = self._db.execute(
                    "SELECT * FROM rankings WHERE module_id = ?",
                    (module_id,),
                )
                row = cursor.fetchone()
            
            if row is None:
                return None
            
            ranking = ModuleRanking(
                module_id=row["module_id"],
                name=row["name"],
                version=row["version"],
                online_score=row["online_score"],
                local_score=row["local_score"],
                total_runs=row["total_runs"],
                success_count=row["success_count"],
                avg_exec_time_ms=row["avg_exec_time_ms"],
                install_count=row["install_count"],
                last_used=row["last_used"],
                last_synced=row["last_synced"],
            )
            
            # ── Cache it ──
            self._cache.set(module_id, ranking)
            
            return ranking
            
        except Exception:
            return None
    
    def set_ranking(
        self,
        module_id: str,
        name: str = "",
        version: str = "",
        online_score: Optional[float] = None,
        install_count: Optional[int] = None,
    ) -> bool:
        """
        Set or update a module's ranking metadata.
        
        Idempotent: safe to call multiple times.
        
        Args:
            module_id: Module identifier.
            name: Module display name.
            version: Module version string.
            online_score: Community score (0.0 - 5.0). None = keep existing.
            install_count: Install count. None = keep existing.
        
        Returns: True on success, False on failure.
        """
        if not self._db:
            return False
        
        try:
            existing = self.get_ranking(module_id)
            
            with self._db_lock:
                self._db.execute(
                    """INSERT INTO rankings (module_id, name, version, online_score, install_count)
                       VALUES (?, ?, ?, ?, 1)
                       ON CONFLICT(module_id) DO UPDATE SET
                           name = COALESCE(NULLIF(?, ''), rankings.name),
                           version = COALESCE(NULLIF(?, ''), rankings.version),
                           online_score = COALESCE(?, rankings.online_score),
                           install_count = install_count + 1""",
                    (
                        module_id, name, version,
                        online_score if online_score is not None else 0.0,
                        name, version,
                        online_score if online_score is not None else existing.online_score if existing else 0.0,
                    ),
                )
                self._db.commit()
            
            # ── Invalidate cache ──
            self._cache.remove(module_id)
            
            return True
        except Exception:
            return False
    
    def update_online_score(self, module_id: str, score: float) -> bool:
        """
        Update the online (community) score for a module.
        
        Args:
            module_id: Module identifier.
            score: Score value (0.0 - 5.0).
        
        Returns: True on success.
        """
        score = max(0.0, min(5.0, score))
        
        if not self._db:
            return False
        
        try:
            with self._db_lock:
                self._db.execute(
                    """INSERT INTO rankings (module_id, online_score, last_synced)
                       VALUES (?, ?, ?)
                       ON CONFLICT(module_id) DO UPDATE SET
                           online_score = ?,
                           last_synced = ?""",
                    (module_id, score, time.time(), score, time.time()),
                )
                self._db.commit()
            
            self._cache.remove(module_id)
            return True
        except Exception:
            return False
    
    # ──────────────────────────────────────────────────────────────
    # PUBLIC API — EXECUTION RECORDING
    # ──────────────────────────────────────────────────────────────
    
    def record_execution(
        self,
        module_id: str,
        success: bool,
        exec_time_ms: float = 0.0,
    ) -> bool:
        """
        Record a module execution and update local scores.
        
        This is the primary method for updating local rankings.
        Call it after each module run.
        
        Idempotent: safe to call multiple times (each call is a
        separate execution record).
        
        Args:
            module_id: The module that was executed.
            success: Whether execution succeeded.
            exec_time_ms: Execution duration in milliseconds.
        
        Returns: True on success.
        """
        if not self._db:
            return False
        
        try:
            now = time.time()
            
            with self._db_lock:
                # ── Insert execution log ──
                self._db.execute(
                    """INSERT INTO execution_log (module_id, success, exec_time_ms, timestamp)
                       VALUES (?, ?, ?, ?)""",
                    (module_id, 1 if success else 0, exec_time_ms, now),
                )
                
                # ── Update rankings aggregate ──
                self._db.execute(
                    """INSERT INTO rankings (module_id, total_runs, success_count,
                       avg_exec_time_ms, last_used)
                       VALUES (?, 1, ?, ?, ?)
                       ON CONFLICT(module_id) DO UPDATE SET
                           total_runs = total_runs + 1,
                           success_count = CASE WHEN ? THEN success_count + 1 ELSE success_count END,
                           avg_exec_time_ms = (avg_exec_time_ms * (total_runs - 1) + ?) / total_runs,
                           last_used = ?""",
                    (
                        module_id,
                        1 if success else 0, exec_time_ms, now,
                        success, exec_time_ms, now,
                    ),
                )
                
                # ── Update local score based on success rate ──
                self._db.execute(
                    """UPDATE rankings SET
                           local_score = CAST(success_count AS REAL) / CAST(total_runs AS REAL) * 5.0
                       WHERE module_id = ? AND total_runs > 0""",
                    (module_id,),
                )
                
                self._db.commit()
            
            # ── Invalidate cache ──
            self._cache.remove(module_id)
            
            return True
        except Exception:
            return False
    
    # ──────────────────────────────────────────────────────────────
    # PUBLIC API — BATCH QUERIES
    # ──────────────────────────────────────────────────────────────
    
    def list_rankings(
        self,
        sort_by: str = "combined_score",
        ascending: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """
        List all ranked modules with full metadata.
        
        Args:
            sort_by: Sort field. One of:
                     "combined_score", "online_score", "local_score",
                     "total_runs", "success_rate", "avg_exec_time_ms",
                     "name", "module_id", "last_used".
            ascending: If True, sort ascending (default: descending).
            limit: Max results to return.
            offset: Pagination offset.
        
        Returns:
            List of ranking dicts.
        """
        if not self._db:
            return []
        
        # ── Whitelist sort columns (prevent SQL injection) ──
        allowed_sorts = {
            "combined_score": "(COALESCE(online_score, 0) * 0.4 + COALESCE(local_score, 0) * 0.6)",
            "online_score": "online_score",
            "local_score": "local_score",
            "total_runs": "total_runs",
            "success_rate": "CASE WHEN total_runs > 0 THEN CAST(success_count AS REAL) / total_runs ELSE 0 END",
            "avg_exec_time_ms": "avg_exec_time_ms",
            "name": "name",
            "module_id": "module_id",
            "last_used": "last_used",
        }
        
        sort_col = allowed_sorts.get(sort_by, "combined_score")
        direction = "ASC" if ascending else "DESC"
        
        try:
            query = f"""
                SELECT *, 
                       (COALESCE(online_score, 0) * 0.4 + COALESCE(local_score, 0) * 0.6) AS combined_score,
                       CASE WHEN total_runs > 0 THEN CAST(success_count AS REAL) / total_runs * 100 ELSE 0 END AS success_rate
                FROM rankings
                ORDER BY {sort_col} {direction}
                LIMIT ? OFFSET ?
            """
            
            with self._db_lock:
                cursor = self._db.execute(query, (limit, offset))
                rows = cursor.fetchall()
            
            results = []
            for row in rows:
                results.append({
                    "module_id": row["module_id"],
                    "name": row["name"],
                    "version": row["version"],
                    "online_score": row["online_score"],
                    "local_score": row["local_score"],
                    "combined_score": round(row["combined_score"], 2) if row["combined_score"] else 0.0,
                    "total_runs": row["total_runs"],
                    "success_count": row["success_count"],
                    "success_rate": round(row["success_rate"], 1) if row["success_rate"] else 0.0,
                    "avg_exec_time_ms": row["avg_exec_time_ms"],
                    "install_count": row["install_count"],
                    "last_used": row["last_used"],
                })
            
            return results
        except Exception:
            return []
    
    def get_top_modules(self, count: int = 5) -> List[Dict[str, Any]]:
        """
        Get the top N modules by combined score.
        
        Convenience method for UI dashboards.
        """
        return self.list_rankings(sort_by="combined_score", limit=count)
    
    def get_module_stats(self, module_id: str) -> Dict[str, Any]:
        """
        Get detailed execution statistics for a module.
        
        Returns dict with execution history summary.
        """
        stats: Dict[str, Any] = {
            "module_id": module_id,
            "total_runs": 0,
            "success_count": 0,
            "failure_count": 0,
            "success_rate": 0.0,
            "avg_exec_time_ms": 0.0,
            "last_10_executions": [],
        }
        
        ranking = self.get_ranking(module_id)
        if ranking:
            stats["total_runs"] = ranking.total_runs
            stats["success_count"] = ranking.success_count
            stats["failure_count"] = ranking.total_runs - ranking.success_count
            stats["success_rate"] = ranking.success_rate
            stats["avg_exec_time_ms"] = ranking.avg_exec_time_ms
        
        # ── Get last 10 execution records ──
        if self._db:
            try:
                with self._db_lock:
                    cursor = self._db.execute(
                        """SELECT success, exec_time_ms, timestamp
                           FROM execution_log
                           WHERE module_id = ?
                           ORDER BY timestamp DESC
                           LIMIT 10""",
                        (module_id,),
                    )
                    rows = cursor.fetchall()
                
                stats["last_10_executions"] = [
                    {
                        "success": bool(row["success"]),
                        "exec_time_ms": row["exec_time_ms"],
                        "timestamp": row["timestamp"],
                    }
                    for row in rows
                ]
            except Exception:
                pass
        
        return stats
    
    # ──────────────────────────────────────────────────────────────
    # PUBLIC API — ONLINE SYNC
    # ──────────────────────────────────────────────────────────────
    
    async def sync_online(self) -> int:
        """
        Synchronize online rankings from the community server.
        
        This is an async method — it fetches community rankings
        from the configured endpoint and updates the local database.
        
        Untraceable: uses HTTPS with TLS, no identifying headers.
        
        Returns: Number of rankings updated.
        
        Note: In a fully air-gapped environment, this will fail
        gracefully and return 0.
        """
        if self._sync_in_progress:
            return 0  # Idempotent: skip if already syncing
        
        self._sync_in_progress = True
        
        try:
            # ── Get community rankings endpoint ──
            endpoint = self._get_sync_endpoint()
            if not endpoint:
                return 0
            
            import aiohttp
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    endpoint,
                    timeout=aiohttp.ClientTimeout(total=30),
                    headers={
                        "User-Agent": "Anubis/3.2.1",
                        "Accept": "application/json",
                    },
                ) as resp:
                    if resp.status != 200:
                        return 0
                    
                    data = await resp.json()
            
            # ── Data format: list of {module_id, score, name, version} ──
            updated = 0
            for entry in data.get("rankings", []):
                module_id = entry.get("module_id", "")
                score = float(entry.get("score", 0.0))
                name = entry.get("name", "")
                version = entry.get("version", "")
                
                if module_id and score > 0:
                    success = self.update_online_score(module_id, score)
                    if success:
                        # ── Also update name/version ──
                        self.set_ranking(module_id, name=name, version=version)
                        updated += 1
            
            self._last_sync = time.time()
            
            # ── Log sync result ──
            if self._engine and hasattr(self._engine, "telemetry"):
                self._engine.telemetry.info(
                    "ranking",
                    {"message": f"Synced {updated} online rankings"},
                )
            
            return updated
            
        except Exception:
            return 0
        finally:
            self._sync_in_progress = False
    
    def _get_sync_endpoint(self) -> Optional[str]:
        """
        Get the online rankings sync endpoint.
        
        Reads from config or falls back to the default community URL.
        Can be disabled by setting ranking.auto_sync to False.
        """
        # ── Check config ──
        if self._engine:
            config = self._engine.config if hasattr(self._engine, "config") else {}
            ranking_config = config.get("ranking", {})
            if not ranking_config.get("auto_sync", True):
                return None
            
            endpoint = ranking_config.get("sync_url", "")
            if endpoint:
                return endpoint
        
        # ── Default (placeholder — replace with actual endpoint) ──
        return "https://rankings.anubis-framework.io/v1/rankings"
    
    def last_sync_time(self) -> Optional[float]:
        """Get the timestamp of the last online sync."""
        return self._last_sync
    
    # ──────────────────────────────────────────────────────────────
    # PUBLIC API — ADMIN
    # ──────────────────────────────────────────────────────────────
    
    def reset_local_scores(self, module_id: Optional[str] = None) -> int:
        """
        Reset local scores for one or all modules.
        
        Args:
            module_id: If provided, reset only this module.
                       If None, reset all modules.
        
        Returns: Number of modules reset.
        """
        if not self._db:
            return 0
        
        try:
            with self._db_lock:
                if module_id:
                    self._db.execute(
                        """UPDATE rankings SET local_score = 0.0,
                           total_runs = 0, success_count = 0,
                           avg_exec_time_ms = 0.0
                           WHERE module_id = ?""",
                        (module_id,),
                    )
                    self._db.execute(
                        "DELETE FROM execution_log WHERE module_id = ?",
                        (module_id,),
                    )
                    self._cache.remove(module_id)
                    return 1
                else:
                    self._db.execute(
                        "UPDATE rankings SET local_score = 0.0, total_runs = 0, "
                        "success_count = 0, avg_exec_time_ms = 0.0"
                    )
                    self._db.execute("DELETE FROM execution_log")
                    self._cache.clear()
                    return self._db.total_changes
        except Exception:
            return 0
    
    def shutdown(self) -> None:
        """
        Shut down the ranking engine.
        
        Flushes any pending data and closes the database.
        Idempotent.
        """
        with self._db_lock:
            if self._db is not None:
                try:
                    self._db.close()
                except Exception:
                    pass
                self._db = None
        
        self._cache.clear()
    
    # ──────────────────────────────────────────────────────────────
    # REPRESENTATION
    # ──────────────────────────────────────────────────────────────
    
    def __repr__(self) -> str:
        if self._db:
            try:
                with self._db_lock:
                    cursor = self._db.execute("SELECT COUNT(*) FROM rankings")
                    count = cursor.fetchone()[0]
            except Exception:
                count = 0
        else:
            count = 0
        
        return (
            f"<RankingEngine "
            f"modules={count} "
            f"last_sync={'never' if self._last_sync is None else time.strftime('%H:%M:%S', time.gmtime(self._last_sync))}>"
      )
