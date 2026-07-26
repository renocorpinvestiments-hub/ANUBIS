-- ═══════════════════════════════════════════════════════════════════
-- ANUBIS v1.0.0 — Database Schema
-- ═══════════════════════════════════════════════════════════════════
-- Engine:     SQLite 3.x
-- Journal:    WAL
-- Encoding:   UTF-8
-- 
-- All table names are runtime-obfuscated via config['table_prefix'].
-- This file is the canonical DDL for clean initialization.
-- Migration history is tracked in _schema_version.
--
-- Conventions:
--   - INTEGER PRIMARY KEY → rowid alias (auto-increment)
--   - timestamps → ISO-8601 TEXT (UTC)
--   - blob fields → base64 TEXT (for portable dump/restore)
--   - All tables have created_at / updated_at
--   - Foreign keys enforced at engine level (PRAGMA foreign_keys = ON)
-- ═══════════════════════════════════════════════════════════════════

-- ── Schema version tracking ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS _schema_version (
    version     INTEGER PRIMARY KEY NOT NULL,
    applied_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S', 'now')),
    description TEXT    NOT NULL DEFAULT '',
    checksum    TEXT    NOT NULL DEFAULT '',
    author      TEXT    NOT NULL DEFAULT 'system',
    success     INTEGER NOT NULL DEFAULT 1
);

INSERT INTO _schema_version (version, description, author)
VALUES (1, 'Initial schema v1.0.0', 'system');

-- ── Modules registry ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS a_modules (
    id              TEXT    PRIMARY KEY NOT NULL,   -- '001', '002', ...
    name            TEXT    NOT NULL,                -- 'Reverse Shell Generator'
    version         TEXT    NOT NULL DEFAULT '1.0.0',
    author          TEXT    NOT NULL DEFAULT '',
    description     TEXT    NOT NULL DEFAULT '',
    category        TEXT    NOT NULL DEFAULT 'uncategorized',
    path            TEXT    NOT NULL DEFAULT '',      -- filesystem path
    tags            TEXT    NOT NULL DEFAULT '[]',    -- JSON array
    compat          TEXT    NOT NULL DEFAULT '{}',    -- JSON object per OS
    enabled         INTEGER NOT NULL DEFAULT 1,
    is_builtin      INTEGER NOT NULL DEFAULT 0,
    install_date    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S', 'now')),
    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S', 'now')),
    last_loaded     TEXT,
    load_count      INTEGER NOT NULL DEFAULT 0,
    checksum        TEXT    NOT NULL DEFAULT '',
    size_bytes      INTEGER NOT NULL DEFAULT 0,
    metadata        TEXT    NOT NULL DEFAULT '{}'     -- JSON blob
);

CREATE INDEX IF NOT EXISTS idx_modules_category ON a_modules(category);
CREATE INDEX IF NOT EXISTS idx_modules_enabled  ON a_modules(enabled);
CREATE INDEX IF NOT EXISTS idx_modules_tags     ON a_modules(tags);

-- ── Module rankings (local scoring engine) ────────────────────────
CREATE TABLE IF NOT EXISTS a_module_rankings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    module_id       TEXT    NOT NULL,
    score           REAL    NOT NULL DEFAULT 0.0,        -- 0.0 - 10.0
    uptime_score    REAL    NOT NULL DEFAULT 0.0,
    success_rate    REAL    NOT NULL DEFAULT 0.0,        -- 0.0 - 1.0
    avg_latency_ms  REAL    NOT NULL DEFAULT 0.0,
    memory_mb       REAL    NOT NULL DEFAULT 0.0,
    stealth_score   REAL    NOT NULL DEFAULT 1.0,        -- 0.0 - 1.0
    versatility     REAL    NOT NULL DEFAULT 0.0,        -- 0.0 - 1.0
    community_rating REAL   NOT NULL DEFAULT 0.0,
    sample_count    INTEGER NOT NULL DEFAULT 0,
    last_updated    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S', 'now')),
    decay_start     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S', 'now')),
    FOREIGN KEY (module_id) REFERENCES a_modules(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_rankings_module ON a_module_rankings(module_id);
CREATE INDEX IF NOT EXISTS idx_rankings_score        ON a_module_rankings(score DESC);

-- ── Execution history / audit log ─────────────────────────────────
CREATE TABLE IF NOT EXISTS a_executions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    module_id       TEXT    NOT NULL,
    session_id      TEXT    NOT NULL,                   -- UUID per engine session
    start_time      TEXT    NOT NULL,
    end_time        TEXT,
    duration_ms     INTEGER,
    status          TEXT    NOT NULL DEFAULT 'started',  -- started | success | error | timeout
    exit_code       INTEGER,
    params          TEXT    NOT NULL DEFAULT '{}',       -- JSON of input parameters
    result          TEXT    NOT NULL DEFAULT '{}',       -- JSON of output result
    error           TEXT    NOT NULL DEFAULT '',
    traceback       TEXT    NOT NULL DEFAULT '',
    cpu_percent     REAL,
    memory_mb       REAL,
    io_read_bytes   INTEGER DEFAULT 0,
    io_write_bytes  INTEGER DEFAULT 0,
    network_sent    INTEGER DEFAULT 0,
    network_recv    INTEGER DEFAULT 0,
    stealth_mode    INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S', 'now')),
    FOREIGN KEY (module_id) REFERENCES a_modules(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_exec_module    ON a_executions(module_id);
CREATE INDEX IF NOT EXISTS idx_exec_status    ON a_executions(status);
CREATE INDEX IF NOT EXISTS idx_exec_session   ON a_executions(session_id);
CREATE INDEX IF NOT EXISTS idx_exec_start     ON a_executions(start_time DESC);
CREATE INDEX IF NOT EXISTS idx_exec_duration  ON a_executions(duration_ms);

-- ── Delivery pipeline cache / history ─────────────────────────────
CREATE TABLE IF NOT EXISTS a_delivery_cache (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256          TEXT    NOT NULL UNIQUE,
    module_id       TEXT    NOT NULL,
    output_path     TEXT    NOT NULL DEFAULT '',
    file_size_bytes INTEGER NOT NULL DEFAULT 0,
    payload_type    TEXT    NOT NULL DEFAULT '',
    target_os       TEXT    NOT NULL DEFAULT '',
    encrypted       INTEGER NOT NULL DEFAULT 0,
    build_time_ms   INTEGER NOT NULL DEFAULT 0,
    delivery_method TEXT    NOT NULL DEFAULT '',
    delivery_target TEXT    NOT NULL DEFAULT '',
    delivery_status TEXT    NOT NULL DEFAULT 'pending',  -- pending | sent | failed
    delivery_time   TEXT,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S', 'now')),
    last_accessed   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S', 'now')),
    access_count    INTEGER NOT NULL DEFAULT 1,
    metadata        TEXT    NOT NULL DEFAULT '{}',
    FOREIGN KEY (module_id) REFERENCES a_modules(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_cache_sha256      ON a_delivery_cache(sha256);
CREATE INDEX IF NOT EXISTS idx_cache_module      ON a_delivery_cache(module_id);
CREATE INDEX IF NOT EXISTS idx_cache_method      ON a_delivery_cache(delivery_method);
CREATE INDEX IF NOT EXISTS idx_cache_accessed    ON a_delivery_cache(last_accessed DESC);

-- ── Telemetry ring buffer (persistent overflow) ───────────────────
CREATE TABLE IF NOT EXISTS a_telemetry_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sequence        INTEGER NOT NULL,                   -- monotonic sequence per session
    timestamp       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.%f', 'now')),
    level           TEXT    NOT NULL DEFAULT 'INFO',     -- DEBUG | INFO | WARNING | ERROR | FATAL
    source          TEXT    NOT NULL DEFAULT '',          -- module_id or system component
    message         TEXT    NOT NULL DEFAULT '',
    data            TEXT    NOT NULL DEFAULT '{}',        -- JSON structured data
    traceback       TEXT    NOT NULL DEFAULT '',
    session_id      TEXT    NOT NULL DEFAULT '',
    thread_id       INTEGER,
    process_id      INTEGER,
    correlation_id  TEXT    NOT NULL DEFAULT '',
    hostname        TEXT    NOT NULL DEFAULT '',
    runtime_ms      REAL
);

CREATE INDEX IF NOT EXISTS idx_telemetry_time    ON a_telemetry_log(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_level   ON a_telemetry_log(level);
CREATE INDEX IF NOT EXISTS idx_telemetry_source  ON a_telemetry_log(source);
CREATE INDEX IF NOT EXISTS idx_telemetry_session ON a_telemetry_log(session_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_seq     ON a_telemetry_log(sequence DESC);

-- ── Configuration snapshots (change tracking) ─────────────────────
CREATE TABLE IF NOT EXISTS a_config_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    version         INTEGER NOT NULL,
    applied_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S', 'now')),
    config_snapshot TEXT    NOT NULL,                   -- full JSON config
    checksum        TEXT    NOT NULL DEFAULT '',
    change_summary  TEXT    NOT NULL DEFAULT '',
    author          TEXT    NOT NULL DEFAULT 'system',
    is_rollback     INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_config_version ON a_config_history(version DESC);

-- ── Sessions (engine lifecycle) ───────────────────────────────────
CREATE TABLE IF NOT EXISTS a_sessions (
    id              TEXT    PRIMARY KEY NOT NULL,        -- UUID
    started_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S', 'now')),
    ended_at        TEXT,
    hostname        TEXT    NOT NULL DEFAULT '',
    username        TEXT    NOT NULL DEFAULT '',
    os_platform     TEXT    NOT NULL DEFAULT '',
    os_version      TEXT    NOT NULL DEFAULT '',
    python_version  TEXT    NOT NULL DEFAULT '',
    anubis_version  TEXT    NOT NULL DEFAULT '',
    modules_loaded  INTEGER NOT NULL DEFAULT 0,
    executions_run  INTEGER NOT NULL DEFAULT 0,
    status          TEXT    NOT NULL DEFAULT 'active',   -- active | closed | crashed
    exit_code       INTEGER,
    shutdown_reason TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_sessions_started ON a_sessions(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_status  ON a_sessions(status);

-- ── Performance metrics bucket (15-min rolling) ───────────────────
CREATE TABLE IF NOT EXISTS a_metrics (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    bucket_start    TEXT    NOT NULL,
    bucket_end      TEXT    NOT NULL,
    cpu_avg         REAL,
    cpu_max         REAL,
    memory_avg_mb   REAL,
    memory_max_mb   REAL,
    modules_active  INTEGER,
    threads_active  INTEGER,
    connections_open INTEGER,
    disk_io_read_mb  REAL,
    disk_io_write_mb REAL,
    net_sent_mb     REAL,
    net_recv_mb     REAL,
    samples         INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_metrics_bucket ON a_metrics(bucket_start DESC);

-- ── Error aggregation ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS a_errors (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    error_hash      TEXT    NOT NULL,                   -- SHA256 of type + message for dedup
    error_type      TEXT    NOT NULL DEFAULT '',
    error_message   TEXT    NOT NULL DEFAULT '',
    source          TEXT    NOT NULL DEFAULT '',
    module_id       TEXT    NOT NULL DEFAULT '',
    first_seen      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S', 'now')),
    last_seen       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S', 'now')),
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    sample_traceback TEXT   NOT NULL DEFAULT '',
    resolved        INTEGER NOT NULL DEFAULT 0,
    resolved_at     TEXT,
    notes           TEXT    NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_errors_hash ON a_errors(error_hash);
CREATE INDEX IF NOT EXISTS idx_errors_last_seen   ON a_errors(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_errors_resolved    ON a_errors(resolved);

-- ── Tags lookup (many-to-many shortcut) ───────────────────────────
CREATE TABLE IF NOT EXISTS a_tags (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    tag             TEXT    NOT NULL UNIQUE,
    module_count    INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_tags_name ON a_tags(tag);

-- ── ─────────────────────────────────────────────────────────────
-- VIEWS (convenience, read-only)
-- ── ─────────────────────────────────────────────────────────────

CREATE VIEW IF NOT EXISTS v_module_performance AS
SELECT
    m.id           AS module_id,
    m.name         AS module_name,
    m.category     AS category,
    COALESCE(r.score, 0.0)               AS rank_score,
    COALESCE(r.success_rate, 0.0)        AS success_rate,
    COALESCE(r.avg_latency_ms, 0.0)      AS avg_latency_ms,
    COALESCE(r.sample_count, 0)          AS sample_count,
    COALESCE(COUNT(e.id), 0)             AS total_executions,
    COALESCE(SUM(CASE WHEN e.status = 'success' THEN 1 ELSE 0 END), 0) AS successful_executions,
    COALESCE(MAX(e.duration_ms), 0)      AS max_duration_ms,
    COALESCE(AVG(e.duration_ms), 0.0)    AS avg_duration_ms
FROM a_modules m
LEFT JOIN a_module_rankings r ON r.module_id = m.id
LEFT JOIN a_executions e ON e.module_id = m.id
WHERE m.enabled = 1
GROUP BY m.id
ORDER BY rank_score DESC;

CREATE VIEW IF NOT EXISTS v_recent_activity AS
SELECT
    timestamp,
    level,
    source,
    message,
    session_id
FROM a_telemetry_log
ORDER BY timestamp DESC
LIMIT 100;

CREATE VIEW IF NOT EXISTS v_error_summary AS
SELECT
    error_type,
    error_message,
    source,
    occurrence_count,
    first_seen,
    last_seen,
    resolved
FROM a_errors
WHERE resolved = 0
ORDER BY occurrence_count DESC, last_seen DESC;

-- ── ─────────────────────────────────────────────────────────────
-- TRIGGERS
-- ── ─────────────────────────────────────────────────────────────

-- Auto-update updated_at on modules
CREATE TRIGGER IF NOT EXISTS trg_modules_updated
    AFTER UPDATE ON a_modules
    FOR EACH ROW
BEGIN
    UPDATE a_modules
    SET updated_at = strftime('%Y-%m-%dT%H:%M:%S', 'now')
    WHERE id = OLD.id;
END;

-- Update tag counts when modules change
CREATE TRIGGER IF NOT EXISTS trg_tags_count_insert
    AFTER INSERT ON a_modules
    FOR EACH ROW
BEGIN
    UPDATE a_tags
    SET module_count = (
        SELECT COUNT(*) FROM a_modules WHERE tags LIKE '%' || a_tags.tag || '%'
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_tags_count_delete
    AFTER DELETE ON a_modules
    FOR EACH ROW
BEGIN
    UPDATE a_tags
    SET module_count = (
        SELECT COUNT(*) FROM a_modules WHERE tags LIKE '%' || a_tags.tag || '%'
    );
END;

-- Log execution status changes to telemetry mirror
CREATE TRIGGER IF NOT EXISTS trg_execution_complete
    AFTER UPDATE OF status ON a_executions
    FOR EACH ROW
    WHEN NEW.status IN ('success', 'error')
BEGIN
    INSERT INTO a_telemetry_log (sequence, level, source, message, data, session_id)
    VALUES (
        (SELECT COALESCE(MAX(sequence), 0) + 1 FROM a_telemetry_log),
        CASE WHEN NEW.status = 'success' THEN 'INFO' ELSE 'ERROR' END,
        NEW.module_id,
        'Execution ' || NEW.status || ' (' || NEW.session_id || ')',
        json_object('execution_id', NEW.id, 'duration_ms', NEW.duration_ms, 'exit_code', NEW.exit_code),
        NEW.session_id
    );
END;

-- ── ─────────────────────────────────────────────────────────────
-- INITIAL DATA (seeded once on first deploy)
-- ── ─────────────────────────────────────────────────────────────

INSERT OR IGNORE INTO a_tags (tag) VALUES
    ('reverse-shell'),
    ('privilege-escalation'),
    ('persistence'),
    ('credential-theft'),
    ('network-scan'),
    ('c2'),
    ('payload-generation'),
    ('encrypted'),
    ('stealth'),
    ('lateral-movement'),
    ('reconnaissance'),
    ('exfiltration'),
    ('defense-evasion'),
    ('discovery'),
    ('collection');

-- ═══════════════════════════════════════════════════════════════════
-- END OF SCHEMA
-- ═══════════════════════════════════════════════════════════════════
