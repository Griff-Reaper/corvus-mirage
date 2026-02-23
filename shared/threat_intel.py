"""
Corvus Mirage — Shared
Threat Intelligence Database

SQLite-backed store for all ThreatEvents from ARIA and Gateway.
Single source of truth for the unified dashboard.

Tables:
    threat_events   — every detection from every component
    attacker_profiles — cross-vector correlation records

Both components import and call write_event().
The dashboard queries get_recent_events() and get_events_by_session().
"""
import sqlite3
import json
import uuid
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime
from pathlib import Path

from .models import ThreatEvent, AttackerProfile, ThreatSource, ThreatStatus


logger = logging.getLogger("corvus.shared.threat_intel")

# DB lives at the monorepo root so both components can reach it
_DEFAULT_DB_PATH = Path(__file__).parent.parent / "threat_intel.db"
_db_path: Path = _DEFAULT_DB_PATH


def init_db(db_path: Optional[str] = None):
    """
    Initialize the threat intelligence database.
    Called at startup by both ARIA and Gateway.
    Safe to call multiple times — CREATE IF NOT EXISTS.
    """
    global _db_path
    if db_path:
        _db_path = Path(db_path)

    conn = _connect()
    try:
        c = conn.cursor()

        c.execute("""
            CREATE TABLE IF NOT EXISTS threat_events (
                id                  TEXT PRIMARY KEY,
                session_id          TEXT NOT NULL,
                source              TEXT NOT NULL,
                timestamp           TEXT NOT NULL,
                caller_id           TEXT,
                user_id             TEXT,
                ip_address          TEXT,
                threat_score        REAL DEFAULT 0.0,
                threat_level        TEXT DEFAULT 'safe',
                is_malicious        INTEGER DEFAULT 0,
                confidence          REAL DEFAULT 0.0,
                categories          TEXT DEFAULT '[]',
                techniques          TEXT DEFAULT '[]',
                mitre_tags          TEXT DEFAULT '[]',
                action_taken        TEXT DEFAULT 'allow',
                sophistication      TEXT,
                raw_content         TEXT,
                sanitized_content   TEXT,
                primary_objective   TEXT,
                evidence            TEXT DEFAULT '[]',
                status              TEXT DEFAULT 'active',
                component_metadata  TEXT DEFAULT '{}'
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS attacker_profiles (
                profile_id          TEXT PRIMARY KEY,
                first_seen          TEXT NOT NULL,
                last_seen           TEXT NOT NULL,
                session_ids         TEXT DEFAULT '[]',
                sources_seen        TEXT DEFAULT '[]',
                total_events        INTEGER DEFAULT 0,
                max_threat_score    REAL DEFAULT 0.0,
                all_techniques      TEXT DEFAULT '[]',
                all_mitre_tags      TEXT DEFAULT '[]',
                caller_id           TEXT,
                ip_address          TEXT,
                risk_rating         TEXT DEFAULT 'low'
            )
        """)

        # Indexes for common query patterns
        c.execute("CREATE INDEX IF NOT EXISTS idx_events_session ON threat_events(session_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_events_source ON threat_events(source)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON threat_events(timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_events_caller ON threat_events(caller_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_events_malicious ON threat_events(is_malicious)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_profiles_caller ON attacker_profiles(caller_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_profiles_ip ON attacker_profiles(ip_address)")

        conn.commit()
        logger.info(f"[✓] Threat intel DB initialized at {_db_path}")
    finally:
        conn.close()


def write_event(event: ThreatEvent) -> str:
    """
    Write a ThreatEvent to the database.
    Returns the generated event ID.
    Also triggers cross-vector correlation check.
    """
    event_id = str(uuid.uuid4())
    conn = _connect()
    try:
        c = conn.cursor()
        c.execute("""
            INSERT INTO threat_events (
                id, session_id, source, timestamp,
                caller_id, user_id, ip_address,
                threat_score, threat_level, is_malicious, confidence,
                categories, techniques, mitre_tags,
                action_taken, sophistication,
                raw_content, sanitized_content,
                primary_objective, evidence,
                status, component_metadata
            ) VALUES (
                ?, ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?,
                ?, ?,
                ?, ?,
                ?, ?,
                ?, ?
            )
        """, (
            event_id,
            event.session_id,
            event.source.value,
            event.timestamp.isoformat(),
            event.caller_id,
            event.user_id,
            event.ip_address,
            event.threat_score,
            event.threat_level,
            1 if event.is_malicious else 0,
            event.confidence,
            json.dumps(event.categories),
            json.dumps(event.techniques),
            json.dumps(event.mitre_tags),
            event.action_taken,
            event.sophistication,
            event.raw_content,
            event.sanitized_content,
            event.primary_objective,
            json.dumps(event.evidence),
            event.status.value,
            json.dumps(event.component_metadata),
        ))
        conn.commit()
        logger.debug(f"Event written: {event_id} | source={event.source.value} | score={event.threat_score}")

        # Run correlation in same connection
        _correlate(conn, event)

    finally:
        conn.close()

    return event_id


def get_recent_events(
    limit: int = 50,
    source: Optional[str] = None,
    malicious_only: bool = False,
    min_score: float = 0.0,
) -> List[Dict[str, Any]]:
    """
    Get recent threat events for the dashboard.
    Ordered newest first.
    """
    conn = _connect()
    try:
        query = "SELECT * FROM threat_events WHERE 1=1"
        params = []

        if source:
            query += " AND source = ?"
            params.append(source)
        if malicious_only:
            query += " AND is_malicious = 1"
        if min_score > 0:
            query += " AND threat_score >= ?"
            params.append(min_score)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        c = conn.cursor()
        c.execute(query, params)
        return [_row_to_dict(row) for row in c.fetchall()]
    finally:
        conn.close()


def get_events_by_session(session_id: str) -> List[Dict[str, Any]]:
    """Get all events for a specific session — both ARIA and Gateway."""
    conn = _connect()
    try:
        c = conn.cursor()
        c.execute(
            "SELECT * FROM threat_events WHERE session_id = ? ORDER BY timestamp ASC",
            (session_id,)
        )
        return [_row_to_dict(row) for row in c.fetchall()]
    finally:
        conn.close()


def get_cross_vector_sessions() -> List[Dict[str, Any]]:
    """
    Find sessions that appear in both ARIA and Gateway events.
    These are the highest-priority attacker profiles — same actor,
    multiple attack vectors.
    """
    conn = _connect()
    try:
        c = conn.cursor()
        c.execute("""
            SELECT session_id, COUNT(DISTINCT source) as source_count,
                   GROUP_CONCAT(DISTINCT source) as sources,
                   MAX(threat_score) as max_score,
                   COUNT(*) as event_count
            FROM threat_events
            GROUP BY session_id
            HAVING source_count > 1
            ORDER BY max_score DESC
        """)
        rows = c.fetchall()
        return [
            {
                "session_id":   r[0],
                "source_count": r[1],
                "sources":      r[2],
                "max_score":    r[3],
                "event_count":  r[4],
            }
            for r in rows
        ]
    finally:
        conn.close()


def get_stats() -> Dict[str, Any]:
    """Aggregate stats for the dashboard summary panel."""
    conn = _connect()
    try:
        c = conn.cursor()

        c.execute("SELECT COUNT(*) FROM threat_events")
        total = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM threat_events WHERE is_malicious = 1")
        malicious = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM threat_events WHERE source = 'aria'")
        aria_count = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM threat_events WHERE source = 'gateway'")
        gateway_count = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM threat_events WHERE action_taken = 'block'")
        blocked = c.fetchone()[0]

        c.execute("SELECT COUNT(DISTINCT session_id) FROM threat_events")
        sessions = c.fetchone()[0]

        c.execute("""
            SELECT COUNT(DISTINCT session_id) FROM (
                SELECT session_id FROM threat_events
                GROUP BY session_id HAVING COUNT(DISTINCT source) > 1
            )
        """)
        cross_vector = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM attacker_profiles")
        profiles = c.fetchone()[0]

        return {
            "total_events":          total,
            "malicious_events":      malicious,
            "aria_events":           aria_count,
            "gateway_events":        gateway_count,
            "blocked":               blocked,
            "unique_sessions":       sessions,
            "cross_vector_sessions": cross_vector,
            "attacker_profiles":     profiles,
        }
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _connect() -> sqlite3.Connection:
    _db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_db_path))
    conn.row_factory = sqlite3.Row
    return conn


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    for field in ("categories", "techniques", "mitre_tags", "evidence",
                  "session_ids", "sources_seen", "all_techniques", "all_mitre_tags",
                  "component_metadata"):
        if field in d and d[field]:
            try:
                d[field] = json.loads(d[field])
            except (json.JSONDecodeError, TypeError):
                pass
    d["is_malicious"] = bool(d.get("is_malicious", 0))
    return d


def _correlate(conn: sqlite3.Connection, event: ThreatEvent):
    """
    Check if this event's session_id or caller_id has been seen before
    from a DIFFERENT source. If so, update or create an attacker profile.
    """
    try:
        c = conn.cursor()

        # Look for existing events from a different source with same session
        c.execute("""
            SELECT DISTINCT source FROM threat_events
            WHERE session_id = ? AND source != ?
        """, (event.session_id, event.source.value))

        cross_sources = [r[0] for r in c.fetchall()]

        if not cross_sources:
            return  # No cross-vector correlation yet

        # Cross-vector hit — update or create attacker profile
        profile_id = f"profile_{event.session_id}"

        c.execute("SELECT * FROM attacker_profiles WHERE profile_id = ?", (profile_id,))
        existing = c.fetchone()

        # Gather all events for this session
        c.execute("""
            SELECT source, threat_score, techniques, mitre_tags
            FROM threat_events WHERE session_id = ?
        """, (event.session_id,))
        all_events = c.fetchall()

        all_sources = list(set(r[0] for r in all_events))
        max_score = max(r[1] for r in all_events)
        all_techniques = list(set(
            t for r in all_events
            for t in json.loads(r[2] or "[]")
        ))
        all_mitre = list(set(
            t for r in all_events
            for t in json.loads(r[3] or "[]")
        ))

        risk = "low"
        if max_score >= 75:  risk = "critical"
        elif max_score >= 55: risk = "high"
        elif max_score >= 35: risk = "medium"

        now = datetime.utcnow().isoformat()

        if existing:
            c.execute("""
                UPDATE attacker_profiles SET
                    last_seen = ?, sources_seen = ?, total_events = ?,
                    max_threat_score = ?, all_techniques = ?,
                    all_mitre_tags = ?, risk_rating = ?
                WHERE profile_id = ?
            """, (
                now,
                json.dumps(all_sources),
                len(all_events),
                max_score,
                json.dumps(all_techniques),
                json.dumps(all_mitre),
                risk,
                profile_id,
            ))
        else:
            c.execute("""
                INSERT INTO attacker_profiles (
                    profile_id, first_seen, last_seen, session_ids,
                    sources_seen, total_events, max_threat_score,
                    all_techniques, all_mitre_tags,
                    caller_id, ip_address, risk_rating
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                profile_id, now, now,
                json.dumps([event.session_id]),
                json.dumps(all_sources),
                len(all_events),
                max_score,
                json.dumps(all_techniques),
                json.dumps(all_mitre),
                event.caller_id,
                event.ip_address,
                risk,
            ))

        conn.commit()
        logger.info(
            f"[!] Cross-vector profile {'updated' if existing else 'created'}: "
            f"{profile_id} | sources={all_sources} | score={max_score}"
        )

    except Exception as e:
        logger.error(f"Correlation error: {e}")
