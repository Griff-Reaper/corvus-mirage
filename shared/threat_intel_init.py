"""
Corvus Mirage — Shared Threat Intelligence Layer
Initializes the shared SQLite database used by all components.
All three components read/write here so patterns learned in one
inform the others.
"""

import sqlite3
import os
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("corvus.threat_intel")

DB_PATH = os.getenv("THREAT_INTEL_DB_PATH", "./shared/data/threat_intel.db")


def init_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # ── Attacker Sessions ──────────────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attacker_sessions (
            id TEXT PRIMARY KEY,
            source TEXT NOT NULL,          -- 'aria_web', 'aria_voice', 'gateway'
            session_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            session_end TIMESTAMP,
            ip_address TEXT,
            phone_number TEXT,
            geolocation TEXT,              -- JSON: country, region, city
            carrier TEXT,
            sophistication TEXT,           -- LOW, MEDIUM, HIGH, CRITICAL
            threat_score INTEGER DEFAULT 0,
            status TEXT DEFAULT 'ACTIVE',  -- ACTIVE, CLOSED, FLAGGED
            notes TEXT
        )
    """)

    # ── Detected Techniques ────────────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS detected_techniques (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            technique TEXT NOT NULL,       -- e.g. 'prompt_injection', 'pretexting'
            mitre_tag TEXT,               -- e.g. 'T1566', 'T1078'
            confidence REAL,              -- 0.0 - 1.0
            detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            raw_input TEXT,
            component TEXT,               -- 'aria', 'gateway', 'red_team'
            FOREIGN KEY (session_id) REFERENCES attacker_sessions(id)
        )
    """)

    # ── Voice Sessions (ARIA vishing) ──────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS voice_sessions (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            call_sid TEXT,                -- Twilio call SID
            caller_number TEXT,
            called_number TEXT,
            call_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            call_end TIMESTAMP,
            duration_seconds INTEGER,
            geolocation TEXT,             -- JSON
            carrier TEXT,
            transcript TEXT,              -- Full real-time transcript
            alert_fired BOOLEAN DEFAULT FALSE,
            alert_fired_at TIMESTAMP,
            FOREIGN KEY (session_id) REFERENCES attacker_sessions(id)
        )
    """)

    # ── Gateway Events ─────────────────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS gateway_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            event_type TEXT NOT NULL,     -- 'blocked', 'flagged', 'allowed'
            detection_category TEXT,      -- 'prompt_injection', 'jailbreak', etc.
            model_target TEXT,            -- which AI model was being attacked
            input_hash TEXT,              -- hashed version of the input
            confidence REAL,
            blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (session_id) REFERENCES attacker_sessions(id)
        )
    """)

    # ── Threat Intelligence Feed ───────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_intel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator_type TEXT NOT NULL, -- 'ip', 'phone', 'technique', 'region'
            indicator_value TEXT NOT NULL,
            threat_level TEXT,            -- LOW, MEDIUM, HIGH, CRITICAL
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            occurrence_count INTEGER DEFAULT 1,
            source_component TEXT,
            notes TEXT
        )
    """)

    # ── Red Team Findings ──────────────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS red_team_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            target_component TEXT NOT NULL, -- 'aria', 'gateway'
            attack_type TEXT NOT NULL,
            severity TEXT,                -- LOW, MEDIUM, HIGH, CRITICAL
            detected BOOLEAN,
            detection_time_ms INTEGER,
            proof_of_concept TEXT,
            reproduction_steps TEXT,
            found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()
    logger.info(f"Threat intelligence database initialized at {DB_PATH}")


if __name__ == "__main__":
    init_db()
