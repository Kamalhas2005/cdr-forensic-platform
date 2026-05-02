import sqlite3
from pathlib import Path
import os

# Global DB path (set once at startup)
DB_PATH = None


def get_db():
    """
    Returns a SQLite connection with Row factory enabled
    """
    global DB_PATH
    if DB_PATH is None:
        DB_PATH = Path("cdr.db")

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path=None):
    """
    Initializes the CDR database.

    Design principles:
    - TABLES store immutable facts (write-only by sanitizer)
    - VIEWS provide read-only dashboards (used by Flask)
    """
    global DB_PATH

    DB_PATH = Path(db_path) if db_path else Path("cdr.db")
    os.makedirs(DB_PATH.parent, exist_ok=True)

    with get_db() as db:

        # ==================================================
        # TABLE: scans
        # One row per scanned document (ground truth)
        # ==================================================
        db.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            -- Original uploaded filename
            original_filename TEXT NOT NULL,

            -- Sanitized output filename
            sanitized_filename TEXT NOT NULL,

            -- Absolute path to original file
            input_path TEXT NOT NULL,

            -- Absolute path to sanitized file
            output_path TEXT NOT NULL,

            -- Sum of all detection scores
            total_score INTEGER NOT NULL,

            -- SHA256 hash (for deduplication & correlation)
            sha256 TEXT,

            -- Batch or group identifier
            group_id TEXT,

            -- Final assessed risk (LOW / MEDIUM / HIGH)
            risk_level TEXT NOT NULL,

            -- Scan timestamp
            scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """)

        # ==================================================
        # TABLE: detections
        # One row per security finding (evidence)
        # ==================================================
        db.execute("""
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            -- FK to scans.id
            scan_id INTEGER NOT NULL,

            -- Type of detected object (URI, OpenAction, Domain, IP)
            item TEXT NOT NULL,

            -- Location inside document
            location TEXT NOT NULL,

            -- Explanation or extracted value
            reason TEXT NOT NULL,

            -- Risk score contribution
            score INTEGER NOT NULL,

            -- Action taken (FOUND / REMOVED)
            action TEXT NOT NULL,

            -- Batch correlation ID
            group_id TEXT,

            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
        """)

        # Speed up forensic lookups
        db.execute("""
        CREATE INDEX IF NOT EXISTS idx_detections_scan_id
        ON detections(scan_id)
        """)

        # ==================================================
        # VIEW: cdr_logs
        # Read-only dashboard aggregation
        # ==================================================
        db.execute("DROP VIEW IF EXISTS cdr_logs")

        db.execute("""
        CREATE VIEW cdr_logs AS
        SELECT
            s.id AS sno,
            s.original_filename,

            -- Aggregated threat types
            GROUP_CONCAT(DISTINCT d.item) AS threat_found,

            -- Aggregated actions
            GROUP_CONCAT(DISTINCT d.action) AS action,

            -- Aggregated locations
            GROUP_CONCAT(DISTINCT d.location) AS location,

            -- Reasons for removed content (excluding IOCs)
            GROUP_CONCAT(
                CASE
                    WHEN d.item NOT IN ('Domain', 'External IP')
                    THEN d.reason
                END
            ) AS removed_content,

            -- Extracted domains
            GROUP_CONCAT(
                DISTINCT CASE
                    WHEN d.item = 'Domain'
                    THEN d.reason
                END
            ) AS domains,

            -- Extracted external IPs
            GROUP_CONCAT(
                DISTINCT CASE
                    WHEN d.item = 'External IP'
                    THEN d.reason
                END
            ) AS ips,

            s.risk_level,
            s.output_path,
            s.sha256,
            s.scanned_at,
            s.input_path

        FROM scans s
        LEFT JOIN detections d ON s.id = d.scan_id
        GROUP BY s.id
        ORDER BY s.id DESC
        """)

        # ==================================================
        # ================= PPT / OOXML CDR EXTENSION =================
        # ADDITIVE ONLY – DOES NOT MODIFY EXISTING TABLES
        # ==================================================

        # Optional: format classification view (PDF vs PPT / OOXML)
        db.execute("DROP VIEW IF EXISTS cdr_logs_with_format")

        db.execute("""
        CREATE VIEW cdr_logs_with_format AS
        SELECT
            *,
            CASE
                WHEN lower(original_filename) LIKE '%.pdf' THEN 'PDF'
                WHEN lower(original_filename) LIKE '%.ppt'
                  OR lower(original_filename) LIKE '%.pptx'
                  OR lower(original_filename) LIKE '%.docx'
                  OR lower(original_filename) LIKE '%.xlsx'
                THEN 'OOXML'
                ELSE 'UNKNOWN'
            END AS file_type
        FROM cdr_logs
        """)
