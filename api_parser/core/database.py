# core/database.py
"""Database operations for firewall blocklist/whitelist."""
import sqlite3
from typing import List, Dict, Optional
from datetime import datetime, timezone
import config

class DatabaseManager:
    """Manages SQLite database operations."""
    
    @staticmethod
    def init_database():
        """Create tables if they don't exist."""
        conn = sqlite3.connect(config.FIREWALL_DB_NAME)
        cursor = conn.cursor()
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            type TEXT NOT NULL,
            duration INTEGER,
            reason TEXT,
            created DATETIME DEFAULT CURRENT_TIMESTAMP,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS white_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            reason TEXT,
            created DATETIME DEFAULT CURRENT_TIMESTAMP,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # One row per whitelisted IP (sparta and the backend-whitelist merge
        # used to append the same IPs on every run).
        cursor.execute(
            "DELETE FROM white_ips WHERE id NOT IN (SELECT MIN(id) FROM white_ips GROUP BY ip)"
        )
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_white_ips_ip ON white_ips(ip)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip ON blocked_ips(ip)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_blocked_ips_created ON blocked_ips(created)")

        conn.commit()
        conn.close()

    # Rows written by sparta for automatic L4 / L7 (l7-guard) blocks that are
    # still running. The panel lists do not contain them, so replacing the
    # tables with the panel lists must keep them, or sparta would unblock those
    # attackers on its next reload. Manual blocks ('Manual blacklist') belong
    # to the panel and are replaced.
    _KEEP_ACTIVE_AUTO = """
        type = 'Auto' AND COALESCE(reason, '') <> 'Manual blacklist'
        AND CAST(duration AS INTEGER) > 0
        AND CAST(strftime('%s', created) AS INTEGER) + CAST(duration AS INTEGER)
            > CAST(strftime('%s', 'now') AS INTEGER)
    """

    @staticmethod
    def _norm_created(value) -> str:
        """sparta parses 'YYYY-MM-DD HH:MM:SS' (UTC); anything else reads as epoch 0."""
        if not value:
            return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        try:
            return DatabaseManager._normalize_datetime(value)
        except ValueError:
            return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _block_rows(blocklist_data) -> List[tuple]:
        rows = []
        for entry in blocklist_data or []:
            if not isinstance(entry, dict):
                continue
            ip = str(entry.get('IP') or entry.get('ip') or '').strip()
            if not ip:
                continue
            type_ = entry.get('TYPE') or entry.get('type') or 'L4'
            duration = entry.get('Duration')
            if duration is None:
                duration = entry.get('duration')
            # 0 is a valid duration; only a missing value means permanent (-1).
            duration = -1 if duration is None or duration == '' else duration
            reason = entry.get('Reason') or entry.get('reason') or ''
            created = DatabaseManager._norm_created(
                entry.get('Created') or entry.get('created') or entry.get('created_at'))
            rows.append((ip, type_, duration, reason, created))
        return rows

    @staticmethod
    def _white_rows(whitelist_data) -> List[tuple]:
        rows = []
        for entry in whitelist_data or []:
            if not isinstance(entry, dict):
                continue
            ip = str(entry.get('IP') or entry.get('ip') or '').strip()
            if not ip:
                continue
            reason = entry.get('Reason') or entry.get('reason') or ''
            created = DatabaseManager._norm_created(
                entry.get('Created') or entry.get('created') or entry.get('created_at'))
            rows.append((ip, reason, created))
        return rows

    @staticmethod
    def replace_lists(blocklist_data=None, whitelist_data=None) -> tuple:
        """Atomically replace the panel-owned rows of either or both tables.

        None leaves a table untouched. Unexpired automatic blocks are kept.
        """
        conn = sqlite3.connect(config.FIREWALL_DB_NAME, timeout=10)
        try:
            cursor = conn.cursor()
            msgs = []
            if blocklist_data is not None:
                rows = DatabaseManager._block_rows(blocklist_data)
                cursor.execute(f"DELETE FROM blocked_ips WHERE NOT ({DatabaseManager._KEEP_ACTIVE_AUTO})")
                kept = cursor.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0]
                cursor.executemany(
                    "INSERT INTO blocked_ips (ip, type, duration, reason, created) VALUES (?, ?, ?, ?, ?)",
                    rows)
                msgs.append(f"stored {len(rows)} blocked IPs (kept {kept} active automatic blocks)")
            if whitelist_data is not None:
                rows = DatabaseManager._white_rows(whitelist_data)
                cursor.execute("DELETE FROM white_ips")
                cursor.executemany(
                    "INSERT OR IGNORE INTO white_ips (ip, reason, created) VALUES (?, ?, ?)", rows)
                msgs.append(f"stored {len(rows)} white IPs")
            conn.commit()
            return True, "; ".join(msgs)
        except sqlite3.Error as e:
            conn.rollback()
            return False, f"Database error: {e}"
        finally:
            conn.close()

    @staticmethod
    def clear_all_tables():
        """Empty both tables, keeping unexpired automatic blocks."""
        ok, msg = DatabaseManager.replace_lists([], [])
        if not ok:
            raise sqlite3.Error(msg)

    @staticmethod
    def store_blocklist(blocklist_data: List[Dict]) -> tuple:
        """
        Replace the panel blocklist (unexpired automatic blocks are kept).

        Supports both legacy and new payload formats, e.g.:
          - {"IP": "...", "TYPE": "...", "Duration": 300, "Reason": "...", "Created": "..."}
          - {"ip": "...", "reason": "...", "created_at": "..."}
        """
        return DatabaseManager.replace_lists(blocklist_data=blocklist_data)

    @staticmethod
    def store_whitelist(whitelist_data: List[Dict]) -> tuple:
        """
        Replace the whitelist.

        Supports both legacy and new payload formats, e.g.:
          - {"IP": "...", "Reason": "...", "Created": "..."}
          - {"ip": "...", "reason": "...", "created_at": "..."}
        """
        return DatabaseManager.replace_lists(whitelist_data=whitelist_data)

    @staticmethod
    def merge_whitelist(whitelist_data: List[Dict]) -> tuple:
        """Insert whitelist IPs that are not already present (no table wipe)."""
        conn = None
        try:
            conn = sqlite3.connect(config.FIREWALL_DB_NAME, timeout=10)
            cursor = conn.cursor()
            added = 0
            for row in DatabaseManager._white_rows(whitelist_data):
                cursor.execute(
                    "INSERT INTO white_ips (ip, reason, created) SELECT ?, ?, ? "
                    "WHERE NOT EXISTS (SELECT 1 FROM white_ips WHERE ip = ?)",
                    row + (row[0],),
                )
                added += cursor.rowcount if cursor.rowcount > 0 else 0

            conn.commit()
            return True, f"Merged {added} white IP(s) ({len(whitelist_data or [])} candidates)"
        except Exception as e:
            return False, f"Error merging whitelist: {str(e)}"
        finally:
            if conn:
                conn.close()

    @staticmethod
    def remove_blocked_ips(ips: List[str]) -> int:
        """Delete matching IPs from blocked_ips. Returns rows deleted."""
        cleaned = [str(ip).strip() for ip in (ips or []) if str(ip).strip()]
        if not cleaned:
            return 0

        conn = None
        try:
            conn = sqlite3.connect(config.FIREWALL_DB_NAME)
            cursor = conn.cursor()
            deleted = 0
            for ip in cleaned:
                cursor.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
                deleted += cursor.rowcount if cursor.rowcount and cursor.rowcount > 0 else 0
            conn.commit()
            return deleted
        except Exception:
            if conn:
                conn.rollback()
            return 0
        finally:
            if conn:
                conn.close()
    
    @staticmethod
    def get_blocklist(
        filter_type: Optional[str] = None,
        filter_ip: Optional[str] = None,
        filter_date: Optional[str] = None
    ) -> List[Dict]:
        """Query blocked_ips with optional filters."""
        sql = """
            SELECT id, ip, type, duration, reason, created, timestamp
            FROM blocked_ips
            WHERE 1=1
        """
        params = []
        
        if filter_type and filter_type.lower() != "x":
            sql += " AND type = ?"
            params.append(filter_type.strip())
        
        if filter_ip and filter_ip.lower() != "x":
            sql += " AND ip = ?"
            params.append(filter_ip.strip())
        
        if filter_date and filter_date.lower() != "x":
            try:
                dt_str = DatabaseManager._normalize_datetime(filter_date)
                sql += " AND created > ?"
                params.append(dt_str)
            except ValueError as e:
                raise ValueError(f"Invalid date format: {e}")
        
        sql += " ORDER BY created DESC"
        
        conn = sqlite3.connect(config.FIREWALL_DB_NAME, timeout=5)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(sql, params)
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows

    @staticmethod
    def get_whitelist(
        filter_ip: Optional[str] = None,
        filter_date: Optional[str] = None,
    ) -> List[Dict]:
        """Query white_ips with optional filters."""
        sql = """
            SELECT id, ip, reason, created, timestamp
            FROM white_ips
            WHERE 1=1
        """
        params = []

        if filter_ip and filter_ip.lower() != "x":
            sql += " AND ip = ?"
            params.append(filter_ip.strip())

        if filter_date and filter_date.lower() != "x":
            try:
                dt_str = DatabaseManager._normalize_datetime(filter_date)
                sql += " AND created > ?"
                params.append(dt_str)
            except ValueError as e:
                raise ValueError(f"Invalid date format: {e}")

        sql += " ORDER BY created DESC"

        conn = sqlite3.connect(config.FIREWALL_DB_NAME, timeout=5)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(sql, params)
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows
    
    @staticmethod
    def _normalize_datetime(s: str) -> str:
        """Normalize datetime string to SQLite format."""
        s = str(s).strip()
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            if dt.tzinfo is not None:
                dt = dt.astimezone(timezone.utc)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            pass
        try:
            return datetime.strptime(s, "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            pass
        try:
            return datetime.strptime(s, "%Y-%m-%d").strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            raise ValueError("Invalid date/time format")
    
    @staticmethod
    def get_counts() -> tuple:
        """Get count of blocked and white IPs."""
        conn = sqlite3.connect(config.FIREWALL_DB_NAME)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM blocked_ips')
        blockcount = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM white_ips')
        whitecount = cursor.fetchone()[0]
        conn.close()
        return blockcount, whitecount

