# core/database.py
"""Database operations for firewall blocklist/whitelist."""
import sqlite3
from typing import List, Dict, Optional
from datetime import datetime
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
        
        conn.commit()
        conn.close()
    
    @staticmethod
    def clear_all_tables():
        """Remove all rows from blocked_ips and white_ips tables."""
        conn = None
        try:
            conn = sqlite3.connect(config.FIREWALL_DB_NAME)
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM blocked_ips")
            cursor.execute("DELETE FROM white_ips")
            cursor.execute(
                "DELETE FROM sqlite_sequence WHERE name IN ('blocked_ips', 'white_ips')"
            )
            conn.commit()
        except sqlite3.Error:
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                conn.close()
    
    @staticmethod
    def store_blocklist(blocklist_data: List[Dict]) -> tuple:
        """Store blocklist entries in database."""
        conn = None
        try:
            conn = sqlite3.connect(config.FIREWALL_DB_NAME)
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM blocked_ips')
            
            for entry in blocklist_data:
                cursor.execute('''
                INSERT OR IGNORE INTO blocked_ips (ip, type, duration, reason, created)
                VALUES (?, ?, ?, ?, ?)
                ''', (
                    entry.get('IP'),
                    entry.get('TYPE'),
                    entry.get('Duration', -1),
                    entry.get('Reason', ''),
                    entry.get('Created', '')
                ))
            
            conn.commit()
            return True, f"Successfully stored {len(blocklist_data)} blocked IPs"
        except sqlite3.Error as e:
            return False, f"Database error: {str(e)}"
        finally:
            if conn:
                conn.close()
    
    @staticmethod
    def store_whitelist(whitelist_data: List[Dict]) -> tuple:
        """Store whitelist entries in database."""
        conn = None
        try:
            conn = sqlite3.connect(config.FIREWALL_DB_NAME)
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM white_ips')
            
            for entry in whitelist_data:
                cursor.execute('''
                INSERT INTO white_ips (ip, reason, created)
                VALUES (?, ?, ?)
                ''', (
                    entry.get('IP', ''),
                    entry.get('Reason', ''),
                    entry.get('Created', '')
                ))
            
            conn.commit()
            return True, f"Successfully stored {len(whitelist_data)} white IPs"
        except Exception as e:
            return False, f"Error processing whitelist: {str(e)}"
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
    def _normalize_datetime(s: str) -> str:
        """Normalize datetime string to SQLite format."""
        s = str(s).strip()
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
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

