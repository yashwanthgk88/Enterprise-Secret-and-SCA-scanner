"""
Database models and schema for Enterprise Secret Scanner & SCA Tool
"""
import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Optional, Tuple
import os

class DatabaseManager:
    """Manages SQLite database operations for the security scanner"""
    
    def __init__(self, db_path: str = "data/scanner.db"):
        self.db_path = db_path
        # Ensure data directory exists
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.init_database()
    
    def get_connection(self) -> sqlite3.Connection:
        """Get database connection with row factory"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def init_database(self):
        """Initialize database with required tables"""
        with self.get_connection() as conn:
            # Applications table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS applications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    repo_type TEXT NOT NULL,  -- github, gitlab, bitbucket, local
                    repo_url TEXT,
                    local_path TEXT,
                    team TEXT,
                    owner TEXT,
                    criticality TEXT DEFAULT 'medium',  -- low, medium, high, critical
                    language TEXT,
                    framework TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_scan_at TIMESTAMP,
                    status TEXT DEFAULT 'active'  -- active, inactive, archived
                )
            """)
            
            # Scans table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_name TEXT NOT NULL,
                    scan_type TEXT NOT NULL,  -- secrets, sca, full
                    status TEXT DEFAULT 'running',  -- running, completed, failed
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP,
                    total_files INTEGER DEFAULT 0,
                    scanned_files INTEGER DEFAULT 0,
                    secrets_found INTEGER DEFAULT 0,
                    vulnerabilities_found INTEGER DEFAULT 0,
                    critical_count INTEGER DEFAULT 0,
                    high_count INTEGER DEFAULT 0,
                    medium_count INTEGER DEFAULT 0,
                    low_count INTEGER DEFAULT 0,
                    error_message TEXT,
                    FOREIGN KEY (app_name) REFERENCES applications (name)
                )
            """)
            
            # Secret findings table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS secret_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    app_name TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    line_number INTEGER NOT NULL,
                    pattern_name TEXT NOT NULL,
                    pattern_type TEXT NOT NULL,  -- regex, entropy, custom
                    severity TEXT NOT NULL,  -- critical, high, medium, low
                    confidence REAL NOT NULL,  -- 0.0 to 1.0
                    secret_hash TEXT NOT NULL,  -- hashed version for deduplication
                    context_before TEXT,
                    context_after TEXT,
                    remediation TEXT,
                    status TEXT DEFAULT 'open',  -- open, false_positive, fixed, ignored
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans (id),
                    FOREIGN KEY (app_name) REFERENCES applications (name)
                )
            """)
            
            # SCA findings table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sca_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    app_name TEXT NOT NULL,
                    package_manager TEXT NOT NULL,  -- npm, pip, maven
                    package_name TEXT NOT NULL,
                    current_version TEXT NOT NULL,
                    vulnerable_version TEXT,
                    fixed_version TEXT,
                    cve_id TEXT,
                    severity TEXT NOT NULL,  -- critical, high, medium, low
                    cvss_score REAL,
                    description TEXT,
                    remediation TEXT,
                    file_path TEXT,  -- package.json, requirements.txt, pom.xml
                    status TEXT DEFAULT 'open',  -- open, fixed, ignored
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans (id),
                    FOREIGN KEY (app_name) REFERENCES applications (name)
                )
            """)
            
            # Create indexes for performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_applications_name ON applications (name)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_app_name ON scans (app_name)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans (started_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_secret_findings_app_name ON secret_findings (app_name)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_secret_findings_severity ON secret_findings (severity)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sca_findings_app_name ON sca_findings (app_name)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sca_findings_severity ON sca_findings (severity)")
            
            conn.commit()
    
    # Application CRUD operations
    def add_application(self, name: str, repo_type: str, repo_url: str = None, 
                       local_path: str = None, team: str = None, owner: str = None,
                       criticality: str = 'medium', language: str = None, 
                       framework: str = None) -> bool:
        """Add new application to database"""
        try:
            with self.get_connection() as conn:
                conn.execute("""
                    INSERT INTO applications 
                    (name, repo_type, repo_url, local_path, team, owner, criticality, language, framework)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (name, repo_type, repo_url, local_path, team, owner, criticality, language, framework))
                conn.commit()
                return True
        except sqlite3.IntegrityError:
            return False
    
    def get_applications(self, status: str = 'active') -> List[Dict]:
        """Get all applications with optional status filter"""
        with self.get_connection() as conn:
            cursor = conn.execute("""
                SELECT * FROM applications 
                WHERE status = ? 
                ORDER BY created_at DESC
            """, (status,))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_application(self, name: str) -> Optional[Dict]:
        """Get single application by name"""
        with self.get_connection() as conn:
            cursor = conn.execute("SELECT * FROM applications WHERE name = ?", (name,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def update_application_scan_time(self, name: str):
        """Update last scan time for application"""
        with self.get_connection() as conn:
            conn.execute("""
                UPDATE applications 
                SET last_scan_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                WHERE name = ?
            """, (name,))
            conn.commit()
    
    # Scan operations
    def create_scan(self, app_name: str, scan_type: str = 'full') -> int:
        """Create new scan record and return scan ID"""
        with self.get_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO scans (app_name, scan_type)
                VALUES (?, ?)
            """, (app_name, scan_type))
            conn.commit()
            return cursor.lastrowid
    
    def update_scan_progress(self, scan_id: int, total_files: int = None, 
                           scanned_files: int = None):
        """Update scan progress"""
        with self.get_connection() as conn:
            if total_files is not None:
                conn.execute("UPDATE scans SET total_files = ? WHERE id = ?", 
                           (total_files, scan_id))
            if scanned_files is not None:
                conn.execute("UPDATE scans SET scanned_files = ? WHERE id = ?", 
                           (scanned_files, scan_id))
            conn.commit()
    
    def complete_scan(self, scan_id: int, secrets_found: int = 0, 
                     vulnerabilities_found: int = 0, critical_count: int = 0,
                     high_count: int = 0, medium_count: int = 0, 
                     low_count: int = 0, error_message: str = None):
        """Mark scan as completed with results"""
        status = 'failed' if error_message else 'completed'
        with self.get_connection() as conn:
            conn.execute("""
                UPDATE scans SET 
                    status = ?, completed_at = CURRENT_TIMESTAMP,
                    secrets_found = ?, vulnerabilities_found = ?,
                    critical_count = ?, high_count = ?, medium_count = ?, low_count = ?,
                    error_message = ?
                WHERE id = ?
            """, (status, secrets_found, vulnerabilities_found, critical_count,
                  high_count, medium_count, low_count, error_message, scan_id))
            conn.commit()
    
    def get_recent_scans(self, limit: int = 10) -> List[Dict]:
        """Get recent scans with application info"""
        with self.get_connection() as conn:
            cursor = conn.execute("""
                SELECT s.*, a.team, a.criticality
                FROM scans s
                JOIN applications a ON s.app_name = a.name
                ORDER BY s.started_at DESC
                LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    # Secret findings operations
    def add_secret_finding(self, scan_id: int, app_name: str, file_path: str,
                          line_number: int, pattern_name: str, pattern_type: str,
                          severity: str, confidence: float, secret_hash: str,
                          context_before: str = None, context_after: str = None,
                          remediation: str = None) -> int:
        """Add secret finding"""
        with self.get_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO secret_findings 
                (scan_id, app_name, file_path, line_number, pattern_name, pattern_type,
                 severity, confidence, secret_hash, context_before, context_after, remediation)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (scan_id, app_name, file_path, line_number, pattern_name, pattern_type,
                  severity, confidence, secret_hash, context_before, context_after, remediation))
            conn.commit()
            return cursor.lastrowid
    
    # SCA findings operations
    def add_sca_finding(self, scan_id: int, app_name: str, package_manager: str,
                       package_name: str, current_version: str, vulnerable_version: str = None,
                       fixed_version: str = None, cve_id: str = None, severity: str = 'medium',
                       cvss_score: float = None, description: str = None,
                       remediation: str = None, file_path: str = None) -> int:
        """Add SCA finding"""
        with self.get_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO sca_findings 
                (scan_id, app_name, package_manager, package_name, current_version,
                 vulnerable_version, fixed_version, cve_id, severity, cvss_score,
                 description, remediation, file_path)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (scan_id, app_name, package_manager, package_name, current_version,
                  vulnerable_version, fixed_version, cve_id, severity, cvss_score,
                  description, remediation, file_path))
            conn.commit()
            return cursor.lastrowid
    
    # Dashboard statistics
    def get_dashboard_stats(self) -> Dict:
        """Get dashboard statistics"""
        with self.get_connection() as conn:
            # Total applications
            total_apps = conn.execute("SELECT COUNT(*) as count FROM applications WHERE status = 'active'").fetchone()['count']
            
            # Total findings by severity
            secret_stats = conn.execute("""
                SELECT severity, COUNT(*) as count 
                FROM secret_findings 
                WHERE status = 'open'
                GROUP BY severity
            """).fetchall()
            
            sca_stats = conn.execute("""
                SELECT severity, COUNT(*) as count 
                FROM sca_findings 
                WHERE status = 'open'
                GROUP BY severity
            """).fetchall()
            
            # Recent scan activity (last 30 days)
            recent_scans = conn.execute("""
                SELECT DATE(started_at) as scan_date, COUNT(*) as count
                FROM scans 
                WHERE started_at >= datetime('now', '-30 days')
                GROUP BY DATE(started_at)
                ORDER BY scan_date
            """).fetchall()
            
            # Top vulnerable applications
            top_vulnerable = conn.execute("""
                SELECT app_name, 
                       SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
                       SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
                       COUNT(*) as total
                FROM (
                    SELECT app_name, severity FROM secret_findings WHERE status = 'open'
                    UNION ALL
                    SELECT app_name, severity FROM sca_findings WHERE status = 'open'
                ) 
                GROUP BY app_name
                ORDER BY critical DESC, high DESC, total DESC
                LIMIT 10
            """).fetchall()
            
            return {
                'total_applications': total_apps,
                'secret_findings': {row['severity']: row['count'] for row in secret_stats},
                'sca_findings': {row['severity']: row['count'] for row in sca_stats},
                'scan_activity': [dict(row) for row in recent_scans],
                'top_vulnerable_apps': [dict(row) for row in top_vulnerable]
            }
    
    def get_findings(self, app_name: str = None, severity: str = None, 
                    finding_type: str = None, limit: int = 100) -> List[Dict]:
        """Get findings with optional filters"""
        with self.get_connection() as conn:
            # Build query based on filters
            conditions = ["status = 'open'"]
            params = []
            
            if app_name:
                conditions.append("app_name = ?")
                params.append(app_name)
            
            if severity:
                conditions.append("severity = ?")
                params.append(severity)
            
            where_clause = " AND ".join(conditions)
            
            findings = []
            
            # Get secret findings
            if not finding_type or finding_type == 'secrets':
                secret_query = f"""
                    SELECT 'secret' as type, id, app_name, file_path, line_number,
                           pattern_name as title, severity, confidence, created_at,
                           remediation, status
                    FROM secret_findings 
                    WHERE {where_clause}
                """
                cursor = conn.execute(secret_query, params)
                findings.extend([dict(row) for row in cursor.fetchall()])
            
            # Get SCA findings
            if not finding_type or finding_type == 'sca':
                sca_query = f"""
                    SELECT 'sca' as type, id, app_name, file_path, 0 as line_number,
                           package_name || ' (' || cve_id || ')' as title, 
                           severity, cvss_score as confidence, created_at,
                           remediation, status
                    FROM sca_findings 
                    WHERE {where_clause}
                """
                cursor = conn.execute(sca_query, params)
                findings.extend([dict(row) for row in cursor.fetchall()])
            
            # Sort by severity and date
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
            findings.sort(key=lambda x: (severity_order.get(x['severity'], 4), x['created_at']), reverse=True)
            
            return findings[:limit]
