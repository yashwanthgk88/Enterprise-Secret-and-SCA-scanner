"""
Core scanning engine for Enterprise Secret Scanner & SCA Tool
Includes secret detection with regex patterns and entropy analysis
"""
import re
import os
import hashlib
import math
import json
import subprocess
import threading
from typing import List, Dict, Tuple, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class SecretPattern:
    """Represents a secret detection pattern"""
    name: str
    pattern: str
    severity: str
    confidence: float
    description: str
    remediation: str
    pattern_type: str = "regex"  # regex, entropy, custom

@dataclass
class Finding:
    """Represents a security finding"""
    file_path: str
    line_number: int
    pattern_name: str
    pattern_type: str
    severity: str
    confidence: float
    secret_hash: str
    context_before: str = ""
    context_after: str = ""
    remediation: str = ""

class EntropyAnalyzer:
    """Analyzes strings for high entropy (randomness) to detect potential secrets"""
    
    def __init__(self, min_length: int = 20, min_entropy: float = 4.5):
        self.min_length = min_length
        self.min_entropy = min_entropy
    
    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0.0
        
        # Count character frequencies
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        text_length = len(text)
        for count in char_counts.values():
            probability = count / text_length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def is_high_entropy(self, text: str) -> Tuple[bool, float]:
        """Check if text has high entropy indicating potential secret"""
        if len(text) < self.min_length:
            return False, 0.0
        
        # Skip if contains common words or patterns
        common_words = ['password', 'secret', 'key', 'token', 'api', 'config', 'test', 'example']
        text_lower = text.lower()
        if any(word in text_lower for word in common_words):
            return False, 0.0
        
        # Skip if mostly repeating characters
        unique_chars = len(set(text))
        if unique_chars < len(text) * 0.3:  # Less than 30% unique characters
            return False, 0.0
        
        entropy = self.calculate_entropy(text)
        return entropy >= self.min_entropy, entropy
    
    def extract_high_entropy_strings(self, line: str) -> List[Tuple[str, float]]:
        """Extract high entropy strings from a line of code"""
        # Look for quoted strings and assignment values
        patterns = [
            r'"([^"]{20,})"',  # Double quoted strings
            r"'([^']{20,})'",  # Single quoted strings
            r'=\s*([A-Za-z0-9+/]{20,})',  # Assignment values
            r':\s*([A-Za-z0-9+/]{20,})',  # JSON/YAML values
        ]
        
        high_entropy_strings = []
        for pattern in patterns:
            matches = re.finditer(pattern, line)
            for match in matches:
                candidate = match.group(1)
                is_high, entropy = self.is_high_entropy(candidate)
                if is_high:
                    high_entropy_strings.append((candidate, entropy))
        
        return high_entropy_strings

class SecretScanner:
    """Main secret scanning engine with pattern matching and entropy analysis"""
    
    def __init__(self, custom_patterns_file: str = None):
        self.entropy_analyzer = EntropyAnalyzer()
        self.patterns = self._load_default_patterns()
        
        if custom_patterns_file and os.path.exists(custom_patterns_file):
            self.patterns.extend(self._load_custom_patterns(custom_patterns_file))
        
        # File extensions to scan
        self.scannable_extensions = {
            '.py', '.js', '.ts', '.java', '.php', '.rb', '.go', '.cs', '.cpp', '.c',
            '.json', '.xml', '.yaml', '.yml', '.properties', '.env', '.config',
            '.sh', '.bat', '.ps1', '.sql', '.md', '.txt', '.ini', '.conf'
        }
        
        # Directories to skip
        self.skip_directories = {
            '.git', '.svn', '.hg', 'node_modules', '__pycache__', '.pytest_cache',
            'venv', 'env', '.env', 'build', 'dist', 'target', 'bin', 'obj',
            '.idea', '.vscode', 'logs', 'tmp', 'temp'
        }
    
    def _load_default_patterns(self) -> List[SecretPattern]:
        """Load default secret detection patterns"""
        return [
            # AWS Secrets
            SecretPattern(
                name="AWS Access Key ID",
                pattern=r'AKIA[0-9A-Z]{16}',
                severity="critical",
                confidence=0.9,
                description="AWS Access Key ID detected",
                remediation="Rotate AWS credentials immediately and use IAM roles or environment variables"
            ),
            SecretPattern(
                name="AWS Secret Access Key",
                pattern=r'aws_secret_access_key\s*=\s*["\']?([A-Za-z0-9+/]{40})["\']?',
                severity="critical",
                confidence=0.95,
                description="AWS Secret Access Key detected",
                remediation="Rotate AWS credentials immediately and use IAM roles or environment variables"
            ),
            
            # API Keys
            SecretPattern(
                name="Generic API Key",
                pattern=r'(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?',
                severity="high",
                confidence=0.8,
                description="Generic API key detected",
                remediation="Move API keys to environment variables or secure key management"
            ),
            
            # Database URLs
            SecretPattern(
                name="Database URL with Password",
                pattern=r'(?i)(mysql|postgresql|mongodb|redis)://[^:]+:([^@]+)@[^/]+',
                severity="high",
                confidence=0.9,
                description="Database connection string with embedded password",
                remediation="Use environment variables for database credentials"
            ),
            
            # JWT Tokens
            SecretPattern(
                name="JWT Token",
                pattern=r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
                severity="medium",
                confidence=0.85,
                description="JWT token detected",
                remediation="Ensure JWT tokens are not hardcoded and have proper expiration"
            ),
            
            # Private Keys
            SecretPattern(
                name="RSA Private Key",
                pattern=r'-----BEGIN RSA PRIVATE KEY-----',
                severity="critical",
                confidence=1.0,
                description="RSA private key detected",
                remediation="Remove private keys from code and use secure key storage"
            ),
            SecretPattern(
                name="SSH Private Key",
                pattern=r'-----BEGIN OPENSSH PRIVATE KEY-----',
                severity="critical",
                confidence=1.0,
                description="SSH private key detected",
                remediation="Remove private keys from code and use secure key storage"
            ),
            
            # GitHub Tokens
            SecretPattern(
                name="GitHub Token",
                pattern=r'ghp_[A-Za-z0-9]{36}',
                severity="high",
                confidence=0.95,
                description="GitHub personal access token detected",
                remediation="Revoke token and use GitHub secrets for CI/CD"
            ),
            
            # Slack Tokens
            SecretPattern(
                name="Slack Token",
                pattern=r'xox[baprs]-[A-Za-z0-9-]{10,}',
                severity="medium",
                confidence=0.9,
                description="Slack token detected",
                remediation="Revoke token and use environment variables"
            ),
            
            # Generic Passwords
            SecretPattern(
                name="Password Assignment",
                pattern=r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']',
                severity="medium",
                confidence=0.7,
                description="Hardcoded password detected",
                remediation="Use environment variables or secure configuration management"
            ),
        ]
    
    def _load_custom_patterns(self, patterns_file: str) -> List[SecretPattern]:
        """Load custom patterns from YAML file"""
        import yaml
        try:
            with open(patterns_file, 'r') as f:
                data = yaml.safe_load(f)
            
            patterns = []
            for pattern_data in data.get('patterns', []):
                patterns.append(SecretPattern(
                    name=pattern_data['name'],
                    pattern=pattern_data['pattern'],
                    severity=pattern_data.get('severity', 'medium'),
                    confidence=pattern_data.get('confidence', 0.8),
                    description=pattern_data.get('description', ''),
                    remediation=pattern_data.get('remediation', ''),
                    pattern_type=pattern_data.get('type', 'regex')
                ))
            return patterns
        except Exception as e:
            logger.error(f"Error loading custom patterns: {e}")
            return []
    
    def _should_scan_file(self, file_path: str) -> bool:
        """Check if file should be scanned based on extension and size"""
        path = Path(file_path)
        
        # Check extension
        if path.suffix.lower() not in self.scannable_extensions:
            return False
        
        # Check file size (skip files larger than 10MB)
        try:
            if path.stat().st_size > 10 * 1024 * 1024:
                return False
        except OSError:
            return False
        
        # Check if in skip directory
        for part in path.parts:
            if part in self.skip_directories:
                return False
        
        return True
    
    def _get_context(self, lines: List[str], line_num: int, context_size: int = 2) -> Tuple[str, str]:
        """Get context lines before and after the finding"""
        before_lines = []
        after_lines = []
        
        # Get lines before
        start = max(0, line_num - context_size)
        for i in range(start, line_num):
            if i < len(lines):
                before_lines.append(lines[i].strip())
        
        # Get lines after
        end = min(len(lines), line_num + context_size + 1)
        for i in range(line_num + 1, end):
            if i < len(lines):
                after_lines.append(lines[i].strip())
        
        return '\n'.join(before_lines), '\n'.join(after_lines)
    
    def _hash_secret(self, secret: str) -> str:
        """Create hash of secret for deduplication"""
        return hashlib.sha256(secret.encode()).hexdigest()[:16]
    
    def scan_file(self, file_path: str) -> List[Finding]:
        """Scan a single file for secrets"""
        if not self._should_scan_file(file_path):
            return []
        
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            for line_num, line in enumerate(lines, 1):
                # Pattern-based detection
                for pattern in self.patterns:
                    matches = re.finditer(pattern.pattern, line, re.IGNORECASE)
                    for match in matches:
                        secret_value = match.group(1) if match.groups() else match.group(0)
                        context_before, context_after = self._get_context(lines, line_num - 1)
                        
                        finding = Finding(
                            file_path=file_path,
                            line_number=line_num,
                            pattern_name=pattern.name,
                            pattern_type=pattern.pattern_type,
                            severity=pattern.severity,
                            confidence=pattern.confidence,
                            secret_hash=self._hash_secret(secret_value),
                            context_before=context_before,
                            context_after=context_after,
                            remediation=pattern.remediation
                        )
                        findings.append(finding)
                
                # Entropy-based detection
                high_entropy_strings = self.entropy_analyzer.extract_high_entropy_strings(line)
                for secret_value, entropy in high_entropy_strings:
                    context_before, context_after = self._get_context(lines, line_num - 1)
                    
                    # Calculate confidence based on entropy
                    confidence = min(0.9, entropy / 6.0)  # Normalize entropy to confidence
                    
                    finding = Finding(
                        file_path=file_path,
                        line_number=line_num,
                        pattern_name="High Entropy String",
                        pattern_type="entropy",
                        severity="medium",
                        confidence=confidence,
                        secret_hash=self._hash_secret(secret_value),
                        context_before=context_before,
                        context_after=context_after,
                        remediation="Review if this high-entropy string is a secret that should be externalized"
                    )
                    findings.append(finding)
        
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
        
        return findings
    
    def scan_directory(self, directory_path: str, progress_callback=None) -> List[Finding]:
        """Scan entire directory for secrets"""
        all_findings = []
        scanned_files = 0
        total_files = 0
        
        # Count total files first
        for root, dirs, files in os.walk(directory_path):
            # Skip directories in skip list
            dirs[:] = [d for d in dirs if d not in self.skip_directories]
            
            for file in files:
                file_path = os.path.join(root, file)
                if self._should_scan_file(file_path):
                    total_files += 1
        
        if progress_callback:
            progress_callback(total_files, 0)
        
        # Scan files
        for root, dirs, files in os.walk(directory_path):
            # Skip directories in skip list
            dirs[:] = [d for d in dirs if d not in self.skip_directories]
            
            for file in files:
                file_path = os.path.join(root, file)
                if self._should_scan_file(file_path):
                    findings = self.scan_file(file_path)
                    all_findings.extend(findings)
                    scanned_files += 1
                    
                    if progress_callback:
                        progress_callback(total_files, scanned_files)
        
        return all_findings

class BatchScanner:
    """Handles scanning multiple applications in parallel"""
    
    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        self.secret_scanner = SecretScanner()
    
    def scan_applications(self, applications: List[Dict], progress_callback=None) -> Dict[str, List[Finding]]:
        """Scan multiple applications in parallel"""
        results = {}
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit scan jobs
            future_to_app = {}
            for app in applications:
                app_name = app['name']
                scan_path = app.get('local_path') or f"./repos/{app_name}"
                
                if os.path.exists(scan_path):
                    future = executor.submit(self._scan_single_app, app_name, scan_path, progress_callback)
                    future_to_app[future] = app_name
            
            # Collect results
            for future in as_completed(future_to_app):
                app_name = future_to_app[future]
                try:
                    findings = future.result(timeout=1800)  # 30 minute timeout
                    results[app_name] = findings
                except Exception as e:
                    logger.error(f"Error scanning application {app_name}: {e}")
                    results[app_name] = []
        
        return results
    
    def _scan_single_app(self, app_name: str, scan_path: str, progress_callback=None) -> List[Finding]:
        """Scan a single application"""
        logger.info(f"Starting scan for application: {app_name}")
        
        def app_progress_callback(total, scanned):
            if progress_callback:
                progress_callback(app_name, total, scanned)
        
        findings = self.secret_scanner.scan_directory(scan_path, app_progress_callback)
        
        logger.info(f"Completed scan for {app_name}: {len(findings)} findings")
        return findings
