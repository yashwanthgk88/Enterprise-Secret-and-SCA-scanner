"""
Software Composition Analysis (SCA) Scanner for vulnerability detection
Supports NPM, Python (pip), and Maven dependency scanning
"""
import os
import json
import subprocess
import re
import logging
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class SCAFinding:
    """Represents an SCA vulnerability finding"""
    package_manager: str
    package_name: str
    current_version: str
    vulnerable_version: str
    fixed_version: str
    cve_id: str
    severity: str
    cvss_score: float
    description: str
    remediation: str
    file_path: str

class SCAScanner:
    """Main SCA scanning engine for detecting vulnerabilities in dependencies"""
    
    def __init__(self):
        self.supported_managers = {
            'npm': self._scan_npm,
            'pip': self._scan_pip,
            'maven': self._scan_maven
        }
    
    def detect_package_managers(self, directory_path: str) -> List[str]:
        """Detect which package managers are used in the project"""
        managers = []
        
        # Check for NPM (package.json, package-lock.json, yarn.lock)
        npm_files = ['package.json', 'package-lock.json', 'yarn.lock']
        if any(os.path.exists(os.path.join(directory_path, f)) for f in npm_files):
            managers.append('npm')
        
        # Check for Python (requirements.txt, Pipfile, pyproject.toml, setup.py)
        python_files = ['requirements.txt', 'Pipfile', 'pyproject.toml', 'setup.py']
        if any(os.path.exists(os.path.join(directory_path, f)) for f in python_files):
            managers.append('pip')
        
        # Check for Maven (pom.xml)
        if os.path.exists(os.path.join(directory_path, 'pom.xml')):
            managers.append('maven')
        
        # Check for Gradle (build.gradle, build.gradle.kts)
        gradle_files = ['build.gradle', 'build.gradle.kts']
        if any(os.path.exists(os.path.join(directory_path, f)) for f in gradle_files):
            managers.append('gradle')
        
        return managers
    
    def scan_directory(self, directory_path: str) -> List[SCAFinding]:
        """Scan directory for vulnerabilities using detected package managers"""
        all_findings = []
        
        # Detect package managers
        managers = self.detect_package_managers(directory_path)
        logger.info(f"Detected package managers in {directory_path}: {managers}")
        
        # Scan with each detected manager
        for manager in managers:
            if manager in self.supported_managers:
                try:
                    findings = self.supported_managers[manager](directory_path)
                    all_findings.extend(findings)
                    logger.info(f"Found {len(findings)} vulnerabilities using {manager}")
                except Exception as e:
                    logger.error(f"Error scanning with {manager}: {e}")
        
        return all_findings
    
    def _scan_npm(self, directory_path: str) -> List[SCAFinding]:
        """Scan NPM dependencies for vulnerabilities"""
        findings = []
        
        # Check if npm is available
        if not self._command_exists('npm'):
            logger.warning("npm command not found, skipping NPM scan")
            return findings
        
        try:
            # Run npm audit
            result = subprocess.run(
                ['npm', 'audit', '--json'],
                cwd=directory_path,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0 or result.stdout:
                audit_data = json.loads(result.stdout)
                
                # Parse npm audit output (npm v7+ format)
                if 'vulnerabilities' in audit_data:
                    for package_name, vuln_info in audit_data['vulnerabilities'].items():
                        findings.extend(self._parse_npm_vulnerability(package_name, vuln_info, directory_path))
                
                # Parse npm audit output (npm v6 format)
                elif 'advisories' in audit_data:
                    for advisory_id, advisory in audit_data['advisories'].items():
                        findings.extend(self._parse_npm_advisory(advisory, directory_path))
        
        except subprocess.TimeoutExpired:
            logger.error("npm audit timed out")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse npm audit output: {e}")
        except Exception as e:
            logger.error(f"Error running npm audit: {e}")
        
        return findings
    
    def _parse_npm_vulnerability(self, package_name: str, vuln_info: Dict, directory_path: str) -> List[SCAFinding]:
        """Parse npm vulnerability information (npm v7+ format)"""
        findings = []
        
        try:
            severity = vuln_info.get('severity', 'unknown')
            
            # Get version information
            current_version = vuln_info.get('range', 'unknown')
            fixed_version = None
            
            # Extract CVE information from via field
            cve_ids = []
            if 'via' in vuln_info:
                for via_item in vuln_info['via']:
                    if isinstance(via_item, dict) and 'cve' in via_item:
                        cve_ids.extend(via_item['cve'])
            
            cve_id = ', '.join(cve_ids) if cve_ids else 'N/A'
            
            # Map severity to CVSS score estimate
            cvss_score = self._severity_to_cvss(severity)
            
            finding = SCAFinding(
                package_manager='npm',
                package_name=package_name,
                current_version=current_version,
                vulnerable_version=current_version,
                fixed_version=fixed_version or 'See npm audit fix',
                cve_id=cve_id,
                severity=severity,
                cvss_score=cvss_score,
                description=f"Vulnerability in {package_name}",
                remediation=f"Run 'npm audit fix' or update {package_name} to a secure version",
                file_path=os.path.join(directory_path, 'package.json')
            )
            findings.append(finding)
        
        except Exception as e:
            logger.error(f"Error parsing npm vulnerability for {package_name}: {e}")
        
        return findings
    
    def _parse_npm_advisory(self, advisory: Dict, directory_path: str) -> List[SCAFinding]:
        """Parse npm advisory information (npm v6 format)"""
        findings = []
        
        try:
            package_name = advisory.get('module_name', 'unknown')
            severity = advisory.get('severity', 'unknown')
            cve_id = advisory.get('cve', 'N/A')
            
            # Get version information
            vulnerable_versions = advisory.get('vulnerable_versions', 'unknown')
            patched_versions = advisory.get('patched_versions', 'unknown')
            
            cvss_score = advisory.get('cvss', {}).get('score', self._severity_to_cvss(severity))
            
            finding = SCAFinding(
                package_manager='npm',
                package_name=package_name,
                current_version=vulnerable_versions,
                vulnerable_version=vulnerable_versions,
                fixed_version=patched_versions,
                cve_id=cve_id,
                severity=severity,
                cvss_score=cvss_score,
                description=advisory.get('title', f"Vulnerability in {package_name}"),
                remediation=advisory.get('recommendation', f"Update {package_name} to a secure version"),
                file_path=os.path.join(directory_path, 'package.json')
            )
            findings.append(finding)
        
        except Exception as e:
            logger.error(f"Error parsing npm advisory: {e}")
        
        return findings
    
    def _scan_pip(self, directory_path: str) -> List[SCAFinding]:
        """Scan Python dependencies for vulnerabilities"""
        findings = []
        
        # Try multiple Python vulnerability scanners
        scanners = [
            ('safety', self._run_safety_scan),
            ('pip-audit', self._run_pip_audit_scan)
        ]
        
        for scanner_name, scanner_func in scanners:
            if self._command_exists(scanner_name):
                try:
                    scanner_findings = scanner_func(directory_path)
                    findings.extend(scanner_findings)
                    break  # Use first available scanner
                except Exception as e:
                    logger.error(f"Error running {scanner_name}: {e}")
        
        if not findings:
            logger.warning("No Python vulnerability scanners available (safety, pip-audit)")
        
        return findings
    
    def _run_safety_scan(self, directory_path: str) -> List[SCAFinding]:
        """Run safety scan for Python vulnerabilities"""
        findings = []
        
        try:
            # Run safety check
            result = subprocess.run(
                ['safety', 'check', '--json'],
                cwd=directory_path,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.stdout:
                safety_data = json.loads(result.stdout)
                
                for vuln in safety_data:
                    finding = SCAFinding(
                        package_manager='pip',
                        package_name=vuln.get('package', 'unknown'),
                        current_version=vuln.get('installed_version', 'unknown'),
                        vulnerable_version=vuln.get('vulnerable_spec', 'unknown'),
                        fixed_version=vuln.get('safe_version', 'See advisory'),
                        cve_id=vuln.get('vulnerability_id', 'N/A'),
                        severity=self._map_safety_severity(vuln.get('vulnerability_id', '')),
                        cvss_score=0.0,  # Safety doesn't provide CVSS scores
                        description=vuln.get('advisory', 'Python package vulnerability'),
                        remediation=f"Update {vuln.get('package', 'package')} to version {vuln.get('safe_version', 'latest')}",
                        file_path=self._find_python_requirements_file(directory_path)
                    )
                    findings.append(finding)
        
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse safety output: {e}")
        except Exception as e:
            logger.error(f"Error running safety: {e}")
        
        return findings
    
    def _run_pip_audit_scan(self, directory_path: str) -> List[SCAFinding]:
        """Run pip-audit scan for Python vulnerabilities"""
        findings = []
        
        try:
            # Run pip-audit
            result = subprocess.run(
                ['pip-audit', '--format=json'],
                cwd=directory_path,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.stdout:
                audit_data = json.loads(result.stdout)
                
                for vuln in audit_data.get('vulnerabilities', []):
                    finding = SCAFinding(
                        package_manager='pip',
                        package_name=vuln.get('package', 'unknown'),
                        current_version=vuln.get('installed_version', 'unknown'),
                        vulnerable_version=vuln.get('vulnerable_spec', 'unknown'),
                        fixed_version=vuln.get('fix_versions', ['See advisory'])[0] if vuln.get('fix_versions') else 'See advisory',
                        cve_id=vuln.get('id', 'N/A'),
                        severity=self._map_pip_audit_severity(vuln.get('id', '')),
                        cvss_score=0.0,  # pip-audit doesn't always provide CVSS scores
                        description=vuln.get('description', 'Python package vulnerability'),
                        remediation=f"Update {vuln.get('package', 'package')} to a secure version",
                        file_path=self._find_python_requirements_file(directory_path)
                    )
                    findings.append(finding)
        
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse pip-audit output: {e}")
        except Exception as e:
            logger.error(f"Error running pip-audit: {e}")
        
        return findings
    
    def _scan_maven(self, directory_path: str) -> List[SCAFinding]:
        """Scan Maven dependencies for vulnerabilities using OWASP Dependency Check"""
        findings = []
        
        # Check if Maven is available
        if not self._command_exists('mvn'):
            logger.warning("Maven command not found, skipping Maven scan")
            return findings
        
        try:
            # Run OWASP Dependency Check
            result = subprocess.run([
                'mvn', 'org.owasp:dependency-check-maven:check',
                '-DfailBuildOnCVSS=0',
                '-Dformat=JSON'
            ], cwd=directory_path, capture_output=True, text=True, timeout=600)
            
            # Look for dependency-check report
            report_path = os.path.join(directory_path, 'target', 'dependency-check-report.json')
            if os.path.exists(report_path):
                findings = self._parse_dependency_check_report(report_path, directory_path)
        
        except subprocess.TimeoutExpired:
            logger.error("Maven dependency check timed out")
        except Exception as e:
            logger.error(f"Error running Maven dependency check: {e}")
        
        return findings
    
    def _parse_dependency_check_report(self, report_path: str, directory_path: str) -> List[SCAFinding]:
        """Parse OWASP Dependency Check JSON report"""
        findings = []
        
        try:
            with open(report_path, 'r') as f:
                report_data = json.load(f)
            
            for dependency in report_data.get('dependencies', []):
                if 'vulnerabilities' in dependency:
                    for vuln in dependency['vulnerabilities']:
                        finding = SCAFinding(
                            package_manager='maven',
                            package_name=dependency.get('fileName', 'unknown'),
                            current_version=self._extract_version_from_filename(dependency.get('fileName', '')),
                            vulnerable_version='unknown',
                            fixed_version='See advisory',
                            cve_id=vuln.get('name', 'N/A'),
                            severity=vuln.get('severity', 'unknown').lower(),
                            cvss_score=vuln.get('cvssv3', {}).get('baseScore', 0.0),
                            description=vuln.get('description', 'Maven dependency vulnerability'),
                            remediation=f"Update dependency to a secure version",
                            file_path=os.path.join(directory_path, 'pom.xml')
                        )
                        findings.append(finding)
        
        except Exception as e:
            logger.error(f"Error parsing dependency check report: {e}")
        
        return findings
    
    def _command_exists(self, command: str) -> bool:
        """Check if a command exists in the system PATH"""
        try:
            subprocess.run([command, '--version'], capture_output=True, timeout=10)
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
            return False
    
    def _severity_to_cvss(self, severity: str) -> float:
        """Map severity string to approximate CVSS score"""
        severity_map = {
            'critical': 9.0,
            'high': 7.5,
            'moderate': 5.0,
            'medium': 5.0,
            'low': 2.5,
            'info': 1.0
        }
        return severity_map.get(severity.lower(), 0.0)
    
    def _map_safety_severity(self, vuln_id: str) -> str:
        """Map Safety vulnerability ID to severity (basic heuristic)"""
        # This is a simple heuristic - in production, you'd want a proper mapping
        if 'CVE' in vuln_id:
            return 'high'
        return 'medium'
    
    def _map_pip_audit_severity(self, vuln_id: str) -> str:
        """Map pip-audit vulnerability ID to severity (basic heuristic)"""
        # This is a simple heuristic - in production, you'd want a proper mapping
        if 'CVE' in vuln_id:
            return 'high'
        return 'medium'
    
    def _find_python_requirements_file(self, directory_path: str) -> str:
        """Find Python requirements file in directory"""
        possible_files = ['requirements.txt', 'Pipfile', 'pyproject.toml', 'setup.py']
        
        for filename in possible_files:
            file_path = os.path.join(directory_path, filename)
            if os.path.exists(file_path):
                return file_path
        
        return os.path.join(directory_path, 'requirements.txt')  # Default
    
    def _extract_version_from_filename(self, filename: str) -> str:
        """Extract version from Maven JAR filename"""
        # Look for version pattern in filename (e.g., library-1.2.3.jar)
        version_pattern = r'-(\d+(?:\.\d+)*(?:-[A-Za-z0-9]+)?)'
        match = re.search(version_pattern, filename)
        return match.group(1) if match else 'unknown'
