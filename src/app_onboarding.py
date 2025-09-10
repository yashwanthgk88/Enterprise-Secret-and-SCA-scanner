"""
Application onboarding module for Enterprise Secret Scanner & SCA Tool
Handles repository validation, cloning, and application management
"""
import os
import json
import subprocess
import requests
import shutil
import logging
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
from pathlib import Path
import yaml

from .models.database import DatabaseManager

logger = logging.getLogger(__name__)

class ApplicationOnboarding:
    """Handles onboarding of applications from various sources"""
    
    def __init__(self, db_manager: DatabaseManager, repos_dir: str = "./repos"):
        self.db = db_manager
        self.repos_dir = repos_dir
        os.makedirs(repos_dir, exist_ok=True)
        
        # Language detection patterns
        self.language_patterns = {
            'python': ['.py', 'requirements.txt', 'setup.py', 'pyproject.toml', 'Pipfile'],
            'javascript': ['package.json', '.js', '.ts', '.jsx', '.tsx'],
            'java': ['.java', 'pom.xml', 'build.gradle', '.gradle'],
            'php': ['.php', 'composer.json'],
            'ruby': ['.rb', 'Gemfile'],
            'go': ['.go', 'go.mod'],
            'csharp': ['.cs', '.csproj', '.sln'],
            'cpp': ['.cpp', '.c', '.h', '.hpp', 'CMakeLists.txt'],
            'rust': ['.rs', 'Cargo.toml'],
            'swift': ['.swift', 'Package.swift']
        }
        
        # Framework detection patterns
        self.framework_patterns = {
            'react': ['package.json', 'src/App.js', 'src/App.tsx'],
            'angular': ['angular.json', 'package.json'],
            'vue': ['vue.config.js', 'package.json'],
            'django': ['manage.py', 'settings.py'],
            'flask': ['app.py', 'requirements.txt'],
            'spring': ['pom.xml', 'src/main/java'],
            'express': ['package.json', 'app.js', 'server.js'],
            'laravel': ['artisan', 'composer.json'],
            'rails': ['Gemfile', 'config/application.rb']
        }
    
    def validate_repository(self, repo_url: str, repo_type: str = 'github', 
                          access_token: str = None) -> Tuple[bool, str]:
        """Validate repository access and existence"""
        try:
            if repo_type.lower() == 'github':
                return self._validate_github_repo(repo_url, access_token)
            elif repo_type.lower() == 'gitlab':
                return self._validate_gitlab_repo(repo_url, access_token)
            elif repo_type.lower() == 'bitbucket':
                return self._validate_bitbucket_repo(repo_url, access_token)
            elif repo_type.lower() == 'local':
                return self._validate_local_path(repo_url)
            else:
                return False, f"Unsupported repository type: {repo_type}"
        
        except Exception as e:
            logger.error(f"Error validating repository {repo_url}: {e}")
            return False, str(e)
    
    def _validate_github_repo(self, repo_url: str, access_token: str = None) -> Tuple[bool, str]:
        """Validate GitHub repository"""
        # Extract owner and repo from URL
        parsed = urlparse(repo_url)
        if 'github.com' not in parsed.netloc:
            return False, "Not a valid GitHub URL"
        
        path_parts = parsed.path.strip('/').split('/')
        if len(path_parts) < 2:
            return False, "Invalid GitHub repository path"
        
        owner, repo = path_parts[0], path_parts[1]
        if repo.endswith('.git'):
            repo = repo[:-4]
        
        # Check repository via GitHub API
        api_url = f"https://api.github.com/repos/{owner}/{repo}"
        headers = {}
        
        if access_token:
            headers['Authorization'] = f"token {access_token}"
        
        try:
            response = requests.get(api_url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                repo_info = response.json()
                return True, f"Repository found: {repo_info.get('full_name', 'Unknown')}"
            elif response.status_code == 404:
                return False, "Repository not found or not accessible"
            elif response.status_code == 401:
                return False, "Authentication required or invalid token"
            else:
                return False, f"GitHub API error: {response.status_code}"
        
        except requests.RequestException as e:
            return False, f"Network error: {e}"
    
    def _validate_gitlab_repo(self, repo_url: str, access_token: str = None) -> Tuple[bool, str]:
        """Validate GitLab repository"""
        # Extract project path from URL
        parsed = urlparse(repo_url)
        if 'gitlab' not in parsed.netloc:
            return False, "Not a valid GitLab URL"
        
        # For GitLab, we'll try to clone to validate (simpler than API)
        return self._validate_git_clone(repo_url, access_token)
    
    def _validate_bitbucket_repo(self, repo_url: str, access_token: str = None) -> Tuple[bool, str]:
        """Validate Bitbucket repository"""
        # For Bitbucket, we'll try to clone to validate
        return self._validate_git_clone(repo_url, access_token)
    
    def _validate_git_clone(self, repo_url: str, access_token: str = None) -> Tuple[bool, str]:
        """Validate repository by attempting a shallow clone"""
        try:
            # Create temporary directory for validation
            temp_dir = f"/tmp/repo_validation_{hash(repo_url)}"
            
            # Prepare git command
            cmd = ['git', 'clone', '--depth', '1', repo_url, temp_dir]
            
            # Run git clone
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            # Clean up
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
            
            if result.returncode == 0:
                return True, "Repository accessible"
            else:
                return False, f"Git clone failed: {result.stderr}"
        
        except subprocess.TimeoutExpired:
            return False, "Repository validation timed out"
        except Exception as e:
            return False, f"Validation error: {e}"
    
    def _validate_local_path(self, path: str) -> Tuple[bool, str]:
        """Validate local directory path"""
        if not os.path.exists(path):
            return False, "Path does not exist"
        
        if not os.path.isdir(path):
            return False, "Path is not a directory"
        
        # Check if it's a git repository
        git_dir = os.path.join(path, '.git')
        if os.path.exists(git_dir):
            return True, "Local git repository found"
        else:
            return True, "Local directory found (not a git repository)"
    
    def clone_repository(self, repo_url: str, app_name: str, access_token: str = None) -> Tuple[bool, str]:
        """Clone repository to local repos directory"""
        try:
            repo_path = os.path.join(self.repos_dir, app_name)
            
            # Remove existing directory if it exists
            if os.path.exists(repo_path):
                shutil.rmtree(repo_path)
            
            # Prepare git clone command
            cmd = ['git', 'clone', repo_url, repo_path]
            
            # Add authentication if token provided
            if access_token and 'github.com' in repo_url:
                # For GitHub, modify URL to include token
                auth_url = repo_url.replace('https://', f'https://{access_token}@')
                cmd = ['git', 'clone', auth_url, repo_path]
            
            # Execute clone
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                return True, repo_path
            else:
                return False, f"Clone failed: {result.stderr}"
        
        except subprocess.TimeoutExpired:
            return False, "Repository clone timed out"
        except Exception as e:
            logger.error(f"Error cloning repository: {e}")
            return False, str(e)
    
    def detect_language_and_framework(self, directory_path: str) -> Tuple[str, str]:
        """Auto-detect programming language and framework from project files"""
        if not os.path.exists(directory_path):
            return 'unknown', 'unknown'
        
        detected_languages = []
        detected_frameworks = []
        
        # Walk through directory and collect file extensions and names
        file_extensions = set()
        file_names = set()
        
        for root, dirs, files in os.walk(directory_path):
            # Skip common directories
            dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '__pycache__', '.venv', 'venv'}]
            
            for file in files:
                file_path = Path(file)
                file_extensions.add(file_path.suffix.lower())
                file_names.add(file_path.name.lower())
        
        # Detect languages
        for language, patterns in self.language_patterns.items():
            matches = 0
            for pattern in patterns:
                if pattern.startswith('.'):
                    # File extension
                    if pattern in file_extensions:
                        matches += 1
                else:
                    # File name
                    if pattern.lower() in file_names:
                        matches += 2  # File names are more specific
            
            if matches > 0:
                detected_languages.append((language, matches))
        
        # Detect frameworks
        for framework, patterns in self.framework_patterns.items():
            matches = 0
            for pattern in patterns:
                if pattern.lower() in file_names:
                    matches += 1
                elif any(pattern in str(f) for f in file_names):
                    matches += 1
            
            if matches > 0:
                detected_frameworks.append((framework, matches))
        
        # Return most likely language and framework
        primary_language = max(detected_languages, key=lambda x: x[1])[0] if detected_languages else 'unknown'
        primary_framework = max(detected_frameworks, key=lambda x: x[1])[0] if detected_frameworks else 'unknown'
        
        return primary_language, primary_framework
    
    def onboard_application(self, name: str, repo_type: str, repo_url: str = None,
                          local_path: str = None, team: str = None, owner: str = None,
                          criticality: str = 'medium', access_token: str = None,
                          auto_scan: bool = True) -> Tuple[bool, str]:
        """Onboard a new application"""
        try:
            # Validate inputs
            if not name:
                return False, "Application name is required"
            
            if repo_type.lower() == 'local' and not local_path:
                return False, "Local path is required for local repositories"
            
            if repo_type.lower() != 'local' and not repo_url:
                return False, "Repository URL is required for remote repositories"
            
            # Check if application already exists
            existing_app = self.db.get_application(name)
            if existing_app:
                return False, f"Application '{name}' already exists"
            
            # Validate repository
            validation_url = local_path if repo_type.lower() == 'local' else repo_url
            is_valid, validation_message = self.validate_repository(validation_url, repo_type, access_token)
            
            if not is_valid:
                return False, f"Repository validation failed: {validation_message}"
            
            # Clone repository if remote
            scan_path = local_path
            if repo_type.lower() != 'local':
                clone_success, clone_result = self.clone_repository(repo_url, name, access_token)
                if not clone_success:
                    return False, f"Failed to clone repository: {clone_result}"
                scan_path = clone_result
            
            # Auto-detect language and framework
            language, framework = self.detect_language_and_framework(scan_path)
            
            # Add application to database
            success = self.db.add_application(
                name=name,
                repo_type=repo_type,
                repo_url=repo_url,
                local_path=scan_path,
                team=team,
                owner=owner,
                criticality=criticality,
                language=language,
                framework=framework
            )
            
            if not success:
                return False, "Failed to add application to database"
            
            # Run initial scan if requested
            if auto_scan:
                from .scanner import SecretScanner
                from .sca_scanner import SCAScanner
                
                try:
                    # Create scan record
                    scan_id = self.db.create_scan(name, 'full')
                    
                    # Run secret scan
                    secret_scanner = SecretScanner()
                    secret_findings = secret_scanner.scan_directory(scan_path)
                    
                    # Run SCA scan
                    sca_scanner = SCAScanner()
                    sca_findings = sca_scanner.scan_directory(scan_path)
                    
                    # Store findings
                    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
                    
                    for finding in secret_findings:
                        self.db.add_secret_finding(
                            scan_id=scan_id,
                            app_name=name,
                            file_path=finding.file_path,
                            line_number=finding.line_number,
                            pattern_name=finding.pattern_name,
                            pattern_type=finding.pattern_type,
                            severity=finding.severity,
                            confidence=finding.confidence,
                            secret_hash=finding.secret_hash,
                            context_before=finding.context_before,
                            context_after=finding.context_after,
                            remediation=finding.remediation
                        )
                        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
                    
                    for finding in sca_findings:
                        self.db.add_sca_finding(
                            scan_id=scan_id,
                            app_name=name,
                            package_manager=finding.package_manager,
                            package_name=finding.package_name,
                            current_version=finding.current_version,
                            vulnerable_version=finding.vulnerable_version,
                            fixed_version=finding.fixed_version,
                            cve_id=finding.cve_id,
                            severity=finding.severity,
                            cvss_score=finding.cvss_score,
                            description=finding.description,
                            remediation=finding.remediation,
                            file_path=finding.file_path
                        )
                        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
                    
                    # Complete scan
                    self.db.complete_scan(
                        scan_id=scan_id,
                        secrets_found=len(secret_findings),
                        vulnerabilities_found=len(sca_findings),
                        critical_count=severity_counts['critical'],
                        high_count=severity_counts['high'],
                        medium_count=severity_counts['medium'],
                        low_count=severity_counts['low']
                    )
                    
                    # Update application scan time
                    self.db.update_application_scan_time(name)
                    
                    logger.info(f"Initial scan completed for {name}: {len(secret_findings)} secrets, {len(sca_findings)} vulnerabilities")
                
                except Exception as scan_error:
                    logger.error(f"Error during initial scan for {name}: {scan_error}")
                    # Don't fail onboarding if scan fails
            
            return True, f"Application '{name}' onboarded successfully. Language: {language}, Framework: {framework}"
        
        except Exception as e:
            logger.error(f"Error onboarding application {name}: {e}")
            return False, str(e)
    
    def bulk_onboard_from_csv(self, csv_file_path: str, access_token: str = None) -> Dict[str, str]:
        """Bulk onboard applications from CSV file"""
        import csv
        results = {}
        
        try:
            with open(csv_file_path, 'r') as csvfile:
                reader = csv.DictReader(csvfile)
                
                for row in reader:
                    name = row.get('name', '').strip()
                    if not name:
                        continue
                    
                    success, message = self.onboard_application(
                        name=name,
                        repo_type=row.get('repo_type', 'github').strip(),
                        repo_url=row.get('repo_url', '').strip() or None,
                        local_path=row.get('local_path', '').strip() or None,
                        team=row.get('team', '').strip() or None,
                        owner=row.get('owner', '').strip() or None,
                        criticality=row.get('criticality', 'medium').strip(),
                        access_token=access_token,
                        auto_scan=row.get('auto_scan', 'true').lower() == 'true'
                    )
                    
                    results[name] = 'Success' if success else f'Failed: {message}'
        
        except Exception as e:
            logger.error(f"Error bulk onboarding from CSV: {e}")
            results['error'] = str(e)
        
        return results
    
    def bulk_onboard_from_json(self, json_file_path: str, access_token: str = None) -> Dict[str, str]:
        """Bulk onboard applications from JSON file"""
        results = {}
        
        try:
            with open(json_file_path, 'r') as jsonfile:
                data = json.load(jsonfile)
                
                applications = data.get('applications', [])
                for app_config in applications:
                    name = app_config.get('name', '').strip()
                    if not name:
                        continue
                    
                    success, message = self.onboard_application(
                        name=name,
                        repo_type=app_config.get('repo_type', 'github'),
                        repo_url=app_config.get('repo_url'),
                        local_path=app_config.get('local_path'),
                        team=app_config.get('team'),
                        owner=app_config.get('owner'),
                        criticality=app_config.get('criticality', 'medium'),
                        access_token=access_token,
                        auto_scan=app_config.get('auto_scan', True)
                    )
                    
                    results[name] = 'Success' if success else f'Failed: {message}'
        
        except Exception as e:
            logger.error(f"Error bulk onboarding from JSON: {e}")
            results['error'] = str(e)
        
        return results
    
    def update_repository(self, app_name: str) -> Tuple[bool, str]:
        """Update repository by pulling latest changes"""
        try:
            app = self.db.get_application(app_name)
            if not app:
                return False, f"Application '{app_name}' not found"
            
            if app['repo_type'] == 'local':
                return True, "Local repository - no update needed"
            
            repo_path = app['local_path']
            if not os.path.exists(repo_path):
                return False, f"Repository path not found: {repo_path}"
            
            # Pull latest changes
            result = subprocess.run(
                ['git', 'pull'],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                return True, "Repository updated successfully"
            else:
                return False, f"Git pull failed: {result.stderr}"
        
        except Exception as e:
            logger.error(f"Error updating repository for {app_name}: {e}")
            return False, str(e)
