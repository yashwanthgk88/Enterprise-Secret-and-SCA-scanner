"""
Flask web server for Enterprise Secret Scanner & SCA Tool
Provides REST API endpoints and serves the dashboard
"""
import os
import json
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional
import threading

from flask import Flask, request, jsonify, render_template, send_from_directory, Response
from flask_cors import CORS
import json
import time
import queue

from .models.database import DatabaseManager
from .app_onboarding import ApplicationOnboarding
from .scanner import SecretScanner, BatchScanner
from .sca_scanner import SCAScanner

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityScannerAPI:
    """Main Flask application for the security scanner"""
    
    def __init__(self):
        self.app = Flask(__name__, 
                        template_folder='../templates',
                        static_folder='../static')
        CORS(self.app)
        
        # Initialize components
        self.db = DatabaseManager()
        self.onboarding = ApplicationOnboarding(self.db)
        self.secret_scanner = SecretScanner()
        self.sca_scanner = SCAScanner()
        self.batch_scanner = BatchScanner()
        
        # Thread pool for async scanning
        self.scan_executor = ThreadPoolExecutor(max_workers=4)
        self.active_scans = {}  # Track active scans
        self.scan_lock = threading.Lock()
        
        # Progress tracking for real-time updates
        self.progress_queues = {}  # Store progress queues for each operation
        self.progress_lock = threading.Lock()
        self.scan_progress = {}  # Store detailed scan progress for each application
        
        # Register routes
        self._register_routes()
    
    def _register_routes(self):
        """Register all API routes"""
        
        # Dashboard route
        @self.app.route('/')
        def dashboard():
            # Get applications for server-side rendering
            try:
                applications = self.db.get_applications('active')
                # Add scan status for each application
                for app in applications:
                    with self.scan_lock:
                        app['scanning'] = app['name'] in self.active_scans
            except Exception as e:
                logger.error(f"Error loading applications for dashboard: {e}")
                applications = []
            
            return render_template('dashboard.html', applications=applications)
        
        # Test route for debugging
        @self.app.route('/test')
        def test_page():
            return send_from_directory('.', 'test_apps.html')
        
        # Simple applications page
        @self.app.route('/apps')
        def simple_apps():
            return send_from_directory('.', 'simple_apps.html')
        
        # Static files
        @self.app.route('/static/<path:filename>')
        def static_files(filename):
            return send_from_directory(self.app.static_folder, filename)
        
        # API Routes
        
        @self.app.route('/api/health', methods=['GET'])
        def health_check():
            """Health check endpoint"""
            return jsonify({
                'status': 'healthy',
                'timestamp': datetime.now().isoformat(),
                'version': '1.0.0'
            })
        
        @self.app.route('/api/applications/onboard', methods=['POST'])
        def onboard_application():
            """Onboard a new application with progress tracking"""
            try:
                data = request.get_json()
                
                # Validate required fields
                required_fields = ['name', 'repo_type']
                for field in required_fields:
                    if field not in data:
                        return jsonify({'error': f'Missing required field: {field}'}), 400
                
                app_name = data['name']
                
                # Create progress queue for this operation
                progress_queue = queue.Queue()
                operation_id = f"onboard_{app_name}_{int(time.time())}"
                
                with self.progress_lock:
                    self.progress_queues[operation_id] = progress_queue
                
                # Start onboarding in background with progress tracking
                future = self.scan_executor.submit(
                    self._onboard_with_progress, 
                    data, 
                    progress_queue
                )
                
                return jsonify({
                    'message': f'Onboarding started for {app_name}',
                    'operation_id': operation_id
                }), 202
            
            except Exception as e:
                logger.error(f"Error starting onboarding: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/applications/validate', methods=['POST'])
        def validate_repository():
            """Validate repository access"""
            try:
                data = request.get_json()
                
                repo_url = data.get('repo_url')
                repo_type = data.get('repo_type', 'github')
                access_token = data.get('access_token')
                
                if not repo_url:
                    return jsonify({'error': 'Repository URL is required'}), 400
                
                is_valid, message = self.onboarding.validate_repository(
                    repo_url, repo_type, access_token
                )
                
                return jsonify({
                    'valid': is_valid,
                    'message': message
                })
            
            except Exception as e:
                logger.error(f"Error validating repository: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/applications/list', methods=['GET'])
        def list_applications():
            """Get list of all applications"""
            try:
                status = request.args.get('status', 'active')
                applications = self.db.get_applications(status)
                
                # Add scan status for each application
                for app in applications:
                    with self.scan_lock:
                        app['scanning'] = app['name'] in self.active_scans
                
                return jsonify({'applications': applications})
            
            except Exception as e:
                logger.error(f"Error listing applications: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/applications/<app_name>', methods=['GET'])
        def get_application(app_name):
            """Get single application details"""
            try:
                app = self.db.get_application(app_name)
                if not app:
                    return jsonify({'error': 'Application not found'}), 404
                
                # Add scan status
                with self.scan_lock:
                    app['scanning'] = app_name in self.active_scans
                
                return jsonify({'application': app})
            
            except Exception as e:
                logger.error(f"Error getting application {app_name}: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/applications/bulk-onboard', methods=['POST'])
        def bulk_onboard():
            """Bulk onboard applications from CSV or JSON"""
            try:
                if 'file' not in request.files:
                    return jsonify({'error': 'No file provided'}), 400
                
                file = request.files['file']
                if file.filename == '':
                    return jsonify({'error': 'No file selected'}), 400
                
                access_token = request.form.get('access_token')
                
                # Save uploaded file temporarily
                temp_path = f"/tmp/{file.filename}"
                file.save(temp_path)
                
                try:
                    if file.filename.endswith('.csv'):
                        results = self.onboarding.bulk_onboard_from_csv(temp_path, access_token)
                    elif file.filename.endswith('.json'):
                        results = self.onboarding.bulk_onboard_from_json(temp_path, access_token)
                    else:
                        return jsonify({'error': 'Unsupported file format. Use CSV or JSON'}), 400
                    
                    return jsonify({'results': results})
                
                finally:
                    # Clean up temp file
                    if os.path.exists(temp_path):
                        os.remove(temp_path)
            
            except Exception as e:
                logger.error(f"Error bulk onboarding: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/scan', methods=['POST'])
        def start_scan():
            """Start security scan for applications"""
            try:
                data = request.get_json()
                app_names = data.get('applications', [])
                scan_type = data.get('scan_type', 'full')  # full, secrets, sca
                
                if not app_names:
                    return jsonify({'error': 'No applications specified'}), 400
                
                # Check if any applications are already being scanned
                with self.scan_lock:
                    already_scanning = [name for name in app_names if name in self.active_scans]
                    if already_scanning:
                        return jsonify({
                            'error': f'Applications already being scanned: {", ".join(already_scanning)}'
                        }), 400
                    
                    # Mark applications as being scanned
                    for app_name in app_names:
                        self.active_scans[app_name] = {
                            'scan_type': scan_type,
                            'started_at': datetime.now(),
                            'status': 'starting'
                        }
                
                # Start async scan
                future = self.scan_executor.submit(self._perform_scan, app_names, scan_type)
                
                return jsonify({
                    'message': f'Scan started for {len(app_names)} applications',
                    'applications': app_names,
                    'scan_type': scan_type
                })
            
            except Exception as e:
                logger.error(f"Error starting scan: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/scan/status', methods=['GET'])
        def scan_status():
            """Get status of active scans"""
            try:
                with self.scan_lock:
                    return jsonify({
                        'active_scans': dict(self.active_scans),
                        'scan_progress': dict(self.scan_progress)
                    })
            
            except Exception as e:
                logger.error(f"Error getting scan status: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/scan/progress/<app_name>', methods=['GET'])
        def get_scan_progress(app_name):
            """Get detailed scan progress for a specific application"""
            try:
                with self.scan_lock:
                    progress = self.scan_progress.get(app_name, {})
                    return jsonify({'progress': progress})
            
            except Exception as e:
                logger.error(f"Error getting scan progress for {app_name}: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/findings', methods=['GET'])
        def get_findings():
            """Get security findings with optional filters"""
            try:
                app_name = request.args.get('app_name')
                severity = request.args.get('severity')
                finding_type = request.args.get('type')  # secrets, sca
                limit = int(request.args.get('limit', 100))
                
                findings = self.db.get_findings(app_name, severity, finding_type, limit)
                
                return jsonify({'findings': findings})
            
            except Exception as e:
                logger.error(f"Error getting findings: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/findings/export', methods=['GET'])
        def export_findings():
            """Export findings to CSV"""
            try:
                import csv
                import io
                
                app_name = request.args.get('app_name')
                severity = request.args.get('severity')
                finding_type = request.args.get('type')
                
                findings = self.db.get_findings(app_name, severity, finding_type, 10000)
                
                # Create CSV
                output = io.StringIO()
                writer = csv.writer(output)
                
                # Write header
                writer.writerow([
                    'Type', 'Application', 'File Path', 'Line Number', 'Title',
                    'Severity', 'Confidence', 'Created At', 'Status'
                ])
                
                # Write data
                for finding in findings:
                    writer.writerow([
                        finding['type'],
                        finding['app_name'],
                        finding['file_path'],
                        finding['line_number'],
                        finding['title'],
                        finding['severity'],
                        finding['confidence'],
                        finding['created_at'],
                        finding['status']
                    ])
                
                # Prepare response
                output.seek(0)
                response = self.app.response_class(
                    output.getvalue(),
                    mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=security_findings.csv'}
                )
                
                return response
            
            except Exception as e:
                logger.error(f"Error exporting findings: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/stats', methods=['GET'])
        def get_dashboard_stats():
            """Get dashboard statistics"""
            try:
                stats = self.db.get_dashboard_stats()
                return jsonify({'stats': stats})
            
            except Exception as e:
                logger.error(f"Error getting dashboard stats: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/scans/recent', methods=['GET'])
        def get_recent_scans():
            """Get recent scan history"""
            try:
                limit = int(request.args.get('limit', 10))
                scans = self.db.get_recent_scans(limit)
                
                return jsonify({'scans': scans})
            
            except Exception as e:
                logger.error(f"Error getting recent scans: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/progress/<operation_id>')
        def get_progress(operation_id):
            """Server-Sent Events endpoint for real-time progress updates"""
            def generate():
                with self.progress_lock:
                    progress_queue = self.progress_queues.get(operation_id)
                
                if not progress_queue:
                    yield f"data: {json.dumps({'error': 'Operation not found'})}\n\n"
                    return
                
                try:
                    while True:
                        try:
                            # Get progress update with timeout
                            progress_data = progress_queue.get(timeout=1)
                            yield f"data: {json.dumps(progress_data)}\n\n"
                            
                            # If operation is complete, clean up and exit
                            if progress_data.get('status') in ['completed', 'failed']:
                                with self.progress_lock:
                                    if operation_id in self.progress_queues:
                                        del self.progress_queues[operation_id]
                                break
                                
                        except queue.Empty:
                            # Send heartbeat to keep connection alive
                            yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
                            continue
                            
                except GeneratorExit:
                    # Client disconnected, clean up
                    with self.progress_lock:
                        if operation_id in self.progress_queues:
                            del self.progress_queues[operation_id]
            
            return Response(
                generate(),
                mimetype='text/event-stream',
                headers={
                    'Cache-Control': 'no-cache',
                    'Connection': 'keep-alive',
                    'Access-Control-Allow-Origin': '*'
                }
            )
    
    def _onboard_with_progress(self, data: Dict, progress_queue: queue.Queue):
        """Onboard application with progress tracking"""
        try:
            app_name = data['name']
            
            # Send initial progress
            progress_queue.put({
                'type': 'progress',
                'status': 'starting',
                'message': f'Starting onboarding for {app_name}',
                'percentage': 0
            })
            
            # Validate repository
            progress_queue.put({
                'type': 'progress',
                'status': 'validating',
                'message': 'Validating repository access...',
                'percentage': 10
            })
            
            validation_url = data.get('local_path') if data['repo_type'] == 'local' else data.get('repo_url')
            is_valid, validation_message = self.onboarding.validate_repository(
                validation_url, data['repo_type'], data.get('access_token')
            )
            
            if not is_valid:
                progress_queue.put({
                    'type': 'progress',
                    'status': 'failed',
                    'message': f'Repository validation failed: {validation_message}',
                    'percentage': 100
                })
                return
            
            # Clone repository if remote
            if data['repo_type'] != 'local':
                progress_queue.put({
                    'type': 'progress',
                    'status': 'cloning',
                    'message': 'Cloning repository...',
                    'percentage': 30
                })
                
                clone_success, clone_result = self.onboarding.clone_repository(
                    data.get('repo_url'), app_name, data.get('access_token')
                )
                
                if not clone_success:
                    progress_queue.put({
                        'type': 'progress',
                        'status': 'failed',
                        'message': f'Failed to clone repository: {clone_result}',
                        'percentage': 100
                    })
                    return
                
                scan_path = clone_result
            else:
                scan_path = data.get('local_path')
            
            # Auto-detect language and framework
            progress_queue.put({
                'type': 'progress',
                'status': 'analyzing',
                'message': 'Analyzing project structure...',
                'percentage': 50
            })
            
            language, framework = self.onboarding.detect_language_and_framework(scan_path)
            
            # Add to database
            progress_queue.put({
                'type': 'progress',
                'status': 'saving',
                'message': 'Saving application to database...',
                'percentage': 70
            })
            
            success = self.db.add_application(
                name=app_name,
                repo_type=data['repo_type'],
                repo_url=data.get('repo_url'),
                local_path=scan_path,
                team=data.get('team'),
                owner=data.get('owner'),
                criticality=data.get('criticality', 'medium'),
                language=language,
                framework=framework
            )
            
            if not success:
                progress_queue.put({
                    'type': 'progress',
                    'status': 'failed',
                    'message': 'Failed to add application to database',
                    'percentage': 100
                })
                return
            
            # Run initial scan if requested
            if data.get('auto_scan', True):
                progress_queue.put({
                    'type': 'progress',
                    'status': 'scanning',
                    'message': 'Running initial security scan...',
                    'percentage': 80
                })
                
                # Create scan record
                scan_id = self.db.create_scan(app_name, 'full')
                
                # Run scans with progress updates
                secret_findings = self._scan_with_progress(scan_path, 'secrets', progress_queue, 80, 90)
                sca_findings = self._scan_with_progress(scan_path, 'sca', progress_queue, 90, 95)
                
                # Store findings
                severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
                
                for finding in secret_findings:
                    self.db.add_secret_finding(
                        scan_id=scan_id,
                        app_name=app_name,
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
                        app_name=app_name,
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
                
                self.db.update_application_scan_time(app_name)
            
            # Complete successfully
            progress_queue.put({
                'type': 'progress',
                'status': 'completed',
                'message': f'Successfully onboarded {app_name}. Language: {language}, Framework: {framework}',
                'percentage': 100,
                'result': {
                    'language': language,
                    'framework': framework,
                    'scan_completed': data.get('auto_scan', True)
                }
            })
            
        except Exception as e:
            logger.error(f"Error in onboarding with progress: {e}")
            progress_queue.put({
                'type': 'progress',
                'status': 'failed',
                'message': f'Onboarding failed: {str(e)}',
                'percentage': 100
            })
    
    def _scan_with_progress(self, scan_path: str, scan_type: str, progress_queue: queue.Queue, start_pct: int, end_pct: int):
        """Run scan with progress updates"""
        try:
            if scan_type == 'secrets':
                findings = self.secret_scanner.scan_directory(scan_path)
            elif scan_type == 'sca':
                findings = self.sca_scanner.scan_directory(scan_path)
            else:
                return []
            
            progress_queue.put({
                'type': 'progress',
                'status': 'scanning',
                'message': f'{scan_type.upper()} scan completed: {len(findings)} findings',
                'percentage': end_pct
            })
            
            return findings
        except Exception as e:
            logger.error(f"Error in {scan_type} scan: {e}")
            return []
    
    def _perform_scan(self, app_names: List[str], scan_type: str):
        """Perform security scan for applications (runs in background)"""
        try:
            for app_name in app_names:
                try:
                    # Initialize progress tracking
                    with self.scan_lock:
                        if app_name in self.active_scans:
                            self.active_scans[app_name]['status'] = 'running'
                        self.scan_progress[app_name] = {
                            'status': 'initializing',
                            'total_files': 0,
                            'scanned_files': 0,
                            'current_file': '',
                            'percentage': 0,
                            'secrets_found': 0,
                            'vulnerabilities_found': 0,
                            'start_time': datetime.now().isoformat(),
                            'estimated_time_remaining': None
                        }
                    
                    # Get application info
                    app = self.db.get_application(app_name)
                    if not app:
                        logger.error(f"Application {app_name} not found")
                        continue
                    
                    scan_path = app['local_path']
                    if not os.path.exists(scan_path):
                        logger.error(f"Scan path not found for {app_name}: {scan_path}")
                        continue
                    
                    # Update repository if remote
                    if app['repo_type'] != 'local':
                        self.onboarding.update_repository(app_name)
                    
                    # Count total files for progress tracking
                    total_files = self._count_scannable_files(scan_path)
                    with self.scan_lock:
                        self.scan_progress[app_name]['total_files'] = total_files
                        self.scan_progress[app_name]['status'] = 'scanning'
                    
                    # Create scan record
                    scan_id = self.db.create_scan(app_name, scan_type)
                    
                    secret_findings = []
                    sca_findings = []
                    
                    # Run secret scan with progress tracking
                    if scan_type in ['full', 'secrets']:
                        logger.info(f"Running secret scan for {app_name}")
                        with self.scan_lock:
                            self.scan_progress[app_name]['status'] = 'scanning_secrets'
                        secret_findings = self._scan_with_enhanced_progress(
                            scan_path, 'secrets', app_name, 0, 50 if scan_type == 'full' else 100
                        )
                    
                    # Run SCA scan with progress tracking
                    if scan_type in ['full', 'sca']:
                        logger.info(f"Running SCA scan for {app_name}")
                        with self.scan_lock:
                            self.scan_progress[app_name]['status'] = 'scanning_dependencies'
                        sca_findings = self._scan_with_enhanced_progress(
                            scan_path, 'sca', app_name, 50 if scan_type == 'full' else 0, 100
                        )
                    
                    # Store findings
                    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
                    
                    for finding in secret_findings:
                        self.db.add_secret_finding(
                            scan_id=scan_id,
                            app_name=app_name,
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
                            app_name=app_name,
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
                    self.db.update_application_scan_time(app_name)
                    
                    logger.info(f"Scan completed for {app_name}: {len(secret_findings)} secrets, {len(sca_findings)} vulnerabilities")
                
                except Exception as e:
                    logger.error(f"Error scanning {app_name}: {e}")
                    # Mark scan as failed in database if scan_id exists
                    try:
                        scan_id = self.db.create_scan(app_name, scan_type)
                        self.db.complete_scan(scan_id, error_message=str(e))
                    except:
                        pass
                
                finally:
                    # Remove from active scans and progress tracking
                    with self.scan_lock:
                        if app_name in self.active_scans:
                            del self.active_scans[app_name]
                        if app_name in self.scan_progress:
                            del self.scan_progress[app_name]
        
        except Exception as e:
            logger.error(f"Error in scan thread: {e}")
    
    def _count_scannable_files(self, scan_path: str) -> int:
        """Count total number of scannable files for progress tracking"""
        try:
            scannable_extensions = {
                '.py', '.js', '.ts', '.java', '.php', '.rb', '.go', '.cs', '.cpp', '.c', '.h',
                '.json', '.xml', '.yaml', '.yml', '.properties', '.config', '.env', '.ini',
                '.sql', '.sh', '.bash', '.ps1', '.dockerfile', '.tf', '.tfvars'
            }
            
            total_files = 0
            for root, dirs, files in os.walk(scan_path):
                # Skip common non-source directories
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in {
                    'node_modules', '__pycache__', 'target', 'build', 'dist', 'vendor'
                }]
                
                for file in files:
                    if any(file.endswith(ext) for ext in scannable_extensions):
                        total_files += 1
            
            return total_files
        except Exception as e:
            logger.error(f"Error counting files: {e}")
            return 0
    
    def _scan_with_enhanced_progress(self, scan_path: str, scan_type: str, app_name: str, 
                                   start_pct: int, end_pct: int):
        """Run scan with enhanced progress tracking for large codebases"""
        try:
            import time
            start_time = time.time()
            
            if scan_type == 'secrets':
                findings = self.secret_scanner.scan_directory(scan_path)
            elif scan_type == 'sca':
                findings = self.sca_scanner.scan_directory(scan_path)
            else:
                return []
            
            # Update progress
            elapsed_time = time.time() - start_time
            with self.scan_lock:
                if app_name in self.scan_progress:
                    self.scan_progress[app_name]['percentage'] = end_pct
                    self.scan_progress[app_name]['secrets_found'] = len(findings) if scan_type == 'secrets' else self.scan_progress[app_name].get('secrets_found', 0)
                    self.scan_progress[app_name]['vulnerabilities_found'] = len(findings) if scan_type == 'sca' else self.scan_progress[app_name].get('vulnerabilities_found', 0)
                    self.scan_progress[app_name]['elapsed_time'] = f"{elapsed_time:.1f}s"
            
            return findings
        except Exception as e:
            logger.error(f"Error in enhanced {scan_type} scan: {e}")
            return []
    
    def run(self, host='0.0.0.0', port=5000, debug=False):
        """Run the Flask application"""
        logger.info(f"Starting Enterprise Security Scanner on {host}:{port}")
        self.app.run(host=host, port=port, debug=debug, threaded=True)

# Create global app instance
security_scanner = SecurityScannerAPI()
app = security_scanner.app

if __name__ == '__main__':
    security_scanner.run(debug=True)
