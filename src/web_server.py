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

from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS

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
        
        # Register routes
        self._register_routes()
    
    def _register_routes(self):
        """Register all API routes"""
        
        # Dashboard route
        @self.app.route('/')
        def dashboard():
            return render_template('dashboard.html')
        
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
            """Onboard a new application"""
            try:
                data = request.get_json()
                
                # Validate required fields
                required_fields = ['name', 'repo_type']
                for field in required_fields:
                    if field not in data:
                        return jsonify({'error': f'Missing required field: {field}'}), 400
                
                # Onboard application
                success, message = self.onboarding.onboard_application(
                    name=data['name'],
                    repo_type=data['repo_type'],
                    repo_url=data.get('repo_url'),
                    local_path=data.get('local_path'),
                    team=data.get('team'),
                    owner=data.get('owner'),
                    criticality=data.get('criticality', 'medium'),
                    access_token=data.get('access_token'),
                    auto_scan=data.get('auto_scan', True)
                )
                
                if success:
                    return jsonify({'message': message}), 201
                else:
                    return jsonify({'error': message}), 400
            
            except Exception as e:
                logger.error(f"Error onboarding application: {e}")
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
                    return jsonify({'active_scans': dict(self.active_scans)})
            
            except Exception as e:
                logger.error(f"Error getting scan status: {e}")
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
    
    def _perform_scan(self, app_names: List[str], scan_type: str):
        """Perform security scan for applications (runs in background)"""
        try:
            for app_name in app_names:
                try:
                    # Update scan status
                    with self.scan_lock:
                        if app_name in self.active_scans:
                            self.active_scans[app_name]['status'] = 'running'
                    
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
                    
                    # Create scan record
                    scan_id = self.db.create_scan(app_name, scan_type)
                    
                    secret_findings = []
                    sca_findings = []
                    
                    # Run secret scan
                    if scan_type in ['full', 'secrets']:
                        logger.info(f"Running secret scan for {app_name}")
                        secret_findings = self.secret_scanner.scan_directory(scan_path)
                    
                    # Run SCA scan
                    if scan_type in ['full', 'sca']:
                        logger.info(f"Running SCA scan for {app_name}")
                        sca_findings = self.sca_scanner.scan_directory(scan_path)
                    
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
                    # Remove from active scans
                    with self.scan_lock:
                        if app_name in self.active_scans:
                            del self.active_scans[app_name]
        
        except Exception as e:
            logger.error(f"Error in scan thread: {e}")
    
    def run(self, host='0.0.0.0', port=5000, debug=False):
        """Run the Flask application"""
        logger.info(f"Starting Enterprise Security Scanner on {host}:{port}")
        self.app.run(host=host, port=port, debug=debug, threaded=True)

# Create global app instance
security_scanner = SecurityScannerAPI()
app = security_scanner.app

if __name__ == '__main__':
    security_scanner.run(debug=True)
