# Enterprise Secret Scanner & SCA Tool

A comprehensive Python-based security scanning tool that detects hardcoded secrets and vulnerabilities in 100+ applications, with a modern web dashboard for management and monitoring.

## 🚀 Features

### Secret Detection
- **Advanced Pattern Matching**: Detects AWS keys, API keys, passwords, private keys, JWT tokens, database URLs
- **Entropy Analysis**: Uses Shannon entropy to identify unknown high-entropy secrets
- **Custom Patterns**: Support for organization-specific secret patterns
- **Context-Aware Filtering**: Minimizes false positives with intelligent filtering
- **Confidence Scoring**: Each finding includes a confidence score (0.0-1.0)

### Vulnerability Scanning (SCA)
- **Multi-Package Manager Support**: NPM, Python (pip), Maven dependencies
- **CVE Detection**: Identifies known vulnerabilities with CVE mapping
- **Automated Remediation**: Suggests fixes and secure versions
- **CVSS Scoring**: Risk assessment with CVSS scores

### Application Management
- **Multi-Source Support**: GitHub, GitLab, Bitbucket, local repositories
- **Auto-Detection**: Automatically detects programming languages and frameworks
- **Bulk Operations**: CSV/JSON import for onboarding multiple applications
- **Repository Validation**: Validates access before onboarding

### Web Dashboard
- **Modern UI**: Glass morphism design with responsive layout
- **Real-Time Monitoring**: Live scan progress and status updates
- **Interactive Charts**: Severity distribution and scan activity trends
- **Export Functionality**: CSV export for findings and reports
- **Search & Filter**: Advanced filtering by application, severity, type

### Enterprise Features
- **Parallel Processing**: Scan 100+ applications simultaneously
- **Historical Data**: Complete audit trail with 1-year retention
- **Team Management**: Application ownership and team assignment
- **Criticality Levels**: Risk-based prioritization
- **API Integration**: RESTful API for CI/CD integration

## 📋 Requirements

### System Requirements
- Python 3.8 or higher
- 4GB RAM minimum (8GB recommended for large-scale scanning)
- 10GB disk space for repositories and database
- Network access for remote repository cloning

### Optional Dependencies
- **Git**: For repository cloning and updates
- **Node.js & NPM**: For JavaScript vulnerability scanning
- **Maven**: For Java dependency scanning
- **Safety/pip-audit**: For Python vulnerability scanning

## 🛠 Installation

### 1. Clone the Repository
```bash
git clone <your-repo-url>
cd Enterprise-Secret-and-SCA-scanner
```

### 2. Create Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Install Optional Security Tools
```bash
# For Python vulnerability scanning
pip install safety pip-audit

# For Node.js scanning (requires Node.js)
npm install -g npm-audit

# For Java scanning (requires Maven)
# Download and install Maven from https://maven.apache.org/
```

### 5. Create Required Directories
```bash
mkdir -p data logs repos config
```

### 6. Initialize Database
```bash
python -c "from src.models.database import DatabaseManager; DatabaseManager()"
```

## 🚀 Quick Start

### 1. Start the Web Server
```bash
python -m src.web_server
```

### 2. Access the Dashboard
Open your browser and navigate to: `http://localhost:5000`

### 3. Onboard Your First Application
1. Click the **"Onboard"** tab
2. Fill in application details:
   - **Name**: Your application name
   - **Repository Type**: GitHub, GitLab, Bitbucket, or Local
   - **Repository URL**: Full URL to your repository
   - **Team/Owner**: For organization and accountability
   - **Criticality**: Risk level (Low, Medium, High, Critical)
3. Click **"Validate Repository"** to test access
4. Click **"Onboard Application"** to add and scan

### 4. View Results
- **Dashboard**: Overview of all findings and statistics
- **Applications**: Manage and scan individual applications
- **Findings**: Detailed view of all security issues
- **Scans**: Historical scan results and status

## 📁 Project Structure

```
Enterprise-Secret-and-SCA-scanner/
├── src/                          # Source code
│   ├── models/                   # Database models
│   │   ├── __init__.py
│   │   └── database.py          # SQLite database management
│   ├── __init__.py
│   ├── app_onboarding.py        # Application onboarding logic
│   ├── scanner.py               # Secret detection engine
│   ├── sca_scanner.py           # Vulnerability scanning
│   └── web_server.py            # Flask web application
├── templates/                    # HTML templates
│   └── dashboard.html           # Main dashboard interface
├── static/                       # Static web assets
│   └── dashboard.js             # Frontend JavaScript
├── config/                       # Configuration files
│   ├── scan_config.yaml         # Main configuration
│   └── custom_patterns.yaml     # Custom secret patterns
├── data/                         # Database and data files
├── logs/                         # Application logs
├── repos/                        # Cloned repositories
├── requirements.txt              # Python dependencies
├── README.md                     # This file
└── LICENSE                       # License information
```

## ⚙️ Configuration

### Main Configuration (`config/scan_config.yaml`)
```yaml
scanner:
  max_workers: 4                  # Parallel scan workers
  scan_timeout: 1800             # 30-minute timeout
  max_file_size: 10485760        # 10MB max file size

database:
  path: "data/scanner.db"
  retention_days: 365

web_server:
  host: "0.0.0.0"
  port: 5000
```

### Custom Patterns (`config/custom_patterns.yaml`)
Add organization-specific secret patterns:
```yaml
patterns:
  - name: "Custom API Key"
    pattern: "(?i)custom[_-]?api[_-]?key\s*[=:]\s*[\"']?([A-Za-z0-9_\\-]{32,})[\"']?"
    severity: "high"
    confidence: 0.85
    description: "Custom organization API key"
    remediation: "Move to environment variables"
```

## 🔧 API Reference

### Authentication
Currently, the API does not require authentication. For production deployment, implement proper authentication and authorization.

### Endpoints

#### Applications
- `POST /api/applications/onboard` - Onboard new application
- `GET /api/applications/list` - List all applications
- `GET /api/applications/<name>` - Get application details
- `POST /api/applications/validate` - Validate repository access
- `POST /api/applications/bulk-onboard` - Bulk onboard from CSV/JSON

#### Scanning
- `POST /api/scan` - Start security scan
- `GET /api/scan/status` - Get active scan status

#### Findings
- `GET /api/findings` - Get security findings (with filters)
- `GET /api/findings/export` - Export findings to CSV

#### Statistics
- `GET /api/stats` - Get dashboard statistics
- `GET /api/scans/recent` - Get recent scan history

### Example API Usage
```bash
# Onboard application
curl -X POST http://localhost:5000/api/applications/onboard \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-app",
    "repo_type": "github",
    "repo_url": "https://github.com/user/repo",
    "team": "security",
    "criticality": "high"
  }'

# Start scan
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "applications": ["my-app"],
    "scan_type": "full"
  }'

# Get findings
curl "http://localhost:5000/api/findings?severity=critical"
```

## 🔒 Security Considerations

### For Production Deployment

1. **Authentication & Authorization**
   - Implement proper user authentication
   - Add role-based access control
   - Use HTTPS/TLS encryption

2. **Secret Management**
   - Store GitHub tokens securely
   - Use environment variables for sensitive config
   - Implement secret rotation policies

3. **Network Security**
   - Run behind reverse proxy (nginx/Apache)
   - Configure firewall rules
   - Use VPN for remote access

4. **Data Protection**
   - Encrypt database at rest
   - Implement backup strategies
   - Regular security updates

## 📊 Performance Optimization

### For Large-Scale Deployments

1. **Database Optimization**
   - Consider PostgreSQL for better performance
   - Implement database connection pooling
   - Regular maintenance and indexing

2. **Scanning Performance**
   - Increase `max_workers` based on CPU cores
   - Use SSD storage for repositories
   - Implement scan result caching

3. **Memory Management**
   - Monitor memory usage during scans
   - Implement scan queuing for resource management
   - Use streaming for large file processing

## 🐛 Troubleshooting

### Common Issues

1. **Repository Clone Failures**
   - Check network connectivity
   - Verify access tokens for private repos
   - Ensure sufficient disk space

2. **Scan Timeouts**
   - Increase `scan_timeout` in configuration
   - Check for large binary files in repositories
   - Monitor system resources

3. **False Positives**
   - Add exclusion patterns in `custom_patterns.yaml`
   - Adjust confidence thresholds
   - Review and tune regex patterns

4. **Performance Issues**
   - Reduce `max_workers` if system is overloaded
   - Check database size and optimize
   - Monitor memory and CPU usage

### Logs and Debugging
- Application logs: `logs/scanner.log`
- Enable debug mode: Set `debug: true` in configuration
- Database queries: Enable SQL logging in database.py

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue in the repository
- Check the troubleshooting section
- Review the API documentation

## 🔄 Updates and Maintenance

### Regular Maintenance Tasks
1. Update secret detection patterns
2. Refresh vulnerability databases
3. Clean up old scan data
4. Update dependencies
5. Review and tune performance

### Monitoring Recommendations
- Set up alerts for scan failures
- Monitor disk space usage
- Track scan completion times
- Review finding trends and patterns
