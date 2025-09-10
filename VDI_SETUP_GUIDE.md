# VDI Setup Guide - Enterprise Secret Scanner & SCA Tool

## 📋 Prerequisites Check

Before starting, ensure your VDI has:
- **Python 3.8+** (check with `python3 --version`)
- **Git** (check with `git --version`)
- **Internet access** for package downloads
- **4GB RAM minimum** (8GB recommended)
- **10GB free disk space**
- **Admin/sudo privileges** (for package installation)

## 🚀 Step-by-Step Installation

### Step 1: Clone the Repository
```bash
# Navigate to your preferred directory
cd /home/username/  # or wherever you want to install

# Clone the repository
git clone https://github.com/yashwanthgk88/Enterprise-Secret-and-SCA-scanner.git

# Navigate to the project directory
cd Enterprise-Secret-and-SCA-scanner

# Verify files are present
ls -la
```

### Step 2: Set Up Python Virtual Environment (Recommended)
```bash
# Create virtual environment
python3 -m venv scanner_env

# Activate virtual environment
source scanner_env/bin/activate  # Linux/Mac
# OR for Windows VDI:
# scanner_env\Scripts\activate

# Verify activation (should show scanner_env in prompt)
which python3
```

### Step 3: Install Python Dependencies
```bash
# Upgrade pip first
pip3 install --upgrade pip

# Install required packages
pip3 install -r requirements.txt

# Install optional security scanning tools
pip3 install safety pip-audit

# Verify installation
pip3 list | grep Flask
```

### Step 4: Install Optional Dependencies (Recommended)

#### For JavaScript Scanning (NPM)
```bash
# Check if Node.js/NPM is installed
node --version
npm --version

# If not installed on Ubuntu/Debian VDI:
sudo apt update
sudo apt install nodejs npm

# If not installed on RHEL/CentOS VDI:
sudo yum install nodejs npm
```

#### For Java Scanning (Maven)
```bash
# Check if Maven is installed
mvn --version

# If not installed on Ubuntu/Debian VDI:
sudo apt install maven

# If not installed on RHEL/CentOS VDI:
sudo yum install maven

# Alternative: Download and install manually
wget https://archive.apache.org/dist/maven/maven-3/3.9.4/binaries/apache-maven-3.9.4-bin.tar.gz
tar xzf apache-maven-3.9.4-bin.tar.gz
sudo mv apache-maven-3.9.4 /opt/maven
echo 'export PATH=/opt/maven/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
```

### Step 5: Configure the Application
```bash
# Check configuration files
ls -la config/

# Optional: Customize scan configuration
nano config/scan_config.yaml

# Optional: Add custom secret patterns
nano config/custom_patterns.yaml
```

### Step 6: Initialize and Test the Application
```bash
# Check dependencies and setup
python3 app.py --check-deps

# Expected output should show:
# ✓ Git: Available
# ✓ NPM: Available
# ✓ Safety: Available
# ⚠ Maven: Available (if installed)
```

### Step 7: Start the Application
```bash
# Start in debug mode for first run
python3 app.py --debug

# Expected output:
# 🛡️  Enterprise Secret Scanner & SCA Tool
# 🚀 Starting server on 0.0.0.0:5000
# 🌐 Dashboard URL: http://0.0.0.0:5000
```

### Step 8: Access the Dashboard
```bash
# The application will be available at:
# http://localhost:5000
# http://127.0.0.1:5000
# http://[YOUR_VDI_IP]:5000

# To find your VDI IP:
hostname -I
# or
ip addr show
```

## 🔧 VDI-Specific Configuration

### For Corporate VDI with Proxy
```bash
# Set proxy environment variables
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080
export NO_PROXY=localhost,127.0.0.1

# Install packages with proxy
pip3 install --proxy http://proxy.company.com:8080 -r requirements.txt
```

### For VDI with Restricted Network
```bash
# If external package installation is restricted:
# 1. Download packages on a machine with internet access
pip3 download -r requirements.txt -d packages/

# 2. Transfer packages to VDI and install offline
pip3 install --find-links packages/ -r requirements.txt --no-index
```

### For VDI with Custom Python Path
```bash
# If Python is installed in custom location
/opt/python3.9/bin/python3 -m venv scanner_env
source scanner_env/bin/activate
/opt/python3.9/bin/pip3 install -r requirements.txt
```

## 🚀 Production Setup for VDI

### Create Startup Script
```bash
# Create startup script
cat > start_scanner.sh << 'EOF'
#!/bin/bash
cd /home/username/Enterprise-Secret-and-SCA-scanner
source scanner_env/bin/activate
python3 app.py --host 0.0.0.0 --port 5000
EOF

# Make executable
chmod +x start_scanner.sh
```

### Run as Background Service
```bash
# Start in background
nohup ./start_scanner.sh > scanner.log 2>&1 &

# Check if running
ps aux | grep python3

# View logs
tail -f scanner.log
```

### Create Systemd Service (Linux VDI)
```bash
# Create service file
sudo tee /etc/systemd/system/enterprise-scanner.service > /dev/null << 'EOF'
[Unit]
Description=Enterprise Secret Scanner
After=network.target

[Service]
Type=simple
User=username
WorkingDirectory=/home/username/Enterprise-Secret-and-SCA-scanner
Environment=PATH=/home/username/Enterprise-Secret-and-SCA-scanner/scanner_env/bin
ExecStart=/home/username/Enterprise-Secret-and-SCA-scanner/scanner_env/bin/python3 app.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable enterprise-scanner
sudo systemctl start enterprise-scanner

# Check status
sudo systemctl status enterprise-scanner
```

## 🔍 Verification Steps

### 1. Test Basic Functionality
```bash
# Test server response
curl -I http://localhost:5000

# Expected: HTTP/1.1 200 OK
```

### 2. Test API Endpoints
```bash
# Test health endpoint
curl http://localhost:5000/api/health

# Test applications list
curl http://localhost:5000/api/applications/list

# Test dashboard stats
curl http://localhost:5000/api/stats
```

### 3. Test Web Interface
1. Open browser and go to: `http://localhost:5000`
2. You should see the Enterprise Security Scanner dashboard
3. Try navigating between tabs: Dashboard, Onboard, Applications, Findings, Scans

## 🛠 Troubleshooting Common VDI Issues

### Issue 1: Permission Denied
```bash
# Fix directory permissions
chmod -R 755 /home/username/Enterprise-Secret-and-SCA-scanner
chown -R username:username /home/username/Enterprise-Secret-and-SCA-scanner
```

### Issue 2: Port 5000 Already in Use
```bash
# Check what's using port 5000
sudo lsof -i :5000

# Use different port
python3 app.py --port 8080
```

### Issue 3: Python Module Not Found
```bash
# Ensure virtual environment is activated
source scanner_env/bin/activate

# Reinstall requirements
pip3 install -r requirements.txt --force-reinstall
```

### Issue 4: Database Permission Issues
```bash
# Create data directory with proper permissions
mkdir -p data logs repos
chmod 755 data logs repos
```

### Issue 5: Network/Firewall Issues
```bash
# Check if port is accessible
telnet localhost 5000

# For corporate VDI, you may need to request firewall rules
# Contact your IT team to open port 5000
```

## 📊 First-Time Usage

### 1. Access Dashboard
- Open browser: `http://localhost:5000`
- You should see the modern dashboard with glass morphism design

### 2. Onboard Your First Application
1. Click **"Onboard"** tab
2. Fill in application details:
   - **Name**: `test-app`
   - **Repository Type**: `Local Path`
   - **Local Path**: `/path/to/your/code`
   - **Team**: `security`
   - **Criticality**: `Medium`
3. Click **"Onboard Application"**

### 3. Run Your First Scan
1. Go to **"Applications"** tab
2. Click **"Scan"** button next to your application
3. Monitor progress in real-time
4. View results in **"Findings"** tab

## 🔒 Security Considerations for VDI

### 1. Network Security
```bash
# Bind to localhost only for security
python3 app.py --host 127.0.0.1 --port 5000
```

### 2. Data Protection
```bash
# Secure data directory
chmod 700 data/
chmod 600 data/*.db
```

### 3. Log Management
```bash
# Rotate logs to prevent disk space issues
logrotate -f /etc/logrotate.d/enterprise-scanner
```

## 📈 Performance Optimization for VDI

### 1. Adjust Worker Threads
Edit `config/scan_config.yaml`:
```yaml
scanner:
  max_workers: 2  # Reduce for VDI with limited resources
```

### 2. Database Optimization
```bash
# For better performance, consider PostgreSQL
pip3 install psycopg2-binary
```

### 3. Memory Management
```bash
# Monitor memory usage
htop
# or
ps aux --sort=-%mem | head
```

## 📞 Support and Maintenance

### Regular Maintenance Tasks
```bash
# Update dependencies monthly
pip3 install --upgrade -r requirements.txt

# Clean old scan data (optional)
python3 -c "from src.models.database import DatabaseManager; db = DatabaseManager(); print('Database maintenance completed')"

# Check disk space
df -h
```

### Backup Strategy
```bash
# Backup database and configuration
tar -czf backup-$(date +%Y%m%d).tar.gz data/ config/ logs/
```

### Getting Help
- Check logs: `tail -f logs/scanner.log`
- GitHub Issues: https://github.com/yashwanthgk88/Enterprise-Secret-and-SCA-scanner/issues
- Documentation: README.md in the repository

---

## ✅ Quick Setup Summary

For experienced users, here's the quick setup:

```bash
git clone https://github.com/yashwanthgk88/Enterprise-Secret-and-SCA-scanner.git
cd Enterprise-Secret-and-SCA-scanner
python3 -m venv scanner_env
source scanner_env/bin/activate
pip3 install -r requirements.txt
pip3 install safety pip-audit
python3 app.py --check-deps
python3 app.py
# Access: http://localhost:5000
```

Your Enterprise Secret Scanner & SCA Tool is now ready for production use in your VDI environment!
