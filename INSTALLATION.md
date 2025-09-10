# Installation Guide for VDI Environment

## Quick Installation for VDI

### Prerequisites
- Python 3.8+ (already available on your system)
- Git (already available on your system)
- NPM (already available on your system)
- Network access for package installation

### Step 1: Install Python Dependencies
```bash
cd /Users/yashwanthgk/SLM/Enterprise-Secret-and-SCA-scanner
pip3 install -r requirements.txt
```

### Step 2: Install Optional Security Tools
```bash
# Install Python vulnerability scanners
pip3 install safety pip-audit

# Maven (optional - for Java scanning)
# Download from: https://maven.apache.org/download.cgi
# Or use homebrew: brew install maven
```

### Step 3: Start the Application
```bash
python3 app.py
```

The application will be available at: http://localhost:5000

### Step 4: Access the Dashboard
1. Open your web browser
2. Navigate to: http://localhost:5000
3. Start onboarding applications using the "Onboard" tab

## Production Configuration for VDI

### 1. Create a startup script
```bash
#!/bin/bash
# save as start_scanner.sh
cd /Users/yashwanthgk/SLM/Enterprise-Secret-and-SCA-scanner
python3 app.py --host 0.0.0.0 --port 5000
```

### 2. Make it executable
```bash
chmod +x start_scanner.sh
```

### 3. Run in background (optional)
```bash
nohup ./start_scanner.sh > scanner.log 2>&1 &
```

## Verification Steps

1. **Check Dependencies**: `python3 app.py --check-deps`
2. **Test Database**: The app will create the database automatically
3. **Test Web Interface**: Access http://localhost:5000
4. **Test Onboarding**: Try onboarding a sample repository

## Troubleshooting

### Common Issues:
1. **Port 5000 in use**: Use `--port 8080` to change port
2. **Permission errors**: Ensure write access to the project directory
3. **Missing dependencies**: Run `pip3 install -r requirements.txt` again

### Performance Tuning for VDI:
- Reduce `max_workers` in config if system is slow
- Increase scan timeout for large repositories
- Monitor disk space in `repos/` directory
