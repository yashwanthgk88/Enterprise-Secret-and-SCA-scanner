#!/usr/bin/env python3
"""
Enterprise Secret Scanner & SCA Tool
Main application entry point

Usage:
    python app.py [--host HOST] [--port PORT] [--debug]
    
Examples:
    python app.py                           # Run with default settings
    python app.py --host 0.0.0.0 --port 8080  # Custom host and port
    python app.py --debug                   # Enable debug mode
"""

import os
import sys
import argparse
import logging
from pathlib import Path

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.web_server import SecurityScannerAPI

def setup_logging(debug=False):
    """Configure application logging"""
    log_level = logging.DEBUG if debug else logging.INFO
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    # Configure logging
    logging.basicConfig(
        level=log_level,
        format=log_format,
        handlers=[
            logging.FileHandler('logs/scanner.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )

def create_directories():
    """Create required directories if they don't exist"""
    directories = ['data', 'logs', 'repos', 'config']
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"✓ Created directory: {directory}")

def check_dependencies():
    """Check if optional dependencies are available"""
    dependencies = {
        'git': 'Git (for repository cloning)',
        'npm': 'NPM (for JavaScript vulnerability scanning)',
        'mvn': 'Maven (for Java dependency scanning)',
        'safety': 'Safety (for Python vulnerability scanning)',
        'pip-audit': 'pip-audit (for Python vulnerability scanning)'
    }
    
    print("\n🔍 Checking optional dependencies:")
    
    for cmd, description in dependencies.items():
        try:
            import subprocess
            result = subprocess.run([cmd, '--version'], 
                                  capture_output=True, 
                                  timeout=5)
            if result.returncode == 0:
                print(f"✓ {description}: Available")
            else:
                print(f"⚠ {description}: Not available")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            print(f"⚠ {description}: Not available")

def main():
    """Main application entry point"""
    parser = argparse.ArgumentParser(
        description='Enterprise Secret Scanner & SCA Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python app.py                           # Run with default settings
  python app.py --host 0.0.0.0 --port 8080  # Custom host and port  
  python app.py --debug                   # Enable debug mode
  python app.py --check-deps              # Check dependencies only
        """
    )
    
    parser.add_argument('--host', 
                       default='0.0.0.0',
                       help='Host to bind the server to (default: 0.0.0.0)')
    
    parser.add_argument('--port', 
                       type=int, 
                       default=5000,
                       help='Port to bind the server to (default: 5000)')
    
    parser.add_argument('--debug', 
                       action='store_true',
                       help='Enable debug mode')
    
    parser.add_argument('--check-deps', 
                       action='store_true',
                       help='Check dependencies and exit')
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.debug)
    logger = logging.getLogger(__name__)
    
    print("🛡️  Enterprise Secret Scanner & SCA Tool")
    print("=" * 50)
    
    # Create required directories
    print("\n📁 Setting up directories:")
    create_directories()
    
    # Check dependencies
    if args.check_deps:
        check_dependencies()
        return
    
    # Check dependencies (non-blocking)
    check_dependencies()
    
    try:
        # Initialize and start the application
        print(f"\n🚀 Starting server on {args.host}:{args.port}")
        print(f"🌐 Dashboard URL: http://{args.host}:{args.port}")
        print("📊 Features available:")
        print("   • Secret Detection with Entropy Analysis")
        print("   • SCA Vulnerability Scanning (NPM, Python, Maven)")
        print("   • GitHub/GitLab/Bitbucket Integration")
        print("   • Modern Web Dashboard")
        print("   • Parallel Processing (100+ applications)")
        print("   • Export & Reporting")
        
        if args.debug:
            print("🐛 Debug mode enabled")
        
        print("\n" + "=" * 50)
        print("Press Ctrl+C to stop the server")
        print("=" * 50)
        
        # Create and run the application
        app = SecurityScannerAPI()
        app.run(host=args.host, port=args.port, debug=args.debug)
        
    except KeyboardInterrupt:
        print("\n\n👋 Shutting down gracefully...")
        logger.info("Application stopped by user")
        
    except Exception as e:
        print(f"\n❌ Error starting application: {e}")
        logger.error(f"Application startup failed: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
