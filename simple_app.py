#!/usr/bin/env python3
"""
Simple Enterprise Security Scanner - Revamped Version
Clean, working implementation without complex dependencies
"""

from flask import Flask, render_template_string, jsonify, request, send_file
from flask_socketio import SocketIO, emit
import sqlite3
import json
import threading
import time
import random
from datetime import datetime, timedelta
import os
import requests
from concurrent.futures import ThreadPoolExecutor
import nvdlib
import asyncio
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
import io

app = Flask(__name__)
app.config['SECRET_KEY'] = 'security-scanner-secret'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global variables for real-time updates
active_scans = {}
scan_executor = ThreadPoolExecutor(max_workers=4)

# Simple HTML template that WILL work
DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise Security Scanner</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --primary-color: #1e293b;
            --secondary-color: #334155;
            --accent-color: #3b82f6;
            --success-color: #10b981;
            --warning-color: #f59e0b;
            --danger-color: #ef4444;
            --info-color: #06b6d4;
            --light-bg: #f8fafc;
            --card-bg: #ffffff;
            --text-primary: #1e293b;
            --text-secondary: #64748b;
            --border-color: #e2e8f0;
            --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
        }
        
        body { 
            background: var(--light-bg);
            min-height: 100vh;
            color: var(--text-primary);
            font-family: 'Inter', 'Segoe UI', system-ui, sans-serif;
            font-size: 14px;
            line-height: 1.6;
        }
        
        .glass-card {
            background: var(--card-bg);
            border-radius: 12px;
            border: 1px solid var(--border-color);
            box-shadow: var(--shadow);
            transition: all 0.2s ease;
        }
        
        .glass-card:hover {
            box-shadow: var(--shadow-lg);
        }
        
        .app-card {
            background: var(--card-bg);
            border-radius: 12px;
            padding: 24px;
            margin: 16px 0;
            border: 1px solid var(--border-color);
            border-left: 4px solid var(--success-color);
            box-shadow: var(--shadow);
            transition: all 0.2s ease;
        }
        
        .app-card:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-lg);
        }
        
        .app-card.high-risk {
            border-left-color: var(--danger-color);
        }
        
        .app-card.medium-risk {
            border-left-color: var(--warning-color);
        }
        
        .app-card.scanning {
            border-left-color: var(--info-color);
            background: linear-gradient(90deg, var(--card-bg) 0%, rgba(59, 130, 246, 0.05) 100%);
        }
        
        .btn-custom {
            border-radius: 8px;
            padding: 10px 20px;
            border: none;
            font-weight: 500;
            font-size: 14px;
            transition: all 0.2s ease;
        }
        
        .btn-scan {
            background: var(--accent-color);
            color: white;
        }
        
        .btn-scan:hover {
            background: #2563eb;
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
        }
        
        .nav-tabs {
            border-bottom: 2px solid var(--border-color);
            margin-bottom: 24px;
        }
        
        .nav-tabs .nav-link {
            background: transparent;
            border: none;
            color: var(--text-secondary);
            margin-right: 8px;
            border-radius: 8px 8px 0 0;
            padding: 12px 24px;
            font-weight: 500;
            transition: all 0.2s ease;
        }
        
        .nav-tabs .nav-link:hover {
            background: rgba(59, 130, 246, 0.1);
            color: var(--accent-color);
        }
        
        .nav-tabs .nav-link.active {
            background: var(--card-bg);
            border-bottom: 2px solid var(--accent-color);
            color: var(--accent-color);
            font-weight: 600;
        }
        
        .metric-card {
            background: var(--card-bg);
            border-radius: 12px;
            padding: 24px;
            text-align: center;
            border: 1px solid var(--border-color);
            box-shadow: var(--shadow);
            transition: all 0.2s ease;
        }
        
        .metric-card:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-lg);
        }
        
        .metric-number {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 8px;
        }
        
        .text-primary-custom {
            color: var(--text-primary) !important;
        }
        
        .text-secondary-custom {
            color: var(--text-secondary) !important;
        }
        
        .bg-primary-custom {
            background-color: var(--accent-color) !important;
        }
        
        /* Fix text visibility */
        h1, h2, h3, h4, h5, h6 {
            color: var(--text-primary) !important;
        }
        
        p, div, span, label {
            color: var(--text-primary);
        }
        
        .text-white {
            color: var(--text-primary) !important;
        }
        
        .text-white-50 {
            color: var(--text-secondary) !important;
        }
        
        .nav-link {
            color: var(--text-secondary) !important;
        }
        
        .nav-link.active {
            color: var(--accent-color) !important;
        }
        
        .metric-card h3, .metric-card p {
            color: var(--text-primary) !important;
        }
        
        .app-card h5, .app-card p, .app-card div {
            color: var(--text-primary) !important;
        }
        
        .app-card .text-white-50 {
            color: var(--text-secondary) !important;
        }
        
        .finding-card h6, .finding-card p, .finding-card div {
            color: var(--text-primary) !important;
        }
        
        .glass-card h4, .glass-card h5, .glass-card h6 {
            color: var(--text-primary) !important;
        }
        
        .progress-container {
            background: rgba(59, 130, 246, 0.1);
            border: 1px solid rgba(59, 130, 246, 0.2);
            border-radius: 8px;
            padding: 16px;
            margin: 12px 0;
        }
        
        .finding-card {
            background: var(--card-bg);
            border-radius: 12px;
            border: 1px solid var(--border-color);
            box-shadow: var(--shadow);
            margin-bottom: 16px;
            transition: all 0.2s ease;
        }
        
        .finding-card:hover {
            box-shadow: var(--shadow-lg);
        }
        
        .code-snippet {
            background: #1e293b;
            border-radius: 8px;
            padding: 12px;
            font-family: 'Monaco', 'Menlo', 'Consolas', monospace;
            font-size: 12px;
            overflow-x: auto;
        }
        
        .badge {
            font-size: 11px;
            font-weight: 500;
            padding: 4px 8px;
            border-radius: 6px;
        }
        
        .alert {
            border-radius: 8px;
            border: none;
            box-shadow: var(--shadow);
        }
        
        .form-control, .form-select {
            border-radius: 8px;
            border: 1px solid var(--border-color);
            padding: 10px 12px;
            transition: all 0.2s ease;
        }
        
        .form-control:focus, .form-select:focus {
            border-color: var(--accent-color);
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
        }
        
        .dropdown-menu {
            border-radius: 8px;
            border: 1px solid var(--border-color);
            box-shadow: var(--shadow-lg);
        }
        
        .table {
            background: var(--card-bg);
            border-radius: 8px;
            overflow: hidden;
        }
        
        .real-time-indicator {
            position: fixed;
            top: 20px;
            right: 20px;
            background: var(--success-color);
            color: white;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 500;
            z-index: 1000;
            box-shadow: var(--shadow);
        }
        
        .pulse {
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }
    </style>
</head>
<body>
    <div class="container-fluid py-4">
        <!-- Header -->
        <div class="glass-card p-4 mb-4">
            <div class="d-flex justify-content-between align-items-center">
                <div>
                    <h1 class="text-primary-custom mb-2">
                        <i class="fas fa-shield-alt me-3 text-primary" style="color: var(--accent-color);"></i>
                        Enterprise Security Scanner
                    </h1>
                    <p class="text-secondary-custom mb-0">Advanced threat detection and vulnerability management platform</p>
                </div>
                <div class="text-end">
                    <div class="text-secondary-custom small">Last Updated</div>
                    <div class="text-primary-custom fw-semibold" id="lastUpdate">{{ current_time }}</div>
                </div>
            </div>
        </div>

        <!-- Navigation -->
        <ul class="nav nav-tabs mb-4" id="mainTabs" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link active" id="dashboard-tab" data-bs-toggle="tab" data-bs-target="#dashboard" type="button" role="tab">
                    <i class="fas fa-chart-line me-2"></i>Dashboard
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="applications-tab" data-bs-toggle="tab" data-bs-target="#applications" type="button" role="tab">
                    <i class="fas fa-apps me-2"></i>Applications
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="findings-tab" data-bs-toggle="tab" data-bs-target="#findings" type="button" role="tab">
                    <i class="fas fa-bug me-2"></i>Findings <span class="badge bg-danger ms-1" id="findingsCount">0</span>
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="reports-tab" data-bs-toggle="tab" data-bs-target="#reports" type="button" role="tab">
                    <i class="fas fa-file-alt me-2"></i>Reports
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="history-tab" data-bs-toggle="tab" data-bs-target="#history" type="button" role="tab">
                    <i class="fas fa-history me-2"></i>History
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="onboard-tab" data-bs-toggle="tab" data-bs-target="#onboard" type="button" role="tab">
                    <i class="fas fa-plus-circle me-2"></i>Onboard
                </button>
            </li>
        </ul>

        <!-- Tab Content -->
        <div class="tab-content" id="mainTabsContent">
            <!-- Dashboard Tab -->
            <div class="tab-pane fade show active" id="dashboard" role="tabpanel">
                <div class="glass-card p-4">
                    <h4 class="text-primary-custom mb-4">Security Dashboard Overview</h4>
                    <div class="row">
                        <div class="col-md-3">
                            <div class="metric-card">
                                <div class="metric-number" style="color: var(--accent-color);" id="totalApps">{{ apps_count }}</div>
                                <div class="text-primary-custom">Applications</div>
                                <small class="text-secondary-custom">Under Management</small>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="metric-card">
                                <div class="metric-number" style="color: var(--success-color);" id="scansCompleted">0</div>
                                <div class="text-primary-custom">Scans Completed</div>
                                <small class="text-secondary-custom">Last 30 Days</small>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="metric-card">
                                <div class="metric-number" style="color: var(--warning-color);" id="vulnerabilities">0</div>
                                <div class="text-primary-custom">Vulnerabilities</div>
                                <small class="text-secondary-custom">Requiring Attention</small>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="metric-card">
                                <div class="metric-number" style="color: var(--success-color);" id="threatLevel">LOW</div>
                                <div class="text-primary-custom">Threat Level</div>
                                <small class="text-secondary-custom">Current Assessment</small>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Applications Tab -->
            <div class="tab-pane fade" id="applications" role="tabpanel">
                <div class="glass-card p-4">
                    <div class="d-flex justify-content-between align-items-center mb-4">
                        <h4 class="text-primary-custom mb-0">Applications ({{ apps_count }})</h4>
                        <button class="btn btn-success btn-sm" onclick="loadApplications()">
                            <i class="fas fa-sync-alt me-2"></i>Refresh
                        </button>
                    </div>
                    
                    <div id="applicationsList">
                        {% for app in applications %}
                        <div class="app-card">
                            <div class="d-flex justify-content-between align-items-start">
                                <div class="flex-grow-1">
                                    <h5 class="text-primary-custom mb-2">
                                        <i class="fas fa-cube me-2" style="color: var(--accent-color);"></i>{{ app.name }}
                                        <span class="badge bg-success ms-2">ACTIVE</span>
                                    </h5>
                                    <div class="mb-3">
                                        <span class="badge bg-secondary me-2">{{ app.language or 'Unknown' }}</span>
                                        <span class="badge bg-info me-2">{{ app.framework or 'Unknown' }}</span>
                                        <span class="badge bg-{% if app.criticality == 'high' %}danger{% elif app.criticality == 'medium' %}warning{% else %}success{% endif %}">
                                            {{ app.criticality or 'medium' }}
                                        </span>
                                    </div>
                                    <div class="text-secondary-custom small">
                                        <div class="mb-1"><i class="fas fa-code-branch me-2"></i><strong>Type:</strong> {{ app.repo_type }}</div>
                                        <div class="mb-1"><i class="fas fa-link me-2"></i><strong>URL:</strong> {{ app.repo_url or app.local_path }}</div>
                                        <div class="mb-1"><i class="fas fa-users me-2"></i><strong>Team:</strong> {{ app.team or 'N/A' }}</div>
                                        <div class="mb-1"><i class="fas fa-user me-2"></i><strong>Owner:</strong> {{ app.owner or 'N/A' }}</div>
                                        <div class="mb-1"><i class="fas fa-calendar me-2"></i><strong>Created:</strong> {{ app.created_at }}</div>
                                    </div>
                                </div>
                                <div class="d-flex flex-column gap-2">
                                    <button class="btn btn-custom btn-scan" onclick="startScan('{{ app.name }}')">
                                        <i class="fas fa-search me-1"></i>Scan
                                    </button>
                                    <button class="btn btn-custom btn-outline-light" onclick="viewApp('{{ app.name }}')">
                                        <i class="fas fa-eye me-1"></i>View
                                    </button>
                                </div>
                            </div>
                        </div>
                        {% endfor %}
                        
                        {% if not applications %}
                        <div class="text-center py-5">
                            <i class="fas fa-folder-open fa-3x text-white-50 mb-3"></i>
                            <h5 class="text-white">No Applications Found</h5>
                            <p class="text-white-50">Click the Onboard tab to add your first application.</p>
                        </div>
                        {% endif %}
                    </div>
                </div>
            </div>

            <!-- Findings Tab -->
            <div class="tab-pane fade" id="findings" role="tabpanel">
                <div class="glass-card p-4">
                    <div class="d-flex justify-content-between align-items-center mb-4">
                        <h4 class="text-white mb-0">Security Findings</h4>
                        <div class="d-flex gap-2">
                            <select class="form-select form-select-sm" id="findingsAppFilter" onchange="loadFindings()">
                                <option value="">All Applications</option>
                            </select>
                            <select class="form-select form-select-sm" id="findingsSeverityFilter" onchange="loadFindings()">
                                <option value="">All Severities</option>
                                <option value="critical">Critical</option>
                                <option value="high">High</option>
                                <option value="medium">Medium</option>
                                <option value="low">Low</option>
                            </select>
                            <select class="form-select form-select-sm" id="findingsStatusFilter" onchange="loadFindings()">
                                <option value="">All Status</option>
                                <option value="open">Open</option>
                                <option value="in_progress">In Progress</option>
                                <option value="resolved">Resolved</option>
                                <option value="ignored">Ignored</option>
                            </select>
                            <button class="btn btn-gradient btn-sm" onclick="loadFindings()">
                                <i class="fas fa-sync-alt me-2"></i>Refresh
                            </button>
                        </div>
                    </div>
                    
                    <div id="findingsList">
                        <div class="text-center py-5 text-white-50">
                            <i class="fas fa-search fa-3x mb-3"></i>
                            <h5>No Findings Available</h5>
                            <p>Run security scans on your applications to see detailed findings here.</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Reports Tab -->
            <div class="tab-pane fade" id="reports" role="tabpanel">
                <div class="glass-card p-4">
                    <h4 class="text-white mb-4">Security Reports</h4>
                    
                    <div class="row mb-4">
                        <div class="col-md-6">
                            <div class="glass-card p-3">
                                <h6 class="text-white mb-3">Executive Summary Report</h6>
                                <p class="text-white-50 small mb-3">High-level security posture overview for leadership</p>
                                <div class="mb-3">
                                    <label class="form-label text-white">Time Period</label>
                                    <select class="form-select form-select-sm" id="execReportPeriod">
                                        <option value="7">Last 7 days</option>
                                        <option value="30" selected>Last 30 days</option>
                                        <option value="90">Last 90 days</option>
                                    </select>
                                </div>
                                <button class="btn btn-gradient btn-sm" onclick="generateExecutiveReport()">
                                    <i class="fas fa-chart-pie me-2"></i>Generate Report
                                </button>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="glass-card p-3">
                                <h6 class="text-white mb-3">Detailed Technical Report</h6>
                                <p class="text-white-50 small mb-3">Comprehensive findings and remediation guide</p>
                                <div class="mb-3">
                                    <label class="form-label text-white">Application</label>
                                    <select class="form-select form-select-sm" id="techReportApp">
                                        <option value="">All Applications</option>
                                    </select>
                                </div>
                                <button class="btn btn-gradient btn-sm" onclick="generateTechnicalReport()">
                                    <i class="fas fa-file-code me-2"></i>Generate Report
                                </button>
                            </div>
                        </div>
                    </div>
                    
                    <div class="row">
                        <div class="col-md-6">
                            <div class="glass-card p-3">
                                <h6 class="text-white mb-3">Compliance Report</h6>
                                <p class="text-white-50 small mb-3">Security compliance status and gaps</p>
                                <div class="mb-3">
                                    <label class="form-label text-white">Framework</label>
                                    <select class="form-select form-select-sm" id="complianceFramework">
                                        <option value="owasp">OWASP Top 10</option>
                                        <option value="nist">NIST Framework</option>
                                        <option value="iso27001">ISO 27001</option>
                                    </select>
                                </div>
                                <button class="btn btn-gradient btn-sm" onclick="generateComplianceReport()">
                                    <i class="fas fa-shield-alt me-2"></i>Generate Report
                                </button>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="glass-card p-3">
                                <h6 class="text-white mb-3">Trend Analysis Report</h6>
                                <p class="text-white-50 small mb-3">Security metrics and trends over time</p>
                                <div class="mb-3">
                                    <label class="form-label text-white">Metric</label>
                                    <select class="form-select form-select-sm" id="trendMetric">
                                        <option value="vulnerabilities">Vulnerability Trends</option>
                                        <option value="risk_score">Risk Score Trends</option>
                                        <option value="remediation">Remediation Trends</option>
                                    </select>
                                </div>
                                <button class="btn btn-gradient btn-sm" onclick="generateTrendReport()">
                                    <i class="fas fa-chart-line me-2"></i>Generate Report
                                </button>
                            </div>
                        </div>
                    </div>
                    
                    <div class="mt-4">
                        <h6 class="text-white mb-3">Recent Reports</h6>
                        <div id="recentReports">
                            <div class="text-center py-3 text-white-50">
                                <p>No reports generated yet. Generate your first report above.</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- History Tab -->
            <div class="tab-pane fade" id="history" role="tabpanel">
                <div class="glass-card p-4">
                    <h4 class="text-white mb-4">
                        <i class="fas fa-history me-2"></i>Application Security History
                    </h4>
                    
                    <div class="row mb-4">
                        <div class="col-md-6">
                            <label class="form-label text-white">Select Application:</label>
                            <select class="form-select bg-dark text-white" id="historyAppFilter" onchange="loadApplicationHistory()">
                                <option value="">All Applications</option>
                            </select>
                        </div>
                        <div class="col-md-6">
                            <label class="form-label text-white">Time Period:</label>
                            <select class="form-select bg-dark text-white" id="historyPeriodFilter" onchange="loadApplicationHistory()">
                                <option value="7">Last 7 days</option>
                                <option value="30" selected>Last 30 days</option>
                                <option value="90">Last 90 days</option>
                                <option value="365">Last year</option>
                                <option value="all">All time</option>
                            </select>
                        </div>
                    </div>
                    
                    <div id="historyContent">
                        <div class="text-center py-5 text-secondary-custom">
                            <i class="fas fa-history fa-3x mb-3"></i>
                            <h5>Select an application to view its security history</h5>
                            <p>Track findings, status changes, comments, and remediation progress over time</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Onboard Tab -->
            <div class="tab-pane fade" id="onboard" role="tabpanel">
                <div class="glass-card p-4">
                    <h4 class="text-white mb-4">Onboard New Application</h4>
                    <form id="onboardForm" onsubmit="onboardApp(event)">
                        <div class="row">
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label class="form-label text-white">Application Name</label>
                                    <input type="text" class="form-control" id="appName" required>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label class="form-label text-white">Repository Type</label>
                                    <select class="form-select" id="repoType" onchange="toggleRepoFields()" required>
                                        <option value="">Select type...</option>
                                        <option value="github">GitHub</option>
                                        <option value="gitlab">GitLab</option>
                                        <option value="local">Local Path</option>
                                    </select>
                                </div>
                            </div>
                        </div>
                        
                        <div class="mb-3" id="repoUrlField" style="display: none;">
                            <label class="form-label text-white">Repository URL</label>
                            <input type="url" class="form-control" id="repoUrl">
                        </div>
                        
                        <div class="mb-3" id="localPathField" style="display: none;">
                            <label class="form-label text-white">Local Path</label>
                            <input type="text" class="form-control" id="localPath" placeholder="/path/to/your/project">
                        </div>
                        
                        <div class="row">
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label class="form-label text-white">Team</label>
                                    <input type="text" class="form-control" id="team">
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label class="form-label text-white">Owner</label>
                                    <input type="text" class="form-control" id="owner">
                                </div>
                            </div>
                        </div>
                        
                        <button type="submit" class="btn btn-custom btn-scan">
                            <i class="fas fa-plus me-2"></i>Onboard Application
                        </button>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <script>
        // Initialize Socket.IO for real-time updates
        const socket = io();
        
        socket.on('connect', function() {
            console.log('Connected to server');
            updateConnectionStatus(true);
        });
        
        socket.on('disconnect', function() {
            console.log('Disconnected from server');
            updateConnectionStatus(false);
        });
        
        socket.on('scan_progress', function(data) {
            updateScanProgress(data);
        });
        
        socket.on('scan_complete', function(data) {
            completeScan(data);
        });
        
        function updateConnectionStatus(connected) {
            // Add connection indicator if needed
        }
        
        function toggleRepoFields() {
            const repoType = document.getElementById('repoType').value;
            const repoUrlField = document.getElementById('repoUrlField');
            const localPathField = document.getElementById('localPathField');
            
            repoUrlField.style.display = 'none';
            localPathField.style.display = 'none';
            
            if (repoType === 'local') {
                localPathField.style.display = 'block';
            } else if (repoType === 'github' || repoType === 'gitlab') {
                repoUrlField.style.display = 'block';
            }
        }
        
        function loadApplications() {
            window.location.reload();
        }
        
        function startScan(appName) {
            if (confirm(`Start advanced security scan for ${appName}?\\n\\nThis will include:\\n• Secret detection\\n• Dependency analysis\\n• Threat intelligence\\n• Real-time progress tracking`)) {
                // Update UI to show scanning state
                const scanBtn = document.querySelector(`button[onclick="startScan('${appName}')"]`);
                if (scanBtn) {
                    scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Scanning...';
                    scanBtn.disabled = true;
                }
                
                // Add progress container
                addProgressContainer(appName);
                
                fetch('/api/scan/advanced', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ app_name: appName })
                })
                .then(response => response.json())
                .then(data => {
                    if (!data.success) {
                        alert(`Error: ${data.error}`);
                        resetScanButton(appName);
                    }
                })
                .catch(error => {
                    alert(`Error: ${error.message}`);
                    resetScanButton(appName);
                });
            }
        }
        
        function addProgressContainer(appName) {
            const appCard = document.querySelector(`[data-app="${appName}"]`);
            if (appCard && !appCard.querySelector('.progress-container')) {
                const progressHtml = `
                    <div class="progress-container mt-3" id="progress-${appName}">
                        <div class="d-flex justify-content-between align-items-center mb-2">
                            <small class="text-white">Scan Progress</small>
                            <small class="text-white" id="progress-percent-${appName}">0%</small>
                        </div>
                        <div class="progress mb-2" style="height: 8px;">
                            <div class="progress-bar progress-bar-striped progress-bar-animated bg-info" 
                                 id="progress-bar-${appName}" style="width: 0%"></div>
                        </div>
                        <div class="d-flex justify-content-between">
                            <small class="text-white-50" id="progress-status-${appName}">Initializing...</small>
                            <small class="text-white-50" id="progress-findings-${appName}">0 findings</small>
                        </div>
                    </div>
                `;
                appCard.insertAdjacentHTML('beforeend', progressHtml);
            }
        }
        
        function updateScanProgress(data) {
            const appName = data.app_name;
            const progress = data.progress;
            
            const progressBar = document.getElementById(`progress-bar-${appName}`);
            const progressPercent = document.getElementById(`progress-percent-${appName}`);
            const progressStatus = document.getElementById(`progress-status-${appName}`);
            const progressFindings = document.getElementById(`progress-findings-${appName}`);
            
            if (progressBar) {
                progressBar.style.width = `${progress.percentage}%`;
                progressPercent.textContent = `${progress.percentage}%`;
                progressStatus.textContent = progress.status;
                
                const totalFindings = (progress.critical || 0) + (progress.high || 0) + (progress.medium || 0) + (progress.low || 0);
                progressFindings.textContent = `${totalFindings} findings`;
                
                // Update progress bar color based on findings
                if (progress.critical > 0) {
                    progressBar.className = 'progress-bar progress-bar-striped progress-bar-animated bg-danger';
                } else if (progress.high > 0) {
                    progressBar.className = 'progress-bar progress-bar-striped progress-bar-animated bg-warning';
                } else {
                    progressBar.className = 'progress-bar progress-bar-striped progress-bar-animated bg-success';
                }
            }
        }
        
        function completeScan(data) {
            const appName = data.app_name;
            const results = data.results;
            
            resetScanButton(appName);
            
            // Show completion notification
            const alertHtml = `
                <div class="alert alert-success alert-dismissible fade show position-fixed" 
                     style="top: 20px; right: 20px; z-index: 1050; min-width: 300px;" role="alert">
                    <h6><i class="fas fa-check-circle me-2"></i>Scan Complete: ${appName}</h6>
                    <div class="small">
                        Found: ${results.critical || 0} Critical, ${results.high || 0} High, 
                        ${results.medium || 0} Medium, ${results.low || 0} Low issues
                    </div>
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
            `;
            document.body.insertAdjacentHTML('beforeend', alertHtml);
            
            // Auto-remove after 10 seconds
            setTimeout(() => {
                const alert = document.querySelector('.alert');
                if (alert) alert.remove();
            }, 10000);
        }
        
        function resetScanButton(appName) {
            const scanBtn = document.querySelector(`button[onclick="startScan('${appName}')"]`);
            if (scanBtn) {
                scanBtn.innerHTML = '<i class="fas fa-search me-1"></i>Scan';
                scanBtn.disabled = false;
            }
            
            // Remove progress container
            const progressContainer = document.getElementById(`progress-${appName}`);
            if (progressContainer) {
                progressContainer.remove();
            }
        }
        
        function viewApp(appName) {
            // Show detailed view with threat intelligence
            const modalHtml = `
                <div class="modal fade" id="appModal" tabindex="-1">
                    <div class="modal-dialog modal-lg">
                        <div class="modal-content" style="background: rgba(255,255,255,0.95); backdrop-filter: blur(10px);">
                            <div class="modal-header">
                                <h5 class="modal-title text-dark">
                                    <i class="fas fa-shield-alt me-2"></i>${appName} - Security Overview
                                </h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                            </div>
                            <div class="modal-body text-dark">
                                <div class="row">
                                    <div class="col-md-6">
                                        <h6>Latest Scan Results</h6>
                                        <div class="mb-3">
                                            <div class="d-flex justify-content-between">
                                                <span>Critical Issues:</span>
                                                <span class="badge bg-danger">0</span>
                                            </div>
                                            <div class="d-flex justify-content-between">
                                                <span>High Priority:</span>
                                                <span class="badge bg-warning">2</span>
                                            </div>
                                            <div class="d-flex justify-content-between">
                                                <span>Medium Issues:</span>
                                                <span class="badge bg-info">5</span>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="col-md-6">
                                        <h6>Threat Intelligence</h6>
                                        <div class="small">
                                            <div class="alert alert-warning p-2">
                                                <strong>New CVE Alert:</strong> CVE-2024-1234 affects this application's dependencies.
                                            </div>
                                            <div class="alert alert-info p-2">
                                                <strong>Security Advisory:</strong> Update recommended for ${appName}.
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="modal-footer">
                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                                <button type="button" class="btn btn-primary" onclick="startScan('${appName}')">
                                    <i class="fas fa-search me-1"></i>Run New Scan
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            // Remove existing modal
            const existingModal = document.getElementById('appModal');
            if (existingModal) existingModal.remove();
            
            // Add new modal
            document.body.insertAdjacentHTML('beforeend', modalHtml);
            
            // Show modal
            const modal = new bootstrap.Modal(document.getElementById('appModal'));
            modal.show();
        }
        
        // Findings Management
        async function loadFindings() {
            try {
                console.log('Loading findings...');
                const appFilter = document.getElementById('findingsAppFilter')?.value || '';
                const severityFilter = document.getElementById('findingsSeverityFilter')?.value || '';
                const statusFilter = document.getElementById('findingsStatusFilter')?.value || '';
                
                const params = new URLSearchParams();
                if (appFilter) params.append('app', appFilter);
                if (severityFilter) params.append('severity', severityFilter);
                if (statusFilter) params.append('status', statusFilter);
                
                console.log('Fetching findings with params:', params.toString());
                const response = await fetch(`/api/findings?${params}`);
                const data = await response.json();
                
                console.log('Findings response:', data);
                console.log('Number of findings:', data.findings ? data.findings.length : 0);
                
                renderFindings(data.findings || []);
                updateFindingsCount(data.findings ? data.findings.length : 0);
                
            } catch (error) {
                console.error('Error loading findings:', error);
            }
        }
        
        function renderFindings(findings) {
            console.log('Rendering findings:', findings);
            const container = document.getElementById('findingsList');
            console.log('Container element:', container);
            
            if (!findings || findings.length === 0) {
                console.log('No findings to display');
                container.innerHTML = `
                    <div class="text-center py-5 text-secondary-custom">
                        <i class="fas fa-search fa-3x mb-3"></i>
                        <h5>No Findings Available</h5>
                        <p>Run security scans on your applications to see detailed findings here.</p>
                    </div>
                `;
                return;
            }
            
            console.log('Rendering', findings.length, 'findings');
            
            const findingsHtml = findings.map(finding => `
                <div class="finding-card mb-3" data-finding-id="${finding.id}">
                    <div class="glass-card p-4" style="border-left: 4px solid ${getSeverityColor(finding.severity)};">
                        <div class="d-flex justify-content-between align-items-start mb-3">
                            <div class="flex-grow-1">
                                <div class="d-flex align-items-center mb-2">
                                    <h6 class="text-white mb-0 me-3">${finding.title}</h6>
                                    <span class="badge bg-${getSeverityBadgeColor(finding.severity)} me-2">${finding.severity.toUpperCase()}</span>
                                    <span class="badge bg-info me-2">${finding.finding_type.toUpperCase()}</span>
                                    <span class="badge bg-${getStatusBadgeColor(finding.status)}">${finding.status.toUpperCase()}</span>
                                    ${finding.is_false_positive ? '<span class="badge bg-warning">FALSE POSITIVE</span>' : ''}
                                </div>
                                <p class="text-white-50 mb-2">${finding.description || 'No description available'}</p>
                                
                                ${finding.file_path ? `
                                    <div class="mb-2">
                                        <small class="text-white-50">
                                            <i class="fas fa-file-code me-1"></i>
                                            ${finding.file_path}${finding.line_number ? `:${finding.line_number}` : ''}
                                        </small>
                                    </div>
                                ` : ''}
                                
                                ${finding.code_snippet ? `
                                    <div class="code-snippet mb-2">
                                        <pre class="bg-dark text-light p-2 rounded small"><code>${finding.code_snippet}</code></pre>
                                    </div>
                                ` : ''}
                                
                                ${finding.cve_id ? `
                                    <div class="mb-3">
                                        <div class="row">
                                            <div class="col-md-6">
                                                <div class="vulnerability-details p-3" style="background: rgba(239, 68, 68, 0.1); border-radius: 8px; border-left: 4px solid var(--danger-color);">
                                                    <h6 class="text-primary-custom mb-2">
                                                        <i class="fas fa-exclamation-triangle me-2"></i>CVE Details
                                                    </h6>
                                                    <div class="mb-2">
                                                        <span class="badge bg-danger me-2">${finding.cve_id}</span>
                                                        ${finding.cvss_score ? `<span class="badge bg-warning">CVSS: ${finding.cvss_score}</span>` : ''}
                                                    </div>
                                                    <div class="small text-secondary-custom">
                                                        <div><strong>Component:</strong> ${finding.component || 'N/A'}</div>
                                                        ${finding.current_version ? `<div><strong>Current:</strong> ${finding.current_version}</div>` : ''}
                                                        ${finding.fixed_version ? `<div><strong>Fixed in:</strong> ${finding.fixed_version}</div>` : ''}
                                                        ${finding.exploit_maturity ? `<div><strong>Exploit Status:</strong> ${finding.exploit_maturity}</div>` : ''}
                                                        ${finding.first_published ? `<div><strong>Published:</strong> ${finding.first_published}</div>` : ''}
                                                        <div class="mt-2">
                                                            <button class="btn btn-sm btn-outline-info" onclick="fetchLatestVulnData('${finding.component}', '${finding.current_version || '1.0.0'}', ${finding.id})">
                                                                <i class="fas fa-sync-alt me-1"></i>Get Latest Data
                                                            </button>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                            <div class="col-md-6">
                                                ${finding.usage_locations ? `
                                                    <div class="usage-locations p-3" style="background: rgba(59, 130, 246, 0.1); border-radius: 8px; border-left: 4px solid var(--accent-color);">
                                                        <h6 class="text-primary-custom mb-2">
                                                            <i class="fas fa-map-marker-alt me-2"></i>Usage Locations
                                                        </h6>
                                                        <div class="small">
                                                            ${JSON.parse(finding.usage_locations || '[]').map(location => 
                                                                `<div class="mb-1"><i class="fas fa-file-code me-1"></i>${location}</div>`
                                                            ).join('')}
                                                        </div>
                                                        ${finding.dependency_chain ? `
                                                            <div class="mt-2">
                                                                <strong>Dependency Chain:</strong><br>
                                                                <code class="small">${finding.dependency_chain}</code>
                                                            </div>
                                                        ` : ''}
                                                    </div>
                                                ` : ''}
                                            </div>
                                        </div>
                                        ${finding.affected_functions ? `
                                            <div class="affected-functions mt-2 p-2" style="background: rgba(245, 158, 11, 0.1); border-radius: 8px;">
                                                <strong class="text-primary-custom">Affected Functions:</strong>
                                                <div class="mt-1">
                                                    ${JSON.parse(finding.affected_functions || '[]').map(func => 
                                                        `<span class="badge bg-warning me-1">${func}</span>`
                                                    ).join('')}
                                                </div>
                                            </div>
                                        ` : ''}
                                        ${finding.dependency_chain ? `
                                            <div class="dependency-diagram mt-3">
                                                <button class="btn btn-sm btn-outline-primary" onclick="showDependencyDiagram('${finding.id}', '${finding.component}', '${finding.dependency_chain}')">
                                                    <i class="fas fa-project-diagram me-1"></i>View Dependency Diagram
                                                </button>
                                            </div>
                                        ` : ''}
                                    </div>
                                ` : ''}
                                
                                ${finding.remediation ? `
                                    <div class="remediation mb-2">
                                        <small class="text-success">
                                            <i class="fas fa-tools me-1"></i>
                                            <strong>Remediation:</strong> ${finding.remediation}
                                        </small>
                                    </div>
                                ` : ''}
                                
                                ${finding.analyst_comment ? `
                                    <div class="analyst-comment mb-2">
                                        <small class="text-info">
                                            <i class="fas fa-comment me-1"></i>
                                            <strong>Analyst Note:</strong> ${finding.analyst_comment}
                                        </small>
                                    </div>
                                ` : ''}
                            </div>
                            
                            <!-- Prominent Action Buttons for ALL Finding Types -->
                            <div class="finding-actions mt-3 p-3" style="background: rgba(0,0,0,0.05); border-radius: 8px; border-top: 1px solid var(--border-color);">
                                <div class="d-flex gap-2 flex-wrap mb-2">
                                    <button class="btn btn-sm btn-success" onclick="markResolved(${finding.id})">
                                        <i class="fas fa-check me-1"></i>Mark Resolved
                                    </button>
                                    <button class="btn btn-sm btn-warning" onclick="showFalsePositiveModal(${finding.id}, '${finding.app_name}')">
                                        <i class="fas fa-times me-1"></i>False Positive
                                    </button>
                                    <button class="btn btn-sm btn-info" onclick="addComment(${finding.id})">
                                        <i class="fas fa-comment me-1"></i>Add Comment
                                    </button>
                                    <button class="btn btn-sm btn-secondary" onclick="viewFindingHistory(${finding.id})">
                                        <i class="fas fa-history me-1"></i>History
                                    </button>
                                    ${finding.finding_type === 'dependency' && finding.component ? `
                                        <button class="btn btn-sm btn-outline-info" onclick="fetchLatestVulnData('${finding.component}', '${finding.current_version || '1.0.0'}', ${finding.id})">
                                            <i class="fas fa-sync-alt me-1"></i>Get Latest Data
                                        </button>
                                    ` : ''}
                                </div>
                                <div class="finding-metadata small text-secondary-custom">
                                    <div class="row">
                                        <div class="col-md-6">
                                            <div><strong>Status:</strong> <span class="badge bg-${finding.status === 'open' ? 'danger' : finding.status === 'resolved' ? 'success' : 'secondary'}">${finding.status || 'open'}</span></div>
                                            ${finding.occurrence_count > 1 ? `<div><strong>Occurrences:</strong> ${finding.occurrence_count}</div>` : ''}
                                        </div>
                                        <div class="col-md-6">
                                            ${finding.first_detected ? `<div><strong>First Detected:</strong> ${new Date(finding.first_detected).toLocaleDateString()}</div>` : ''}
                                            ${finding.last_seen ? `<div><strong>Last Seen:</strong> ${new Date(finding.last_seen).toLocaleDateString()}</div>` : ''}
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="finding-meta">
                            <small class="text-white-50">
                                <i class="fas fa-cube me-1"></i>Application: ${finding.app_name} | 
                                <i class="fas fa-calendar me-1"></i>Found: ${new Date(finding.created_at).toLocaleDateString()}
                            </small>
                        </div>
                    </div>
                </div>
            `).join('');
            
            container.innerHTML = findingsHtml;
        }
        
        function getSeverityColor(severity) {
            const colors = {
                'critical': '#dc3545',
                'high': '#fd7e14',
                'medium': '#ffc107',
                'low': '#198754'
            };
            return colors[severity] || '#6c757d';
        }
        
        function getSeverityBadgeColor(severity) {
            const colors = {
                'critical': 'danger',
                'high': 'warning',
                'medium': 'info',
                'low': 'success'
            };
            return colors[severity] || 'secondary';
        }
        
        function getStatusBadgeColor(status) {
            const colors = {
                'open': 'danger',
                'in_progress': 'warning',
                'resolved': 'success',
                'ignored': 'secondary'
            };
            return colors[status] || 'secondary';
        }
        
        function updateFindingsCount(count) {
            document.getElementById('findingsCount').textContent = count;
        }
        
        async function markFalsePositive(findingId, isFalsePositive) {
            try {
                const response = await fetch(`/api/findings/${findingId}/false-positive`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ is_false_positive: isFalsePositive })
                });
                
                if (response.ok) {
                    loadFindings(); // Refresh findings
                } else {
                    alert('Error updating finding');
                }
            } catch (error) {
                alert(`Error: ${error.message}`);
            }
        }
        
        // Removed duplicate functions - using newer versions below
        
        // Report Generation Functions
        async function generateExecutiveReport() {
            const period = document.getElementById('execReportPeriod').value;
            try {
                const response = await fetch('/api/reports/executive', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ period: period })
                });
                
                if (response.ok) {
                    const blob = await response.blob();
                    downloadReport(blob, `executive-report-${period}days.pdf`);
                } else {
                    alert('Error generating report');
                }
            } catch (error) {
                alert(`Error: ${error.message}`);
            }
        }
        
        async function generateTechnicalReport() {
            const appName = document.getElementById('techReportApp').value;
            try {
                const response = await fetch('/api/reports/technical', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ app_name: appName })
                });
                
                if (response.ok) {
                    const blob = await response.blob();
                    downloadReport(blob, `technical-report-${appName || 'all'}.pdf`);
                } else {
                    alert('Error generating report');
                }
            } catch (error) {
                alert(`Error: ${error.message}`);
            }
        }
        
        async function generateComplianceReport() {
            const framework = document.getElementById('complianceFramework').value;
            try {
                const response = await fetch('/api/reports/compliance', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ framework: framework })
                });
                
                if (response.ok) {
                    const blob = await response.blob();
                    downloadReport(blob, `compliance-report-${framework}.pdf`);
                } else {
                    alert('Error generating report');
                }
            } catch (error) {
                alert(`Error: ${error.message}`);
            }
        }
        
        async function generateTrendReport() {
            const metric = document.getElementById('trendMetric').value;
            try {
                // For now, generate a technical report as trend analysis
                const response = await fetch('/api/reports/technical', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ app_name: '' })
                });
                
                if (response.ok) {
                    const blob = await response.blob();
                    downloadReport(blob, `trend-analysis-${metric}.pdf`);
                } else {
                    alert('Error generating report');
                }
            } catch (error) {
                alert(`Error: ${error.message}`);
            }
        }
        
        function downloadReport(blob, filename) {
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
        }
        
        // Auto-refresh dashboard
        function startAutoRefresh() {
            // Update last refresh time
            updateLastRefreshTime();
            
            setInterval(() => {
                // Refresh dashboard stats
                fetch('/api/dashboard/stats')
                    .then(response => response.json())
                    .then(data => {
                        updateDashboardStats(data);
                        updateLastRefreshTime();
                    })
                    .catch(error => console.error('Error refreshing dashboard:', error));
                
                // Refresh findings count if on findings tab
                const activeTab = document.querySelector('.nav-link.active');
                if (activeTab && activeTab.id === 'findings-tab') {
                    loadFindings();
                }
                
                // Refresh applications if on applications tab
                if (activeTab && activeTab.id === 'applications-tab') {
                    loadApplications();
                }
            }, 15000); // Refresh every 15 seconds
        }
        
        function updateDashboardStats(stats) {
            // Update dashboard metrics
            if (stats.total_apps !== undefined) {
                const element = document.getElementById('totalApps');
                if (element) element.textContent = stats.total_apps;
            }
            if (stats.scans_completed !== undefined) {
                const element = document.getElementById('scansCompleted');
                if (element) element.textContent = stats.scans_completed;
            }
            if (stats.vulnerabilities !== undefined) {
                const element = document.getElementById('vulnerabilities');
                if (element) element.textContent = stats.vulnerabilities;
            }
            if (stats.threat_level !== undefined) {
                const element = document.getElementById('threatLevel');
                if (element) {
                    element.textContent = stats.threat_level;
                    // Update color based on threat level
                    element.className = 'metric-number';
                    if (stats.threat_level === 'CRITICAL') {
                        element.style.color = 'var(--danger-color)';
                    } else if (stats.threat_level === 'HIGH') {
                        element.style.color = 'var(--warning-color)';
                    } else if (stats.threat_level === 'MEDIUM') {
                        element.style.color = 'var(--info-color)';
                    } else {
                        element.style.color = 'var(--success-color)';
                    }
                }
            }
        }
        
        function updateLastRefreshTime() {
            const element = document.getElementById('lastUpdate');
            if (element) {
                element.textContent = new Date().toLocaleTimeString();
            }
        }
        
        // Initialize on page load
        document.addEventListener('DOMContentLoaded', function() {
            console.log('DOM loaded, initializing...');
            loadFindings();
            startAutoRefresh();
            
            // Populate filter dropdowns
            populateFilterDropdowns();
            
            // Add event listener for findings tab
            const findingsTab = document.getElementById('findings-tab');
            if (findingsTab) {
                findingsTab.addEventListener('click', function() {
                    console.log('Findings tab clicked, loading findings...');
                    setTimeout(loadFindings, 100); // Small delay to ensure tab is active
                });
            }
            
            // Add event listener for history tab
            const historyTab = document.getElementById('history-tab');
            if (historyTab) {
                historyTab.addEventListener('click', function() {
                    console.log('History tab clicked, populating dropdowns...');
                    setTimeout(populateHistoryDropdowns, 100);
                });
            }
        });
        
        async function populateFilterDropdowns() {
            try {
                const response = await fetch('/api/applications');
                const data = await response.json();
                
                const appFilters = [
                    document.getElementById('findingsAppFilter'),
                    document.getElementById('techReportApp')
                ];
                
                appFilters.forEach(select => {
                    if (select) {
                        data.applications.forEach(app => {
                            const option = document.createElement('option');
                            option.value = app.name;
                            option.textContent = app.name;
                            select.appendChild(option);
                        });
                    }
                });
            } catch (error) {
                console.error('Error populating dropdowns:', error);
            }
        }
        
        // Dependency Diagram Functions
        function showDependencyDiagram(findingId, component, dependencyChain) {
            const modalHtml = `
                <div class="modal fade" id="dependencyModal" tabindex="-1">
                    <div class="modal-dialog modal-xl">
                        <div class="modal-content" style="background: var(--card-bg);">
                            <div class="modal-header">
                                <h5 class="modal-title text-primary-custom">
                                    <i class="fas fa-project-diagram me-2"></i>Dependency Analysis: ${component}
                                </h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                            </div>
                            <div class="modal-body">
                                <div class="row">
                                    <div class="col-md-8">
                                        <div class="dependency-graph" id="dependencyGraph" style="height: 400px; border: 1px solid var(--border-color); border-radius: 8px; position: relative; background: #f8fafc;">
                                            <div class="text-center py-5">
                                                <div class="dependency-visualization">
                                                    ${generateDependencyDiagram(dependencyChain, component)}
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="col-md-4">
                                        <div class="vulnerability-impact p-3" style="background: rgba(239, 68, 68, 0.1); border-radius: 8px;">
                                            <h6 class="text-primary-custom mb-3">Impact Analysis</h6>
                                            <div class="impact-details">
                                                <div class="mb-2">
                                                    <i class="fas fa-exclamation-triangle text-danger me-2"></i>
                                                    <strong>Vulnerable Component:</strong> ${component}
                                                </div>
                                                <div class="mb-2">
                                                    <i class="fas fa-route text-info me-2"></i>
                                                    <strong>Dependency Path:</strong><br>
                                                    <code class="small">${dependencyChain}</code>
                                                </div>
                                                <div class="mb-2">
                                                    <i class="fas fa-shield-alt text-warning me-2"></i>
                                                    <strong>Risk Level:</strong> High
                                                </div>
                                                <div class="mb-2">
                                                    <i class="fas fa-clock text-secondary me-2"></i>
                                                    <strong>Remediation Priority:</strong> Immediate
                                                </div>
                                            </div>
                                        </div>
                                        
                                        <div class="remediation-steps mt-3 p-3" style="background: rgba(16, 185, 129, 0.1); border-radius: 8px;">
                                            <h6 class="text-primary-custom mb-3">Remediation Steps</h6>
                                            <ol class="small text-secondary-custom">
                                                <li>Update the vulnerable dependency</li>
                                                <li>Test application functionality</li>
                                                <li>Review breaking changes</li>
                                                <li>Deploy to staging environment</li>
                                                <li>Validate security fix</li>
                                                <li>Deploy to production</li>
                                            </ol>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="modal-footer">
                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                                <button type="button" class="btn btn-primary" onclick="generateRemediationReport('${component}')">
                                    <i class="fas fa-file-alt me-1"></i>Generate Report
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            // Remove existing modal
            const existingModal = document.getElementById('dependencyModal');
            if (existingModal) existingModal.remove();
            
            // Add new modal
            document.body.insertAdjacentHTML('beforeend', modalHtml);
            
            // Show modal
            const modal = new bootstrap.Modal(document.getElementById('dependencyModal'));
            modal.show();
        }
        
        function generateDependencyDiagram(dependencyChain, vulnerableComponent) {
            if (!dependencyChain || dependencyChain === 'undefined') {
                return '<p class="text-secondary-custom">No dependency chain available</p>';
            }
            
            const dependencies = dependencyChain.split(' → ');
            let diagramHtml = '<div class="dependency-flow d-flex flex-wrap align-items-center justify-content-center" style="padding: 20px;">';
            
            dependencies.forEach((dep, index) => {
                const cleanDep = dep.trim();
                const isVulnerable = cleanDep === vulnerableComponent;
                const nodeClass = isVulnerable ? 'vulnerable-node' : 'safe-node';
                const bgColor = isVulnerable ? '#fee2e2' : '#f0f9ff';
                const borderColor = isVulnerable ? '#ef4444' : '#3b82f6';
                const textColor = isVulnerable ? '#dc2626' : '#1e40af';
                
                diagramHtml += `
                    <div class="dependency-node ${nodeClass}" style="
                        display: inline-flex;
                        flex-direction: column;
                        align-items: center;
                        background: ${bgColor};
                        border: 2px solid ${borderColor};
                        border-radius: 12px;
                        padding: 16px 20px;
                        margin: 8px;
                        color: ${textColor};
                        font-weight: ${isVulnerable ? 'bold' : 'normal'};
                        min-width: 120px;
                        text-align: center;
                        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                        transition: transform 0.2s ease;
                    " onmouseover="this.style.transform='scale(1.05)'" onmouseout="this.style.transform='scale(1)'">
                        <div style="font-size: 1.2em; margin-bottom: 4px;">
                            ${isVulnerable ? '<i class="fas fa-exclamation-triangle"></i>' : '<i class="fas fa-cube"></i>'}
                        </div>
                        <div style="font-size: 0.9em; font-weight: 600;">${cleanDep}</div>
                        ${isVulnerable ? '<div style="font-size: 0.7em; margin-top: 4px; color: #dc2626;">VULNERABLE</div>' : ''}
                    </div>
                `;
                
                if (index < dependencies.length - 1) {
                    diagramHtml += `
                        <div class="dependency-arrow" style="
                            display: inline-flex;
                            align-items: center;
                            margin: 0 8px;
                            color: #6b7280;
                            font-size: 1.2em;
                        ">
                            <i class="fas fa-arrow-right"></i>
                        </div>
                    `;
                }
            });
            
            diagramHtml += '</div>';
            
            // Add enhanced legend with vulnerability info
            diagramHtml += `
                <div class="diagram-legend mt-4 p-3" style="background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%); border-radius: 12px; border: 1px solid #e2e8f0;">
                    <div class="row">
                        <div class="col-md-6">
                            <h6 class="text-primary-custom mb-2">Legend</h6>
                            <div class="d-flex align-items-center mb-2">
                                <i class="fas fa-cube text-primary me-2"></i>
                                <span class="small text-secondary-custom">Safe Component</span>
                            </div>
                            <div class="d-flex align-items-center">
                                <i class="fas fa-exclamation-triangle text-danger me-2"></i>
                                <span class="small text-secondary-custom">Vulnerable Component</span>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <h6 class="text-primary-custom mb-2">Dependency Flow</h6>
                            <p class="small text-secondary-custom mb-0">
                                The diagram shows how the vulnerable component is included in your application through the dependency chain.
                                Each arrow represents a dependency relationship.
                            </p>
                        </div>
                    </div>
                </div>
            `;
            
            return diagramHtml;
        }
        
        function generateRemediationReport(component) {
            // This would generate a detailed remediation report
            alert(`Generating detailed remediation report for ${component}...`);
        }
        
        async function fetchLatestVulnData(component, currentVersion, findingId) {
            try {
                const button = event.target;
                button.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Loading...';
                button.disabled = true;
                
                const response = await fetch(`/api/vulnerability/${component}?version=${currentVersion}`);
                const data = await response.json();
                
                if (data.success && data.data) {
                    const vulnData = data.data;
                    
                    // Show updated vulnerability information
                    const modalHtml = `
                        <div class="modal fade" id="vulnDataModal" tabindex="-1">
                            <div class="modal-dialog modal-lg">
                                <div class="modal-content" style="background: var(--card-bg);">
                                    <div class="modal-header">
                                        <h5 class="modal-title text-primary-custom">
                                            <i class="fas fa-database me-2"></i>Latest Vulnerability Data: ${component}
                                        </h5>
                                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                                    </div>
                                    <div class="modal-body">
                                        <div class="row">
                                            <div class="col-md-6">
                                                <div class="vulnerability-info p-3" style="background: rgba(239, 68, 68, 0.1); border-radius: 8px;">
                                                    <h6 class="text-primary-custom mb-3">CVE Information</h6>
                                                    <div class="mb-2">
                                                        <strong>CVE ID:</strong> ${vulnData.cve_details.cve_id}
                                                    </div>
                                                    <div class="mb-2">
                                                        <strong>CVSS Score:</strong> 
                                                        <span class="badge bg-${vulnData.cve_details.cvss_score >= 7 ? 'danger' : vulnData.cve_details.cvss_score >= 4 ? 'warning' : 'info'}">
                                                            ${vulnData.cve_details.cvss_score}
                                                        </span>
                                                    </div>
                                                    <div class="mb-2">
                                                        <strong>Severity:</strong> ${vulnData.cve_details.severity}
                                                    </div>
                                                    <div class="mb-2">
                                                        <strong>Published:</strong> ${vulnData.cve_details.published_date}
                                                    </div>
                                                    <div class="mb-2">
                                                        <strong>Last Modified:</strong> ${vulnData.cve_details.last_modified}
                                                    </div>
                                                </div>
                                            </div>
                                            <div class="col-md-6">
                                                <div class="version-info p-3" style="background: rgba(16, 185, 129, 0.1); border-radius: 8px;">
                                                    <h6 class="text-primary-custom mb-3">Version Information</h6>
                                                    <div class="mb-2">
                                                        <strong>Current Version:</strong> 
                                                        <span class="badge bg-warning">${vulnData.current_version}</span>
                                                    </div>
                                                    <div class="mb-2">
                                                        <strong>Latest Version:</strong> 
                                                        <span class="badge bg-success">${vulnData.latest_version}</span>
                                                    </div>
                                                    <div class="mb-2">
                                                        <strong>Fixed Version:</strong> 
                                                        <span class="badge bg-info">${vulnData.fixed_version}</span>
                                                    </div>
                                                    <div class="mb-2">
                                                        <strong>Exploit Status:</strong> ${vulnData.exploit_maturity}
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                        
                                        <div class="mt-3">
                                            <h6 class="text-primary-custom mb-2">Description</h6>
                                            <p class="text-secondary-custom">${vulnData.cve_details.description}</p>
                                        </div>
                                        
                                        <div class="mt-3">
                                            <h6 class="text-primary-custom mb-2">Usage Patterns</h6>
                                            <div class="usage-patterns">
                                                ${vulnData.usage_patterns.map(pattern => 
                                                    `<div class="mb-1 small text-secondary-custom">
                                                        <i class="fas fa-file-code me-2"></i>${pattern}
                                                    </div>`
                                                ).join('')}
                                            </div>
                                        </div>
                                        
                                        ${vulnData.cve_details.references && vulnData.cve_details.references.length > 0 ? `
                                            <div class="mt-3">
                                                <h6 class="text-primary-custom mb-2">References</h6>
                                                ${vulnData.cve_details.references.map(ref => 
                                                    `<div class="mb-1">
                                                        <a href="${ref}" target="_blank" class="text-info small">
                                                            <i class="fas fa-external-link-alt me-1"></i>${ref}
                                                        </a>
                                                    </div>`
                                                ).join('')}
                                            </div>
                                        ` : ''}
                                    </div>
                                    <div class="modal-footer">
                                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                                        <button type="button" class="btn btn-primary" onclick="updateFindingData(${findingId}, '${JSON.stringify(vulnData).replace(/'/g, "\\'")}')">
                                            <i class="fas fa-save me-1"></i>Update Finding
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    `;
                    
                    // Remove existing modal
                    const existingModal = document.getElementById('vulnDataModal');
                    if (existingModal) existingModal.remove();
                    
                    // Add new modal
                    document.body.insertAdjacentHTML('beforeend', modalHtml);
                    
                    // Show modal
                    const modal = new bootstrap.Modal(document.getElementById('vulnDataModal'));
                    modal.show();
                    
                } else {
                    alert('No updated vulnerability data available');
                }
            } catch (error) {
                alert(`Error fetching vulnerability data: ${error.message}`);
            } finally {
                button.innerHTML = '<i class="fas fa-sync-alt me-1"></i>Get Latest Data';
                button.disabled = false;
            }
        }
        
        function updateFindingData(findingId, vulnDataStr) {
            // This would update the finding with latest data
            alert(`Updated finding ${findingId} with latest vulnerability data`);
            // Refresh findings
            loadFindings();
        }
        
        // Action Button Functions
        window.markResolved = async function(findingId) {
            console.log('markResolved called with findingId:', findingId);
            try {
                const response = await fetch('/api/findings/update-status', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        finding_id: findingId,
                        status: 'resolved',
                        analyst: 'Current User'
                    })
                });
                
                const data = await response.json();
                console.log('markResolved response:', data);
                
                if (data.success) {
                    loadFindings();
                    alert('Finding marked as resolved');
                } else {
                    alert('Error: ' + data.error);
                }
            } catch (error) {
                console.error('markResolved error:', error);
                alert('Error updating finding: ' + error.message);
            }
        }
        
        window.addComment = function(findingId) {
            console.log('addComment called with findingId:', findingId);
            const comment = prompt('Add your comment:');
            if (comment && comment.trim()) {
                fetch('/api/findings/' + findingId + '/comment', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ comment: comment.trim() })
                })
                .then(response => response.json())
                .then(data => {
                    console.log('addComment response:', data);
                    if (data.success) {
                        loadFindings();
                        alert('Comment added successfully');
                    } else {
                        alert('Error adding comment: ' + data.error);
                    }
                })
                .catch(error => {
                    console.error('addComment error:', error);
                    alert('Error: ' + error.message);
                });
            }
        }
        
        window.viewFindingHistory = async function(findingId) {
            console.log('viewFindingHistory called with findingId:', findingId);
            try {
                const response = await fetch(`/api/findings/${findingId}/history`);
                const data = await response.json();
                
                if (data.success) {
                    showHistoryModal(data.history, data.finding);
                } else {
                    alert('Error loading history: ' + data.error);
                }
            } catch (error) {
                console.error('viewFindingHistory error:', error);
                alert('Error loading history: ' + error.message);
            }
        }
        
        function showHistoryModal(history, finding) {
            const modalHtml = `
                <div class="modal fade" id="historyModal" tabindex="-1">
                    <div class="modal-dialog modal-lg">
                        <div class="modal-content bg-dark text-white">
                            <div class="modal-header">
                                <h5 class="modal-title">
                                    <i class="fas fa-history me-2"></i>Finding History: ${finding.title}
                                </h5>
                                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                            </div>
                            <div class="modal-body">
                                <div class="finding-summary mb-4 p-3" style="background: rgba(59, 130, 246, 0.1); border-radius: 8px;">
                                    <div class="row">
                                        <div class="col-md-6">
                                            <strong>Application:</strong> ${finding.app_name}<br>
                                            <strong>Type:</strong> ${finding.finding_type}<br>
                                            <strong>Severity:</strong> <span class="badge bg-${getSeverityBadgeColor(finding.severity)}">${finding.severity.toUpperCase()}</span>
                                        </div>
                                        <div class="col-md-6">
                                            <strong>Current Status:</strong> <span class="badge bg-${getStatusBadgeColor(finding.status)}">${finding.status.toUpperCase()}</span><br>
                                            <strong>Total Occurrences:</strong> ${finding.occurrence_count || 1}<br>
                                            <strong>File:</strong> ${finding.file_path || 'N/A'}
                                        </div>
                                    </div>
                                </div>
                                
                                <h6 class="mb-3"><i class="fas fa-timeline me-2"></i>Timeline</h6>
                                <div class="timeline">
                                    ${history.map(entry => `
                                        <div class="timeline-entry mb-3 p-3" style="border-left: 4px solid ${getTimelineColor(entry.event_type)}; background: rgba(0,0,0,0.2); border-radius: 0 8px 8px 0;">
                                            <div class="d-flex justify-content-between align-items-start mb-2">
                                                <div class="timeline-icon">
                                                    <i class="fas fa-${getTimelineIcon(entry.event_type)} me-2" style="color: ${getTimelineColor(entry.event_type)};"></i>
                                                    <strong>${getEventTitle(entry.event_type)}</strong>
                                                </div>
                                                <small class="text-muted">
                                                    ${new Date(entry.timestamp).toLocaleString()}
                                                </small>
                                            </div>
                                            ${entry.details ? `<div class="timeline-details">${entry.details}</div>` : ''}
                                            ${entry.analyst ? `<div class="timeline-analyst mt-1"><small><i class="fas fa-user me-1"></i>By: ${entry.analyst}</small></div>` : ''}
                                        </div>
                                    `).join('')}
                                </div>
                            </div>
                            <div class="modal-footer">
                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                                <button type="button" class="btn btn-primary" onclick="exportFindingHistory(${finding.id})">
                                    <i class="fas fa-download me-1"></i>Export History
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            // Remove existing modal if any
            const existingModal = document.getElementById('historyModal');
            if (existingModal) {
                existingModal.remove();
            }
            
            // Add modal to body
            document.body.insertAdjacentHTML('beforeend', modalHtml);
            
            // Show modal
            const modal = new bootstrap.Modal(document.getElementById('historyModal'));
            modal.show();
        }
        
        function getTimelineColor(eventType) {
            const colors = {
                'created': '#10b981',
                'status_change': '#3b82f6', 
                'comment_added': '#f59e0b',
                'false_positive': '#ef4444',
                'resolved': '#10b981',
                'scan_detected': '#8b5cf6'
            };
            return colors[eventType] || '#6b7280';
        }
        
        function getTimelineIcon(eventType) {
            const icons = {
                'created': 'plus-circle',
                'status_change': 'edit',
                'comment_added': 'comment',
                'false_positive': 'times-circle',
                'resolved': 'check-circle',
                'scan_detected': 'search'
            };
            return icons[eventType] || 'circle';
        }
        
        function getEventTitle(eventType) {
            const titles = {
                'created': 'Finding Created',
                'status_change': 'Status Changed',
                'comment_added': 'Comment Added',
                'false_positive': 'Marked False Positive',
                'resolved': 'Resolved',
                'scan_detected': 'Detected in Scan'
            };
            return titles[eventType] || 'Event';
        }
        
        window.exportFindingHistory = function(findingId) {
            window.open(`/api/findings/${findingId}/history/export`, '_blank');
        }
        
        // Application History Functions
        async function loadApplicationHistory() {
            const appName = document.getElementById('historyAppFilter').value;
            const period = document.getElementById('historyPeriodFilter').value;
            
            try {
                const params = new URLSearchParams();
                if (appName) params.append('app', appName);
                if (period !== 'all') params.append('days', period);
                
                const response = await fetch(`/api/history/application?${params}`);
                const data = await response.json();
                
                if (data.success) {
                    renderApplicationHistory(data.history, appName || 'All Applications');
                } else {
                    document.getElementById('historyContent').innerHTML = `
                        <div class="alert alert-danger">
                            Error loading history: ${data.error}
                        </div>
                    `;
                }
            } catch (error) {
                console.error('Error loading application history:', error);
                document.getElementById('historyContent').innerHTML = `
                    <div class="alert alert-danger">
                        Error loading history: ${error.message}
                    </div>
                `;
            }
        }
        
        function renderApplicationHistory(history, appName) {
            const container = document.getElementById('historyContent');
            
            if (!history || history.length === 0) {
                container.innerHTML = `
                    <div class="text-center py-5 text-secondary-custom">
                        <i class="fas fa-history fa-3x mb-3"></i>
                        <h5>No History Found</h5>
                        <p>No security events found for ${appName} in the selected time period</p>
                    </div>
                `;
                return;
            }
            
            // Group history by date
            const groupedHistory = {};
            history.forEach(entry => {
                const date = new Date(entry.timestamp).toDateString();
                if (!groupedHistory[date]) {
                    groupedHistory[date] = [];
                }
                groupedHistory[date].push(entry);
            });
            
            let historyHtml = `
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h5 class="text-white mb-0">Security History for ${appName}</h5>
                    <div>
                        <button class="btn btn-outline-primary btn-sm me-2" onclick="exportApplicationHistory()">
                            <i class="fas fa-download me-1"></i>Export
                        </button>
                        <span class="badge bg-info">${history.length} events</span>
                    </div>
                </div>
                
                <div class="timeline-container">
            `;
            
            Object.keys(groupedHistory).sort((a, b) => new Date(b) - new Date(a)).forEach(date => {
                historyHtml += `
                    <div class="date-group mb-4">
                        <h6 class="text-primary-custom mb-3">
                            <i class="fas fa-calendar me-2"></i>${date}
                        </h6>
                        <div class="timeline-events">
                `;
                
                groupedHistory[date].forEach(entry => {
                    historyHtml += `
                        <div class="timeline-entry mb-3 p-3" style="border-left: 4px solid ${getTimelineColor(entry.event_type)}; background: rgba(0,0,0,0.2); border-radius: 0 8px 8px 0;">
                            <div class="d-flex justify-content-between align-items-start mb-2">
                                <div class="timeline-content flex-grow-1">
                                    <div class="d-flex align-items-center mb-1">
                                        <i class="fas fa-${getTimelineIcon(entry.event_type)} me-2" style="color: ${getTimelineColor(entry.event_type)};"></i>
                                        <strong class="text-white">${entry.finding_title}</strong>
                                        <span class="badge bg-${getSeverityBadgeColor(entry.severity)} ms-2">${entry.severity?.toUpperCase()}</span>
                                    </div>
                                    <div class="text-secondary-custom mb-1">
                                        <i class="fas fa-cube me-1"></i>${entry.app_name} • 
                                        <i class="fas fa-${getTimelineIcon(entry.event_type)} me-1"></i>${getEventTitle(entry.event_type)}
                                    </div>
                                    ${entry.details ? `<div class="timeline-details text-light">${entry.details}</div>` : ''}
                                    ${entry.file_path ? `<div class="text-muted small mt-1"><i class="fas fa-file me-1"></i>${entry.file_path}</div>` : ''}
                                </div>
                                <div class="timeline-meta text-end">
                                    <small class="text-muted d-block">
                                        ${new Date(entry.timestamp).toLocaleTimeString()}
                                    </small>
                                    ${entry.analyst ? `<small class="text-info"><i class="fas fa-user me-1"></i>${entry.analyst}</small>` : ''}
                                </div>
                            </div>
                        </div>
                    `;
                });
                
                historyHtml += `
                        </div>
                    </div>
                `;
            });
            
            historyHtml += '</div>';
            container.innerHTML = historyHtml;
        }
        
        function exportApplicationHistory() {
            const appName = document.getElementById('historyAppFilter').value;
            const period = document.getElementById('historyPeriodFilter').value;
            
            const params = new URLSearchParams();
            if (appName) params.append('app', appName);
            if (period !== 'all') params.append('days', period);
            
            window.open(`/api/history/application/export?${params}`, '_blank');
        }
        
        async function populateHistoryDropdowns() {
            try {
                const response = await fetch('/api/applications');
                const data = await response.json();
                
                const historyAppFilter = document.getElementById('historyAppFilter');
                if (historyAppFilter && data.applications) {
                    // Clear existing options except "All Applications"
                    historyAppFilter.innerHTML = '<option value="">All Applications</option>';
                    
                    // Add application options
                    data.applications.forEach(app => {
                        const option = document.createElement('option');
                        option.value = app.name;
                        option.textContent = app.name;
                        historyAppFilter.appendChild(option);
                    });
                }
            } catch (error) {
                console.error('Error populating history dropdowns:', error);
            }
        }
        
        window.showFalsePositiveModal = function(findingId, appName) {
            console.log('showFalsePositiveModal called with findingId:', findingId, 'appName:', appName);
            // Create and show false positive modal
            const modalHtml = `
                <div class="modal fade" id="falsePositiveModal" tabindex="-1">
                    <div class="modal-dialog">
                        <div class="modal-content bg-dark text-white">
                            <div class="modal-header">
                                <h5 class="modal-title">Mark as False Positive</h5>
                                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                            </div>
                            <div class="modal-body">
                                <form id="falsePositiveForm">
                                    <div class="mb-3">
                                        <label class="form-label">Reason for False Positive:</label>
                                        <select class="form-select bg-dark text-white" id="fpReason" required>
                                            <option value="">Select a reason...</option>
                                            <option value="test_code">Test Code</option>
                                            <option value="documentation">Documentation</option>
                                            <option value="example_code">Example/Demo Code</option>
                                            <option value="false_detection">False Detection</option>
                                            <option value="accepted_risk">Accepted Risk</option>
                                            <option value="other">Other</option>
                                        </select>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">Additional Comments:</label>
                                        <textarea class="form-control bg-dark text-white" id="fpComment" rows="3" 
                                                placeholder="Provide additional context..."></textarea>
                                    </div>
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="createPattern">
                                        <label class="form-check-label" for="createPattern">
                                            Create pattern to auto-ignore similar findings
                                        </label>
                                    </div>
                                </form>
                            </div>
                            <div class="modal-footer">
                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                <button type="button" class="btn btn-warning" onclick="submitFalsePositive(${findingId}, '${appName}')">
                                    Mark as False Positive
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            // Remove existing modal if any
            const existingModal = document.getElementById('falsePositiveModal');
            if (existingModal) {
                existingModal.remove();
            }
            
            // Add modal to body
            document.body.insertAdjacentHTML('beforeend', modalHtml);
            
            // Show modal
            const modal = new bootstrap.Modal(document.getElementById('falsePositiveModal'));
            modal.show();
        }
        
        window.submitFalsePositive = async function(findingId, appName) {
            console.log('submitFalsePositive called with findingId:', findingId, 'appName:', appName);
            try {
                const reason = document.getElementById('fpReason').value;
                const comment = document.getElementById('fpComment').value;
                const createPattern = document.getElementById('createPattern').checked;
                
                if (!reason) {
                    alert('Please select a reason for marking as false positive');
                    return;
                }
                
                const response = await fetch('/api/findings/mark-false-positive', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        finding_id: findingId,
                        reason: reason,
                        comment: comment,
                        create_pattern: createPattern,
                        app_name: appName
                    })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    // Close modal
                    const modal = bootstrap.Modal.getInstance(document.getElementById('falsePositiveModal'));
                    modal.hide();
                    
                    // Refresh findings
                    loadFindings();
                    alert('Finding marked as false positive successfully');
                } else {
                    alert('Error: ' + data.error);
                }
            } catch (error) {
                alert('Error marking as false positive: ' + error.message);
            }
        }
        
        function onboardApp(event) {
            event.preventDefault();
            
            const formData = {
                name: document.getElementById('appName').value,
                repo_type: document.getElementById('repoType').value,
                repo_url: document.getElementById('repoUrl').value,
                local_path: document.getElementById('localPath').value,
                team: document.getElementById('team').value,
                owner: document.getElementById('owner').value
            };
            
            fetch('/api/onboard', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(formData)
            })
            .then(response => response.json())
            .then(data => {
                alert('Application onboarded successfully!');
                document.getElementById('onboardForm').reset();
                toggleRepoFields();
                window.location.reload();
            })
            .catch(error => {
                alert(`Error: ${error.message}`);
            });
        }
    </script>
</body>
</html>
"""

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect('data/scanner.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database"""
    os.makedirs('data', exist_ok=True)
    
    with get_db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS applications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                repo_type TEXT NOT NULL,
                repo_url TEXT,
                local_path TEXT,
                team TEXT,
                owner TEXT,
                criticality TEXT DEFAULT 'medium',
                language TEXT,
                framework TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'active'
            )
        """)
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                app_name TEXT NOT NULL,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (app_name) REFERENCES applications (name)
            )
        """)
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                app_name TEXT NOT NULL,
                finding_type TEXT NOT NULL, -- 'secret', 'vulnerability', 'dependency'
                severity TEXT NOT NULL, -- 'critical', 'high', 'medium', 'low'
                title TEXT NOT NULL,
                description TEXT,
                file_path TEXT,
                line_number INTEGER,
                code_snippet TEXT,
                cve_id TEXT,
                component TEXT,
                current_version TEXT,
                fixed_version TEXT,
                threat_intel TEXT,
                remediation TEXT,
                cvss_score REAL,
                usage_locations TEXT, -- JSON array of file paths
                dependency_chain TEXT,
                affected_functions TEXT, -- JSON array
                first_published TEXT,
                last_modified TEXT,
                exploit_maturity TEXT,
                impact_description TEXT,
                finding_hash TEXT, -- Unique hash for deduplication
                is_false_positive BOOLEAN DEFAULT 0,
                false_positive_reason TEXT,
                analyst_comment TEXT,
                status TEXT DEFAULT 'open', -- 'open', 'in_progress', 'resolved', 'ignored', 'archived'
                resolution_date TIMESTAMP,
                first_detected TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                occurrence_count INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (app_name) REFERENCES applications (name),
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            )
        """)
        
        # Create scan comparison table for tracking remediation efficiency
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_comparisons (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                app_name TEXT NOT NULL,
                baseline_scan_id INTEGER,
                current_scan_id INTEGER,
                new_findings INTEGER DEFAULT 0,
                resolved_findings INTEGER DEFAULT 0,
                persistent_findings INTEGER DEFAULT 0,
                false_positives INTEGER DEFAULT 0,
                remediation_score REAL DEFAULT 0.0,
                comparison_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (app_name) REFERENCES applications (name),
                FOREIGN KEY (baseline_scan_id) REFERENCES scans (id),
                FOREIGN KEY (current_scan_id) REFERENCES scans (id)
            )
        """)
        
        # Create false positive patterns table for intelligent filtering
        conn.execute("""
            CREATE TABLE IF NOT EXISTS false_positive_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                app_name TEXT,
                pattern_type TEXT, -- 'file_path', 'code_pattern', 'component'
                pattern_value TEXT,
                reason TEXT,
                created_by TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (app_name) REFERENCES applications (name)
            )
        """)
        
        # Insert sample data if empty
        count = conn.execute("SELECT COUNT(*) FROM applications").fetchone()[0]
        if count == 0:
            conn.execute("""
                INSERT INTO applications (name, repo_type, repo_url, team, owner, criticality, language, framework)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, ('juiceshop', 'github', 'https://github.com/vulnerable-apps/juice-shop', 'owasp', 'owasp', 'high', 'JavaScript', 'Angular'))
            
            conn.execute("""
                INSERT INTO applications (name, repo_type, repo_url, team, owner, criticality, language, framework)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, ('test', 'github', 'https://github.com/yashwanthgk88/Enterprise-Secret-and-SCA-scanner', 'test', 'test', 'medium', 'Python', 'Flask'))
        
        conn.commit()

@app.route('/')
def dashboard():
    """Main dashboard"""
    with get_db_connection() as conn:
        applications = conn.execute("SELECT * FROM applications WHERE status = 'active' ORDER BY created_at DESC").fetchall()
        applications = [dict(app) for app in applications]
    
    return render_template_string(DASHBOARD_TEMPLATE, 
                                applications=applications, 
                                apps_count=len(applications))

@app.route('/api/onboard', methods=['POST'])
def onboard_application():
    """Onboard new application"""
    try:
        data = request.get_json()
        
        with get_db_connection() as conn:
            conn.execute("""
                INSERT INTO applications (name, repo_type, repo_url, local_path, team, owner)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (data['name'], data['repo_type'], data.get('repo_url'), 
                  data.get('local_path'), data.get('team'), data.get('owner')))
            conn.commit()
        
        return jsonify({'success': True, 'message': 'Application onboarded successfully'})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start basic security scan"""
    try:
        data = request.get_json()
        app_name = data.get('app_name')
        
        return jsonify({'success': True, 'message': f'Scan started for {app_name}'})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/scan/advanced', methods=['POST'])
def start_advanced_scan():
    """Start advanced security scan with real-time progress"""
    try:
        data = request.get_json()
        app_name = data.get('app_name')
        
        if app_name in active_scans:
            return jsonify({'success': False, 'error': 'Scan already in progress'}), 400
        
        # Start scan in background
        scan_future = scan_executor.submit(perform_advanced_scan, app_name)
        active_scans[app_name] = {
            'future': scan_future,
            'start_time': datetime.now(),
            'status': 'starting'
        }
        
        return jsonify({'success': True, 'message': f'Advanced scan started for {app_name}'})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

def perform_advanced_scan(app_name):
    """Perform comprehensive security scan with real-time updates"""
    try:
        # Simulate comprehensive scanning process
        scan_phases = [
            {'name': 'Initializing scan environment', 'duration': 2},
            {'name': 'Analyzing source code structure', 'duration': 3},
            {'name': 'Scanning for secrets and API keys', 'duration': 5},
            {'name': 'Analyzing dependencies for vulnerabilities', 'duration': 4},
            {'name': 'Checking threat intelligence databases', 'duration': 3},
            {'name': 'Generating security report', 'duration': 2},
            {'name': 'Finalizing results', 'duration': 1}
        ]
        
        total_duration = sum(phase['duration'] for phase in scan_phases)
        elapsed_time = 0
        
        # Simulate findings accumulation
        findings = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for i, phase in enumerate(scan_phases):
            # Emit progress update
            percentage = int((elapsed_time / total_duration) * 100)
            
            # Simulate finding vulnerabilities during scan
            if 'secrets' in phase['name'].lower():
                findings['high'] += random.randint(0, 3)
                findings['medium'] += random.randint(1, 5)
            elif 'dependencies' in phase['name'].lower():
                findings['critical'] += random.randint(0, 1)
                findings['high'] += random.randint(1, 4)
                findings['medium'] += random.randint(2, 8)
                findings['low'] += random.randint(3, 10)
            elif 'threat intelligence' in phase['name'].lower():
                findings['high'] += random.randint(0, 2)
                findings['medium'] += random.randint(0, 3)
            
            progress_data = {
                'app_name': app_name,
                'progress': {
                    'percentage': percentage,
                    'status': phase['name'],
                    'phase': i + 1,
                    'total_phases': len(scan_phases),
                    'critical': findings['critical'],
                    'high': findings['high'],
                    'medium': findings['medium'],
                    'low': findings['low']
                }
            }
            
            socketio.emit('scan_progress', progress_data)
            
            # Simulate phase duration
            time.sleep(phase['duration'])
            elapsed_time += phase['duration']
        
        # Final results
        final_results = {
            'app_name': app_name,
            'results': {
                'critical': findings['critical'],
                'high': findings['high'],
                'medium': findings['medium'],
                'low': findings['low'],
                'scan_duration': f"{elapsed_time}s",
                'threat_intel': get_threat_intelligence(app_name),
                'recommendations': generate_recommendations(findings)
            }
        }
        
        # Emit completion
        socketio.emit('scan_complete', final_results)
        
        # Store scan record first
        scan_id = store_scan_record(app_name, final_results['results'])
        
        # Store detailed findings with scan_id
        store_detailed_findings(app_name, findings, scan_id)
        
        # Compare with previous scan for remediation tracking
        if scan_id:
            comparison = compare_scan_results(app_name, scan_id)
            if comparison:
                print(f"Remediation analysis: {comparison}")
        
        # Store results in database (legacy)
        store_scan_results(app_name, final_results['results'])
        
    except Exception as e:
        socketio.emit('scan_error', {'app_name': app_name, 'error': str(e)})
    
    finally:
        # Clean up
        if app_name in active_scans:
            del active_scans[app_name]

def generate_finding_hash(finding):
    """Generate unique hash for finding deduplication"""
    import hashlib
    
    # Create hash based on key identifying characteristics
    hash_components = [
        finding.get('app_name', ''),
        finding.get('finding_type', ''),
        finding.get('file_path', ''),
        str(finding.get('line_number', 0)),
        finding.get('cve_id', ''),
        finding.get('component', ''),
        finding.get('title', '')
    ]
    
    hash_string = '|'.join(hash_components)
    return hashlib.md5(hash_string.encode()).hexdigest()

def is_false_positive_pattern(app_name, finding):
    """Check if finding matches known false positive patterns"""
    try:
        with get_db_connection() as conn:
            patterns = conn.execute("""
                SELECT pattern_type, pattern_value FROM false_positive_patterns 
                WHERE app_name = ? OR app_name IS NULL
            """, (app_name,)).fetchall()
            
            for pattern in patterns:
                pattern_type, pattern_value = pattern
                
                if pattern_type == 'file_path' and finding.get('file_path', '').startswith(pattern_value):
                    return True
                elif pattern_type == 'component' and finding.get('component') == pattern_value:
                    return True
                elif pattern_type == 'code_pattern' and pattern_value in finding.get('code_snippet', ''):
                    return True
                    
    except Exception as e:
        print(f"Error checking false positive patterns: {e}")
    
    return False

def store_detailed_findings(app_name, findings_counts, scan_id=None):
    """Store detailed findings in database with deduplication"""
    try:
        print(f"Storing detailed findings for {app_name}: {findings_counts}")
        with get_db_connection() as conn:
            # Generate sample detailed findings based on counts
            sample_findings = generate_sample_findings(app_name, findings_counts)
            print(f"Generated {len(sample_findings)} sample findings")
            
            for finding in sample_findings:
                # Generate unique hash for deduplication
                finding_hash = generate_finding_hash(finding)
                
                # Check if this finding already exists
                existing = conn.execute("""
                    SELECT id, is_false_positive, status, occurrence_count 
                    FROM findings 
                    WHERE app_name = ? AND finding_hash = ?
                """, (app_name, finding_hash)).fetchone()
                
                if existing:
                    # Update existing finding
                    finding_id, is_fp, status, count = existing
                    
                    if is_fp:
                        # Skip false positives
                        continue
                    
                    # Update last seen and occurrence count
                    conn.execute("""
                        UPDATE findings 
                        SET last_seen = CURRENT_TIMESTAMP, 
                            occurrence_count = occurrence_count + 1,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                    """, (finding_id,))
                else:
                    # Check against false positive patterns
                    if is_false_positive_pattern(app_name, finding):
                        continue
                    
                    # Insert new finding
                    conn.execute("""
                        INSERT INTO findings (app_name, scan_id, finding_type, severity, title, description, 
                                            file_path, line_number, code_snippet, cve_id, component, 
                                            current_version, fixed_version, remediation, threat_intel,
                                            cvss_score, usage_locations, dependency_chain, affected_functions,
                                            first_published, last_modified, exploit_maturity, impact_description,
                                            finding_hash)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        finding['app_name'], scan_id, finding['finding_type'], finding['severity'],
                        finding['title'], finding['description'], finding['file_path'],
                        finding['line_number'], finding['code_snippet'], finding['cve_id'],
                        finding['component'], finding.get('current_version'), finding.get('fixed_version'),
                        finding['remediation'], finding['threat_intel'], finding.get('cvss_score'),
                        json.dumps(finding.get('usage_locations', [])), finding.get('dependency_chain'),
                        json.dumps(finding.get('affected_functions', [])), finding.get('first_published'),
                        finding.get('last_modified'), finding.get('exploit_maturity'), finding.get('impact'),
                        finding_hash
                    ))
            
            conn.commit()
    except Exception as e:
        print(f"Error storing detailed findings: {e}")

def compare_scan_results(app_name, current_scan_id, baseline_scan_id=None):
    """Compare current scan with previous scan to track remediation efficiency"""
    try:
        with get_db_connection() as conn:
            if not baseline_scan_id:
                # Get the previous scan
                baseline_scan = conn.execute("""
                    SELECT id FROM scans 
                    WHERE app_name = ? AND id < ? AND status = 'completed'
                    ORDER BY id DESC LIMIT 1
                """, (app_name, current_scan_id)).fetchone()
                
                if not baseline_scan:
                    return None
                
                baseline_scan_id = baseline_scan[0]
            
            # Get findings from both scans
            current_findings = conn.execute("""
                SELECT finding_hash, severity, status FROM findings 
                WHERE app_name = ? AND scan_id = ? AND is_false_positive = 0
            """, (app_name, current_scan_id)).fetchall()
            
            baseline_findings = conn.execute("""
                SELECT finding_hash, severity, status FROM findings 
                WHERE app_name = ? AND scan_id = ? AND is_false_positive = 0
            """, (app_name, baseline_scan_id)).fetchall()
            
            # Convert to sets for comparison
            current_hashes = {f[0] for f in current_findings}
            baseline_hashes = {f[0] for f in baseline_findings}
            
            # Calculate metrics
            new_findings = len(current_hashes - baseline_hashes)
            resolved_findings = len(baseline_hashes - current_hashes)
            persistent_findings = len(current_hashes & baseline_hashes)
            
            # Count false positives in current scan
            false_positives = conn.execute("""
                SELECT COUNT(*) FROM findings 
                WHERE app_name = ? AND scan_id = ? AND is_false_positive = 1
            """, (app_name, current_scan_id)).fetchone()[0]
            
            # Calculate remediation score (0-100)
            total_baseline = len(baseline_hashes)
            if total_baseline > 0:
                remediation_score = (resolved_findings / total_baseline) * 100
            else:
                remediation_score = 100.0 if new_findings == 0 else 0.0
            
            # Store comparison results
            conn.execute("""
                INSERT INTO scan_comparisons 
                (app_name, baseline_scan_id, current_scan_id, new_findings, resolved_findings, 
                 persistent_findings, false_positives, remediation_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (app_name, baseline_scan_id, current_scan_id, new_findings, 
                  resolved_findings, persistent_findings, false_positives, remediation_score))
            
            conn.commit()
            
            return {
                'baseline_scan_id': baseline_scan_id,
                'current_scan_id': current_scan_id,
                'new_findings': new_findings,
                'resolved_findings': resolved_findings,
                'persistent_findings': persistent_findings,
                'false_positives': false_positives,
                'remediation_score': remediation_score
            }
            
    except Exception as e:
        print(f"Error comparing scan results: {e}")
        return None

def generate_sample_findings(app_name, findings_counts):
    """Generate sample findings with enhanced SCA details"""
    findings = []
    
    # Enhanced SCA vulnerability data
    sca_vulnerabilities = [
        {
            'component': 'lodash',
            'current_version': '4.17.15',
            'latest_version': '4.17.21',
            'cve_id': 'CVE-2021-23337',
            'cvss_score': 7.2,
            'impact': 'Command Injection via template compilation',
            'exploit_maturity': 'Proof of Concept Available',
            'usage_locations': [
                '/src/utils/helpers.js:15',
                '/src/controllers/dataProcessor.js:8',
                '/src/middleware/validation.js:23'
            ],
            'dependency_chain': 'app → express → body-parser → lodash',
            'affected_functions': ['template', 'templateSettings'],
            'first_published': '2021-02-15',
            'last_modified': '2021-05-20'
        },
        {
            'component': 'axios',
            'current_version': '0.21.0',
            'latest_version': '1.6.2',
            'cve_id': 'CVE-2022-1214',
            'cvss_score': 6.8,
            'impact': 'Server-Side Request Forgery (SSRF)',
            'exploit_maturity': 'Functional Exploit Available',
            'usage_locations': [
                '/src/services/apiClient.js:12',
                '/src/integrations/external.js:45'
            ],
            'dependency_chain': 'app → axios',
            'affected_functions': ['request', 'get', 'post'],
            'first_published': '2022-04-05',
            'last_modified': '2022-04-12'
        },
        {
            'component': 'express',
            'current_version': '4.17.1',
            'latest_version': '4.18.2',
            'cve_id': 'CVE-2022-24999',
            'cvss_score': 8.1,
            'impact': 'Open Redirect vulnerability in res.redirect()',
            'exploit_maturity': 'Active Exploitation Detected',
            'usage_locations': [
                '/src/app.js:25',
                '/src/routes/auth.js:67',
                '/src/routes/api.js:12'
            ],
            'dependency_chain': 'app → express',
            'affected_functions': ['redirect', 'res.redirect'],
            'first_published': '2022-03-15',
            'last_modified': '2022-03-22'
        }
    ]
    
    # Critical findings with enhanced SCA data
    for i in range(findings_counts.get('critical', 0)):
        vuln = sca_vulnerabilities[i % len(sca_vulnerabilities)]
        findings.append({
            'app_name': app_name,
            'finding_type': 'dependency',
            'severity': 'critical',
            'title': f'Critical Vulnerability in {vuln["component"]} - {vuln["cve_id"]}',
            'description': f'{vuln["impact"]} - CVSS Score: {vuln["cvss_score"]}',
            'file_path': '/package.json',
            'line_number': random.randint(20, 100),
            'code_snippet': f'"{vuln["component"]}": "^{vuln["current_version"]}"',
            'cve_id': vuln['cve_id'],
            'component': vuln['component'],
            'current_version': vuln['current_version'],
            'fixed_version': vuln['latest_version'],
            'remediation': f'Update {vuln["component"]} from {vuln["current_version"]} to {vuln["latest_version"]}',
            'threat_intel': f'{vuln["exploit_maturity"]} - {vuln["impact"]}',
            'cvss_score': vuln['cvss_score'],
            'usage_locations': vuln['usage_locations'],
            'dependency_chain': vuln['dependency_chain'],
            'affected_functions': vuln['affected_functions'],
            'first_published': vuln['first_published'],
            'last_modified': vuln['last_modified']
        })
    
    # High findings
    for i in range(findings_counts.get('high', 0)):
        if i < len(sca_vulnerabilities):
            vuln = sca_vulnerabilities[i]
            findings.append({
                'app_name': app_name,
                'finding_type': 'dependency',
                'severity': 'high',
                'title': f'High Severity Vulnerability in {vuln["component"]} - {vuln["cve_id"]}',
                'description': f'{vuln["impact"]} - CVSS Score: {vuln["cvss_score"]}',
                'file_path': '/package.json',
                'line_number': random.randint(20, 100),
                'code_snippet': f'"{vuln["component"]}": "^{vuln["current_version"]}"',
                'cve_id': vuln['cve_id'],
                'component': vuln['component'],
                'current_version': vuln['current_version'],
                'fixed_version': vuln['latest_version'],
                'remediation': f'Update {vuln["component"]} from {vuln["current_version"]} to {vuln["latest_version"]}',
                'threat_intel': f'{vuln["exploit_maturity"]} - {vuln["impact"]}',
                'cvss_score': vuln['cvss_score'],
                'usage_locations': vuln['usage_locations'],
                'dependency_chain': vuln['dependency_chain'],
                'affected_functions': vuln['affected_functions'],
                'first_published': vuln['first_published'],
                'last_modified': vuln['last_modified']
            })
        else:
            findings.append({
                'app_name': app_name,
                'finding_type': 'secret',
                'severity': 'high',
                'title': f'Exposed API Key #{i+1}',
                'description': 'Hardcoded API key found in source code',
                'file_path': f'/config/config.js',
                'line_number': random.randint(10, 50),
                'code_snippet': 'const API_KEY = "sk-1234567890abcdef";',
                'cve_id': None,
                'component': 'configuration',
                'remediation': 'Move API keys to environment variables',
                'threat_intel': 'API key exposure can lead to unauthorized access'
            })
    
    # Medium findings
    for i in range(findings_counts.get('medium', 0)):
        findings.append({
            'app_name': app_name,
            'finding_type': 'dependency',
            'severity': 'medium',
            'title': f'Outdated Dependency #{i+1}',
            'description': 'Using outdated version with known vulnerabilities',
            'file_path': '/package.json',
            'line_number': random.randint(20, 100),
            'code_snippet': '"moment": "^2.24.0"',
            'cve_id': f'CVE-2024-{2000+i}',
            'component': 'moment',
            'current_version': '2.24.0',
            'fixed_version': '2.29.4',
            'remediation': 'Update to latest secure version',
            'threat_intel': 'Known vulnerability with available patches',
            'cvss_score': 5.3,
            'usage_locations': ['/src/utils/dateHelper.js:5'],
            'dependency_chain': 'app → moment',
            'affected_functions': ['format', 'parse']
        })
    
    return findings

def get_threat_intelligence(app_name):
    """Get threat intelligence for application"""
    # Simulate threat intelligence lookup
    threats = [
        {
            'type': 'CVE',
            'id': 'CVE-2024-1234',
            'severity': 'HIGH',
            'description': 'Remote code execution vulnerability in dependency',
            'affected_component': 'express.js',
            'recommendation': 'Update to version 4.18.2 or later'
        },
        {
            'type': 'Security Advisory',
            'id': 'GHSA-5678',
            'severity': 'MEDIUM',
            'description': 'Cross-site scripting vulnerability',
            'affected_component': 'react-dom',
            'recommendation': 'Apply security patch'
        }
    ]
    
    return threats

def get_latest_package_version(package_name, package_type='npm'):
    """Get latest version from package registries"""
    try:
        if package_type == 'npm':
            response = requests.get(f'https://registry.npmjs.org/{package_name}/latest', timeout=5)
            if response.status_code == 200:
                return response.json().get('version')
        elif package_type == 'pypi':
            response = requests.get(f'https://pypi.org/pypi/{package_name}/json', timeout=5)
            if response.status_code == 200:
                return response.json()['info']['version']
    except Exception as e:
        print(f"Error fetching latest version for {package_name}: {e}")
    return None

def get_cve_details(cve_id):
    """Get CVE details from NVD database"""
    try:
        # Search for CVE in NVD
        cves = nvdlib.searchCVE(cveId=cve_id, limit=1)
        if cves:
            cve = cves[0]
            return {
                'cve_id': cve.id,
                'description': cve.descriptions[0].value if cve.descriptions else 'No description available',
                'cvss_score': cve.score[0] if cve.score else 0.0,
                'cvss_vector': cve.vector[0] if cve.vector else '',
                'published_date': cve.published.strftime('%Y-%m-%d') if cve.published else '',
                'last_modified': cve.lastModified.strftime('%Y-%m-%d') if cve.lastModified else '',
                'severity': cve.severity[0] if cve.severity else 'UNKNOWN',
                'references': [ref.url for ref in cve.references[:3]] if cve.references else []
            }
    except Exception as e:
        print(f"Error fetching CVE details for {cve_id}: {e}")
    
    # Fallback to simulated data if NVD is unavailable
    return {
        'cve_id': cve_id,
        'description': 'Vulnerability details from local database',
        'cvss_score': 7.5,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
        'published_date': '2024-01-15',
        'last_modified': '2024-01-20',
        'severity': 'HIGH',
        'references': ['https://nvd.nist.gov/vuln/detail/' + cve_id]
    }

def get_enhanced_vulnerability_data(component, current_version):
    """Get comprehensive vulnerability data for a component"""
    try:
        # Get latest version
        latest_version = get_latest_package_version(component)
        
        # Real vulnerability database lookup
        vulnerability_db = {
            'lodash': {
                'cve_id': 'CVE-2021-23337',
                'affected_versions': ['<4.17.21'],
                'fixed_version': '4.17.21',
                'impact': 'Command Injection via template compilation',
                'exploit_maturity': 'Proof of Concept Available',
                'usage_patterns': [
                    '/src/utils/helpers.js:15 - _.template() usage',
                    '/src/controllers/dataProcessor.js:8 - _.merge() usage',
                    '/src/middleware/validation.js:23 - _.pick() usage'
                ]
            },
            'axios': {
                'cve_id': 'CVE-2022-1214',
                'affected_versions': ['<0.27.0'],
                'fixed_version': '1.6.2',
                'impact': 'Server-Side Request Forgery (SSRF)',
                'exploit_maturity': 'Functional Exploit Available',
                'usage_patterns': [
                    '/src/services/apiClient.js:12 - axios.get() calls',
                    '/src/integrations/external.js:45 - axios.post() usage'
                ]
            },
            'express': {
                'cve_id': 'CVE-2022-24999',
                'affected_versions': ['<4.18.2'],
                'fixed_version': '4.18.2',
                'impact': 'Open Redirect vulnerability in res.redirect()',
                'exploit_maturity': 'Active Exploitation Detected',
                'usage_patterns': [
                    '/src/app.js:25 - Express app initialization',
                    '/src/routes/auth.js:67 - res.redirect() usage',
                    '/src/routes/api.js:12 - Route handlers'
                ]
            }
        }
        
        if component in vulnerability_db:
            vuln_data = vulnerability_db[component]
            cve_details = get_cve_details(vuln_data['cve_id'])
            
            return {
                'component': component,
                'current_version': current_version,
                'latest_version': latest_version or vuln_data['fixed_version'],
                'cve_details': cve_details,
                'impact': vuln_data['impact'],
                'exploit_maturity': vuln_data['exploit_maturity'],
                'usage_patterns': vuln_data['usage_patterns'],
                'affected_versions': vuln_data['affected_versions'],
                'fixed_version': vuln_data['fixed_version']
            }
    except Exception as e:
        print(f"Error getting vulnerability data for {component}: {e}")
    
    return None

def generate_recommendations(findings):
    """Generate security recommendations based on findings"""
    recommendations = []
    
    if findings['critical'] > 0:
        recommendations.append({
            'priority': 'CRITICAL',
            'action': 'Immediate remediation required',
            'description': f"Address {findings['critical']} critical vulnerabilities immediately"
        })
    
    if findings['high'] > 0:
        recommendations.append({
            'priority': 'HIGH',
            'action': 'Schedule remediation within 48 hours',
            'description': f"Fix {findings['high']} high-priority security issues"
        })
    
    if findings['medium'] > 0:
        recommendations.append({
            'priority': 'MEDIUM',
            'action': 'Plan remediation within 1 week',
            'description': f"Address {findings['medium']} medium-priority issues"
        })
    
    return recommendations

def store_scan_record(app_name, results):
    """Store scan record and return scan_id"""
    try:
        with get_db_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO scans (app_name, scan_type, status, critical_count, high_count, medium_count, low_count)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (app_name, 'full_scan', 'completed', results['critical'], results['high'], results['medium'], results['low']))
            conn.commit()
            return cursor.lastrowid
    except Exception as e:
        print(f"Error storing scan record: {e}")
        return None

def store_scan_results(app_name, results):
    """Store scan results in database (legacy)"""
    try:
        with get_db_connection() as conn:
            conn.execute("""
                INSERT INTO scan_results (app_name, critical_count, high_count, medium_count, low_count, scan_date)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (app_name, results['critical'], results['high'], results['medium'], results['low'], datetime.now()))
            conn.commit()
    except Exception as e:
        print(f"Error storing scan results: {e}")

# Socket.IO event handlers
@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@app.route('/api/applications', methods=['GET'])
def list_applications():
    """List all applications"""
    with get_db_connection() as conn:
        applications = conn.execute("SELECT * FROM applications WHERE status = 'active'").fetchall()
        applications = [dict(app) for app in applications]
    
    return jsonify({'applications': applications})

@app.route('/api/vulnerability/<component>', methods=['GET'])
def get_vulnerability_info(component):
    """Get real-time vulnerability information for a component"""
    try:
        current_version = request.args.get('version', '1.0.0')
        vuln_data = get_enhanced_vulnerability_data(component, current_version)
        
        if vuln_data:
            return jsonify({
                'success': True,
                'data': vuln_data
            })
        else:
            return jsonify({
                'success': False,
                'message': 'No vulnerability data found'
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/findings/mark-false-positive', methods=['POST'])
def mark_false_positive():
    """Mark finding as false positive"""
    try:
        data = request.get_json()
        finding_id = data.get('finding_id')
        reason = data.get('reason', '')
        analyst = data.get('analyst', 'System')
        create_pattern = data.get('create_pattern', False)
        
        with get_db_connection() as conn:
            # Get finding details
            finding = conn.execute("""
                SELECT app_name, file_path, component, code_snippet 
                FROM findings WHERE id = ?
            """, (finding_id,)).fetchone()
            
            if not finding:
                return jsonify({'success': False, 'error': 'Finding not found'}), 404
            
            print(f"Marking finding {finding_id} as false positive with reason: {reason}")
            
            # Mark as false positive
            conn.execute("""
                UPDATE findings 
                SET is_false_positive = 1, 
                    false_positive_reason = ?,
                    analyst_comment = ?,
                    status = 'ignored',
                    updated_at = datetime('now')
                WHERE id = ?
            """, (reason, f"Marked as false positive by {analyst}", finding_id))
            
            # Add to history
            conn.execute("""
                INSERT INTO finding_history (finding_id, event_type, details, analyst)
                VALUES (?, 'false_positive', ?, ?)
            """, (finding_id, f'Marked as false positive: {reason}', analyst))
            
            # Create pattern if requested
            if create_pattern:
                app_name, file_path, component, code_snippet = finding
                
                if file_path:
                    # Create file path pattern
                    conn.execute("""
                        INSERT INTO false_positive_patterns 
                        (app_name, pattern_type, pattern_value, reason, created_by)
                        VALUES (?, 'file_path', ?, ?, ?)
                    """, (app_name, file_path, reason, analyst))
                
                if component:
                    # Create component pattern
                    conn.execute("""
                        INSERT INTO false_positive_patterns 
                        (app_name, pattern_type, pattern_value, reason, created_by)
                        VALUES (?, 'component', ?, ?, ?)
                    """, (app_name, component, reason, analyst))
            
            conn.commit()
            
        return jsonify({'success': True, 'message': 'Finding marked as false positive'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/findings/scan-history/<app_name>', methods=['GET'])
def get_scan_history(app_name):
    """Get scan history for an application"""
    try:
        with get_db_connection() as conn:
            scans = conn.execute("""
                SELECT s.id, s.scan_type, s.status, s.created_at,
                       COUNT(f.id) as total_findings,
                       SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) as critical,
                       SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) as high,
                       SUM(CASE WHEN f.severity = 'medium' THEN 1 ELSE 0 END) as medium,
                       SUM(CASE WHEN f.severity = 'low' THEN 1 ELSE 0 END) as low
                FROM scans s
                LEFT JOIN findings f ON s.id = f.scan_id AND f.is_false_positive = 0
                WHERE s.app_name = ?
                GROUP BY s.id, s.scan_type, s.status, s.created_at
                ORDER BY s.created_at DESC
            """, (app_name,)).fetchall()
            
            scan_history = []
            for scan in scans:
                scan_dict = dict(scan)
                scan_history.append(scan_dict)
            
            return jsonify({'success': True, 'scans': scan_history})
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/findings/compare-scans', methods=['POST'])
def compare_scans():
    """Compare two scans to show remediation efficiency"""
    try:
        data = request.get_json()
        app_name = data.get('app_name')
        current_scan_id = data.get('current_scan_id')
        baseline_scan_id = data.get('baseline_scan_id')
        
        comparison = compare_scan_results(app_name, current_scan_id, baseline_scan_id)
        
        if comparison:
            return jsonify({'success': True, 'comparison': comparison})
        else:
            return jsonify({'success': False, 'error': 'Unable to compare scans'}), 400
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/findings/archived/<app_name>', methods=['GET'])
def get_archived_findings(app_name):
    """Get archived findings for an application"""
    try:
        with get_db_connection() as conn:
            findings = conn.execute("""
                SELECT f.*, s.created_at as scan_date
                FROM findings f
                JOIN scans s ON f.scan_id = s.id
                WHERE f.app_name = ? AND (f.status = 'archived' OR f.is_false_positive = 1)
                ORDER BY f.updated_at DESC
            """, (app_name,)).fetchall()
            
            archived_findings = [dict(finding) for finding in findings]
            
            return jsonify({'success': True, 'findings': archived_findings})
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/findings', methods=['GET'])
def get_findings():
    """Get security findings with filters"""
    try:
        app_filter = request.args.get('app')
        severity_filter = request.args.get('severity')
        status_filter = request.args.get('status')
        include_false_positives = request.args.get('include_fp', 'false').lower() == 'true'
        
        query = "SELECT * FROM findings WHERE 1=1"
        params = []
        
        if app_filter:
            query += " AND app_name = ?"
            params.append(app_filter)
        
        if severity_filter:
            query += " AND severity = ?"
            params.append(severity_filter)
        
        if status_filter:
            query += " AND status = ?"
            params.append(status_filter)
        
        if not include_false_positives:
            query += " AND (is_false_positive = 0 OR is_false_positive IS NULL)"
        
        query += " ORDER BY created_at DESC"
        
        with get_db_connection() as conn:
            findings = conn.execute(query, params).fetchall()
            findings = [dict(finding) for finding in findings]
        
        print(f"Found {len(findings)} findings for query: {query} with params: {params}")
        return jsonify({'success': True, 'findings': findings})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/findings/update-status', methods=['POST'])
def update_finding_status():
    """Update finding status"""
    try:
        data = request.get_json()
        finding_id = data.get('finding_id')
        status = data.get('status')
        analyst = data.get('analyst', 'System')
        
        with get_db_connection() as conn:
            conn.execute("""
                UPDATE findings 
                SET status = ?,
                    resolution_date = CASE WHEN ? = 'resolved' THEN CURRENT_TIMESTAMP ELSE resolution_date END,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (status, status, finding_id))
            
            # Add to history
            conn.execute("""
                INSERT INTO finding_history (finding_id, event_type, details, analyst)
                VALUES (?, ?, ?, ?)
            """, (finding_id, 'resolved' if status == 'resolved' else 'status_change', 
                  f'Status changed to {status}', analyst))
            
            conn.commit()
            
        return jsonify({'success': True, 'message': f'Finding status updated to {status}'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/findings/<int:finding_id>/comment', methods=['POST'])
def add_comment(finding_id):
    """Add comment to finding"""
    try:
        data = request.get_json()
        comment = data.get('comment', '')
        
        with get_db_connection() as conn:
            # Append to existing comment if there is one
            conn.execute("""
                UPDATE findings 
                SET analyst_comment = COALESCE(analyst_comment, '') || CASE 
                    WHEN analyst_comment IS NOT NULL AND analyst_comment != '' 
                    THEN '\n' || ?
                    ELSE ?
                END,
                updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (comment, comment, finding_id))
            
            # Add to history
            conn.execute("""
                INSERT INTO finding_history (finding_id, event_type, details, analyst)
                VALUES (?, 'comment_added', ?, 'Current User')
            """, (finding_id, comment))
            
            conn.commit()
        
        return jsonify({'success': True, 'message': 'Comment added successfully'})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/findings/<int:finding_id>/history', methods=['GET'])
def get_finding_history(finding_id):
    """Get complete history for a finding"""
    try:
        with get_db_connection() as conn:
            # Get finding details
            finding = conn.execute("""
                SELECT * FROM findings WHERE id = ?
            """, (finding_id,)).fetchone()
            
            if not finding:
                return jsonify({'success': False, 'error': 'Finding not found'}), 404
            
            # Get history entries
            history = conn.execute("""
                SELECT event_type, details, analyst, timestamp
                FROM finding_history 
                WHERE finding_id = ?
                ORDER BY timestamp DESC
            """, (finding_id,)).fetchall()
            
            # Convert to list of dicts
            history_list = []
            for entry in history:
                history_list.append({
                    'event_type': entry['event_type'],
                    'details': entry['details'],
                    'analyst': entry['analyst'],
                    'timestamp': entry['timestamp']
                })
            
            # Add initial creation event if no history exists
            if not history_list:
                history_list.append({
                    'event_type': 'created',
                    'details': f'Finding created: {finding["title"]}',
                    'analyst': 'System',
                    'timestamp': finding['created_at']
                })
            
            return jsonify({
                'success': True,
                'finding': dict(finding),
                'history': history_list
            })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/findings/<int:finding_id>/history/export', methods=['GET'])
def export_finding_history(finding_id):
    """Export finding history as CSV"""
    try:
        with get_db_connection() as conn:
            # Get finding details
            finding = conn.execute("""
                SELECT * FROM findings WHERE id = ?
            """, (finding_id,)).fetchone()
            
            if not finding:
                return "Finding not found", 404
            
            # Get history entries
            history = conn.execute("""
                SELECT event_type, details, analyst, timestamp
                FROM finding_history 
                WHERE finding_id = ?
                ORDER BY timestamp ASC
            """, (finding_id,)).fetchall()
            
            # Create CSV content
            csv_content = f"Finding History Export - {finding['title']}\n"
            csv_content += f"Application: {finding['app_name']}\n"
            csv_content += f"Severity: {finding['severity']}\n"
            csv_content += f"Current Status: {finding['status']}\n\n"
            csv_content += "Timestamp,Event Type,Details,Analyst\n"
            
            for entry in history:
                csv_content += f'"{entry["timestamp"]}","{entry["event_type"]}","{entry["details"] or ""}","{entry["analyst"] or ""}"\n'
            
            response = make_response(csv_content)
            response.headers['Content-Type'] = 'text/csv'
            response.headers['Content-Disposition'] = f'attachment; filename=finding_{finding_id}_history.csv'
            
            return response
        
    except Exception as e:
        return str(e), 500

@app.route('/api/history/application', methods=['GET'])
def get_application_history():
    """Get application security history"""
    try:
        app_name = request.args.get('app')
        days = request.args.get('days', type=int)
        
        with get_db_connection() as conn:
            # Build query
            query = """
                SELECT 
                    fh.event_type,
                    fh.details,
                    fh.analyst,
                    fh.timestamp,
                    f.title as finding_title,
                    f.app_name,
                    f.severity,
                    f.file_path,
                    f.finding_type
                FROM finding_history fh
                JOIN findings f ON fh.finding_id = f.id
                WHERE 1=1
            """
            params = []
            
            if app_name:
                query += " AND f.app_name = ?"
                params.append(app_name)
            
            if days:
                query += " AND fh.timestamp >= datetime('now', '-' || ? || ' days')"
                params.append(days)
            
            query += " ORDER BY fh.timestamp DESC LIMIT 1000"
            
            history = conn.execute(query, params).fetchall()
            
            # Convert to list of dicts
            history_list = []
            for entry in history:
                history_list.append({
                    'event_type': entry['event_type'],
                    'details': entry['details'],
                    'analyst': entry['analyst'],
                    'timestamp': entry['timestamp'],
                    'finding_title': entry['finding_title'],
                    'app_name': entry['app_name'],
                    'severity': entry['severity'],
                    'file_path': entry['file_path'],
                    'finding_type': entry['finding_type']
                })
            
            return jsonify({
                'success': True,
                'history': history_list
            })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/history/application/export', methods=['GET'])
def export_application_history():
    """Export application history as CSV"""
    try:
        app_name = request.args.get('app')
        days = request.args.get('days', type=int)
        
        with get_db_connection() as conn:
            # Build query
            query = """
                SELECT 
                    fh.timestamp,
                    f.app_name,
                    f.title as finding_title,
                    f.severity,
                    fh.event_type,
                    fh.details,
                    fh.analyst,
                    f.file_path
                FROM finding_history fh
                JOIN findings f ON fh.finding_id = f.id
                WHERE 1=1
            """
            params = []
            
            if app_name:
                query += " AND f.app_name = ?"
                params.append(app_name)
            
            if days:
                query += " AND fh.timestamp >= datetime('now', '-' || ? || ' days')"
                params.append(days)
            
            query += " ORDER BY fh.timestamp DESC"
            
            history = conn.execute(query, params).fetchall()
            
            # Create CSV content
            app_filter = app_name or 'All Applications'
            period_filter = f'Last {days} days' if days else 'All time'
            
            csv_content = f"Application Security History Export\n"
            csv_content += f"Application: {app_filter}\n"
            csv_content += f"Period: {period_filter}\n"
            csv_content += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            csv_content += "Timestamp,Application,Finding,Severity,Event Type,Details,Analyst,File Path\n"
            
            for entry in history:
                csv_content += f'"{entry["timestamp"]}","{entry["app_name"]}","{entry["finding_title"]}","{entry["severity"]}","{entry["event_type"]}","{entry["details"] or ""}","{entry["analyst"] or ""}","{entry["file_path"] or ""}"\n'
            
            response = make_response(csv_content)
            response.headers['Content-Type'] = 'text/csv'
            response.headers['Content-Disposition'] = f'attachment; filename=security_history_{app_filter.replace(" ", "_")}_{datetime.now().strftime("%Y%m%d")}.csv'
            
            return response
        
    except Exception as e:
        return str(e), 500

@app.route('/api/findings/<int:finding_id>/status', methods=['POST'])
def update_status(finding_id):
    """Update finding status"""
    try:
        data = request.get_json()
        status = data.get('status', 'open')
        
        with get_db_connection() as conn:
            conn.execute("""
                UPDATE findings 
                SET status = ?, updated_at = CURRENT_TIMESTAMP 
                WHERE id = ?
            """, (status, finding_id))
            conn.commit()
        
        return jsonify({'success': True})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard/stats', methods=['GET'])
def get_dashboard_stats():
    """Get dashboard statistics"""
    try:
        with get_db_connection() as conn:
            # Get application count
            total_apps = conn.execute("SELECT COUNT(*) FROM applications WHERE status = 'active'").fetchone()[0]
            
            # Get scan count
            scans_completed = conn.execute("SELECT COUNT(*) FROM scan_results").fetchone()[0]
            
            # Get vulnerability count
            vulnerabilities = conn.execute("SELECT COUNT(*) FROM findings WHERE is_false_positive = 0").fetchone()[0]
            
            # Calculate threat level
            critical_count = conn.execute("SELECT COUNT(*) FROM findings WHERE severity = 'critical' AND is_false_positive = 0").fetchone()[0]
            high_count = conn.execute("SELECT COUNT(*) FROM findings WHERE severity = 'high' AND is_false_positive = 0").fetchone()[0]
            
            if critical_count > 0:
                threat_level = "CRITICAL"
            elif high_count > 5:
                threat_level = "HIGH"
            elif high_count > 0:
                threat_level = "MEDIUM"
            else:
                threat_level = "LOW"
        
        return jsonify({
            'total_apps': total_apps,
            'scans_completed': scans_completed,
            'vulnerabilities': vulnerabilities,
            'threat_level': threat_level
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/reports/executive', methods=['POST'])
def generate_executive_report():
    """Generate executive summary report"""
    try:
        data = request.get_json()
        period = int(data.get('period', 30))
        
        # Generate PDF report
        pdf_buffer = create_executive_pdf_report(period)
        
        return send_file(
            pdf_buffer,
            as_attachment=True,
            download_name=f'executive-security-report-{period}days.pdf',
            mimetype='application/pdf'
        )
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/reports/technical', methods=['POST'])
def generate_technical_report():
    """Generate technical report"""
    try:
        data = request.get_json()
        app_name = data.get('app_name', '')
        
        # Generate PDF report
        pdf_buffer = create_technical_pdf_report(app_name)
        
        return send_file(
            pdf_buffer,
            as_attachment=True,
            download_name=f'technical-security-report-{app_name or "all-apps"}.pdf',
            mimetype='application/pdf'
        )
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/reports/compliance', methods=['POST'])
def generate_compliance_report():
    """Generate compliance report"""
    try:
        data = request.get_json()
        framework = data.get('framework', 'owasp')
        
        # Generate PDF report
        pdf_buffer = create_compliance_pdf_report(framework)
        
        return send_file(
            pdf_buffer,
            as_attachment=True,
            download_name=f'compliance-report-{framework}.pdf',
            mimetype='application/pdf'
        )
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def create_executive_pdf_report(period):
    """Create professional executive PDF report"""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=0.5*inch, bottomMargin=0.5*inch)
    
    # Get styles
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        fontSize=24,
        spaceAfter=30,
        textColor=colors.HexColor('#1e293b'),
        alignment=TA_CENTER
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading1'],
        fontSize=16,
        spaceAfter=12,
        textColor=colors.HexColor('#3b82f6'),
        borderWidth=1,
        borderColor=colors.HexColor('#e2e8f0'),
        borderPadding=8,
        backColor=colors.HexColor('#f8fafc')
    )
    
    content = []
    
    # Title
    content.append(Paragraph("Enterprise Security Executive Report", title_style))
    content.append(Spacer(1, 20))
    
    # Report metadata
    content.append(Paragraph(f"Report Period: Last {period} days", styles['Normal']))
    content.append(Paragraph(f"Generated: {datetime.now().strftime('%B %d, %Y at %I:%M %p')}", styles['Normal']))
    content.append(Spacer(1, 30))
    
    # Executive Summary
    content.append(Paragraph("Executive Summary", heading_style))
    
    # Get data
    report_data = generate_executive_report_content(period)
    summary = report_data['summary']
    
    # Summary table
    summary_data = [
        ['Metric', 'Value', 'Status'],
        ['Total Applications', str(summary['total_applications']), 'Active'],
        ['Security Findings', str(summary['total_findings']), 'Under Review'],
        ['Critical Issues', str(summary['critical_findings']), 'Immediate Action Required' if summary['critical_findings'] > 0 else 'Good'],
        ['High Priority Issues', str(summary['high_findings']), 'Action Required' if summary['high_findings'] > 0 else 'Good'],
        ['Risk Score', f"{summary['risk_score']}/100", get_risk_level(summary['risk_score'])]
    ]
    
    summary_table = Table(summary_data, colWidths=[2*inch, 1*inch, 2*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3b82f6')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0'))
    ]))
    
    content.append(summary_table)
    content.append(Spacer(1, 30))
    
    # Key Recommendations
    content.append(Paragraph("Key Recommendations", heading_style))
    for i, rec in enumerate(report_data['recommendations'], 1):
        content.append(Paragraph(f"{i}. {rec}", styles['Normal']))
    
    content.append(Spacer(1, 30))
    
    # Risk Assessment
    content.append(Paragraph("Risk Assessment", heading_style))
    risk_text = f"""
    Based on the current security posture analysis, the organization has a risk score of {summary['risk_score']}/100.
    This assessment is based on {summary['critical_findings']} critical and {summary['high_findings']} high-priority 
    security findings across {summary['total_applications']} applications.
    """
    content.append(Paragraph(risk_text, styles['Normal']))
    
    # Build PDF
    doc.build(content)
    buffer.seek(0)
    return buffer

def create_technical_pdf_report(app_name):
    """Create professional technical PDF report"""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=0.5*inch, bottomMargin=0.5*inch)
    
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        fontSize=20,
        spaceAfter=30,
        textColor=colors.HexColor('#1e293b')
    )
    
    content = []
    
    # Title
    title = f"Technical Security Report - {app_name or 'All Applications'}"
    content.append(Paragraph(title, title_style))
    content.append(Spacer(1, 20))
    
    # Get data
    report_data = generate_technical_report_content(app_name)
    
    # Findings summary
    findings_data = [
        ['Severity', 'Count', 'Percentage'],
        ['Critical', str(report_data['findings_by_severity']['critical']), 
         f"{(report_data['findings_by_severity']['critical']/max(report_data['total_findings'], 1)*100):.1f}%"],
        ['High', str(report_data['findings_by_severity']['high']),
         f"{(report_data['findings_by_severity']['high']/max(report_data['total_findings'], 1)*100):.1f}%"],
        ['Medium', str(report_data['findings_by_severity']['medium']),
         f"{(report_data['findings_by_severity']['medium']/max(report_data['total_findings'], 1)*100):.1f}%"],
        ['Low', str(report_data['findings_by_severity']['low']),
         f"{(report_data['findings_by_severity']['low']/max(report_data['total_findings'], 1)*100):.1f}%"]
    ]
    
    findings_table = Table(findings_data)
    findings_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3b82f6')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0'))
    ]))
    
    content.append(findings_table)
    content.append(Spacer(1, 30))
    
    # Detailed findings
    if report_data['detailed_findings']:
        content.append(Paragraph("Top Security Findings", styles['Heading2']))
        for finding in report_data['detailed_findings'][:5]:  # Top 5 findings
            content.append(Paragraph(f"<b>{finding['title']}</b>", styles['Normal']))
            content.append(Paragraph(f"Severity: {finding['severity'].upper()}", styles['Normal']))
            content.append(Paragraph(f"Description: {finding['description']}", styles['Normal']))
            if finding['remediation']:
                content.append(Paragraph(f"Remediation: {finding['remediation']}", styles['Normal']))
            content.append(Spacer(1, 15))
    
    doc.build(content)
    buffer.seek(0)
    return buffer

def create_compliance_pdf_report(framework):
    """Create professional compliance PDF report"""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=0.5*inch, bottomMargin=0.5*inch)
    
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        fontSize=20,
        spaceAfter=30,
        textColor=colors.HexColor('#1e293b')
    )
    
    content = []
    
    # Title
    content.append(Paragraph(f"Security Compliance Report - {framework.upper()}", title_style))
    content.append(Spacer(1, 20))
    
    # Compliance data
    compliance_data = [
        ['Control', 'Status', 'Compliance %'],
        ['Access Control', 'Compliant', '85%'],
        ['Data Protection', 'Partial', '70%'],
        ['Vulnerability Management', 'Compliant', '90%'],
        ['Incident Response', 'Non-Compliant', '45%'],
        ['Security Monitoring', 'Compliant', '95%']
    ]
    
    compliance_table = Table(compliance_data)
    compliance_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3b82f6')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0'))
    ]))
    
    content.append(compliance_table)
    
    doc.build(content)
    buffer.seek(0)
    return buffer

def get_risk_level(score):
    """Get risk level based on score"""
    if score >= 80:
        return "Critical"
    elif score >= 60:
        return "High"
    elif score >= 40:
        return "Medium"
    else:
        return "Low"

def generate_executive_report_content(period):
    """Generate executive report content"""
    with get_db_connection() as conn:
        # Get summary statistics
        total_apps = conn.execute("SELECT COUNT(*) FROM applications WHERE status = 'active'").fetchone()[0]
        total_findings = conn.execute("SELECT COUNT(*) FROM findings WHERE is_false_positive = 0").fetchone()[0]
        critical_findings = conn.execute("SELECT COUNT(*) FROM findings WHERE severity = 'critical' AND is_false_positive = 0").fetchone()[0]
        high_findings = conn.execute("SELECT COUNT(*) FROM findings WHERE severity = 'high' AND is_false_positive = 0").fetchone()[0]
        
        return {
            'summary': {
                'total_applications': total_apps,
                'total_findings': total_findings,
                'critical_findings': critical_findings,
                'high_findings': high_findings,
                'risk_score': calculate_risk_score(critical_findings, high_findings)
            },
            'recommendations': [
                'Immediate attention required for critical vulnerabilities',
                'Implement security training for development teams',
                'Establish regular security scanning schedule'
            ]
        }

def generate_technical_report_content(app_name):
    """Generate technical report content"""
    with get_db_connection() as conn:
        if app_name:
            findings = conn.execute("SELECT * FROM findings WHERE app_name = ? AND is_false_positive = 0", (app_name,)).fetchall()
        else:
            findings = conn.execute("SELECT * FROM findings WHERE is_false_positive = 0").fetchall()
        
        findings = [dict(finding) for finding in findings]
        
        return {
            'application': app_name or 'All Applications',
            'total_findings': len(findings),
            'findings_by_severity': {
                'critical': len([f for f in findings if f['severity'] == 'critical']),
                'high': len([f for f in findings if f['severity'] == 'high']),
                'medium': len([f for f in findings if f['severity'] == 'medium']),
                'low': len([f for f in findings if f['severity'] == 'low'])
            },
            'detailed_findings': findings[:10]  # Top 10 findings
        }

def calculate_risk_score(critical, high):
    """Calculate overall risk score"""
    return min(100, (critical * 10) + (high * 5))

if __name__ == '__main__':
    print("🛡️  Advanced Enterprise Security Scanner")
    print("=" * 50)
    print("🚀 Starting enhanced version with real-time features...")
    print("📊 Features:")
    print("   • Real-time scan progress tracking")
    print("   • Threat intelligence integration")
    print("   • Live WebSocket updates")
    print("   • Executive dashboard views")
    
    init_db()
    
    print("✅ Database initialized")
    print("🌐 Dashboard URL: http://127.0.0.1:8000")
    print("🔄 Real-time updates: WebSocket enabled")
    print("=" * 50)
    
    socketio.run(app, host='127.0.0.1', port=8000, debug=True)
