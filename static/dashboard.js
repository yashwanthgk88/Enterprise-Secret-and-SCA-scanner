/**
 * Dashboard JavaScript for Enterprise Security Scanner
 * Handles UI interactions, API calls, and chart rendering
 */

// Global variables
let severityChart = null;
let activityChart = null;
let applications = [];
let findings = [];

// Initialize dashboard when page loads
document.addEventListener('DOMContentLoaded', function() {
    loadDashboardStats();
    loadApplications();
    loadFindings();
    loadRecentScans();
    
    // Set up form submission
    document.getElementById('onboardForm').addEventListener('submit', handleOnboardSubmit);
    
    // Set up repository type change handler
    document.getElementById('repoType').addEventListener('change', handleRepoTypeChange);
    
    // Set up local path browser
    document.getElementById('browseLocalPath').addEventListener('click', handleBrowseLocalPath);
    document.getElementById('localPathPicker').addEventListener('change', handleLocalPathSelection);
    
    // Auto-refresh every 30 seconds
    setInterval(loadDashboardStats, 30000);
});

// API helper functions
async function apiCall(endpoint, options = {}) {
    try {
        const response = await fetch(`/api${endpoint}`, {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || `HTTP ${response.status}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error(`API call failed for ${endpoint}:`, error);
        showAlert('error', `API Error: ${error.message}`);
        throw error;
    }
}

// Dashboard statistics
async function loadDashboardStats() {
    try {
        const data = await apiCall('/stats');
        const stats = data.stats;
        
        // Update stat cards
        document.getElementById('totalApps').textContent = stats.total_applications || 0;
        
        const secretFindings = stats.secret_findings || {};
        const scaFindings = stats.sca_findings || {};
        
        const critical = (secretFindings.critical || 0) + (scaFindings.critical || 0);
        const high = (secretFindings.high || 0) + (scaFindings.high || 0);
        const medium = (secretFindings.medium || 0) + (scaFindings.medium || 0);
        const low = (secretFindings.low || 0) + (scaFindings.low || 0);
        
        document.getElementById('criticalFindings').textContent = critical;
        document.getElementById('highFindings').textContent = high;
        document.getElementById('totalFindings').textContent = critical + high + medium + low;
        
        // Update charts
        updateSeverityChart(critical, high, medium, low);
        updateActivityChart(stats.scan_activity || []);
        
    } catch (error) {
        console.error('Failed to load dashboard stats:', error);
    }
}

// Chart functions
function updateSeverityChart(critical, high, medium, low) {
    const ctx = document.getElementById('severityChart').getContext('2d');
    
    if (severityChart) {
        severityChart.destroy();
    }
    
    severityChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [critical, high, medium, low],
                backgroundColor: [
                    '#dc3545',
                    '#fd7e14',
                    '#ffc107',
                    '#198754'
                ],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    labels: {
                        color: 'white'
                    }
                }
            }
        }
    });
}

function updateActivityChart(activityData) {
    const ctx = document.getElementById('activityChart').getContext('2d');
    
    if (activityChart) {
        activityChart.destroy();
    }
    
    const labels = activityData.map(item => item.scan_date);
    const data = activityData.map(item => item.count);
    
    activityChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Scans',
                data: data,
                borderColor: '#4facfe',
                backgroundColor: 'rgba(79, 172, 254, 0.1)',
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: 'white'
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                },
                x: {
                    ticks: {
                        color: 'white'
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                }
            },
            plugins: {
                legend: {
                    labels: {
                        color: 'white'
                    }
                }
            }
        }
    });
}

// Application management
async function loadApplications() {
    try {
        console.log('Loading applications...');
        const data = await apiCall('/applications/list');
        console.log('Applications data received:', data);
        applications = data.applications;
        console.log('Applications array:', applications);
        renderApplications();
        updateFindingsFilter();
    } catch (error) {
        console.error('Failed to load applications:', error);
        // Show error in UI
        const container = document.getElementById('applicationsList');
        if (container) {
            container.innerHTML = '<div class="text-danger text-center py-4">Error loading applications. Please refresh the page.</div>';
        }
    }
}

function renderApplications() {
    const container = document.getElementById('applicationsList');
    console.log('Rendering applications, container:', container);
    console.log('Applications to render:', applications);
    
    if (!container) {
        console.error('Applications container not found!');
        return;
    }
    
    if (!applications || applications.length === 0) {
        container.innerHTML = '<div class="text-white text-center py-4">No applications onboarded yet.</div>';
        return;
    }
    
    const html = applications.map(app => `
        <div class="app-card">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <h5 class="mb-2">
                        ${app.name}
                        ${app.scanning ? '<span class="badge bg-warning ms-2">Scanning...</span>' : ''}
                    </h5>
                    <div class="mb-2">
                        <span class="badge bg-secondary me-2">${app.language || 'Unknown'}</span>
                        <span class="badge bg-info me-2">${app.framework || 'Unknown'}</span>
                        <span class="badge bg-${getCriticalityColor(app.criticality)}">${app.criticality}</span>
                    </div>
                    <div class="text-white-50 small">
                        <div><i class="fas fa-code-branch me-2"></i>${app.repo_type}: ${app.repo_url || app.local_path}</div>
                        <div><i class="fas fa-users me-2"></i>Team: ${app.team || 'N/A'} | Owner: ${app.owner || 'N/A'}</div>
                        <div><i class="fas fa-clock me-2"></i>Last scan: ${formatDate(app.last_scan_at)}</div>
                    </div>
                </div>
                <div class="d-flex gap-2">
                    <button class="btn btn-sm btn-gradient" onclick="scanApplication('${app.name}')" ${app.scanning ? 'disabled' : ''}>
                        <i class="fas fa-search me-1"></i>Scan
                    </button>
                    <button class="btn btn-sm btn-outline-light" onclick="viewApplication('${app.name}')">
                        <i class="fas fa-eye me-1"></i>View
                    </button>
                </div>
            </div>
        </div>
    `).join('');
    
    container.innerHTML = html;
}

function getCriticalityColor(criticality) {
    const colors = {
        'low': 'success',
        'medium': 'warning',
        'high': 'danger',
        'critical': 'dark'
    };
    return colors[criticality] || 'secondary';
}

function formatDate(dateString) {
    if (!dateString) return 'Never';
    return new Date(dateString).toLocaleDateString();
}

// Onboarding functions
async function validateRepository() {
    const repoUrl = document.getElementById('repoUrl').value;
    const repoType = document.getElementById('repoType').value;
    const accessToken = document.getElementById('accessToken').value;
    
    if (!repoUrl) {
        showAlert('warning', 'Please enter a repository URL or path');
        return;
    }
    
    showLoading('Validating repository...');
    
    try {
        const data = await apiCall('/applications/validate', {
            method: 'POST',
            body: JSON.stringify({
                repo_url: repoUrl,
                repo_type: repoType,
                access_token: accessToken
            })
        });
        
        hideLoading();
        
        if (data.valid) {
            showAlert('success', `Repository validated: ${data.message}`);
        } else {
            showAlert('error', `Validation failed: ${data.message}`);
        }
    } catch (error) {
        hideLoading();
        showAlert('danger', 'Error validating repository: ' + error.message);
    }
}

// Onboard application with progress tracking
async function onboardApplication() {
    const formData = {
        name: document.getElementById('appName').value,
        repo_type: document.getElementById('repoType').value,
        repo_url: document.getElementById('repoUrl').value,
        local_path: document.getElementById('localPath').value,
        team: document.getElementById('team').value,
        owner: document.getElementById('owner').value,
        criticality: document.getElementById('criticality').value,
        access_token: document.getElementById('accessToken').value,
        auto_scan: document.getElementById('autoScan').checked
    };

    try {
        // Show progress section
        showProgress();
        
        const response = await fetch('/api/applications/onboard', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(formData)
        });

        const result = await response.json();
        
        if (response.ok) {
            // Start listening for progress updates
            listenForProgress(result.operation_id);
        } else {
            hideProgress();
            showAlert('danger', result.error);
        }
    } catch (error) {
        hideProgress();
        showAlert('danger', 'Error onboarding application: ' + error.message);
    }
}

// Show progress section
function showProgress() {
    document.getElementById('onboardProgress').style.display = 'block';
    document.getElementById('progressDetails').style.display = 'block';
    document.getElementById('onboardForm').style.opacity = '0.6';
    document.getElementById('onboardForm').style.pointerEvents = 'none';
    
    // Reset progress
    updateProgress(0, 'Initializing...', 'starting');
    resetProgressSteps();
}

// Hide progress section
function hideProgress() {
    document.getElementById('onboardProgress').style.display = 'none';
    document.getElementById('onboardForm').style.opacity = '1';
    document.getElementById('onboardForm').style.pointerEvents = 'auto';
}

// Update progress bar and message
function updateProgress(percentage, message, status) {
    const progressBar = document.getElementById('progressBar');
    const progressPercentage = document.getElementById('progressPercentage');
    const progressMessage = document.getElementById('progressMessage');
    
    progressBar.style.width = percentage + '%';
    progressPercentage.textContent = percentage + '%';
    progressMessage.textContent = message;
    
    // Update progress bar color based on status
    progressBar.className = 'progress-bar progress-bar-striped progress-bar-animated';
    if (status === 'completed') {
        progressBar.classList.add('bg-success');
    } else if (status === 'failed') {
        progressBar.classList.add('bg-danger');
    } else {
        progressBar.classList.add('bg-primary');
    }
}

// Reset progress steps
function resetProgressSteps() {
    const steps = ['stepValidating', 'stepCloning', 'stepAnalyzing', 'stepScanning'];
    steps.forEach(stepId => {
        const step = document.getElementById(stepId);
        const icon = step.querySelector('i');
        icon.className = 'fas fa-check-circle text-muted';
    });
}

// Update progress step
function updateProgressStep(stepName, status) {
    const stepId = 'step' + stepName.charAt(0).toUpperCase() + stepName.slice(1);
    const step = document.getElementById(stepId);
    if (!step) return;
    
    const icon = step.querySelector('i');
    
    if (status === 'active') {
        icon.className = 'fas fa-spinner fa-spin text-primary';
    } else if (status === 'completed') {
        icon.className = 'fas fa-check-circle text-success';
    } else if (status === 'failed') {
        icon.className = 'fas fa-times-circle text-danger';
    }
}

// Listen for progress updates using Server-Sent Events
function listenForProgress(operationId) {
    const eventSource = new EventSource(`/api/progress/${operationId}`);
    
    eventSource.onmessage = function(event) {
        try {
            const data = JSON.parse(event.data);
            
            if (data.type === 'heartbeat') {
                return; // Ignore heartbeat messages
            }
            
            if (data.error) {
                hideProgress();
                showAlert('danger', data.error);
                eventSource.close();
                return;
            }
            
            // Update progress bar
            updateProgress(data.percentage, data.message, data.status);
            
            // Update progress steps based on status
            if (data.status === 'validating') {
                updateProgressStep('validating', 'active');
            } else if (data.status === 'cloning') {
                updateProgressStep('validating', 'completed');
                updateProgressStep('cloning', 'active');
            } else if (data.status === 'analyzing') {
                updateProgressStep('cloning', 'completed');
                updateProgressStep('analyzing', 'active');
            } else if (data.status === 'scanning') {
                updateProgressStep('analyzing', 'completed');
                updateProgressStep('scanning', 'active');
            } else if (data.status === 'completed') {
                updateProgressStep('scanning', 'completed');
                
                setTimeout(() => {
                    hideProgress();
                    showAlert('success', data.message);
                    document.getElementById('onboardForm').reset();
                    loadApplications();
                    eventSource.close();
                }, 2000);
            } else if (data.status === 'failed') {
                // Mark current step as failed
                const currentStep = getCurrentStep(data.percentage);
                if (currentStep) {
                    updateProgressStep(currentStep, 'failed');
                }
                
                setTimeout(() => {
                    hideProgress();
                    showAlert('danger', data.message);
                    eventSource.close();
                }, 2000);
            }
            
        } catch (error) {
            console.error('Error parsing progress data:', error);
        }
    };
    
    eventSource.onerror = function(event) {
        console.error('EventSource failed:', event);
        hideProgress();
        showAlert('danger', 'Connection lost. Please try again.');
        eventSource.close();
    };
}

// Get current step based on percentage
function getCurrentStep(percentage) {
    if (percentage <= 20) return 'validating';
    if (percentage <= 40) return 'cloning';
    if (percentage <= 70) return 'analyzing';
    if (percentage <= 95) return 'scanning';
    return null;
}

// Handle repository type change
function handleRepoTypeChange() {
    const repoType = document.getElementById('repoType').value;
    const repoUrlGroup = document.getElementById('repoUrlGroup');
    const localPathGroup = document.getElementById('localPathGroup');
    
    // Hide both groups first
    repoUrlGroup.style.display = 'none';
    localPathGroup.style.display = 'none';
    
    // Show appropriate group based on selection
    if (repoType === 'local') {
        localPathGroup.style.display = 'block';
    } else if (repoType && repoType !== '') {
        repoUrlGroup.style.display = 'block';
    }
}

// Handle browse local path button click
function handleBrowseLocalPath() {
    document.getElementById('localPathPicker').click();
}

// Handle local path selection
function handleLocalPathSelection(event) {
    const files = event.target.files;
    if (files.length > 0) {
        // Get the directory path from the first file
        const firstFile = files[0];
        const directoryPath = firstFile.webkitRelativePath.split('/')[0];
        
        // For security reasons, browsers don't provide full system paths
        // Show the relative directory name and prompt for full path
        const localPathInput = document.getElementById('localPath');
        
        // If the input is empty, suggest the directory name
        if (!localPathInput.value.trim()) {
            localPathInput.value = directoryPath;
        }
        
        // Show informative message
        showAlert('info', `Directory "${directoryPath}" selected (${files.length} files). Please verify or update the full path in the input field.`);
        
        // Focus on the input field for manual editing
        localPathInput.focus();
        localPathInput.select();
    }
}

// Scanning functions
async function scanApplication(appName) {
    showLoading(`Starting scan for ${appName}...`);
    
    try {
        await apiCall('/scan', {
            method: 'POST',
            body: JSON.stringify({
                applications: [appName],
                scan_type: 'full'
            })
        });
        
        hideLoading();
        showAlert('success', `Scan started for ${appName}`);
        loadApplications(); // Refresh to show scanning status
        
    } catch (error) {
        hideLoading();
        showAlert('error', `Failed to start scan: ${error.message}`);
    }
}

// Findings management
async function loadFindings() {
    try {
        const appFilter = document.getElementById('findingsFilter')?.value || '';
        const severityFilter = document.getElementById('severityFilter')?.value || '';
        
        const params = new URLSearchParams();
        if (appFilter) params.append('app_name', appFilter);
        if (severityFilter) params.append('severity', severityFilter);
        
        const data = await apiCall(`/findings?${params.toString()}`);
        findings = data.findings;
        renderFindings();
        
    } catch (error) {
        console.error('Failed to load findings:', error);
    }
}

function renderFindings() {
    const container = document.getElementById('findingsList');
    
    if (findings.length === 0) {
        container.innerHTML = '<div class="text-white text-center py-4">No findings found.</div>';
        return;
    }
    
    const html = findings.map(finding => `
        <div class="app-card">
            <div class="d-flex justify-content-between align-items-start">
                <div class="flex-grow-1">
                    <div class="d-flex align-items-center mb-2">
                        <span class="badge bg-${getSeverityColor(finding.severity)} me-2">${finding.severity.toUpperCase()}</span>
                        <span class="badge bg-secondary me-2">${finding.type.toUpperCase()}</span>
                        <h6 class="mb-0">${finding.title}</h6>
                    </div>
                    <div class="text-white-50 small">
                        <div><i class="fas fa-cube me-2"></i>Application: ${finding.app_name}</div>
                        <div><i class="fas fa-file me-2"></i>File: ${finding.file_path}:${finding.line_number}</div>
                        <div><i class="fas fa-clock me-2"></i>Found: ${formatDate(finding.created_at)}</div>
                        ${finding.confidence ? `<div><i class="fas fa-percentage me-2"></i>Confidence: ${Math.round(finding.confidence * 100)}%</div>` : ''}
                    </div>
                </div>
                <div class="text-end">
                    <span class="badge bg-${finding.status === 'open' ? 'danger' : 'success'}">${finding.status}</span>
                </div>
            </div>
        </div>
    `).join('');
    
    container.innerHTML = html;
}

function getSeverityColor(severity) {
    const colors = {
        'critical': 'danger',
        'high': 'warning',
        'medium': 'info',
        'low': 'success'
    };
    return colors[severity] || 'secondary';
}

function updateFindingsFilter() {
    const select = document.getElementById('findingsFilter');
    if (!select) return;
    
    const currentValue = select.value;
    select.innerHTML = '<option value="">All Applications</option>';
    
    applications.forEach(app => {
        const option = document.createElement('option');
        option.value = app.name;
        option.textContent = app.name;
        if (app.name === currentValue) option.selected = true;
        select.appendChild(option);
    });
}

// Scan history
async function loadRecentScans() {
    try {
        console.log('Loading recent scans...');
        const data = await apiCall('/scans/recent?limit=20');
        console.log('Scans data received:', data);
        renderRecentScans(data.scans);
    } catch (error) {
        console.error('Failed to load recent scans:', error);
        // Show error in UI
        const container = document.getElementById('scansList');
        if (container) {
            container.innerHTML = '<div class="text-danger text-center py-4">Error loading scans. Please refresh the page.</div>';
        }
    }
}

function renderRecentScans(scans) {
    const container = document.getElementById('scansList');
    console.log('Rendering scans, container:', container);
    console.log('Scans to render:', scans);
    
    if (!container) {
        console.error('Scans container not found!');
        return;
    }
    
    if (!scans || scans.length === 0) {
        container.innerHTML = '<div class="text-white text-center py-4">No scans found.</div>';
        return;
    }
    
    const html = scans.map(scan => `
        <div class="app-card">
            <div class="d-flex justify-content-between align-items-center">
                <div>
                    <h6 class="mb-2">${scan.app_name}</h6>
                    <div class="text-white-50 small">
                        <div><i class="fas fa-search me-2"></i>Type: ${scan.scan_type}</div>
                        <div><i class="fas fa-clock me-2"></i>Started: ${formatDateTime(scan.started_at)}</div>
                        ${scan.completed_at ? `<div><i class="fas fa-check me-2"></i>Completed: ${formatDateTime(scan.completed_at)}</div>` : ''}
                    </div>
                </div>
                <div class="text-end">
                    <span class="badge bg-${getScanStatusColor(scan.status)} mb-2">${scan.status}</span>
                    <div class="small text-white-50">
                        <div>Secrets: ${scan.secrets_found || 0}</div>
                        <div>Vulnerabilities: ${scan.vulnerabilities_found || 0}</div>
                    </div>
                </div>
            </div>
        </div>
    `).join('');
    
    container.innerHTML = html;
}

function getScanStatusColor(status) {
    const colors = {
        'running': 'warning',
        'completed': 'success',
        'failed': 'danger'
    };
    return colors[status] || 'secondary';
}

function formatDateTime(dateString) {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleString();
}

// Export functions
async function exportFindings() {
    try {
        const appFilter = document.getElementById('findingsFilter')?.value || '';
        const severityFilter = document.getElementById('severityFilter')?.value || '';
        
        const params = new URLSearchParams();
        if (appFilter) params.append('app_name', appFilter);
        if (severityFilter) params.append('severity', severityFilter);
        
        const response = await fetch(`/api/findings/export?${params.toString()}`);
        
        if (!response.ok) {
            throw new Error(`Export failed: ${response.status}`);
        }
        
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'security_findings.csv';
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        
        showAlert('success', 'Findings exported successfully!');
        
    } catch (error) {
        showAlert('error', `Export failed: ${error.message}`);
    }
}

// Utility functions
function refreshApplications() {
    loadApplications();
    loadDashboardStats();
}

function viewApplication(appName) {
    // Switch to findings tab and filter by application
    const findingsTab = document.getElementById('findings-tab');
    const findingsFilter = document.getElementById('findingsFilter');
    
    findingsTab.click();
    setTimeout(() => {
        findingsFilter.value = appName;
        loadFindings();
    }, 100);
}

function showLoading(text = 'Loading...') {
    document.getElementById('loadingText').textContent = text;
    const modal = new bootstrap.Modal(document.getElementById('loadingModal'));
    modal.show();
}

function hideLoading() {
    const modal = bootstrap.Modal.getInstance(document.getElementById('loadingModal'));
    if (modal) modal.hide();
}

function showAlert(type, message) {
    // Create alert element
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type === 'error' ? 'danger' : type} alert-dismissible fade show position-fixed`;
    alertDiv.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(alertDiv);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (alertDiv.parentNode) {
            alertDiv.remove();
        }
    }, 5000);
}
