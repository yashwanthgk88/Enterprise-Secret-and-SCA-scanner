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
    // Use timeout to ensure DOM is fully ready
    setTimeout(() => {
        loadApplications();
    }, 1000);
    loadFindings();
    loadRecentScans();
    
    // Set up form submission
    document.getElementById('onboardForm').addEventListener('submit', handleOnboardSubmit);
    
    // Set up repository type change handler
    const repoTypeElement = document.getElementById('repoType');
    if (repoTypeElement) {
        repoTypeElement.addEventListener('change', handleRepoTypeChange);
        console.log('Repository type change handler attached');
    } else {
        console.error('Repository type element not found');
    }
    
    // Set up local path browser
    const browseButton = document.getElementById('browseLocalPath');
    const pathPicker = document.getElementById('localPathPicker');
    if (browseButton) {
        browseButton.addEventListener('click', handleBrowseLocalPath);
    }
    if (pathPicker) {
        pathPicker.addEventListener('change', handleLocalPathSelection);
    }
    
    // Auto-refresh every 30 seconds
    setInterval(loadDashboardStats, 30000);
    
    // Auto-refresh applications every 10 seconds to show scan progress
    setInterval(loadApplications, 10000);
    
    // Initialize form state
    initializeOnboardForm();
    
    // Start real-time progress monitoring
    startProgressMonitoring();
});

// Initialize onboard form state
function initializeOnboardForm() {
    // Ensure repository input groups are properly hidden initially
    const repoUrlGroup = document.getElementById('repoUrlGroup');
    const localPathGroup = document.getElementById('localPathGroup');
    
    if (repoUrlGroup) repoUrlGroup.style.display = 'none';
    if (localPathGroup) localPathGroup.style.display = 'none';
    
    console.log('Onboard form initialized');
}

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
    console.log('=== Loading applications ===');
    const container = document.getElementById('applicationsList');
    
    if (!container) {
        console.error('Applications container not found!');
        return;
    }
    
    try {
        // Show loading state
        container.innerHTML = '<div class="text-center py-4"><div class="spinner-border text-light" role="status"></div><div class="text-white mt-2">Loading applications...</div></div>';
        
        // Direct fetch instead of using apiCall
        const response = await fetch('/api/applications/list');
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const data = await response.json();
        console.log('Applications data received:', data);
        
        if (!data || !Array.isArray(data.applications)) {
            throw new Error('Invalid response format');
        }
        
        applications = data.applications;
        console.log('Found', applications.length, 'applications');
        
        // Render applications immediately
        renderApplicationsSimple();
        updateFindingsFilter();
        
    } catch (error) {
        console.error('Failed to load applications:', error);
        container.innerHTML = `
            <div class="text-center py-4">
                <div class="text-danger mb-3">
                    <i class="fas fa-exclamation-triangle fa-2x"></i>
                </div>
                <h5 class="text-white">Error Loading Applications</h5>
                <p class="text-white-50">${error.message}</p>
                <button class="btn btn-gradient" onclick="loadApplications()">
                    <i class="fas fa-sync-alt me-2"></i>Retry
                </button>
                <button class="btn btn-warning ms-2" onclick="debugApplications()">
                    Debug
                </button>
            </div>
        `;
    }
}

// Simple, reliable rendering function
function renderApplicationsSimple() {
    const container = document.getElementById('applicationsList');
    
    if (!container) {
        console.error('Container not found');
        return;
    }
    
    if (!applications || applications.length === 0) {
        container.innerHTML = `
            <div class="text-center py-5">
                <div class="text-white-50 mb-3">
                    <i class="fas fa-folder-open fa-3x"></i>
                </div>
                <h5 class="text-white">No Applications Found</h5>
                <p class="text-white-50">Get started by onboarding your first application.</p>
                <button class="btn btn-gradient" onclick="document.getElementById('onboard-tab').click()">
                    <i class="fas fa-plus me-2"></i>Onboard Application
                </button>
            </div>
        `;
        return;
    }
    
    let html = '';
    applications.forEach(app => {
        html += `
            <div class="app-card mb-3" style="background: rgba(255,255,255,0.1); border-radius: 15px; padding: 20px;">
                <div class="d-flex justify-content-between align-items-start">
                    <div class="flex-grow-1">
                        <h5 class="text-white mb-2">
                            <i class="fas fa-cube me-2"></i>${app.name}
                            ${app.scanning ? '<span class="badge bg-warning ms-2"><i class="fas fa-spinner fa-spin me-1"></i>Scanning...</span>' : ''}
                        </h5>
                        <div class="mb-2">
                            <span class="badge bg-secondary me-2">${app.language || 'Unknown'}</span>
                            <span class="badge bg-info me-2">${app.framework || 'Unknown'}</span>
                            <span class="badge bg-${getCriticalityColor(app.criticality)}">${app.criticality || 'medium'}</span>
                        </div>
                        <div class="text-white-50 small">
                            <div><i class="fas fa-code-branch me-2"></i>${app.repo_type}: ${(app.repo_url || app.local_path || '').substring(0, 60)}${(app.repo_url || app.local_path || '').length > 60 ? '...' : ''}</div>
                            <div><i class="fas fa-users me-2"></i>Team: ${app.team || 'N/A'} | Owner: ${app.owner || 'N/A'}</div>
                            <div><i class="fas fa-clock me-2"></i>Created: ${new Date(app.created_at).toLocaleDateString()}</div>
                        </div>
                    </div>
                    <div class="d-flex flex-column gap-2">
                        <button class="btn btn-sm btn-gradient" onclick="scanApplication('${app.name}')" ${app.scanning ? 'disabled' : ''}>
                            <i class="fas fa-search me-1"></i>Scan
                        </button>
                        <button class="btn btn-sm btn-outline-light" onclick="viewApplication('${app.name}')">
                            <i class="fas fa-eye me-1"></i>View
                        </button>
                    </div>
                </div>
            </div>
        `;
    });
    
    container.innerHTML = html;
    console.log('Applications rendered successfully');
}

function renderApplications() {
    console.log('=== renderApplications called ===');
    const container = document.getElementById('applicationsList');
    console.log('Container element:', container);
    console.log('Container innerHTML before:', container ? container.innerHTML.substring(0, 100) : 'null');
    console.log('Applications array:', applications);
    console.log('Applications length:', applications ? applications.length : 'null');
    
    if (!container) {
        console.error('Applications container not found!');
        return;
    }
    
    if (!applications || applications.length === 0) {
        container.innerHTML = `
            <div class="text-center py-5">
                <div class="text-white-50 mb-3">
                    <i class="fas fa-folder-open fa-3x"></i>
                </div>
                <h5 class="text-white">No Applications Found</h5>
                <p class="text-white-50">Get started by onboarding your first application.</p>
                <button class="btn btn-gradient" onclick="document.getElementById('onboard-tab').click()">
                    <i class="fas fa-plus me-2"></i>Onboard Application
                </button>
            </div>
        `;
        return;
    }
    
    const html = applications.map(app => `
        <div class="app-card" id="app-${app.name}">
            <div class="d-flex justify-content-between align-items-start">
                <div class="flex-grow-1">
                    <h5 class="mb-2">
                        ${app.name}
                        ${app.scanning ? '<span class="badge bg-warning ms-2"><i class="fas fa-spinner fa-spin me-1"></i>Scanning...</span>' : ''}
                    </h5>
                    <div class="mb-2">
                        <span class="badge bg-secondary me-2">${app.language || 'Unknown'}</span>
                        <span class="badge bg-info me-2">${app.framework || 'Unknown'}</span>
                        <span class="badge bg-${getCriticalityColor(app.criticality)}">${app.criticality}</span>
                    </div>
                    <div class="text-white-50 small mb-2">
                        <div><i class="fas fa-code-branch me-2"></i>${app.repo_type}: ${truncateText(app.repo_url || app.local_path, 50)}</div>
                        <div><i class="fas fa-users me-2"></i>Team: ${app.team || 'N/A'} | Owner: ${app.owner || 'N/A'}</div>
                        <div><i class="fas fa-clock me-2"></i>Last scan: ${formatDate(app.last_scan_at)}</div>
                    </div>
                    ${app.scanning ? `
                        <div id="progress-${app.name}" class="mb-2">
                            <div class="d-flex justify-content-between align-items-center mb-1">
                                <small class="text-white-50">Scan Progress</small>
                                <small class="text-white-50" id="progress-percentage-${app.name}">0%</small>
                            </div>
                            <div class="progress" style="height: 6px;">
                                <div id="progress-bar-${app.name}" class="progress-bar progress-bar-striped progress-bar-animated" 
                                     role="progressbar" style="width: 0%"></div>
                            </div>
                            <small id="progress-status-${app.name}" class="text-white-50">Initializing...</small>
                        </div>
                    ` : ''}
                </div>
                <div class="d-flex flex-column gap-2">
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
    
    console.log('Generated HTML length:', html.length);
    console.log('Generated HTML preview:', html.substring(0, 200));
    container.innerHTML = html;
    console.log('Container innerHTML after setting:', container.innerHTML.substring(0, 200));
    console.log('=== renderApplications complete ===');
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

function truncateText(text, maxLength) {
    if (!text) return 'N/A';
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...';
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
    
    console.log('Repository type changed to:', repoType);
    
    if (!repoUrlGroup || !localPathGroup) {
        console.error('Repository input groups not found');
        return;
    }
    
    // Hide both groups first
    repoUrlGroup.style.display = 'none';
    localPathGroup.style.display = 'none';
    
    // Show appropriate group based on selection
    if (repoType === 'local') {
        localPathGroup.style.display = 'block';
        console.log('Showing local path group');
    } else if (repoType && repoType !== '') {
        repoUrlGroup.style.display = 'block';
        console.log('Showing repository URL group');
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

// Force load applications function
async function forceLoadApplications() {
    const container = document.getElementById('applicationsList');
    container.innerHTML = '<div class="text-center py-4"><div class="spinner-border text-light"></div><div class="text-white mt-2">Force loading...</div></div>';
    
    try {
        const response = await fetch('/api/applications/list');
        const data = await response.json();
        const apps = data.applications || [];
        
        if (apps.length > 0) {
            let html = '';
            apps.forEach(app => {
                html += `
                    <div class="mb-3" style="background: rgba(255,255,255,0.1); border-radius: 15px; padding: 20px;">
                        <div class="d-flex justify-content-between align-items-start">
                            <div class="flex-grow-1">
                                <h5 class="text-white mb-2">
                                    <i class="fas fa-cube me-2"></i>${app.name}
                                </h5>
                                <div class="mb-2">
                                    <span class="badge bg-secondary me-2">${app.language || 'Unknown'}</span>
                                    <span class="badge bg-info me-2">${app.framework || 'Unknown'}</span>
                                    <span class="badge bg-warning">${app.criticality || 'medium'}</span>
                                </div>
                                <div class="text-white-50 small">
                                    <div><i class="fas fa-code-branch me-2"></i>${app.repo_type}: ${(app.repo_url || app.local_path || '').substring(0, 60)}</div>
                                    <div><i class="fas fa-users me-2"></i>Team: ${app.team || 'N/A'} | Owner: ${app.owner || 'N/A'}</div>
                                    <div><i class="fas fa-clock me-2"></i>Created: ${app.created_at}</div>
                                </div>
                            </div>
                            <div class="d-flex flex-column gap-2">
                                <button class="btn btn-sm btn-gradient" onclick="scanApplication('${app.name}')">
                                    <i class="fas fa-search me-1"></i>Scan
                                </button>
                                <button class="btn btn-sm btn-outline-light" onclick="viewApplication('${app.name}')">
                                    <i class="fas fa-eye me-1"></i>View
                                </button>
                            </div>
                        </div>
                    </div>
                `;
            });
            container.innerHTML = html;
        } else {
            container.innerHTML = '<div class="text-center py-4 text-white">No applications found</div>';
        }
    } catch (error) {
        container.innerHTML = `<div class="text-center py-4 text-danger">Error: ${error.message}</div>`;
    }
}

// Show applications directly (hardcoded known apps)
function showApplicationsDirectly() {
    const container = document.getElementById('applicationsList');
    container.innerHTML = `
        <div class="mb-3" style="background: rgba(255,255,255,0.1); border-radius: 15px; padding: 20px;">
            <div class="d-flex justify-content-between align-items-start">
                <div class="flex-grow-1">
                    <h5 class="text-white mb-2">
                        <i class="fas fa-cube me-2"></i>juiceshop
                    </h5>
                    <div class="mb-2">
                        <span class="badge bg-secondary me-2">JavaScript</span>
                        <span class="badge bg-info me-2">Angular</span>
                        <span class="badge bg-danger">high</span>
                    </div>
                    <div class="text-white-50 small">
                        <div><i class="fas fa-code-branch me-2"></i>github: https://github.com/vulnerable-apps/juice-shop</div>
                        <div><i class="fas fa-users me-2"></i>Team: owasp | Owner: owasp</div>
                        <div><i class="fas fa-clock me-2"></i>Created: 2025-09-10 13:29:50</div>
                    </div>
                </div>
                <div class="d-flex flex-column gap-2">
                    <button class="btn btn-sm btn-gradient" onclick="scanApplication('juiceshop')">
                        <i class="fas fa-search me-1"></i>Scan
                    </button>
                    <button class="btn btn-sm btn-outline-light" onclick="viewApplication('juiceshop')">
                        <i class="fas fa-eye me-1"></i>View
                    </button>
                </div>
            </div>
        </div>
        <div class="mb-3" style="background: rgba(255,255,255,0.1); border-radius: 15px; padding: 20px;">
            <div class="d-flex justify-content-between align-items-start">
                <div class="flex-grow-1">
                    <h5 class="text-white mb-2">
                        <i class="fas fa-cube me-2"></i>test
                    </h5>
                    <div class="mb-2">
                        <span class="badge bg-secondary me-2">Unknown</span>
                        <span class="badge bg-info me-2">Unknown</span>
                        <span class="badge bg-warning">medium</span>
                    </div>
                    <div class="text-white-50 small">
                        <div><i class="fas fa-code-branch me-2"></i>github: https://github.com/yashwanthgk88/Enterprise-Secret-and-SCA-scanner/</div>
                        <div><i class="fas fa-users me-2"></i>Team: test | Owner: test</div>
                        <div><i class="fas fa-clock me-2"></i>Created: 2025-09-10 13:25:04</div>
                    </div>
                </div>
                <div class="d-flex flex-column gap-2">
                    <button class="btn btn-sm btn-gradient" onclick="scanApplication('test')">
                        <i class="fas fa-search me-1"></i>Scan
                    </button>
                    <button class="btn btn-sm btn-outline-light" onclick="viewApplication('test')">
                        <i class="fas fa-eye me-1"></i>View
                    </button>
                </div>
            </div>
        </div>
    `;
}

// Test API function
async function testAPI() {
    const container = document.getElementById('applicationsList');
    container.innerHTML = '<div class="text-center py-4"><div class="text-white">Testing API...</div></div>';
    
    try {
        const response = await fetch('/api/applications/list');
        const data = await response.json();
        
        container.innerHTML = `
            <div class="text-white p-4">
                <h5>API Test Results:</h5>
                <p><strong>Status:</strong> ${response.status}</p>
                <p><strong>Applications Count:</strong> ${data.applications ? data.applications.length : 0}</p>
                <pre style="background: #222; padding: 10px; border-radius: 5px; font-size: 12px;">${JSON.stringify(data, null, 2)}</pre>
                <button class="btn btn-success mt-3" onclick="forceLoadApplications()">Load Applications</button>
            </div>
        `;
    } catch (error) {
        container.innerHTML = `<div class="text-danger p-4">API Test Failed: ${error.message}</div>`;
    }
}

// Debug function
async function debugApplications() {
    testAPI();
}

// Real-time progress monitoring
function startProgressMonitoring() {
    setInterval(updateScanProgress, 2000); // Update every 2 seconds
}

async function updateScanProgress() {
    try {
        const data = await apiCall('/scan/status');
        const activeScans = data.active_scans || {};
        const scanProgress = data.scan_progress || {};
        
        // Update progress for each active scan
        Object.keys(activeScans).forEach(appName => {
            const progress = scanProgress[appName];
            if (progress) {
                updateProgressUI(appName, progress);
            }
        });
        
    } catch (error) {
        console.error('Failed to update scan progress:', error);
    }
}

function updateProgressUI(appName, progress) {
    const progressBar = document.getElementById(`progress-bar-${appName}`);
    const progressPercentage = document.getElementById(`progress-percentage-${appName}`);
    const progressStatus = document.getElementById(`progress-status-${appName}`);
    
    if (progressBar && progressPercentage && progressStatus) {
        const percentage = progress.percentage || 0;
        progressBar.style.width = `${percentage}%`;
        progressPercentage.textContent = `${percentage}%`;
        
        let statusText = progress.status || 'Scanning...';
        if (progress.current_file) {
            statusText += ` - ${truncateText(progress.current_file, 30)}`;
        }
        if (progress.secrets_found || progress.vulnerabilities_found) {
            statusText += ` (${progress.secrets_found || 0} secrets, ${progress.vulnerabilities_found || 0} vulns)`;
        }
        progressStatus.textContent = statusText;
        
        // Update progress bar color based on findings
        progressBar.className = 'progress-bar progress-bar-striped progress-bar-animated';
        if (progress.secrets_found > 0 || progress.vulnerabilities_found > 0) {
            progressBar.classList.add('bg-warning');
        }
    }
}

async function scanApplication(appName) {
    try {
        showLoading('Starting scan...');
        
        const response = await apiCall('/scan', {
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
