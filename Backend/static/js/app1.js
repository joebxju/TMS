// Global Variables
const API_URL = window.location.origin;
let authToken = localStorage.getItem('authToken');
let currentUser = JSON.parse(localStorage.getItem('currentUser') || 'null');

// DOM Elements
const loginPage = document.getElementById('login-page');
const userDashboard = document.getElementById('user-dashboard');
const adminDashboard = document.getElementById('admin-dashboard');
const alertContainer = document.getElementById('alert-container');
const loginBtn = document.getElementById('login-btn');
const logoutBtn = document.getElementById('logout-btn');
const adminLogoutBtn = document.getElementById('admin-logout-btn');
const emailInput = document.getElementById('email');
const passwordInput = document.getElementById('password');

// User Dashboard Elements
const dashboardTab = document.getElementById('dashboard-tab');
const loginDetailsTab = document.getElementById('login-details-tab');
const dashboardSection = document.getElementById('dashboard-section');
const loginDetailsSection = document.getElementById('login-details-section');

// Tab Elements for Admin Dashboard
const loginAttemptsTab = document.getElementById('login-attempts-tab');
const blockedUsersTab = document.getElementById('blocked-users-tab');
const securityLogsTab = document.getElementById('security-logs-tab');
const apiCallsTab = document.getElementById('api-calls-tab');

// Section Elements for Admin Dashboard
const loginAttemptsSection = document.getElementById('login-attempts-section');
const blockedUsersSection = document.getElementById('blocked-users-section');
const securityLogsSection = document.getElementById('security-logs-section');
const apiCallsSection = document.getElementById('api-calls-section');

// Refresh Buttons
const refreshUserData = document.getElementById('refresh-user-data');
const refreshLoginAttempts = document.getElementById('refresh-login-attempts');
const refreshBlockedUsers = document.getElementById('refresh-blocked-users');
const refreshSecurityLogs = document.getElementById('refresh-security-logs');
const refreshApiCalls = document.getElementById('refresh-api-calls');

// Helper Functions
function showAlert(message, type = 'error') {
    alertContainer.textContent = message;
    alertContainer.className = `alert-container ${type}`;
    setTimeout(() => {
        alertContainer.className = 'alert-container';
    }, 5000);
}

function formatDateTime(isoString) {
    const date = new Date(isoString);
    return date.toLocaleString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: 'numeric',
        minute: 'numeric',
        second: 'numeric',
        hour12: true
    });
}

function updateDateTime() {
    const dateTimeElements = document.querySelectorAll('.date-time');
    const now = new Date();
    const formattedDateTime = now.toLocaleString('en-US', {
        weekday: 'long',
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: 'numeric',
        minute: 'numeric',
        second: 'numeric',
        hour12: true
    });
    
    dateTimeElements.forEach(element => {
        if (element) element.textContent = formattedDateTime;
    });
}

function showPage(pageId) {
    // Hide all pages
    document.querySelectorAll('.page').forEach(page => {
        page.classList.remove('active');
    });
    
    // Show the requested page
    document.getElementById(pageId).classList.add('active');
    
    // Update date and time
    updateDateTime();
}

function logout() {
    localStorage.removeItem('authToken');
    localStorage.removeItem('currentUser');
    authToken = null;
    currentUser = null;
    showPage('login-page');
}

// API Functions
async function login(email, password) {
    try {
        const response = await fetch(`${API_URL}/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, password })
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            if (response.status === 403) {
                if (data.message && data.message.includes('blocked')) {
                    showAlert(`Your account is temporarily blocked. ${data.message}`, 'warning');
                } else if (data.error && data.error.includes('Suspicious')) {
                    showAlert('Suspicious activity detected. If this was not you, please contact the administrator immediately.', 'error');
                } else {
                    throw new Error(data.error || 'Login failed');
                }
            } else {
                throw new Error(data.error || 'Login failed');
            }
            return false;
        }
        
        // Save auth token and user info
        authToken = data.token;
        localStorage.setItem('authToken', authToken);
        
        // Get user role from JWT token
        const tokenParts = authToken.split('.');
        const payload = JSON.parse(atob(tokenParts[1]));
        
        currentUser = {
            id: data.user_id,
            email: payload.email,
            role: payload.role
        };
        
        localStorage.setItem('currentUser', JSON.stringify(currentUser));
        
        // Redirect based on role
        if (currentUser.role === 'Admin') {
            document.getElementById('admin-email').textContent = currentUser.email;
            document.getElementById('admin-name').textContent = 'Administrator';
            showPage('admin-dashboard');
            loadAdminDashboardData();
        } else {
            document.getElementById('user-email').textContent = currentUser.email;
            document.getElementById('user-name').textContent = 'User';
            showPage('user-dashboard');
            loadUserDashboardData();
        }
        
        return true;
    } catch (error) {
        showAlert(error.message);
        return false;
    }
}

async function fetchWithAuth(url) {
    try {
        const response = await fetch(url, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        if (response.status === 401) {
            // Token expired or invalid
            showAlert('Your session has expired. Please login again.', 'warning');
            logout();
            return null;
        }
        
        if (!response.ok) {
            const data = await response.json();
            throw new Error(data.error || 'Request failed');
        }
        
        return await response.json();
    } catch (error) {
        showAlert(error.message);
        return null;
    }
}

// User Dashboard Functions
async function loadUserDashboardData() {
    const loginAttempts = await fetchWithAuth(`${API_URL}/user/login_attempts`);
    
    if (loginAttempts) {
        // Update login details table (without IP address)
        const tableBody = document.querySelector('#user-login-table tbody');
        tableBody.innerHTML = '';
        
        // Sort by timestamp (newest first)
        loginAttempts.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        
        loginAttempts.forEach(attempt => {
            const row = document.createElement('tr');
            
            const timeCell = document.createElement('td');
            timeCell.textContent = formatDateTime(attempt.timestamp);
            
            const statusCell = document.createElement('td');
            const statusBadge = document.createElement('span');
            statusBadge.className = `status-badge status-${attempt.status}`;
            statusBadge.textContent = attempt.status.charAt(0).toUpperCase() + attempt.status.slice(1);
            statusCell.appendChild(statusBadge);
            
            row.appendChild(timeCell);
            row.appendChild(statusCell);
            
            tableBody.appendChild(row);
        });
        
        // Setup security data for dashboard
        document.getElementById('login-attempts-count').textContent = loginAttempts.length;
        document.getElementById('security-status').textContent = 'Secure';
        
        // Set last login time
        if (loginAttempts.length > 0) {
            const lastSuccessfulLogin = loginAttempts.find(attempt => attempt.status === 'success');
            if (lastSuccessfulLogin) {
                document.getElementById('last-login').textContent = formatDateTime(lastSuccessfulLogin.timestamp);
            } else {
                document.getElementById('last-login').textContent = 'No successful logins';
            }
        } else {
            document.getElementById('last-login').textContent = 'No login history';
        }
    }
}

// Admin Dashboard Functions
async function loadAdminDashboardData() {
    try {
        // Show loading indicators
        document.getElementById('admin-login-attempts-count').textContent = '...';
        document.getElementById('blocked-users-count').textContent = '...';
        document.getElementById('security-alerts-count').textContent = '...';
        document.getElementById('total-users-count').textContent = '...';
        
        // Load all data in parallel
        const [loginAttempts, blockedUsers, securityLogs, apiCalls] = await Promise.all([
            fetchWithAuth(`${API_URL}/admin/login_attempts`),
            fetchWithAuth(`${API_URL}/admin/blocked_users`),
            fetchWithAuth(`${API_URL}/admin/logs`),
            fetchWithAuth(`${API_URL}/admin/api_calls`)
        ]);
        
        console.log('Security Logs:', securityLogs);
        console.log('API Calls:', apiCalls);
        
        if (loginAttempts) {
            // Update stats
            document.getElementById('admin-login-attempts-count').textContent = loginAttempts.length;
            
            // Get unique users
            const uniqueUsers = new Set();
            loginAttempts.forEach(attempt => {
                if (attempt.email) uniqueUsers.add(attempt.email);
            });
            document.getElementById('total-users-count').textContent = uniqueUsers.size;
            
            // Update login attempts table
            updateLoginAttemptsTable(loginAttempts);
        } else {
            document.getElementById('admin-login-attempts-count').textContent = '0';
        }
        
        if (blockedUsers) {
            // Update stats
            document.getElementById('blocked-users-count').textContent = blockedUsers.length;
            
            // Update blocked users table
            updateBlockedUsersTable(blockedUsers);
        } else {
            document.getElementById('blocked-users-count').textContent = '0';
        }
        
        if (securityLogs) {
            // Update stats
            document.getElementById('security-alerts-count').textContent = securityLogs.length;
            
            // Update security logs table
            updateSecurityLogsTable(securityLogs);
        } else {
            document.getElementById('security-alerts-count').textContent = '0';
            updateSecurityLogsTable([]);
        }
        
        if (apiCalls) {
            // Update API calls table
            updateApiCallsTable(apiCalls);
        } else {
            updateApiCallsTable([]);
        }
    } catch (error) {
        console.error('Error loading admin dashboard data:', error);
        showAlert('Failed to load dashboard data. Please try again.', 'error');
    }
}

function updateLoginAttemptsTable(loginAttempts) {
    const tableBody = document.querySelector('#login-attempts-table tbody');
    tableBody.innerHTML = '';
    
    // Sort by timestamp (newest first)
    loginAttempts.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    
    loginAttempts.forEach(attempt => {
        const row = document.createElement('tr');
        
        const timeCell = document.createElement('td');
        timeCell.textContent = formatDateTime(attempt.timestamp);
        
        const emailCell = document.createElement('td');
        emailCell.textContent = attempt.email || 'N/A';
        
        const ipCell = document.createElement('td');
        ipCell.textContent = attempt.ip_address;
        
        const statusCell = document.createElement('td');
        const statusBadge = document.createElement('span');
        statusBadge.className = `status-badge status-${attempt.status}`;
        statusBadge.textContent = attempt.status.charAt(0).toUpperCase() + attempt.status.slice(1);
        statusCell.appendChild(statusBadge);
        
        row.appendChild(timeCell);
        row.appendChild(emailCell);
        row.appendChild(ipCell);
        row.appendChild(statusCell);
        
        tableBody.appendChild(row);
    });
}

function updateBlockedUsersTable(blockedUsers) {
    const tableBody = document.querySelector('#blocked-users-table tbody');
    tableBody.innerHTML = '';
    
    // Sort by blocked_at (newest first)
    blockedUsers.sort((a, b) => new Date(b.blocked_at) - new Date(a.blocked_at));
    
    blockedUsers.forEach(user => {
        const row = document.createElement('tr');
        
        const emailCell = document.createElement('td');
        emailCell.textContent = user.email || 'N/A';
        
        const ipCell = document.createElement('td');
        ipCell.textContent = user.ip_address;
        
        const blockedAtCell = document.createElement('td');
        blockedAtCell.textContent = formatDateTime(user.blocked_at);
        
        const unblockAtCell = document.createElement('td');
        unblockAtCell.textContent = formatDateTime(user.unblock_at);
        
        const reasonCell = document.createElement('td');
        reasonCell.textContent = user.reason;
        
        row.appendChild(emailCell);
        row.appendChild(ipCell);
        row.appendChild(blockedAtCell);
        row.appendChild(unblockAtCell);
        row.appendChild(reasonCell);
        
        tableBody.appendChild(row);
    });
}

function updateSecurityLogsTable(securityLogs) {
    const tableBody = document.querySelector('#security-logs-table tbody');
    tableBody.innerHTML = '';
    
    if (!securityLogs || securityLogs.length === 0) {
        const emptyRow = document.createElement('tr');
        const emptyCell = document.createElement('td');
        emptyCell.colSpan = 4;
        emptyCell.textContent = 'No security logs available';
        emptyCell.style.textAlign = 'center';
        emptyCell.style.padding = '20px';
        emptyRow.appendChild(emptyCell);
        tableBody.appendChild(emptyRow);
        return;
    }
    
    // Sort by timestamp (newest first)
    securityLogs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    
    securityLogs.forEach(log => {
        const row = document.createElement('tr');
        
        const timeCell = document.createElement('td');
        timeCell.textContent = formatDateTime(log.timestamp);
        
        const ipCell = document.createElement('td');
        ipCell.textContent = log.ip_address || 'Unknown';
        
        const attackTypeCell = document.createElement('td');
        attackTypeCell.textContent = log.attack_type || 'Unknown';
        
        const statusCell = document.createElement('td');
        const statusBadge = document.createElement('span');
        // Ensure status exists and is a string before calling toLowerCase
        const statusClass = log.status ? log.status.toLowerCase() : 'unknown';
        statusBadge.className = `status-badge status-${statusClass}`;
        statusBadge.textContent = log.status || 'Unknown';
        statusCell.appendChild(statusBadge);
        
        row.appendChild(timeCell);
        row.appendChild(ipCell);
        row.appendChild(attackTypeCell);
        row.appendChild(statusCell);
        
        tableBody.appendChild(row);
    });
    
    // Make the section visible
    document.getElementById('security-logs-section').classList.remove('hidden');
}

function updateApiCallsTable(apiCalls) {
    const tableBody = document.querySelector('#api-calls-table tbody');
    tableBody.innerHTML = '';
    
    if (!apiCalls || apiCalls.length === 0) {
        const emptyRow = document.createElement('tr');
        const emptyCell = document.createElement('td');
        emptyCell.colSpan = 4;
        emptyCell.textContent = 'No API calls data available';
        emptyCell.style.textAlign = 'center';
        emptyCell.style.padding = '20px';
        emptyRow.appendChild(emptyCell);
        tableBody.appendChild(emptyRow);
        return;
    }
    
    // Sort by timestamp (newest first)
    apiCalls.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    
    apiCalls.forEach(call => {
        const row = document.createElement('tr');
        
        const timeCell = document.createElement('td');
        timeCell.textContent = formatDateTime(call.timestamp);
        
        const ipCell = document.createElement('td');
        ipCell.textContent = call.ip_address;
        
        const endpointCell = document.createElement('td');
        endpointCell.textContent = call.endpoint;
        
        const methodCell = document.createElement('td');
        const methodBadge = document.createElement('span');
        // Ensure method exists and is a string before calling toLowerCase
        const methodClass = call.method ? call.method.toLowerCase() : 'unknown';
        methodBadge.className = `status-badge status-${methodClass}`;
        methodBadge.textContent = call.method || 'Unknown';
        methodCell.appendChild(methodBadge);
        
        row.appendChild(timeCell);
        row.appendChild(ipCell);
        row.appendChild(endpointCell);
        row.appendChild(methodCell);
        
        tableBody.appendChild(row);
    });
    
    // Make the section visible
    document.getElementById('api-calls-section').classList.remove('hidden');
}

// Event Listeners
document.addEventListener('DOMContentLoaded', () => {
    // Check if user is already logged in
    if (authToken && currentUser) {
        if (currentUser.role === 'Admin') {
            document.getElementById('admin-email').textContent = currentUser.email;
            document.getElementById('admin-name').textContent = 'Administrator';
            showPage('admin-dashboard');
            loadAdminDashboardData();
        } else {
            document.getElementById('user-email').textContent = currentUser.email;
            document.getElementById('user-name').textContent = 'User';
            showPage('user-dashboard');
            loadUserDashboardData();
        }
    } else {
        showPage('login-page');
    }
    
    // Update date and time every second
    setInterval(updateDateTime, 1000);
    
    // User Dashboard Tab Navigation
    if (dashboardTab) {
        dashboardTab.addEventListener('click', (e) => {
            e.preventDefault();
            document.querySelectorAll('.data-section').forEach(section => section.classList.add('hidden'));
            dashboardSection.classList.remove('hidden');
            
            document.querySelectorAll('.sidebar-menu li').forEach(item => item.classList.remove('active'));
            dashboardTab.parentElement.classList.add('active');
        });
    }
    
    if (loginDetailsTab) {
        loginDetailsTab.addEventListener('click', (e) => {
            e.preventDefault();
            document.querySelectorAll('.data-section').forEach(section => section.classList.add('hidden'));
            loginDetailsSection.classList.remove('hidden');
            
            document.querySelectorAll('.sidebar-menu li').forEach(item => item.classList.remove('active'));
            loginDetailsTab.parentElement.classList.add('active');
        });
    }
    
    // Login button
    loginBtn.addEventListener('click', async () => {
        const email = emailInput.value.trim();
        const password = passwordInput.value.trim();
        
        if (!email || !password) {
            showAlert('Please enter both email and password');
            return;
        }
        
        loginBtn.disabled = true;
        loginBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Logging in...';
        
        const success = await login(email, password);
        
        loginBtn.disabled = false;
        loginBtn.innerHTML = 'Login <i class="fas fa-sign-in-alt"></i>';
        
        if (success) {
            emailInput.value = '';
            passwordInput.value = '';
        }
    });
    
    // Logout buttons
    if (logoutBtn) logoutBtn.addEventListener('click', logout);
    if (adminLogoutBtn) adminLogoutBtn.addEventListener('click', logout);
    
    // Admin dashboard tabs
    if (loginAttemptsTab) {
        loginAttemptsTab.addEventListener('click', (e) => {
            e.preventDefault();
            document.querySelectorAll('.data-section').forEach(section => section.classList.add('hidden'));
            loginAttemptsSection.classList.remove('hidden');
            
            document.querySelectorAll('.sidebar-menu li').forEach(item => item.classList.remove('active'));
            loginAttemptsTab.parentElement.classList.add('active');
        });
    }
    
    if (blockedUsersTab) {
        blockedUsersTab.addEventListener('click', (e) => {
            e.preventDefault();
            document.querySelectorAll('.data-section').forEach(section => section.classList.add('hidden'));
            blockedUsersSection.classList.remove('hidden');
            
            document.querySelectorAll('.sidebar-menu li').forEach(item => item.classList.remove('active'));
            blockedUsersTab.parentElement.classList.add('active');
        });
    }
    
    if (securityLogsTab) {
        securityLogsTab.addEventListener('click', (e) => {
            e.preventDefault();
            document.querySelectorAll('.data-section').forEach(section => section.classList.add('hidden'));
            securityLogsSection.classList.remove('hidden');
            
            document.querySelectorAll('.sidebar-menu li').forEach(item => item.classList.remove('active'));
            securityLogsTab.parentElement.classList.add('active');
        });
    }
    
    if (apiCallsTab) {
        apiCallsTab.addEventListener('click', (e) => {
            e.preventDefault();
            document.querySelectorAll('.data-section').forEach(section => section.classList.add('hidden'));
            apiCallsSection.classList.remove('hidden');
            
            document.querySelectorAll('.sidebar-menu li').forEach(item => item.classList.remove('active'));
            apiCallsTab.parentElement.classList.add('active');
        });
    }
    
    // Refresh buttons
    if (refreshUserData) refreshUserData.addEventListener('click', loadUserDashboardData);
    if (refreshLoginAttempts) refreshLoginAttempts.addEventListener('click', () => fetchWithAuth(`${API_URL}/admin/login_attempts`).then(updateLoginAttemptsTable));
    if (refreshBlockedUsers) refreshBlockedUsers.addEventListener('click', () => fetchWithAuth(`${API_URL}/admin/blocked_users`).then(updateBlockedUsersTable));
    if (refreshSecurityLogs) refreshSecurityLogs.addEventListener('click', () => fetchWithAuth(`${API_URL}/admin/logs`).then(updateSecurityLogsTable));
    if (refreshApiCalls) refreshApiCalls.addEventListener('click', () => fetchWithAuth(`${API_URL}/admin/api_calls`).then(updateApiCallsTable));
    
    // Enter key for login
    passwordInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            loginBtn.click();
        }
    });
});