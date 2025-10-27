// Admin Panel JavaScript

// State
let isAuthenticated = false;
let sessionStartTime = null;
let sessionTimerInterval = null;
const SESSION_TIMEOUT_SECONDS = 300; // 5 minutes
let sessionExpiredByTimeout = false; // Track if logout was due to timeout
let allLogs = []; // Store all logs for filtering
let currentTab = 'api-keys'; // Track current tab
let currentLogFile = ''; // Track currently selected log file
let liveViewInterval = null; // Interval for live view auto-refresh
let availableLogFiles = []; // Store available log files

// DOM Elements
const loginSection = document.getElementById('login-section');
const adminDashboard = document.getElementById('admin-dashboard');
const loginForm = document.getElementById('login-form');
const loginError = document.getElementById('login-error');
const addKeyForm = document.getElementById('add-key-form');
const generatedKeySection = document.getElementById('generated-key-section');
const generatedKey = document.getElementById('generated-key');
const keysList = document.getElementById('keys-list');
const logoutBtn = document.getElementById('logout-btn');
let timerDisplay = null;
let sessionTimer = null;
let timeoutBanner = null;

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    // Get timer elements after DOM is loaded
    timerDisplay = document.getElementById('timer-display');
    sessionTimer = document.getElementById('session-timer');
    timeoutBanner = document.getElementById('timeout-banner');
    
    // Try to load keys to check if already authenticated
    checkAuthentication();

    // Whitelist allowed characters in key name field
    const keyNameInput = document.getElementById('key-name');
    if (keyNameInput) {
        keyNameInput.addEventListener('input', (e) => {
            // Only allow alphanumeric, hyphens, underscores, and spaces
            const sanitized = e.target.value.replace(/[^A-Za-z0-9_ -]/g, '');
            if (e.target.value !== sanitized) {
                e.target.value = sanitized;
            }
        });
    }

    // Permission checkboxes and admin key
    const permCheckboxIds = [
        'perm-generate-secret',
        'perm-repositories-add',
        'perm-repositories-verify',
        'perm-repositories-update',
        'perm-repositories-delete',
        'perm-events-list',
        'perm-permissions-list',
        'perm-permissions-calculate',
        'perm-permissions-decode'
    ];
    const adminKeyCheckbox = document.getElementById('is-admin-key');
    const generateBtn = document.getElementById('generate-key-btn');

    function updateGenerateBtnState() {
        const anyChecked = permCheckboxIds.some(id => document.getElementById(id).checked);
        if (adminKeyCheckbox.checked || anyChecked) {
            generateBtn.disabled = false;
            generateBtn.textContent = 'Generate API Key';
            generateBtn.title = '';
        } else {
            generateBtn.disabled = true;
            generateBtn.textContent = 'Select at least one permission';
            generateBtn.title = 'Please select at least one permission or enable admin key';
        }
    }
    permCheckboxIds.forEach(id => {
        document.getElementById(id).addEventListener('change', updateGenerateBtnState);
    });
    adminKeyCheckbox.addEventListener('change', updateGenerateBtnState);
    updateGenerateBtnState();
});

// Login
loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const password = document.getElementById('admin-password').value;

    try {
        const response = await fetch('/admin/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password })
        });

        if (response.ok) {
            isAuthenticated = true;
            sessionStartTime = Date.now();
            sessionExpiredByTimeout = false; // Reset timeout flag on successful login
            showDashboard();
            startSessionTimer();
            loadKeys();
        } else {
            const data = await response.json();
            showError(data.error || 'Invalid password');
        }
    } catch (error) {
        showError('Login failed. Please try again.');
        console.error('Login error:', error);
    }
});

// Logout
logoutBtn.addEventListener('click', async () => {
    try {
        await fetch('/admin/api/logout', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        sessionExpiredByTimeout = false; // User initiated logout, not a timeout
        performLogout();
    } catch (error) {
        console.error('Logout error:', error);
        sessionExpiredByTimeout = false;
        performLogout();
    }
});

// Add Key
addKeyForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const name = document.getElementById('key-name').value;
    const isAdminKey = document.getElementById('is-admin-key').checked;
    
    let permissionsBitmap = 0, rate_limit;
    if (isAdminKey) {
        // Admin keys have special permissions and unlimited rate
        permissionsBitmap = -1; // Use -1 or a special value for full access
        rate_limit = 0;
    } else {
        // Build bitmap from checkboxes (bits 0-8 for 9 permissions)
        if (document.getElementById('perm-generate-secret').checked) permissionsBitmap |= (1 << 0);
        if (document.getElementById('perm-repositories-add').checked) permissionsBitmap |= (1 << 1);
        if (document.getElementById('perm-repositories-verify').checked) permissionsBitmap |= (1 << 2);
        if (document.getElementById('perm-repositories-update').checked) permissionsBitmap |= (1 << 3);
        if (document.getElementById('perm-repositories-delete').checked) permissionsBitmap |= (1 << 4);
        if (document.getElementById('perm-events-list').checked) permissionsBitmap |= (1 << 5);
        if (document.getElementById('perm-permissions-list').checked) permissionsBitmap |= (1 << 6);
        if (document.getElementById('perm-permissions-calculate').checked) permissionsBitmap |= (1 << 7);
        if (document.getElementById('perm-permissions-decode').checked) permissionsBitmap |= (1 << 8);
        rate_limit = parseInt(document.getElementById('key-rate-limit').value);
    }

    try {
        const response = await fetch('/admin/api/keys', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, permissions: permissionsBitmap, rate_limit, is_admin_key: isAdminKey })
        });

        if (response.ok) {
            const data = await response.json();
            showGeneratedKey(data.api_key, data.permissions, data.rate_limit, data.is_admin_key);
            document.getElementById('key-name').value = '';
            document.getElementById('is-admin-key').checked = false;
            document.getElementById('perm-generate-secret').checked = false;
            document.getElementById('perm-repositories-add').checked = false;
            document.getElementById('perm-repositories-verify').checked = false;
            document.getElementById('perm-repositories-update').checked = false;
            document.getElementById('perm-repositories-delete').checked = false;
            document.getElementById('perm-events-list').checked = false;
            document.getElementById('perm-permissions-list').checked = false;
            document.getElementById('perm-permissions-calculate').checked = false;
            document.getElementById('perm-permissions-decode').checked = false;
            document.getElementById('key-rate-limit').value = '100';
            toggleAdminKeyOptions(); // Reset visibility
            resetSessionTimer(); // Reset timer on successful API call
            loadKeys();
            // Update button state after reset
            const generateBtn = addKeyForm.querySelector('button[type="submit"]');
            generateBtn.disabled = true;
        } else if (response.status === 401) {
            const data = await response.json();
            const errorMsg = data.error || 'Unauthorized';
            if (errorMsg.includes('Session expired') || errorMsg.includes('Session invalidated')) {
                sessionExpiredByTimeout = true;
                performLogout();
            } else {
                alert('Error: ' + (data.error || 'Failed to create API key'));
            }
        } else {
            const data = await response.json();
            alert('Error: ' + (data.error || 'Failed to create API key'));
        }
    } catch (error) {
        alert('Failed to create API key. Please try again.');
        console.error('Create key error:', error);
    }
});

// Toggle admin key options visibility
function toggleAdminKeyOptions() {
    const isAdminKey = document.getElementById('is-admin-key').checked;
    const regularOptions = document.getElementById('regular-key-options');
    
    if (isAdminKey) {
        regularOptions.style.display = 'none';
    } else {
        regularOptions.style.display = 'block';
    }
}

// Check Authentication
async function checkAuthentication() {
    // Try to load keys to check if session is still valid
    try {
        const response = await fetch('/admin/api/keys');
        if (response.ok) {
            // Session is still valid, show dashboard
            isAuthenticated = true;
            sessionStartTime = Date.now();
            sessionExpiredByTimeout = false;
            showDashboard();
            startSessionTimer();
            const data = await response.json();
            renderKeys(data.keys);
        } else {
            // Not authenticated, show login
            showLogin();
        }
    } catch (error) {
        // Network error or other issue, show login
        console.error('Auth check error:', error);
        showLogin();
    }
}

// Load Keys
async function loadKeys() {
    try {
        const response = await fetch('/admin/api/keys');
        if (response.ok) {
            const data = await response.json();
            renderKeys(data.keys);
            resetSessionTimer(); // Reset timer on successful API call
        } else if (response.status === 401) {
            const data = await response.json();
            const errorMsg = data.error || 'Unauthorized';
            
            // Handle session expiration/invalidation
            if (errorMsg.includes('Session expired') || errorMsg.includes('Session invalidated')) {
                sessionExpiredByTimeout = true;
                performLogout();
            } else {
                isAuthenticated = false;
                showLogin();
            }
        } else {
            keysList.innerHTML = '<p class="error-message">Failed to load API keys</p>';
        }
    } catch (error) {
        keysList.innerHTML = '<p class="error-message">Failed to load API keys</p>';
        console.error('Load keys error:', error);
    }
}

// Render Keys
function renderKeys(keys) {
    if (keys.length === 0) {
        keysList.innerHTML = `
            <div class="empty-state">
                <p>No API keys yet.</p>
                <p>Generate one above to get started.</p>
            </div>
        `;
        document.getElementById('bulk-actions').style.display = 'none';
        return;
    }

    const table = document.createElement('table');
    table.className = 'keys-table';
    
    // Create thead
    const thead = document.createElement('thead');
    thead.innerHTML = `
        <tr>
            <th class="col-checkbox"><input type="checkbox" class="key-checkbox-header" onchange="toggleSelectAll(this)"></th>
            <th class="col-name">Name</th>
            <th class="col-type">Type</th>
            <th class="col-status">Status</th>
            <th class="col-permissions">Permissions</th>
            <th class="col-rate">Rate Limit</th>
            <th class="col-created">Created</th>
            <th class="col-used">Last Used</th>
            <th class="col-actions">Actions</th>
        </tr>
    `;
    table.appendChild(thead);
    
    // Create tbody using DOM methods instead of innerHTML for security
    const tbody = document.createElement('tbody');
    
    keys.forEach(key => {
        const isAdminKey = key.is_admin_key || false;
        const permissionsBitmap = key.permissions || 0;
        
        const tr = document.createElement('tr');
        
        // Checkbox column
        const tdCheckbox = document.createElement('td');
        tdCheckbox.className = 'col-checkbox';
        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.className = 'key-checkbox';
        checkbox.value = String(key.id);
        checkbox.onchange = updateBulkActions;
        tdCheckbox.appendChild(checkbox);
        tr.appendChild(tdCheckbox);
        
        // Name column
        const tdName = document.createElement('td');
        tdName.className = 'col-name';
        tdName.title = key.name;
        tdName.textContent = key.name;
        tr.appendChild(tdName);
        
        // Type column
        const tdType = document.createElement('td');
        tdType.className = 'col-type';
        tdType.innerHTML = `<span class="badge badge-type ${isAdminKey ? 'badge-admin' : 'badge-regular'}">${isAdminKey ? '👑 Admin' : '🔑 Regular'}</span>`;
        tr.appendChild(tdType);
        
        // Status column
        const tdStatus = document.createElement('td');
        tdStatus.className = 'col-status';
        tdStatus.innerHTML = `<span class="badge badge-status ${key.is_active ? 'badge-active' : 'badge-inactive'}">${key.is_active ? '✅ Active' : '❌ Inactive'}</span>`;
        tr.appendChild(tdStatus);
        
        // Permissions column
        const tdPerms = document.createElement('td');
        tdPerms.className = 'col-permissions';
        if (isAdminKey || permissionsBitmap === -1) {
            tdPerms.innerHTML = '<span class="perm-full-access">FULL ACCESS</span>';
        } else {
            const permFullNames = [
                'Generate Secret',
                'Add Repository',
                'Verify Repository',
                'Update Repository',
                'Delete Repository'
            ];
            let enabled = [];
            for (let i = 0; i < permFullNames.length; i++) {
                if ((permissionsBitmap & (1 << i)) !== 0) {
                    enabled.push(permFullNames[i]);
                }
            }
            if (enabled.length === 0) {
                tdPerms.innerHTML = '<span class="perm-none">No Permissions</span>';
            } else {
                const permsDiv = document.createElement('div');
                permsDiv.className = 'perm-badges';
                enabled.forEach(p => {
                    const badge = document.createElement('span');
                    badge.className = 'perm-badge';
                    badge.textContent = p;
                    permsDiv.appendChild(badge);
                });
                tdPerms.appendChild(permsDiv);
            }
        }
        tr.appendChild(tdPerms);
        
        // Rate limit column
        const tdRate = document.createElement('td');
        tdRate.className = 'col-rate';
        const rateSpan = document.createElement('span');
        rateSpan.className = 'rate-limit';
        rateSpan.textContent = isAdminKey ? '∞' : (key.rate_limit === 0 ? '∞' : String(key.rate_limit || 100) + '/hr');
        tdRate.appendChild(rateSpan);
        tr.appendChild(tdRate);
        
        // Created column
        const tdCreated = document.createElement('td');
        tdCreated.className = 'col-created';
        tdCreated.textContent = formatDate(key.created_at);
        tr.appendChild(tdCreated);
        
        // Last used column
        const tdUsed = document.createElement('td');
        tdUsed.className = 'col-used';
        if (key.last_used) {
            tdUsed.textContent = formatDate(key.last_used);
        } else {
            tdUsed.innerHTML = '<span class="text-muted">Never</span>';
        }
        tr.appendChild(tdUsed);
        
        // Actions column
        const tdActions = document.createElement('td');
        tdActions.className = 'col-actions';
        const actionsDiv = document.createElement('div');
        actionsDiv.className = 'action-buttons';
        
        const canEdit = !isAdminKey;
        
        if (canEdit) {
            const editBtn = document.createElement('button');
            editBtn.className = 'btn btn-sm btn-primary';
            editBtn.textContent = 'Edit';
            editBtn.title = 'Edit this API key';
            editBtn.onclick = () => editKey(Number(key.id), Number(permissionsBitmap), Number(key.rate_limit || 100));
            actionsDiv.appendChild(editBtn);
        } else {
            const disabledBtn = document.createElement('button');
            disabledBtn.className = 'btn btn-sm btn-disabled';
            disabledBtn.disabled = true;
            disabledBtn.textContent = "Can't edit admin key";
            disabledBtn.title = 'Admin keys cannot be edited';
            actionsDiv.appendChild(disabledBtn);
        }
        
        const toggleBtn = document.createElement('button');
        toggleBtn.className = `btn btn-sm ${key.is_active ? 'btn-warning' : 'btn-success'}`;
        toggleBtn.textContent = key.is_active ? 'Deactivate' : 'Activate';
        toggleBtn.title = key.is_active ? 'Deactivate this API key' : 'Activate this API key';
        toggleBtn.onclick = () => toggleKey(Number(key.id));
        actionsDiv.appendChild(toggleBtn);
        
        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'btn btn-sm btn-danger';
        deleteBtn.textContent = 'Delete';
        deleteBtn.title = 'Delete this API key permanently';
        deleteBtn.onclick = () => deleteKey(Number(key.id), key.name);
        actionsDiv.appendChild(deleteBtn);
        
        tdActions.appendChild(actionsDiv);
        tr.appendChild(tdActions);
        
        tbody.appendChild(tr);
    });
    
    table.appendChild(tbody);
    keysList.innerHTML = '';
    keysList.appendChild(table);
    updateBulkActions();
}

// Toggle Key
async function toggleKey(keyId) {
    try {
        const response = await fetch(`/admin/api/keys/${keyId}/toggle`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        if (response.ok) {
            resetSessionTimer(); // Reset timer on successful API call
            loadKeys();
        } else if (response.status === 401) {
            const data = await response.json();
            const errorMsg = data.error || 'Unauthorized';
            if (errorMsg.includes('Session expired') || errorMsg.includes('Session invalidated')) {
                sessionExpiredByTimeout = true;
                performLogout();
            } else {
                alert('Error: ' + (data.error || 'Failed to toggle API key'));
            }
        } else {
            const data = await response.json();
            alert('Error: ' + (data.error || 'Failed to toggle API key'));
        }
    } catch (error) {
        alert('Failed to toggle API key. Please try again.');
        console.error('Toggle key error:', error);
    }
}

// Delete Key
async function deleteKey(keyId, keyName) {
    if (!confirm(`Are you sure you want to delete the API key "${keyName}"?\n\nThis action cannot be undone and will immediately revoke access for this key.`)) {
        return;
    }

    try {
        const response = await fetch(`/admin/api/keys/${keyId}`, {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' }
        });

        if (response.ok) {
            resetSessionTimer(); // Reset timer on successful API call
            loadKeys();
        } else if (response.status === 401) {
            const data = await response.json();
            const errorMsg = data.error || 'Unauthorized';
            if (errorMsg.includes('Session expired') || errorMsg.includes('Session invalidated')) {
                sessionExpiredByTimeout = true;
                performLogout();
            } else {
                alert('Error: ' + (data.error || 'Failed to delete API key'));
            }
        } else {
            const data = await response.json();
            alert('Error: ' + (data.error || 'Failed to delete API key'));
        }
    } catch (error) {
        alert('Failed to delete API key. Please try again.');
        console.error('Delete key error:', error);
    }
}

// Show Generated Key
function showGeneratedKey(apiKey, permissions, rateLimit, isAdminKey) {
    generatedKey.textContent = apiKey;
    generatedKeySection.style.display = 'block';
    
    const infoText = generatedKeySection.querySelector('.info-text');
    infoText.innerHTML = ''; // Clear existing content
    
    // Create elements using DOM methods for security
    const typeLabel = document.createElement('strong');
    typeLabel.textContent = 'Type:';
    infoText.appendChild(typeLabel);
    infoText.appendChild(document.createTextNode(' ' + (isAdminKey ? 'Admin Key' : 'Regular API Key')));
    infoText.appendChild(document.createElement('br'));
    
    const permLabel = document.createElement('strong');
    permLabel.textContent = 'Permissions:';
    infoText.appendChild(permLabel);
    infoText.appendChild(document.createTextNode(' '));
    
    if (isAdminKey || permissions === -1) {
        const adminSpan = document.createElement('strong');
        adminSpan.style.color = 'var(--warning-color)';
        adminSpan.textContent = 'FULL ACCESS (Admin Key)';
        infoText.appendChild(adminSpan);
    } else {
        const permNames = [
            'Generate-Secret',
            'Add Repository',
            'Verify Repository',
            'Update Repository',
            'Delete Repository'
        ];
        let enabled = [];
        for (let i = 0; i < permNames.length; i++) {
            if ((permissions & (1 << i)) !== 0) enabled.push(permNames[i]);
        }
        infoText.appendChild(document.createTextNode(enabled.length ? enabled.join(', ') : 'No Access'));
    }
    infoText.appendChild(document.createElement('br'));
    
    const rateLabel = document.createElement('strong');
    rateLabel.textContent = 'Rate Limit:';
    infoText.appendChild(rateLabel);
    infoText.appendChild(document.createTextNode(' '));
    
    const rateLimitText = (isAdminKey || rateLimit === 0) ? 'unlimited' : String(rateLimit) + ' requests/hour';
    infoText.appendChild(document.createTextNode(rateLimitText));
    infoText.appendChild(document.createElement('br'));
    
    infoText.appendChild(document.createTextNode('Use this key in the Authorization header: '));
    const codeEl = document.createElement('code');
    codeEl.textContent = 'Authorization: Bearer YOUR_API_KEY';
    infoText.appendChild(codeEl);
    
    // Scroll to the generated key
    generatedKeySection.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

// Copy Generated Key
function copyGeneratedKey(event) {
    const key = generatedKey.textContent;
    navigator.clipboard.writeText(key).then(() => {
        const btn = event ? event.target : document.querySelector('#generated-key-section button');
        const originalText = btn.textContent;
        btn.textContent = 'Copied!';
        btn.style.backgroundColor = '#28a745';
        setTimeout(() => {
            btn.textContent = originalText;
            btn.style.backgroundColor = '';
        }, 2000);
    }).catch(err => {
        console.error('Copy failed:', err);
        alert('Failed to copy to clipboard');
    });
}

// UI Helpers
function showDashboard() {
    loginSection.style.display = 'none';
    adminDashboard.style.display = 'block';
    generatedKeySection.style.display = 'none';
    // Hide timeout banner when dashboard is shown
    if (timeoutBanner) {
        timeoutBanner.style.display = 'none';
    }
}

function showLogin() {
    loginSection.style.display = 'block';
    adminDashboard.style.display = 'none';
    document.getElementById('admin-password').value = '';
    loginError.style.display = 'none';
    // Don't hide timeout banner here - let it stay visible if it was shown
}

function showError(message) {
    loginError.textContent = message;
    loginError.style.display = 'block';
}

// Session Management
function startSessionTimer() {
    // Clear any existing timer
    if (sessionTimerInterval) {
        clearInterval(sessionTimerInterval);
    }

    updateTimerDisplay();
    
    sessionTimerInterval = setInterval(() => {
        updateTimerDisplay();
    }, 1000); // Update every second
}

function resetSessionTimer() {
    // Reset the session start time to extend the session
    sessionStartTime = Date.now();
    updateTimerDisplay();
}

function updateTimerDisplay() {
    if (!sessionStartTime) {
        return;
    }
    
    if (!timerDisplay || !sessionTimer) {
        return;
    }

    const elapsedSeconds = Math.floor((Date.now() - sessionStartTime) / 1000);
    const remainingSeconds = Math.max(0, SESSION_TIMEOUT_SECONDS - elapsedSeconds);

    // Format as MM:SS
    const minutes = Math.floor(remainingSeconds / 60);
    const seconds = remainingSeconds % 60;
    const timeString = `${minutes}:${seconds.toString().padStart(2, '0')}`;
    
    timerDisplay.textContent = timeString;

    // Update timer styling based on remaining time
    if (remainingSeconds <= 60) {
        sessionTimer.classList.remove('warning');
        sessionTimer.classList.add('critical');
    } else if (remainingSeconds <= 120) {
        sessionTimer.classList.remove('critical');
        sessionTimer.classList.add('warning');
    } else {
        sessionTimer.classList.remove('warning', 'critical');
    }

    // Auto-logout when time expires
    if (remainingSeconds <= 0) {
        clearInterval(sessionTimerInterval);
        sessionExpiredByTimeout = true; // Set flag to show timeout banner
        performLogout();
    }
}

function performLogout() {
    isAuthenticated = false;
    sessionStartTime = null;
    
    if (sessionTimerInterval) {
        clearInterval(sessionTimerInterval);
        sessionTimerInterval = null;
    }
    
    // Close edit modal if open
    closeEditModal();
    
    // Stop live view when logging out
    stopLiveView();
    
    showLogin();
    
    // Show timeout banner if logout was due to timeout
    if (sessionExpiredByTimeout && timeoutBanner) {
        timeoutBanner.style.display = 'block';
    }
}

// Utility Functions
function formatDate(dateString) {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    // Use locale-specific date and time format
    return date.toLocaleString(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        hour12: false
    });
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Bulk Actions
function toggleSelectAll(checkbox) {
    const checkboxes = document.querySelectorAll('.key-checkbox');
    checkboxes.forEach(cb => {
        cb.checked = checkbox.checked;
    });
    updateBulkActions();
}

function updateBulkActions() {
    const checkboxes = document.querySelectorAll('.key-checkbox:checked');
    const bulkActions = document.getElementById('bulk-actions');
    const selectedCount = document.getElementById('selected-count');
    
    if (checkboxes.length > 0) {
        bulkActions.style.display = 'flex';
        selectedCount.textContent = `${checkboxes.length} selected`;
    } else {
        bulkActions.style.display = 'none';
    }
}

async function bulkAction(action) {
    const checkboxes = document.querySelectorAll('.key-checkbox:checked');
    const keyIds = Array.from(checkboxes).map(cb => parseInt(cb.value));
    
    if (keyIds.length === 0) {
        alert('No keys selected');
        return;
    }
    
    const actionText = action === 'delete' ? 'delete' : action === 'activate' ? 'activate' : 'deactivate';
    const confirmMsg = `Are you sure you want to ${actionText} ${keyIds.length} API key(s)?`;
    
    if (action === 'delete' && !confirm(confirmMsg + '\n\nThis action cannot be undone.')) {
        return;
    }
    
    try {
        const response = await fetch('/admin/api/keys/bulk', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action, key_ids: keyIds })
        });
        
        if (response.ok) {
            resetSessionTimer();
            loadKeys();
            // Uncheck the select all checkbox
            const selectAllCheckbox = document.querySelector('.key-checkbox-header');
            if (selectAllCheckbox) {
                selectAllCheckbox.checked = false;
            }
        } else if (response.status === 401) {
            const data = await response.json();
            const errorMsg = data.error || 'Unauthorized';
            if (errorMsg.includes('Session expired') || errorMsg.includes('Session invalidated')) {
                sessionExpiredByTimeout = true;
                performLogout();
            } else {
                alert('Error: ' + (data.error || 'Bulk action failed'));
            }
        } else {
            const data = await response.json();
            alert('Error: ' + (data.error || 'Bulk action failed'));
        }
    } catch (error) {
        alert('Bulk action failed. Please try again.');
        console.error('Bulk action error:', error);
    }
}

// Edit Key
function editKey(keyId, permissions, rateLimit) {
    document.getElementById('edit-key-id').value = keyId;
    // Set checkboxes based on bitmap (bits 0-8 for 9 permissions)
    document.getElementById('edit-perm-generate-secret').checked = (permissions & (1 << 0)) !== 0;
    document.getElementById('edit-perm-repositories-add').checked = (permissions & (1 << 1)) !== 0;
    document.getElementById('edit-perm-repositories-verify').checked = (permissions & (1 << 2)) !== 0;
    document.getElementById('edit-perm-repositories-update').checked = (permissions & (1 << 3)) !== 0;
    document.getElementById('edit-perm-repositories-delete').checked = (permissions & (1 << 4)) !== 0;
    document.getElementById('edit-perm-events-list').checked = (permissions & (1 << 5)) !== 0;
    document.getElementById('edit-perm-permissions-list').checked = (permissions & (1 << 6)) !== 0;
    document.getElementById('edit-perm-permissions-calculate').checked = (permissions & (1 << 7)) !== 0;
    document.getElementById('edit-perm-permissions-decode').checked = (permissions & (1 << 8)) !== 0;
    document.getElementById('edit-key-rate-limit').value = rateLimit;
    document.getElementById('edit-key-modal').style.display = 'block';
}

function closeEditModal() {
    document.getElementById('edit-key-modal').style.display = 'none';
}

// Handle edit form submission
document.getElementById('edit-key-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const keyId = document.getElementById('edit-key-id').value;
    
    // Build bitmap from checkboxes (bits 0-8 for 9 permissions)
    let permissionsBitmap = 0;
    if (document.getElementById('edit-perm-generate-secret').checked) permissionsBitmap |= (1 << 0);
    if (document.getElementById('edit-perm-repositories-add').checked) permissionsBitmap |= (1 << 1);
    if (document.getElementById('edit-perm-repositories-verify').checked) permissionsBitmap |= (1 << 2);
    if (document.getElementById('edit-perm-repositories-update').checked) permissionsBitmap |= (1 << 3);
    if (document.getElementById('edit-perm-repositories-delete').checked) permissionsBitmap |= (1 << 4);
    if (document.getElementById('edit-perm-events-list').checked) permissionsBitmap |= (1 << 5);
    if (document.getElementById('edit-perm-permissions-list').checked) permissionsBitmap |= (1 << 6);
    if (document.getElementById('edit-perm-permissions-calculate').checked) permissionsBitmap |= (1 << 7);
    if (document.getElementById('edit-perm-permissions-decode').checked) permissionsBitmap |= (1 << 8);
    
    // Validate that at least one permission is selected
    if (permissionsBitmap === 0) {
        alert('Please select at least one permission for this API key.');
        return;
    }
    
    const rate_limit = parseInt(document.getElementById('edit-key-rate-limit').value);
    try {
        const response = await fetch(`/admin/api/keys/${keyId}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ permissions: permissionsBitmap, rate_limit })
        });
        
        if (response.ok) {
            resetSessionTimer();
            closeEditModal();
            loadKeys();
        } else if (response.status === 401) {
            const data = await response.json();
            const errorMsg = data.error || 'Unauthorized';
            if (errorMsg.includes('Session expired') || errorMsg.includes('Session invalidated')) {
                sessionExpiredByTimeout = true;
                performLogout();
            } else {
                alert('Error: ' + (data.error || 'Failed to update API key'));
            }
        } else {
            const data = await response.json();
            alert('Error: ' + (data.error || 'Failed to update API key'));
        }
    } catch (error) {
        alert('Failed to update API key. Please try again.');
        console.error('Update key error:', error);
    }
});

// Close modal when clicking outside of it
window.onclick = function(event) {
    const modal = document.getElementById('edit-key-modal');
    if (event.target === modal) {
        closeEditModal();
    }
};

// Tab Management
function switchTab(tabName) {
    currentTab = tabName;
    
    // Update tab buttons
    const tabButtons = document.querySelectorAll('.tab-button');
    tabButtons.forEach(btn => {
        btn.classList.remove('active');
    });
    event.target.classList.add('active');
    
    // Update tab content
    const tabContents = document.querySelectorAll('.tab-content');
    tabContents.forEach(content => {
        content.classList.remove('active');
    });
    document.getElementById(`${tabName}-tab`).classList.add('active');
    
    // Load data for the tab
    if (tabName === 'api-keys') {
        loadKeys();
        // Stop live view when leaving logs tab
        stopLiveView();
    } else if (tabName === 'logs') {
        loadLogFiles();
        loadLogs();
        // Start live view if checkbox is checked
        const liveViewToggle = document.getElementById('live-view-toggle');
        if (liveViewToggle && liveViewToggle.checked && !liveViewToggle.disabled) {
            startLiveView();
        }
    }
}

// Logs Management
async function loadLogFiles() {
    try {
        const response = await fetch('/admin/api/logs/list');
        if (response.ok) {
            const data = await response.json();
            availableLogFiles = data.files;
            populateLogFileSelector();
            resetSessionTimer();
        } else if (response.status === 401) {
            const data = await response.json();
            const errorMsg = data.error || 'Unauthorized';
            if (errorMsg.includes('Session expired') || errorMsg.includes('Session invalidated')) {
                sessionExpiredByTimeout = true;
                performLogout();
            }
        }
    } catch (error) {
        console.error('Load log files error:', error);
    }
}

function populateLogFileSelector() {
    const selector = document.getElementById('log-file-selector');
    if (!selector || availableLogFiles.length === 0) {
        if (selector) {
            selector.innerHTML = '<option value="">No log files found</option>';
        }
        return;
    }
    
    selector.innerHTML = '';
    
    availableLogFiles.forEach((file, index) => {
        const option = document.createElement('option');
        option.value = file.name;
        
        // Format file size
        const sizeKB = (file.size / 1024).toFixed(2);
        const sizeMB = (file.size / (1024 * 1024)).toFixed(2);
        const sizeText = file.size > 1024 * 1024 ? `${sizeMB} MB` : `${sizeKB} KB`;
        
        // Mark current log file
        const isCurrent = index === 0; // First file is the newest (current)
        option.text = `${file.name}${isCurrent ? ' (current)' : ''} - ${sizeText}`;
        
        selector.appendChild(option);
    });
    
    // Select the first (current) log file by default
    if (availableLogFiles.length > 0) {
        currentLogFile = availableLogFiles[0].name;
        selector.value = currentLogFile;
    }
}

function changeLogFile() {
    const selector = document.getElementById('log-file-selector');
    const selectedFile = selector.value;
    
    if (!selectedFile) return;
    
    currentLogFile = selectedFile;
    
    // Determine if this is the current log file (first in the list)
    const isCurrentLog = availableLogFiles.length > 0 && selectedFile === availableLogFiles[0].name;
    
    // Update live view checkbox availability
    const liveViewToggle = document.getElementById('live-view-toggle');
    const liveViewControl = document.querySelector('.live-view-control');
    
    if (isCurrentLog) {
        liveViewToggle.disabled = false;
        liveViewControl.style.opacity = '1';
        liveViewControl.title = 'Auto-refresh logs every 3 seconds';
    } else {
        liveViewToggle.disabled = true;
        liveViewToggle.checked = false;
        liveViewControl.style.opacity = '0.5';
        liveViewControl.title = 'Live view only available for current log';
        stopLiveView();
    }
    
    loadLogs();
}

function toggleLiveView() {
    const liveViewToggle = document.getElementById('live-view-toggle');
    
    if (liveViewToggle.checked) {
        startLiveView();
    } else {
        stopLiveView();
    }
}

function startLiveView() {
    // Clear any existing interval
    stopLiveView();
    
    // Auto-refresh every 3 seconds
    liveViewInterval = setInterval(() => {
        loadLogs(true); // Pass true to indicate auto-refresh (no loading message)
    }, 3000);
}

function stopLiveView() {
    if (liveViewInterval) {
        clearInterval(liveViewInterval);
        liveViewInterval = null;
    }
}

async function loadLogs(isAutoRefresh = false) {
    const logsContent = document.getElementById('logs-content');
    if (!isAutoRefresh) {
        logsContent.innerHTML = '<p class="loading">Loading logs...</p>';
    }
    
    try {
        const fileParam = currentLogFile ? `?file=${encodeURIComponent(currentLogFile)}` : '';
        const response = await fetch(`/admin/api/logs${fileParam}`);
        if (response.ok) {
            const data = await response.json();
            allLogs = data.logs;
            displayLogs(allLogs);
            
            // Update logger filter dropdown
            if (data.loggers) {
                updateLoggerFilter(data.loggers);
            }
            
            filterLogs(); // Apply current filter settings after displaying logs
            resetSessionTimer();
        } else if (response.status === 401) {
            const data = await response.json();
            const errorMsg = data.error || 'Unauthorized';
            if (errorMsg.includes('Session expired') || errorMsg.includes('Session invalidated')) {
                sessionExpiredByTimeout = true;
                performLogout();
            } else {
                logsContent.innerHTML = '<p class="error-message">Failed to load logs: Unauthorized</p>';
            }
        } else {
            logsContent.innerHTML = '<p class="error-message">Failed to load logs</p>';
        }
    } catch (error) {
        logsContent.innerHTML = '<p class="error-message">Failed to load logs</p>';
        console.error('Load logs error:', error);
    }
}

function displayLogs(logs) {
    const logsContent = document.getElementById('logs-content');
    
    if (!logs || logs.length === 0) {
        logsContent.innerHTML = '<p style="color: var(--text-muted);">No logs available.</p>';
        return;
    }
    
    // Clear existing content
    logsContent.innerHTML = '';
    
    // Use DOM methods instead of innerHTML for security
    logs.slice().reverse().forEach(log => {
        const level = extractLogLevel(log);
        const loggerName = extractLoggerName(log);
        
        const logDiv = document.createElement('div');
        logDiv.className = `log-line ${level}`;
        logDiv.setAttribute('data-level', level);
        logDiv.setAttribute('data-logger', loggerName);
        logDiv.textContent = log; // Use textContent for safety
        
        logsContent.appendChild(logDiv);
    });
}

function extractLogLevel(logLine) {
    // Extract log level from the log line format: [timestamp] [PID] [LEVEL   ] ...
    const match = logLine.match(/\[([A-Z]+)\s*\]/);
    if (match) {
        return match[1].trim();
    }
    return '';
}

function extractLoggerName(logLine) {
    // Extract logger name from format: [timestamp] [PID:xxx] [LEVEL] logger_name: message
    try {
        const parts = logLine.split(']');
        if (parts.length >= 4) {
            const loggerPart = parts[3].split(':', 1)[0].trim();
            return loggerPart || '';
        }
    } catch (e) {
        return '';
    }
    return '';
}

function updateLoggerFilter(loggers) {
    const loggerFilter = document.getElementById('log-logger-filter');
    const currentValue = loggerFilter.value;
    
    // Clear existing options except "All Loggers"
    loggerFilter.innerHTML = '<option value="all">All Loggers</option>';
    
    // Add logger options
    loggers.forEach(logger => {
        const option = document.createElement('option');
        option.value = logger;
        option.textContent = logger;
        loggerFilter.appendChild(option);
    });
    
    // Restore previous selection if still valid
    if (currentValue !== 'all' && loggers.includes(currentValue)) {
        loggerFilter.value = currentValue;
    }
}

function filterLogs() {
    const levelFilter = document.getElementById('log-level-filter').value;
    const loggerFilter = document.getElementById('log-logger-filter').value;
    const searchText = document.getElementById('log-search').value.toLowerCase();
    
    const logLines = document.querySelectorAll('.log-line');
    
    logLines.forEach(line => {
        const level = line.dataset.level;
        const logger = line.dataset.logger;
        const text = line.textContent.toLowerCase();
        
        let show = true;
        
        // Apply level filter
        if (levelFilter !== 'all' && level !== levelFilter) {
            show = false;
        }
        
        // Apply logger filter
        if (loggerFilter !== 'all' && logger !== loggerFilter) {
            show = false;
        }
        
        // Apply search filter
        if (searchText && !text.includes(searchText)) {
            show = false;
        }
        
        if (show) {
            line.classList.remove('filtered-out');
        } else {
            line.classList.add('filtered-out');
        }
    });
}

async function downloadLogs() {
    try {
        const fileParam = currentLogFile ? `?file=${encodeURIComponent(currentLogFile)}` : '';
        const response = await fetch(`/admin/api/logs/download${fileParam}`);
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            // Sanitize filename to prevent any potential issues
            const safeFilename = (currentLogFile || 'logs').replace(/[^a-zA-Z0-9._-]/g, '_');
            const downloadName = `${safeFilename.replace('.log', '')}_${new Date().toISOString().split('T')[0]}.log`;
            a.setAttribute('download', downloadName); // Use setAttribute for safety
            a.style.display = 'none';
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            a.remove(); // Use remove() instead of removeChild
            resetSessionTimer();
        } else if (response.status === 401) {
            const data = await response.json();
            const errorMsg = data.error || 'Unauthorized';
            if (errorMsg.includes('Session expired') || errorMsg.includes('Session invalidated')) {
                sessionExpiredByTimeout = true;
                performLogout();
            } else {
                alert('Error: Failed to download logs');
            }
        } else {
            alert('Error: Failed to download logs');
        }
    } catch (error) {
        alert('Failed to download logs. Please try again.');
        console.error('Download logs error:', error);
    }
}

// Make functions available globally
window.toggleKey = toggleKey;
window.deleteKey = deleteKey;
window.copyGeneratedKey = copyGeneratedKey;
