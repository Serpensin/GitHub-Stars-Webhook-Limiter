// Admin Panel JavaScript
//
// AUTHENTICATION ARCHITECTURE:
// - Admin panel uses session-based authentication (cookies) for the web UI
// - Login/logout endpoints (/admin/api/login, /admin/api/logout) are INTERNAL ONLY
// - These routes are NOT documented in the public API (not in openapi.yaml or /docs)
// - For programmatic API access with admin privileges, use an admin API key instead
// - Session auth is browser-only; API keys are for scripts/tools/external access
//
// SECURITY RATIONALE:
// - Session cookies: Good for web UIs (automatic, HTTP-only, SameSite protection)
// - CSRF tokens: Prevent external API calls to login endpoint
// - API keys: Better for APIs (CSRF-proof, stateless, granular control, cross-origin)
// - This separation follows industry best practices

// Get CSRF token from meta tag
function getCSRFToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : null;
}

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

// Pagination state
let currentPage = 1;
let keysPerPage = 10;
let totalKeys = 0;
let totalPages = 0;

// Store cleanup configuration
window.cleanupConfig = null;

// Store centralized permission configuration
window.permissionsConfig = null;

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

// Helper functions - MUST be in global scope so they can be called from anywhere
function _permId(name) {
    return 'perm-' + String(name).replace(/[^A-Za-z0-9_\-]/g, '-');
}

function _editPermId(name) {
    return 'edit-perm-' + String(name).replace(/[^A-Za-z0-9_\-]/g, '-');
}

// Enable/disable the generate button depending on selected permissions
function updateGenerateBtnState() {
    const adminKeyCheckbox = document.getElementById('is-admin-key');
    const generateBtn = document.getElementById('generate-key-btn');
    
    if (!generateBtn) return; // Guard against calling before DOM is ready
    
    let anyChecked = false;
    if (adminKeyCheckbox && adminKeyCheckbox.checked) anyChecked = true;
    if (!anyChecked && window.permissionsConfig && Array.isArray(window.permissionsConfig)) {
        for (const perm of window.permissionsConfig) {
            const el = document.getElementById(_permId(perm.name));
            if (el && el.checked) { anyChecked = true; break; }
        }
    }

    if (anyChecked) {
        generateBtn.disabled = false;
        generateBtn.textContent = 'Generate API Key';
        generateBtn.title = '';
    } else {
        generateBtn.disabled = true;
        generateBtn.textContent = 'Select at least one permission';
        generateBtn.title = 'Please select at least one permission or enable admin key';
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    // Get timer elements after DOM is loaded
    timerDisplay = document.getElementById('timer-display');
    sessionTimer = document.getElementById('session-timer');
    timeoutBanner = document.getElementById('timeout-banner');
    
    // Check authentication status from server
    // Server tells us if there's an active admin session
    if (window.SERVER_AUTH_STATUS === true) {
        // User has valid session, show dashboard and load keys
        isAuthenticated = true;
        sessionStartTime = Date.now();
        sessionExpiredByTimeout = false;
        showDashboard();
        startSessionTimer();
        loadKeys();
    } else {
        // No active session, show login form
        showLogin();
    }

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
});

// Login
loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const password = document.getElementById('admin-password').value;
    const csrfToken = getCSRFToken();

    if (!csrfToken) {
        showError('Security token missing. Please refresh the page.');
        return;
    }

    try {
        const response = await fetch('/admin/api/login', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ password, csrf_token: csrfToken })
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
            credentials: 'same-origin'
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
        // Build bitmap from dynamically-rendered permission checkboxes
        if (window.permissionsConfig && Array.isArray(window.permissionsConfig)) {
            for (const perm of window.permissionsConfig) {
                const el = document.getElementById(_permId(perm.name));
                if (el && el.checked) {
                    // perm.value comes from server and should be numeric
                    permissionsBitmap |= Number(perm.value);
                }
            }
        }
        rate_limit = parseInt(document.getElementById('key-rate-limit').value);
    }

    try {
        const response = await fetch('/admin/api/keys', {
            method: 'POST',
            credentials: 'same-origin',
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
            document.getElementById('perm-stats').checked = false;
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
    const response = await fetch('/admin/api/keys', { credentials: 'same-origin' });
        if (response.ok) {
            // Session is still valid, show dashboard
            isAuthenticated = true;
            sessionStartTime = Date.now();
            sessionExpiredByTimeout = false;
            showDashboard();
            startSessionTimer();
            // Fetch configs first, then render keys
            await fetchCleanupConfig();
            await fetchPermissionsConfig();
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
        // Fetch configs first if not already loaded
        if (!window.cleanupConfig) {
            await fetchCleanupConfig();
        }
        if (!window.permissionsConfig) {
            await fetchPermissionsConfig();
        }
        
        // Build query string with filters
        const params = new URLSearchParams({
            page: currentPage,
            per_page: keysPerPage
        });
        
        // Add search filters if present
        const nameFilter = document.getElementById('search-name')?.value.trim();
        const typeFilter = document.getElementById('filter-type')?.value;
        const statusFilter = document.getElementById('filter-status')?.value;
        const rateLimitFilter = document.getElementById('filter-rate-limit')?.value;
        
        if (nameFilter) params.append('name', nameFilter);
        if (typeFilter) params.append('type', typeFilter);
        if (statusFilter) params.append('status', statusFilter);
        if (rateLimitFilter) params.append('rate_limit', rateLimitFilter);
        
        // Add permissions filter
        const searchPermsContainer = document.getElementById('search-permissions-container');
        if (searchPermsContainer && window.permissionsConfig) {
            let selectedPerms = 0;
            for (const perm of window.permissionsConfig) {
                const searchId = 'search-perm-' + String(perm.name).replace(/[^A-Za-z0-9_\-]/g, '-');
                const checkbox = document.getElementById(searchId);
                if (checkbox && checkbox.checked) {
                    selectedPerms |= Number(perm.value);
                }
            }
            if (selectedPerms > 0) {
                params.append('permissions', selectedPerms);
            }
        }
        
        const response = await fetch(`/admin/api/keys?${params.toString()}`, { credentials: 'same-origin' });
        if (response.ok) {
            const data = await response.json();
            
            // Update pagination state
            if (data.pagination) {
                totalKeys = data.pagination.total;
                totalPages = data.pagination.total_pages;
                currentPage = data.pagination.page;
                keysPerPage = data.pagination.per_page;
            }
            
            renderKeys(data.keys);
            renderPagination();
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

// Pagination functions
function renderPagination() {
    const paginationInfo = document.getElementById('pagination-info');
    const paginationButtons = document.getElementById('pagination-buttons');
    const gotoPageContainer = document.getElementById('goto-page-container');
    
    if (!paginationInfo || !paginationButtons) return;
    
    // Update info text
    if (keysPerPage === -1) {
        paginationInfo.textContent = `Showing all ${totalKeys} keys`;
    } else {
        const start = (currentPage - 1) * keysPerPage + 1;
        const end = Math.min(currentPage * keysPerPage, totalKeys);
        paginationInfo.textContent = `Showing ${start}-${end} of ${totalKeys}`;
    }
    
    // Show/hide goto page based on whether there are multiple pages
    if (gotoPageContainer) {
        if (keysPerPage === -1 || totalPages <= 1) {
            gotoPageContainer.style.display = 'none';
        } else {
            gotoPageContainer.style.display = 'flex';
        }
    }
    
    // Update buttons
    paginationButtons.innerHTML = '';
    
    if (keysPerPage === -1 || totalPages <= 1) {
        // Don't show pagination buttons if showing all or only one page
        return;
    }
    
    // Previous button
    const prevBtn = document.createElement('button');
    prevBtn.className = 'btn btn-small btn-secondary';
    prevBtn.textContent = '‹ Previous';
    prevBtn.disabled = currentPage === 1;
    prevBtn.onclick = () => changePage(currentPage - 1);
    paginationButtons.appendChild(prevBtn);
    
    // Page number buttons
    const maxButtons = 5;
    let startPage = Math.max(1, currentPage - Math.floor(maxButtons / 2));
    let endPage = Math.min(totalPages, startPage + maxButtons - 1);
    
    if (endPage - startPage < maxButtons - 1) {
        startPage = Math.max(1, endPage - maxButtons + 1);
    }
    
    if (startPage > 1) {
        const firstBtn = document.createElement('button');
        firstBtn.className = 'btn btn-small btn-secondary';
        firstBtn.textContent = '1';
        firstBtn.onclick = () => changePage(1);
        paginationButtons.appendChild(firstBtn);
        
        if (startPage > 2) {
            const ellipsis = document.createElement('span');
            ellipsis.textContent = '...';
            ellipsis.style.padding = '0 10px';
            paginationButtons.appendChild(ellipsis);
        }
    }
    
    for (let i = startPage; i <= endPage; i++) {
        const pageBtn = document.createElement('button');
        pageBtn.className = i === currentPage ? 'btn btn-small btn-primary' : 'btn btn-small btn-secondary';
        pageBtn.textContent = String(i);
        pageBtn.onclick = () => changePage(i);
        paginationButtons.appendChild(pageBtn);
    }
    
    if (endPage < totalPages) {
        if (endPage < totalPages - 1) {
            const ellipsis = document.createElement('span');
            ellipsis.textContent = '...';
            ellipsis.style.padding = '0 10px';
            paginationButtons.appendChild(ellipsis);
        }
        
        const lastBtn = document.createElement('button');
        lastBtn.className = 'btn btn-small btn-secondary';
        lastBtn.textContent = String(totalPages);
        lastBtn.onclick = () => changePage(totalPages);
        paginationButtons.appendChild(lastBtn);
    }
    
    // Next button
    const nextBtn = document.createElement('button');
    nextBtn.className = 'btn btn-small btn-secondary';
    nextBtn.textContent = 'Next ›';
    nextBtn.disabled = currentPage === totalPages;
    nextBtn.onclick = () => changePage(currentPage + 1);
    paginationButtons.appendChild(nextBtn);
}

function changePage(page) {
    if (page < 1 || page > totalPages) return;
    currentPage = page;
    loadKeys();
}

function changeKeysPerPage() {
    const select = document.getElementById('keys-per-page');
    keysPerPage = parseInt(select.value);
    currentPage = 1; // Reset to first page when changing per page
    loadKeys();
}

// Go to specific page
function gotoPage() {
    const input = document.getElementById('goto-page');
    const page = parseInt(input.value);
    
    if (!page || isNaN(page)) {
        alert('Please enter a valid page number');
        return;
    }
    
    if (page < 1) {
        alert('Page number must be at least 1');
        input.value = '';
        return;
    }
    
    if (page > totalPages) {
        alert(`Page number cannot exceed ${totalPages}`);
        input.value = '';
        return;
    }
    
    currentPage = page;
    input.value = ''; // Clear input after jumping
    loadKeys();
}

// Apply search filters
function applyFilters() {
    currentPage = 1; // Reset to first page when applying filters
    loadKeys();
}

// Clear all filters
function clearFilters() {
    document.getElementById('search-name').value = '';
    document.getElementById('filter-type').value = '';
    document.getElementById('filter-status').value = '';
    document.getElementById('filter-rate-limit').value = '';
    
    // Clear permissions checkboxes
    const searchPermsContainer = document.getElementById('search-permissions-container');
    if (searchPermsContainer && window.permissionsConfig) {
        for (const perm of window.permissionsConfig) {
            const searchId = 'search-perm-' + String(perm.name).replace(/[^A-Za-z0-9_\-]/g, '-');
            const checkbox = document.getElementById(searchId);
            if (checkbox) checkbox.checked = false;
        }
    }
    
    currentPage = 1;
    loadKeys();
}

// Toggle permissions filter visibility
function togglePermissionsFilter() {
    const container = document.getElementById('permissions-filter-container');
    const btn = document.getElementById('toggle-perms-btn');
    if (!container || !btn) return;
    
    if (container.style.display === 'none') {
        container.style.display = 'block';
        btn.textContent = '▲ Permissions';
    } else {
        container.style.display = 'none';
        btn.textContent = '▼ Permissions';
    }
}

// Fetch cleanup configuration from API
async function fetchCleanupConfig() {
    try {
        const response = await fetch('/api/stats');
        if (response.ok) {
            const data = await response.json();
            if (data.cleanup_config) {
                window.cleanupConfig = data.cleanup_config;
                console.log('Cleanup config loaded:', window.cleanupConfig);
                // Re-render keys if they're already displayed to update deletion dates
                const currentKeys = keysList.querySelectorAll('tbody tr');
                if (currentKeys.length > 0) {
                    loadKeys(); // Reload to update deletion dates
                }
            } else {
                console.warn('No cleanup_config in response:', data);
            }
        } else {
            console.error('Failed to fetch cleanup config:', response.status, response.statusText);
        }
    } catch (error) {
        console.error('Could not fetch cleanup config:', error);
    }
}

// Fetch permissions configuration from API
async function fetchPermissionsConfig() {
    try {
    const response = await fetch('/admin/api/permissions', { credentials: 'same-origin' });
        if (response.ok) {
            const data = await response.json();
            if (data.permissions) {
                window.permissionsConfig = data.permissions;
                console.log('Permissions config loaded:', window.permissionsConfig);
                // Render the permission checkboxes dynamically now that we have config
                renderPermissionCheckboxes();
            } else {
                console.warn('No permissions in response:', data);
            }
        } else {
            console.error('Failed to fetch permissions config:', response.status, response.statusText);
        }
    } catch (error) {
        console.error('Could not fetch permissions config:', error);
    }
}

// Render permission checkboxes for both the add-key form and edit modal
function renderPermissionCheckboxes() {
    if (!window.permissionsConfig || !Array.isArray(window.permissionsConfig)) return;
    const container = document.getElementById('permissions-container');
    const editContainer = document.getElementById('edit-permissions-container');
    const searchContainer = document.getElementById('search-permissions-container');
    if (!container || !editContainer) return;

    container.innerHTML = '';
    editContainer.innerHTML = '';
    if (searchContainer) searchContainer.innerHTML = '';

    for (const perm of window.permissionsConfig) {
        const id = _permId(perm.name);
        const editId = _editPermId(perm.name);
        const searchId = 'search-perm-' + String(perm.name).replace(/[^A-Za-z0-9_\-]/g, '-');

        // Add checkbox for add-key form
        const label = document.createElement('label');
        label.className = 'permission-checkbox';
        label.title = perm.description || '';

        const input = document.createElement('input');
        input.type = 'checkbox';
        input.id = id;
        input.dataset.permValue = String(perm.value);
        label.appendChild(input);

        const span = document.createElement('span');
        span.textContent = perm.friendly_name || perm.name;
        label.appendChild(span);

        container.appendChild(label);

        // Add checkbox for edit modal
        const editLabel = label.cloneNode(true);
        const editInput = editLabel.querySelector('input');
        editInput.id = editId;
        editContainer.appendChild(editLabel);
        
        // Add checkbox for search filter
        if (searchContainer) {
            const searchLabel = label.cloneNode(true);
            const searchInput = searchLabel.querySelector('input');
            searchInput.id = searchId;
            searchInput.dataset.permValue = String(perm.value);
            searchContainer.appendChild(searchLabel);
        }

        // Wire change events to update generate button state
        input.addEventListener('change', updateGenerateBtnState);
        editInput.addEventListener('change', () => {}); // placeholder if needed later
    }

    // Ensure admin checkbox also updates the button state
    const adminKeyCheckbox = document.getElementById('is-admin-key');
    if (adminKeyCheckbox) {
        // Remove any existing listeners to avoid duplicates
        adminKeyCheckbox.removeEventListener('change', updateGenerateBtnState);
        adminKeyCheckbox.addEventListener('change', updateGenerateBtnState);
    }
    // initial state
    updateGenerateBtnState();
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
            <th class="col-deletion">Deletion Date</th>
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
        } else if (window.permissionsConfig) {
            // Use centralized permission configuration
            let enabled = [];
            for (const perm of window.permissionsConfig) {
                if ((permissionsBitmap & perm.value) !== 0) {
                    enabled.push(perm.friendly_name);
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
        } else {
            // Fallback if permissions config not loaded yet
            tdPerms.innerHTML = '<span class="text-muted">Loading...</span>';
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
        
        // Deletion date column (only for non-admin keys)
        const tdDeletion = document.createElement('td');
        tdDeletion.className = 'col-deletion';
        if (isAdminKey) {
            tdDeletion.innerHTML = '<span class="text-muted">Never</span>';
        } else if (window.cleanupConfig && window.cleanupConfig.api_keys_inactive_days) {
            // Use last_used if available, otherwise use created_at
            const baseTimestamp = key.last_used || key.created_at;
            if (baseTimestamp) {
                // Convert ISO string to Date, add days, then format
                const baseDate = new Date(baseTimestamp);
                const deletionDate = new Date(baseDate.getTime() + (window.cleanupConfig.api_keys_inactive_days * 86400 * 1000));
                tdDeletion.textContent = formatDate(deletionDate.toISOString());
            } else {
                // This should never happen since created_at is always set
                tdDeletion.innerHTML = '<span class="text-muted">Unknown</span>';
            }
        } else {
            // Config not loaded yet - will be updated once config arrives
            tdDeletion.innerHTML = '<span class="text-muted">Loading...</span>';
        }
        tr.appendChild(tdDeletion);
        
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
    
    // Create wrapper for responsive scrolling
    const wrapper = document.createElement('div');
    wrapper.className = 'keys-table-wrapper';
    wrapper.appendChild(table);
    
    keysList.innerHTML = '';
    keysList.appendChild(wrapper);
    updateBulkActions();
}

// Toggle Key
async function toggleKey(keyId) {
    try {
        const response = await fetch(`/admin/api/keys/${keyId}/toggle`, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
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
            credentials: 'same-origin'
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
        // Use the server-provided permission list to translate bitmap to names
        let enabled = [];
        if (window.permissionsConfig && Array.isArray(window.permissionsConfig)) {
            for (const perm of window.permissionsConfig) {
                try {
                    if ((permissions & Number(perm.value)) !== 0) enabled.push(perm.friendly_name || perm.name);
                } catch (e) {
                    // ignore parsing errors
                }
            }
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
    // Set dynamically-rendered edit modal checkboxes based on bitmap
    if (window.permissionsConfig && Array.isArray(window.permissionsConfig)) {
        for (const perm of window.permissionsConfig) {
            const el = document.getElementById(_editPermId(perm.name));
            if (el) {
                try {
                    el.checked = (permissions & Number(perm.value)) !== 0;
                } catch (e) {
                    el.checked = false;
                }
            }
        }
    }
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
    
    // Build bitmap from checkboxes (bits 0-9 for 10 permissions)
    let permissionsBitmap = 0;
    if (window.permissionsConfig && Array.isArray(window.permissionsConfig)) {
        for (const perm of window.permissionsConfig) {
            const el = document.getElementById(_editPermId(perm.name));
            if (el && el.checked) {
                permissionsBitmap |= Number(perm.value);
            }
        }
    }
    
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
    // Logs are already in reverse chronological order from backend (newest first)
    logs.forEach(log => {
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
