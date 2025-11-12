// Tab switching
function showTab(tabName, clickEvent) {
    // Hide all tabs
    for (const tab of document.querySelectorAll('.tab-content')) {
        tab.classList.remove('active');
    }
    for (const button of document.querySelectorAll('.tab-button')) {
        button.classList.remove('active');
    }
    
    // Show selected tab
    document.getElementById(`${tabName}-tab`).classList.add('active');
    if (clickEvent?.target) {
        clickEvent.target.classList.add('active');
    } else {
        // If called programmatically, find and activate the button
        for (const button of document.querySelectorAll('.tab-button')) {
            if (button.getAttribute('onclick').includes(tabName)) {
                button.classList.add('active');
            }
        }
    }
    
    // Reset manage tab state when switching away
    if (tabName === 'manage') {
        document.getElementById('edit-section').style.display = 'none';
        document.getElementById('verify-form').style.display = 'block';
        document.getElementById('verify-form').reset();
    }
    
    // Hide status message when switching tabs
    hideStatus();
}

// Generate random secret
async function generateSecret(inputId) {
    try {
        const response = await fetch('/api/generate-secret', {
            headers: {
                'X-CSRF-Token': globalThis.CSRF_TOKEN,
                'X-Request-Time': Math.floor(Date.now() / 1000).toString(),
                'X-Request-Nonce': generateNonce()
            }
        });
     const data = await response.json();

        if (data.secret) {
         document.getElementById(inputId).value = data.secret;
         showStatus('Secret generated successfully! Don\'t forget to copy it.', 'success');
        } else if (data.new_token) {
            // Token expired, update and retry
            globalThis.CSRF_TOKEN = data.new_token;
            return generateSecret(inputId);
        }
    } catch (error) {
        showStatus('Failed to generate secret: ' + error.message, 'error');
    }
}

// Generate a cryptographically secure random nonce for each request (prevents replay attacks)
function generateNonce() {
    const array = new Uint32Array(4);
    crypto.getRandomValues(array);
    return Array.from(array, num => num.toString(16).padStart(8, '0')).join('');
}

// Copy to clipboard
async function copyToClipboard(inputId) {
    const input = document.getElementById(inputId);
    if (!input?.value) {
        showStatus('No secret to copy!', 'error');
        return;
    }

    try {
        await navigator.clipboard.writeText(input.value);
        showStatus('Secret copied to clipboard!', 'success');
    } catch (err) {
        showStatus('Copy failed: ' + err.message, 'error');
    }
}

// Show status message
function showStatus(message, type = 'info') {
    const statusDiv = document.getElementById('status-message');
    statusDiv.textContent = message;
    statusDiv.className = `status-message ${type}`;
    statusDiv.style.display = 'block';
    
    // Auto-hide after 5 seconds for success messages
    if (type === 'success') {
 setTimeout(hideStatus, 5000);
    }
}

// Hide status message
function hideStatus() {
    const statusDiv = document.getElementById('status-message');
    statusDiv.style.display = 'none';
}

// Add repository form submission
const addForm = document.getElementById('add-form');
if (addForm) {
    addForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const repoUrl = document.getElementById('add-repo-url').value.trim();
    const secret = document.getElementById('add-secret').value.trim();
    const discordWebhook = document.getElementById('add-discord-webhook').value.trim();
    
    // Get enabled events
    const eventCheckboxes = document.querySelectorAll('input[name="events"]:checked');
    const enabledEvents = Array.from(eventCheckboxes).map(cb => cb.value).join(',');
    
    if (!enabledEvents) {
        showStatus('Please select at least one event type!', 'error');
        return;
    }
    
    try {
        showStatus('Adding repository...', 'info');
        
        const response = await fetch('/api/repositories', {
   method: 'POST',
         headers: {
       'Content-Type': 'application/json',
                'X-CSRF-Token': globalThis.CSRF_TOKEN,
                'X-Request-Time': Math.floor(Date.now() / 1000).toString(),
                'X-Request-Nonce': generateNonce()
            },
            body: JSON.stringify({
        repo_url: repoUrl,
         secret: secret,
         discord_webhook_url: discordWebhook,
      enabled_events: enabledEvents
   })
        });
     
        const data = await response.json();
     
        if (response.ok) {
         showStatus(`✅ ${data.message} - ${data.repo_full_name}`, 'success');
       document.getElementById('add-form').reset();
// Re-check default events
            for (const cb of document.querySelectorAll('input[name="events"]')) {
                cb.checked = true;
            }
} else {
        showStatus(`❌ ${data.error}`, 'error');
        }
    } catch (error) {
 showStatus(`❌ Network error: ${error.message}`, 'error');
    }
    });
}

// Verify repository form submission
const verifyForm = document.getElementById('verify-form');
if (verifyForm) {
    verifyForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const repoUrl = document.getElementById('verify-repo-url').value.trim();
    const discordWebhook = document.getElementById('verify-discord-webhook').value.trim();
    
    try {
        showStatus('Verifying credentials...', 'info');
        
        const response = await fetch('/api/repositories/verify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': globalThis.CSRF_TOKEN,
                'X-Request-Time': Math.floor(Date.now() / 1000).toString(),
                'X-Request-Nonce': generateNonce()
            },
            body: JSON.stringify({
                repo_url: repoUrl,
                discord_webhook_url: discordWebhook
            })
        });
        
        const data = await response.json();

        if (response.ok) {
            showStatus(`✅ Repository verified: ${data.repo_full_name}`, 'success');
            
            // Populate edit form
            document.getElementById('edit-repo-id').value = data.repo_id;
            document.getElementById('edit-repo-name').value = data.repo_full_name;
            
            // Set enabled events
            const events = data.enabled_events.split(',');
            document.getElementById('edit-event-star').checked = events.includes('star');
            document.getElementById('edit-event-watch').checked = events.includes('watch');
            
            // Show edit section
            document.getElementById('edit-section').style.display = 'block';
            document.getElementById('verify-form').style.display = 'none';
        } else {
            showStatus(`❌ ${data.error}`, 'error');
        }
    } catch (error) {
        showStatus(`❌ Network error: ${error.message}`, 'error');
    }
    });
}

// Edit repository form submission
const editForm = document.getElementById('edit-form');
if (editForm) {
    editForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const repoId = document.getElementById('edit-repo-id').value;
    const oldSecret = document.getElementById('edit-old-secret').value;
    const newSecret = document.getElementById('edit-new-secret').value.trim();
    const discordWebhook = document.getElementById('edit-discord-webhook').value.trim();
    
    // Get enabled events
    const eventCheckboxes = document.querySelectorAll('input[name="edit-events"]:checked');
    const enabledEvents = Array.from(eventCheckboxes).map(cb => cb.value).join(',');
    
    if (!enabledEvents) {
        showStatus('Please select at least one event type!', 'error');
     return;
    }
    
    const payload = {
        old_secret: oldSecret,
        enabled_events: enabledEvents
  };
    
    if (newSecret) payload.new_secret = newSecret;
    if (discordWebhook) payload.discord_webhook_url = discordWebhook;
    
    try {
  showStatus('Updating repository...', 'info');
      
        const response = await fetch(`/api/repositories/${repoId}`, {
            method: 'PUT',
    headers: {
     'Content-Type': 'application/json',
                'X-CSRF-Token': globalThis.CSRF_TOKEN,
                'X-Request-Time': Math.floor(Date.now() / 1000).toString(),
                'X-Request-Nonce': generateNonce()
     },
  body: JSON.stringify(payload)
        });
   
        const data = await response.json();
        
        if (response.ok) {
   showStatus(`✅ ${data.message}`, 'success');
       
            // Update old secret if new secret was set
   if (newSecret) {
                document.getElementById('edit-old-secret').value = newSecret;
       }
       
            // Clear optional fields
       document.getElementById('edit-new-secret').value = '';
    document.getElementById('edit-discord-webhook').value = '';
        } else {
            showStatus(`❌ ${data.error}`, 'error');
      }
    } catch (error) {
        showStatus(`❌ Network error: ${error.message}`, 'error');
    }
    });
}

// Delete repository
async function deleteRepository() {
    if (!confirm('Are you sure you want to delete this repository configuration? This action cannot be undone.')) {
        return;
    }
    
    const repoId = document.getElementById('edit-repo-id').value;
 const secret = document.getElementById('edit-old-secret').value;
    
    try {
        showStatus('Deleting repository...', 'info');
        
     const response = await fetch(`/api/repositories/${repoId}`, {
            method: 'DELETE',
       headers: {
      'Content-Type': 'application/json',
                'X-CSRF-Token': globalThis.CSRF_TOKEN,
                'X-Request-Time': Math.floor(Date.now() / 1000).toString(),
                'X-Request-Nonce': generateNonce()
  },
  body: JSON.stringify({
   secret: secret
            })
        });
        
        const data = await response.json();
    
        if (response.ok) {
  showStatus(`✅ ${data.message}`, 'success');
   
            // Reset forms
 document.getElementById('verify-form').reset();
     document.getElementById('verify-form').style.display = 'block';
  document.getElementById('edit-section').style.display = 'none';
        } else {
            showStatus(`❌ ${data.error}`, 'error');
        }
    } catch (error) {
        showStatus(`❌ Network error: ${error.message}`, 'error');
    }
}

// Set webhook URL dynamically
globalThis.addEventListener('DOMContentLoaded', () => {
    const webhookUrl = `${globalThis.location.origin}/webhook`;
    const webhookUrlElement = document.getElementById('webhook-url');
    if (webhookUrlElement) {
        webhookUrlElement.textContent = webhookUrl;
    }
    
    // Fetch and populate cleanup config values
    fetch('/api/stats', {
        headers: {
            'X-CSRF-Token': globalThis.CSRF_TOKEN,
            'X-Request-Time': Math.floor(Date.now() / 1000).toString(),
            'X-Request-Nonce': generateNonce()
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.cleanup_config) {
            const reposDays = document.getElementById('cleanup-repos-days');
            const apiKeysDays = document.getElementById('cleanup-apikeys-days');
            
            if (reposDays) {
                reposDays.textContent = data.cleanup_config.repositories_inactive_days;
            }
            if (apiKeysDays) {
                apiKeysDays.textContent = data.cleanup_config.api_keys_inactive_days;
            }
        }
    })
    .catch(error => {
        console.log('Could not fetch cleanup config:', error);
        // Keep default values if fetch fails
    });
});
