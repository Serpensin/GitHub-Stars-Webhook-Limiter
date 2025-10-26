// Tab switching
function showTab(tabName) {
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => {
   tab.classList.remove('active');
    });
    document.querySelectorAll('.tab-button').forEach(button => {
        button.classList.remove('active');
    });
  
// Show selected tab
    document.getElementById(`${tabName}-tab`).classList.add('active');
    event.target.classList.add('active');
    
    // Hide status message when switching tabs
    hideStatus();
}

// Generate random secret
async function generateSecret(inputId) {
    try {
        const response = await fetch('/api/generate-secret', {
            headers: {
                'X-CSRF-Token': window.CSRF_TOKEN,
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
            window.CSRF_TOKEN = data.new_token;
            return generateSecret(inputId);
        }
    } catch (error) {
        showStatus('Failed to generate secret: ' + error.message, 'error');
    }
}

// Generate a unique nonce for each request (prevents replay attacks)
function generateNonce() {
    return Math.random().toString(36).substring(2) + Date.now().toString(36);
}

// Copy to clipboard
function copyToClipboard(inputId) {
    const input = document.getElementById(inputId);
    if (!input.value) {
   showStatus('No secret to copy!', 'error');
      return;
    }
    
    input.select();
    document.execCommand('copy');
    showStatus('Secret copied to clipboard!', 'success');
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
document.getElementById('add-form').addEventListener('submit', async (e) => {
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
                'X-CSRF-Token': window.CSRF_TOKEN,
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
            document.querySelectorAll('input[name="events"]').forEach(cb => cb.checked = true);
} else {
        showStatus(`❌ ${data.error}`, 'error');
        }
    } catch (error) {
 showStatus(`❌ Network error: ${error.message}`, 'error');
    }
});

// Verify repository form submission
document.getElementById('verify-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const repoUrl = document.getElementById('verify-repo-url').value.trim();
const secret = document.getElementById('verify-secret').value.trim();
    const discordWebhook = document.getElementById('verify-discord-webhook').value.trim();
    
    try {
        showStatus('Verifying credentials...', 'info');
        
      const response = await fetch('/api/repositories/verify', {
            method: 'POST',
       headers: {
     'Content-Type': 'application/json',
                'X-CSRF-Token': window.CSRF_TOKEN,
                'X-Request-Time': Math.floor(Date.now() / 1000).toString(),
                'X-Request-Nonce': generateNonce()
     },
            body: JSON.stringify({
         repo_url: repoUrl,
      secret: secret,
discord_webhook_url: discordWebhook
            })
        });
        
        const data = await response.json();

   if (response.ok) {
            showStatus(`✅ Repository verified: ${data.repo_full_name}`, 'success');
            
      // Populate edit form
            document.getElementById('edit-repo-id').value = data.repo_id;
      document.getElementById('edit-repo-name').value = data.repo_full_name;
  document.getElementById('edit-old-secret').value = secret;
  
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

// Edit repository form submission
document.getElementById('edit-form').addEventListener('submit', async (e) => {
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
                'X-CSRF-Token': window.CSRF_TOKEN,
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
                'X-CSRF-Token': window.CSRF_TOKEN,
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
window.addEventListener('DOMContentLoaded', () => {
    const webhookUrl = `${window.location.origin}/webhook`;
    const webhookUrlElement = document.getElementById('webhook-url');
    if (webhookUrlElement) {
        webhookUrlElement.textContent = webhookUrl;
    }
});
