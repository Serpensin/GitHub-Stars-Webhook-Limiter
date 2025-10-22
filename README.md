# GitHub Events Limiter

A Flask application that listens for GitHub webhook events (star, watch), validates them,
and sends notifications to Discord webhooks if a user performs an action for the first time.
It uses SQLite for persistence and supports Sentry for error monitoring.

## Features

- ✅ **Multiple Event Types**: Supports star and watch events
- ✅ **Webhook Secret Validation**: Validates GitHub webhook secrets using HMAC SHA-256
- ✅ **Encrypted Secrets**: Secrets are encrypted at rest for security
- ✅ **Deduplication**: Prevents duplicate notifications for the same user/repo/event combination
- ✅ **Discord Notifications**: Sends formatted embeds to Discord webhooks
- ✅ **Web Interface**: Easy-to-use front-end for repository management
- ✅ **SQLite Database**: All configuration stored in SQLite (no config files needed)
- ✅ **Repository ID Tracking**: Uses GitHub repository and owner IDs for resilience against name changes
- ✅ **Webhook Verification**: Responds to GitHub's ping event for webhook verification
- ✅ **Health Check**: Provides monitoring endpoint
- ✅ **Sentry Integration**: Optional error tracking and performance monitoring

## New in v2.0.0

- 🎉 **Watch Event Support**: Now tracks first-time watchers in addition to stars
- 🎉 **Web UI**: Manage repositories through a beautiful web interface
- 🎉 **No Config Files**: All configuration moved to SQLite database with encrypted secrets
- 🎉 **Secure Secret Generation**: Built-in secure random secret generator
- 🎉 **Discord Webhook Verification**: Validates Discord webhooks before saving
- 🎉 **GitHub API Integration**: Automatically fetches repository metadata (ID, owner ID)
- 🎉 **CRUD Operations**: Add, update, verify, and delete repository configurations
- 🎉 **Encrypted Secret Storage**: Secrets encrypted with Fernet for security

## Setup Instructions

### 1. Installation

#### Using Docker (Recommended)

```bash
docker build -t github-events-limiter .
docker run -d -p 5000:5000 \
  -v $(pwd)/GitHub_Events_Limiter:/app/GitHub_Events_Limiter \
  -e ENCRYPTION_KEY="your-encryption-key" \
  -e SENTRY_DSN="your-sentry-dsn" \
  github-events-limiter
```

#### Manual Installation

```bash
pip install -r requirements.txt
python main.py
```

On first run, if no `ENCRYPTION_KEY` is set, the application will generate one and print it to console. **Save this key to your `.env` file!**

### 2. Environment Variables

Create a `.env` file:

```env
ENCRYPTION_KEY=your-encryption-key-here  # REQUIRED: Generated on first run or use Fernet.generate_key()
SENTRY_DSN=your-sentry-dsn-here          # Optional: For error monitoring
```

**Important**: The `ENCRYPTION_KEY` is required to decrypt secrets stored in the database. Keep it secure and backed up!

### 3. Add Repository via Web Interface

1. Open your browser to `http://localhost:5000` or `https://your-domain.com`
2. Click "Add Repository" tab
3. Fill in the form:
   - **Repository URL**: `https://github.com/owner/repo`
   - **Secret**: Click "Generate" to create a secure secret, then "Copy"
   - **Discord Webhook URL**: Your Discord webhook URL
   - **Events**: Select star and/or watch events
4. Click "Add Repository"

### 4. Configure GitHub Webhook

1. Go to your GitHub repository → **Settings** → **Webhooks** → **Add webhook**
2. Set **Payload URL** to: `https://your-domain.com/webhook`
3. Set **Content type** to: `application/json`
4. Paste your secret in the **Secret** field (the one you generated/copied in step 3)
5. Select individual events:
   - ☑️ **Stars** (if enabled)
   - ☑️ **Watches** (if enabled)
6. Ensure **Active** is checked
7. Click **Add webhook**
8. GitHub will send a ping event to verify the webhook - you should see a green checkmark

### 5. Test

Star or watch your repository to verify Discord notifications work!

## API Endpoints

### Web Interface
- `GET /` - Main web interface for repository management

### Webhook
- `POST /webhook` - GitHub webhook endpoint (handles star, watch, ping events)

### Repository Management API
- `POST /api/repositories` - Add new repository configuration
- `POST /api/repositories/verify` - Verify repository credentials for editing
- `PUT /api/repositories/<repo_id>` - Update repository configuration
- `DELETE /api/repositories/<repo_id>` - Delete repository configuration
- `GET /api/generate-secret` - Generate secure random secret (44 chars)

## Database Schema

### repositories Table
```sql
CREATE TABLE repositories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id INTEGER NOT NULL UNIQUE,
    repo_full_name TEXT NOT NULL,
  owner_id INTEGER NOT NULL,
    secret_encrypted TEXT NOT NULL,
    discord_webhook_url TEXT NOT NULL,
    enabled_events TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
```

### user_events Table
```sql
CREATE TABLE user_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    github_user_id INTEGER NOT NULL,
    repository_id INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    UNIQUE(github_user_id, repository_id, event_type)
)
```

## Managing Repositories

### Update Configuration

1. Go to "Manage Repository" tab
2. Enter your repository URL, current secret, and current Discord webhook URL
3. Click "Verify & Load"
4. Update the fields you want to change:
- **New Secret**: Leave empty to keep current secret
   - **New Discord Webhook**: Leave empty to keep current webhook
   - **Events**: Select which events should trigger notifications
5. Click "Update Repository"

### Delete Repository

1. Follow the verification steps above
2. Click "Delete Repository"
3. Confirm the deletion

**Note**: Deleting a repository removes all configuration and event history for that repository.

## Security Notes

- **Secrets Storage**: Secrets are encrypted using Fernet (symmetric encryption) before storage
- **Encryption Key**: The `ENCRYPTION_KEY` must be kept secure and backed up - without it, secrets cannot be decrypted
- **Database Location**: `GitHub_Events_Limiter/data.db` - ensure this directory is backed up and secured
- **Webhook Verification**: Always use HTTPS in production to protect webhook secrets in transit
- **Discord Webhook Validation**: The app verifies Discord webhooks are active before saving
- **HMAC Signature Validation**: All GitHub webhook payloads are validated using HMAC SHA-256

## Troubleshooting

### GitHub webhook shows error
- Verify your secret matches exactly (case-sensitive)
- Check that the webhook URL is accessible from the internet (use HTTPS)
- Review the webhook delivery logs in GitHub Settings → Webhooks
- Ensure you selected the correct events (Stars and/or Watches)

### Discord notifications not received
- Verify the Discord webhook URL is correct and active
- Check the enabled events in your configuration match the GitHub webhook events
- Review application logs for errors: `docker logs <container-id>` or console output
- Test the Discord webhook manually with a curl command

### Repository name changed
- No action needed! The app uses repository IDs which persist across name changes
- The `repo_full_name` field will be outdated but the webhook will still work

### Encryption key lost
- If you lose the `ENCRYPTION_KEY`, you cannot decrypt stored secrets
- You will need to delete all repositories and re-add them with new secrets
- **Always backup your encryption key securely!**

### Application won't start
- Check that the `ENCRYPTION_KEY` is set in your `.env` file
- Ensure all dependencies are installed: `pip install -r requirements.txt`
- Verify the database file has write permissions

## Development

### Running Locally

```bash
# Install dependencies
pip install -r requirements.txt

# Run in debug mode
python main.py
```

The application will be available at `http://localhost:5000`

### Running Linters

```bash
# Check code style
pylint main.py --fail-under=10.0
flake8 main.py
```

### File Structure

```
.
├── main.py          # Main application file
├── requirements.txt    # Python dependencies
├── .env          # Environment variables (not in git)
├── templates/
│   └── index.html  # Web interface
├── static/
│   ├── style.css    # Styles
│   └── script.js       # Frontend JavaScript
├── GitHub_Events_Limiter/
│   └── data.db         # SQLite database (created on first run)
├── Dockerfile   # Docker configuration
└── README.md         # This file
```

## Migration from v1.x

If you're upgrading from v1.x (config.json based):

1. **Backup your data**: Save your old `config.json` and `data.db`
2. **Note your secrets**: You'll need to re-add repositories with their secrets
3. **Set encryption key**: Generate and save an encryption key
4. **Use Web UI**: Add each repository through the new web interface
5. **Update webhooks**: No changes needed in GitHub if the webhook URL is the same

The old `starred_repo` table data will be preserved (user stars history).

## License

MIT License - See repository for details

## Contributing

Contributions welcome! Please open an issue or pull request on GitHub.

### Development Guidelines

- Follow PEP 8 style guide
- Run pylint and flake8 before committing

