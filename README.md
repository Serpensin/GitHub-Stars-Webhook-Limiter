# GitHub Stars Limiter

A Flask application that listens for GitHub 'star' webhook events, validates them,
and sends notifications to Discord webhooks if a user stars a repository for the first time.
It uses SQLite for persistence and supports Sentry for error monitoring.

Main features:
- Validates GitHub webhook secrets.
- Prevents duplicate notifications for the same user/repo pair.
- Sends Discord notifications for new stars.
- Provides a health check endpoint.
