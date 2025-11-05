"""
Discord Handler Module

Provides Discord webhook functionality including verification, notification sending,
and embed formatting for GitHub events and cleanup notifications.

Usage:
    from modules.DiscordHandler import DiscordHandler

    discord_handler = DiscordHandler(logger=logger)

    # Verify a webhook
    is_valid = discord_handler.verify_webhook("https://discord.com/api/webhooks/...")

    # Send event notification
    success = discord_handler.send_notification(
        webhook_url="https://discord.com/api/webhooks/...",
        event_data=event_payload,
        event_type="star"
    )

    # Send cleanup notification
    success = discord_handler.send_notification(
        webhook_url="https://discord.com/api/webhooks/...",
        cleanup_type="repo_inactive",
        repo_name="owner/repo",
        reason="No events for 90 days"
    )
"""

import logging
import time

import requests


class DiscordHandler:
    """
    Handles Discord webhook operations including verification and notification sending.
    """

    def __init__(self, logger=None):
        """
        Initialize the Discord handler.

        Args:
            logger: Optional logger instance for logging operations.
        """
        # Initialize logger
        if logger is None:
            self.logger = logging.getLogger("modules.discordhandler")
        else:
            self.logger = logger.getChild("modules.discordhandler")

    def verify_webhook(self, webhook_url: str) -> bool:
        """
        Verifies that a Discord webhook URL is valid and active.

        Args:
            webhook_url (str): The Discord webhook URL to verify.

        Returns:
            bool: True if the webhook is valid and active, False otherwise.
        """
        try:
            if self.logger:
                self.logger.debug(f"Verifying Discord webhook: {webhook_url[:50]}...")
            response = requests.get(webhook_url, timeout=5)
            if response.status_code == 200:
                if self.logger:
                    self.logger.debug("Discord webhook verification successful")
                return True
            if self.logger:
                self.logger.warning(
                    f"Discord webhook verification failed: HTTP {response.status_code}"
                )
            return False
        except requests.RequestException as e:
            if self.logger:
                self.logger.error(f"Discord webhook verification error: {e}")
            return False

    def send_notification(
        self,
        webhook_url: str,
        event_data: dict | None = None,
        event_type: str = "",
        cleanup_type: str = "",
        repo_name: str = "",
        reason: str = "",
    ) -> bool:
        """
        Sends a notification to Discord about a GitHub event or cleanup action.

        Args:
            webhook_url (str): The Discord webhook URL.
            event_data (dict | None): The GitHub event payload (for star/watch events).
            event_type (str): The event type (star, watch, or empty for cleanup).
            cleanup_type (str): Type of cleanup ("repo_inactive", "repo_deleted",
                "webhook_deleted").
            repo_name (str): Repository name (for cleanup notifications).
            reason (str): Reason for cleanup (for cleanup notifications).

        Returns:
            bool: True if successful, False otherwise.
        """
        try:
            # Cleanup notifications
            if cleanup_type:
                return self._send_cleanup_notification(
                    webhook_url, cleanup_type, repo_name, reason
                )

            # Regular event notifications (star/watch)
            if not event_data:
                if self.logger:
                    self.logger.error("No event data provided for regular notification")
                return False

            return self._send_event_notification(webhook_url, event_data, event_type)

        except (KeyError, requests.RequestException) as e:
            if self.logger:
                self.logger.error(f"Failed to send Discord notification: {e}")
            return False

    def _send_cleanup_notification(
        self, webhook_url: str, cleanup_type: str, repo_name: str, reason: str
    ) -> bool:
        """
        Sends a cleanup notification to Discord.

        Args:
            webhook_url (str): The Discord webhook URL.
            cleanup_type (str): Type of cleanup.
            repo_name (str): Repository name.
            reason (str): Reason for cleanup.

        Returns:
            bool: True if successful, False otherwise.
        """
        if self.logger:
            self.logger.info(
                f"Sending Discord cleanup notification: {cleanup_type} for {repo_name}"
            )

        cleanup_colors = {
            "repo_inactive": 0xFF9800,  # Orange
            "repo_deleted": 0xF44336,  # Red
            "webhook_deleted": 0x9C27B0,  # Purple
        }

        cleanup_titles = {
            "repo_inactive": "🗑️ Repository Removed - Inactive",
            "repo_deleted": "❌ Repository Removed - Deleted",
            "webhook_deleted": "⚠️ Repository Removed - Webhook Invalid",
        }

        payload = {
            "username": "GitHub Events Bot - Cleanup",
            "avatar_url": "https://cdn-icons-png.flaticon.com/512/616/616489.png",
            "embeds": [
                {
                    "title": cleanup_titles.get(cleanup_type, "Repository Removed"),
                    "description": f"**Repository:** {repo_name}\n**Reason:** {reason}",
                    "color": cleanup_colors.get(cleanup_type, 0x9E9E9E),
                    "footer": {"text": "Automatic cleanup by GitHub Events Limiter"},
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
                }
            ],
        }

        response = requests.post(webhook_url, json=payload, timeout=5)
        response.raise_for_status()

        if self.logger:
            self.logger.info(f"Discord cleanup notification sent successfully: {cleanup_type}")
        return True

    def _send_event_notification(
        self, webhook_url: str, event_data: dict, event_type: str
    ) -> bool:
        """
        Sends a GitHub event notification to Discord.

        Args:
            webhook_url (str): The Discord webhook URL.
            event_data (dict): The GitHub event payload.
            event_type (str): The event type (star or watch).

        Returns:
            bool: True if successful, False otherwise.
        """
        event_names = {"star": "star added", "watch": "watcher added"}

        event_colors = {
            "star": 0xFFC107,  # Amber for stars
            "watch": 0x1ABC9C,  # Teal for watches
        }

        user_login = event_data["sender"]["login"]
        repo_name_from_event = event_data["repository"]["full_name"]

        if self.logger:
            self.logger.info(
                f"Sending Discord notification: {event_type} event "
                f"by {user_login} on {repo_name_from_event}"
            )

        payload = {
            "username": "GitHub Events Bot",
            "avatar_url": "https://cdn-icons-png.flaticon.com/512/616/616489.png",
            "embeds": [
                {
                    "author": {
                        "name": user_login,
                        "icon_url": event_data["sender"]["avatar_url"],
                        "url": event_data["sender"]["html_url"],
                    },
                    "title": (
                        f"[{repo_name_from_event}] "
                        f"New {event_names.get(event_type, event_type)}"
                    ),
                    "url": event_data["repository"]["html_url"],
                    "color": event_colors.get(event_type, 0x1ABC9C),
                    "footer": {"text": f"GitHub {event_type.capitalize()} Event"},
                }
            ],
        }

        response = requests.post(webhook_url, json=payload, timeout=5)
        response.raise_for_status()

        if self.logger:
            self.logger.info(f"Discord notification sent successfully: {event_type} by {user_login}")
        return True
