"""
GitHub Handler Module

Provides GitHub API functionality including repository URL parsing, repository data fetching,
and GitHub API interactions.

Usage:
    from modules.GitHubHandler import GitHubHandler

    github_handler = GitHubHandler(logger=logger)

    # Extract repo info from URL
    owner, repo = github_handler.extract_repo_info_from_url(
        "https://github.com/owner/repo"
    )

    # Fetch repository data from GitHub API
    repo_data = github_handler.fetch_repo_data(owner, repo)
    # Returns: {"repo_id": 12345, "repo_full_name": "owner/repo", "owner_id": 67890}
"""

import logging
import re

import requests


class GitHubHandler:
    """
    Handles GitHub API operations including URL parsing and repository data fetching.
    """

    def __init__(self, logger=None, token=None):
        """
        Initialize the GitHub handler.

        Args:
            logger: Optional logger instance for logging operations.
            token: Optional GitHub personal access token for API authentication.
        """
        # Initialize logger
        if logger is None:
            self.logger = logging.getLogger("modules.githubhandler")
        else:
            self.logger = logger.getChild("modules.githubhandler")

        # Store GitHub token
        self.token = token

    def extract_repo_info_from_url(self, repo_url: str) -> tuple[str, str] | None:
        """
        Extracts owner and repo name from a GitHub repository URL.

        Args:
            repo_url (str): The GitHub repository URL.

        Returns:
            tuple[str, str] | None: A tuple of (owner, repo) or None if invalid.
        """
        try:
            # Remove trailing slashes and .git
            repo_url = repo_url.rstrip("/").rstrip(".git")

            # Handle various GitHub URL formats
            if "github.com/" in repo_url:
                parts = repo_url.split("github.com/")[-1].split("/")
                if len(parts) >= 2:
                    if self.logger:
                        self.logger.debug(f"Extracted repo info: {parts[0]}/{parts[1]}")
                    return parts[0], parts[1]
        except Exception as e:  # pylint: disable=broad-exception-caught
            if self.logger:
                self.logger.error(f"Failed to extract repo info from URL '{repo_url}': {e}")

        if self.logger:
            self.logger.warning(f"Invalid GitHub repository URL: {repo_url}")
        return None

    def fetch_repo_data(self, owner: str, repo: str) -> dict | None:
        """
        Fetches repository data from GitHub API.

        Args:
            owner (str): The repository owner.
            repo (str): The repository name.

        Returns:
            dict | None: Repository data including repo_id and owner_id, or None if error.
                Example: {
                    "repo_id": 12345,
                    "repo_full_name": "owner/repo",
                    "owner_id": 67890
                }
        """
        try:
            # Security: Validate owner and repo names to prevent SSRF and path traversal
            # Only allow alphanumeric, hyphens, underscores, and dots
            if not re.match(r"^[a-zA-Z0-9._-]+$", owner) or not re.match(
                r"^[a-zA-Z0-9._-]+$", repo
            ):
                if self.logger:
                    self.logger.warning(f"Invalid owner/repo name format: {owner}/{repo}")
                return None

            if self.logger:
                self.logger.debug(f"Fetching repository data from GitHub: {owner}/{repo}")

            # Build headers with optional authentication
            headers = {"Accept": "application/vnd.github.v3+json"}
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"

            response = requests.get(
                f"https://api.github.com/repos/{owner}/{repo}",
                headers=headers,
                timeout=5,
            )

            if response.status_code == 200:
                data = response.json()
                if self.logger:
                    self.logger.info(
                        f"Successfully fetched GitHub repo data: "
                        f"{data['full_name']} (ID: {data['id']})"
                    )
                return {
                    "repo_id": data["id"],
                    "repo_full_name": data["full_name"],
                    "owner_id": data["owner"]["id"],
                }

            if self.logger:
                self.logger.warning(
                    f"Failed to fetch GitHub repo data: HTTP {response.status_code}"
                )

        except requests.RequestException as e:
            if self.logger:
                self.logger.error(f"GitHub API request failed for {owner}/{repo}: {e}")

        return None
