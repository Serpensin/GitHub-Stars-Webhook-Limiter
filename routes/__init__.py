"""
Routes Package

This package contains all Flask route blueprints organized by functionality:
- web: Public web routes (index, webhook)
- api: Frontend API routes (/api/*)
- admin: Admin panel routes (/admin/*)
"""

from flask import Flask

from .admin import admin_bp, init_admin_routes
from .api import api_bp, init_api_routes
from .web import init_web_routes, web_bp


def register_blueprints(app: Flask, helpers: dict):
    """
    Register all blueprints with the Flask application and initialize their dependencies.

    Args:
        app: The Flask application instance
        helpers: Dictionary containing all helper functions and objects needed by routes
    """
    # Initialize web routes
    init_web_routes(
        helpers["logger"],
        helpers["db_type"],
        helpers["get_repository_by_id"],
        helpers["decrypt_secret"],
        helpers["verify_github_signature"],
        helpers["has_user_triggered_event_before"],
        helpers["discord_handler"],
        helpers["add_user_event"],
        helpers["get_db"],
        helpers["increment_stat"],
        helpers["get_all_stats"],
        helpers["get_top_users"],
    )

    # Initialize API routes
    init_api_routes(
        helpers["logger"],
        helpers["require_api_key_or_csrf"],
        helpers["github_handler"],
        helpers["discord_handler"],
        helpers["encrypt_secret"],
        helpers["get_db"],
        helpers["get_repository_by_id"],
        helpers["verify_secret"],
        helpers["bitmap_handler"],
        helpers["increment_stat"],
        helpers["get_all_stats"],
        helpers["get_top_users"],
    )

    # Initialize admin routes
    init_admin_routes(
        helpers["logger"],
        helpers["require_admin_auth"],
        helpers["verify_admin_password"],
        helpers["hash_api_key"],
        helpers["get_db"],
        helpers["get_repository_by_id"],
        helpers["increment_stat"],
        helpers["internal_server_secret"],
        helpers["discord_handler"],
        helpers["encrypt_secret"],
    )

    # Register blueprints
    app.register_blueprint(web_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(admin_bp)


__all__ = ["register_blueprints", "web_bp", "api_bp", "admin_bp"]
