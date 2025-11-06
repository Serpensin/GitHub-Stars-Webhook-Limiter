"""
Authentication Handler Module

Provides authentication and authorization utilities including API key management,
admin password verification, rate limiting, and decorators for route protection.

Usage:
    from CustomModules.AuthenticationHandler import AuthenticationHandler
    from argon2 import PasswordHasher

    ph = PasswordHasher()
    auth_handler = AuthenticationHandler(
        password_hasher=ph,
        admin_password_hash=admin_hash,
        get_db_func=get_db,
        bitmap_handler=bitmap_handler,
        server_start_time=SERVER_START_TIME,
        logger=logger
    )

    # Hash an API key
    key_hash = auth_handler.hash_api_key("my_api_key")

    # Verify an API key
    is_valid = auth_handler.verify_api_key("my_api_key", key_hash)

    # Use decorators on Flask routes
    @app.route("/api/endpoint")
    @auth_handler.require_api_key_or_csrf
    def my_endpoint():
        return {"status": "ok"}
"""

import hmac
import logging
import re
import secrets
import time
from functools import wraps
from typing import Callable, Tuple

from argon2.exceptions import VerifyMismatchError
from flask import g, jsonify, make_response, request, session


class AuthenticationHandler:
    """
    Handles authentication, authorization, and rate limiting for API keys and admin access.
    """

    def __init__(
        self,
        password_hasher,
        admin_password_hash: str,
        get_db_func: Callable,
        bitmap_handler,
        server_start_time: int,
        logger=None,
    ):
        """
        Initialize the authentication handler.

        Args:
            password_hasher: Argon2 PasswordHasher instance
            admin_password_hash: The hashed admin password
            get_db_func: Function to get database connection
            bitmap_handler: BitmapHandler instance for permission checks
            server_start_time: Server startup timestamp (for session invalidation)
            logger: Logger instance for debug/error logging (optional)
        """
        self.ph = password_hasher
        self.admin_password_hash = admin_password_hash
        self.get_db = get_db_func
        self.bitmap_handler = bitmap_handler
        self.server_start_time = server_start_time

        # Initialize logger
        if logger is None:
            self.logger = logging.getLogger("modules.authenticationhandler")
        else:
            self.logger = logger.getChild("modules.authenticationhandler")

    def hash_api_key(self, api_key: str) -> str:
        """
        Hashes an API key using Argon2id.

        Args:
            api_key (str): The plaintext API key to hash.

        Returns:
            str: The hashed API key.
        """
        if self.logger:
            self.logger.debug("Hashing API key")
        return self.ph.hash(api_key)

    def verify_api_key(self, api_key: str, key_hash: str) -> bool:
        """
        Verifies an API key against its hash.

        Args:
            api_key (str): The plaintext API key to verify.
            key_hash (str): The stored hash to verify against.

        Returns:
            bool: True if the key matches, False otherwise.
        """
        try:
            self.ph.verify(key_hash, api_key)
            if self.logger:
                self.logger.debug("API key verification successful")
            return True
        except VerifyMismatchError:
            if self.logger:
                self.logger.debug("API key verification failed")
            return False

    def check_api_key_in_db(self, api_key: str) -> bool:
        """
        Checks if an API key is valid and active in the database.
        Updates the last_used timestamp if valid.

        Args:
            api_key (str): The API key to check.

        Returns:
            bool: True if valid and active, False otherwise.
        """
        db = self.get_db()
        cursor = db.cursor()
        cursor.execute(
            "SELECT id, key_hash, permissions, rate_limit, is_admin_key "
            "FROM api_keys WHERE is_active = 1"
        )
        keys = cursor.fetchall()

        for key in keys:
            if self.verify_api_key(api_key, key["key_hash"]):
                g.api_key_id = key["id"]
                g.is_admin_key = bool(key["is_admin_key"] if key["is_admin_key"] is not None else 0)
                g.api_key_permissions = key["permissions"] or 0  # bitmap int
                g.api_key_rate_limit = key["rate_limit"] if key["rate_limit"] is not None else 100
                db.execute(
                    "UPDATE api_keys SET last_used = CURRENT_TIMESTAMP WHERE id = ?", (key["id"],)
                )
                if self.logger:
                    self.logger.info(
                        "Valid API key used (ID: %s, Admin: %s)", key["id"], g.is_admin_key
                    )
                return True

        if self.logger:
            self.logger.warning("Invalid or inactive API key attempted")
        return False

    def verify_admin_password(self, password: str) -> bool:
        """
        Verifies the admin password against the stored hash.

        Args:
            password (str): The plaintext password to verify.

        Returns:
            bool: True if the password matches, False otherwise.
        """
        if not self.admin_password_hash:
            if self.logger:
                self.logger.warning("Admin password verification failed: no hash configured")
            return False

        try:
            self.ph.verify(self.admin_password_hash, password)
            if self.logger:
                self.logger.info("Admin password verification successful")
            return True
        except VerifyMismatchError:
            if self.logger:
                self.logger.warning("Admin password verification failed")
            return False

    def check_rate_limit(self, api_key_id: int, rate_limit: int) -> Tuple[bool, int]:
        """
        Check if an API key has exceeded its rate limit.

        Rate limits are enforced per hour. Admin keys (rate_limit=0) have unlimited access.
        Tracks usage with: api_key_id, first_request_time, request_count.
        The tracking window is reset by the periodic cleanup task, not here.

        Args:
            api_key_id (int): The ID of the API key
            rate_limit (int): The hourly rate limit (0 = unlimited)

        Returns:
            tuple[bool, int]: (True if within rate limit, current request count)
        """
        # Admin keys or unlimited rate limit
        if rate_limit == 0:
            return True, 0

        db = self.get_db()
        cursor = db.cursor()

        # Get current tracking record for this API key
        cursor.execute(
            """
            SELECT first_request_time, request_count
            FROM api_rate_limit_tracking
            WHERE api_key_id = ?
            """,
            (api_key_id,),
        )

        result = cursor.fetchone()
        current_time = int(time.time())

        if result:
            request_count = result["request_count"]

            # Check if rate limit is exceeded
            if request_count >= rate_limit:
                if self.logger:
                    self.logger.warning(
                        "Rate limit exceeded for API key ID %s: %s/%s requests in current hour",
                        api_key_id,
                        request_count,
                        rate_limit,
                    )
                return False, request_count

            # Increment request count
            db.execute(
                """
                UPDATE api_rate_limit_tracking
                SET request_count = request_count + 1
                WHERE api_key_id = ?
                """,
                (api_key_id,),
            )

            if self.logger:
                self.logger.debug(
                    "Rate limit check passed for API key ID %s: %s/%s requests",
                    api_key_id,
                    request_count + 1,
                    rate_limit,
                )
            return True, request_count + 1
        else:
            # First request for this API key - create tracking record
            db.execute(
                """
                INSERT INTO api_rate_limit_tracking (api_key_id, first_request_time, request_count)
                VALUES (?, ?, 1)
                """,
                (api_key_id, current_time),
            )

            if self.logger:
                self.logger.debug(
                    "Rate limit check passed for API key ID %s: 1/%s requests "
                    "(new tracking window)",
                    api_key_id,
                    rate_limit,
                )
            return True, 1

    def check_api_key_permission(self, endpoint: str, required_permission: str) -> bool:
        """
        Check if the current API key has the required permission for a specific endpoint.

        Args:
            endpoint (str): The endpoint to check.
            required_permission (str): The permission to check.

        Returns:
            bool: True if the API key has the required permission, False otherwise.
        """
        permissions_bitmap = getattr(g, "api_key_permissions", 0)
        return self.bitmap_handler.check_key_in_bitkey(endpoint, permissions_bitmap)

    def require_api_key_or_csrf(self, f):  # NOSONAR
        """
        Decorator to require either a valid API key or a valid CSRF token.
        This allows the frontend to access API routes securely while requiring API keys
        for programmatic access. CSRF tokens are session-specific and prevent
        cross-site request forgery attacks.

        Anti-replay protection:
        - Each token can only be used once (nonce)
        - Tokens expire after 5 minutes
        - Browser fingerprinting detects session hijacking
        """

        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check for API key in Authorization header
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                api_key = auth_header[7:]  # Remove "Bearer " prefix
                if self.check_api_key_in_db(api_key):
                    # Check rate limit after successful authentication
                    within_limit, current_count = self.check_rate_limit(
                        g.api_key_id, g.api_key_rate_limit
                    )

                    if not within_limit:
                        if self.logger:
                            self.logger.warning(
                                "API route access denied: rate limit exceeded for API key ID %s",
                                g.api_key_id,
                            )
                        response = jsonify({"error": "Rate limit exceeded"})
                        response.headers["RateLimit"] = f"{current_count}/{g.api_key_rate_limit}"
                        return response, 429

                    # Execute the route function
                    result = f(*args, **kwargs)

                    # Add rate limit header to successful responses
                    if isinstance(result, tuple):
                        response, status_code = result[0], result[1] if len(result) > 1 else 200
                    else:
                        response, status_code = result, 200

                    # Ensure response is a Response object
                    if not hasattr(response, "headers"):
                        response = make_response(response)

                    # Add rate limit header if we have a rate limit and response has headers
                    if g.api_key_rate_limit > 0 and hasattr(response, "headers"):
                        response.headers["RateLimit"] = f"{current_count}/{g.api_key_rate_limit}"

                    return response, status_code if isinstance(result, tuple) else response

                if self.logger:
                    self.logger.warning("API route access denied: invalid API key")
                return jsonify({"error": "Invalid API key"}), 401

            # Check for CSRF token in custom header
            csrf_token = request.headers.get("X-CSRF-Token")
            if csrf_token:
                session_token = session.get("csrf_token")
                if not session_token:
                    if self.logger:
                        self.logger.warning(
                            "API route access denied: no CSRF token in session from %s",
                            request.remote_addr,
                        )
                    return jsonify({"error": "Invalid CSRF token"}), 403

                # Validate token matches
                if not hmac.compare_digest(csrf_token, session_token):
                    if self.logger:
                        self.logger.warning(
                            "API route access denied: CSRF token mismatch from %s",
                            request.remote_addr,
                        )
                    return jsonify({"error": "Invalid CSRF token"}), 403

                # Check token timestamp (5 minute expiry)
                token_timestamp = session.get("csrf_token_timestamp", 0)
                current_time = int(request.headers.get("X-Request-Time", "0"))

                # Validate timestamp exists and is recent
                if current_time > 0:
                    time_diff = abs(current_time - token_timestamp)
                    if time_diff > 300:  # 5 minutes = 300 seconds
                        if self.logger:
                            self.logger.warning(
                                "API route access denied: CSRF token expired "
                                "(%d seconds old) from %s",
                                time_diff,
                                request.remote_addr,
                            )
                        # Generate new token
                        session["csrf_token"] = secrets.token_hex(32)
                        req_time = request.headers.get("X-Request-Time", "0")
                        session["csrf_token_timestamp"] = int(req_time)
                        return (
                            jsonify(
                                {"error": "CSRF token expired", "new_token": session["csrf_token"]}
                            ),
                            403,
                        )

                # Check nonce to prevent replay attacks (required for CSRF-based auth)
                nonce = request.headers.get("X-Request-Nonce")
                if not nonce:
                    if self.logger:
                        self.logger.warning(
                            "API route access denied: missing nonce from %s",
                            request.remote_addr,
                        )
                    return jsonify({"error": "Nonce required"}), 403

                # Validate nonce format: must be exactly 32 hexadecimal characters
                if not re.match(r"^[a-f0-9]{32}$", nonce):
                    if self.logger:
                        self.logger.warning(
                            "API route access denied: invalid nonce format from %s (nonce: %s)",
                            request.remote_addr,
                            nonce[:16],
                        )
                    return jsonify({"error": "Invalid nonce format"}), 403

                # Stateless nonce validation: Store minimal data, auto-expires with CSRF token
                # Get current CSRF token timestamp (nonces are only valid within this window)
                token_timestamp = session.get("csrf_token_timestamp", 0)
                current_time = int(request.headers.get("X-Request-Time", "0"))

                # Calculate time window for this CSRF token (5 minutes)
                time_window = f"{token_timestamp}_{session.get('csrf_token', '')[:8]}"

                # Get nonces for current time window only
                used_nonces = session.get("used_nonces", {})

                # Clean up nonces from old CSRF tokens (different time windows)
                # This happens automatically when CSRF token refreshes
                if time_window not in used_nonces:
                    used_nonces = {time_window: set()}
                    session["used_nonces"] = used_nonces

                # Check if nonce was already used in current window
                if nonce in used_nonces.get(time_window, set()):
                    if self.logger:
                        self.logger.warning(
                            "API route access denied: nonce replay detected from %s (nonce: %s)",
                            request.remote_addr,
                            nonce[:16],
                        )
                    return jsonify({"error": "Replay attack detected"}), 403

                # Store nonce in current time window
                if time_window not in used_nonces:
                    used_nonces[time_window] = set()
                used_nonces[time_window].add(nonce)

                # Keep only current window (automatic cleanup)
                session["used_nonces"] = {time_window: used_nonces[time_window]}

                # Browser fingerprinting - detect session hijacking
                user_agent = request.headers.get("User-Agent", "")

                # Support multiple recent user-agents per session to allow small
                # legitimate differences (e.g. browser minor updates or opening
                # the same session in a second window). Migrate existing
                # `user_agent` single-value to `user_agents` list for backward
                # compatibility.
                user_agents = session.get("user_agents")
                if user_agents is None and session.get("user_agent"):
                    user_agents = [session.get("user_agent")]

                # Helper: determine whether two UAs are "compatible" — same
                # OS and browser family and close major versions (<=1 diff).
                def _ua_compatible(old: str, new: str) -> bool:
                    if not old or not new:
                        return False

                    # Simple OS token check
                    os_tokens = [
                        r"Windows NT",
                        r"Macintosh",
                        r"Android",
                        r"Linux",
                        r"iPhone",
                        r"iPad",
                    ]
                    old_os = next((t for t in os_tokens if t in old), None)
                    new_os = next((t for t in os_tokens if t in new), None)
                    if old_os != new_os:
                        return False

                    # Browser family + major version
                    def _find_browser_and_major(s: str):
                        # Order matters — Edge may include Chrome token too
                        patterns = [
                            r"Edg/(\d+)",
                            r"Chrome/(\d+)",
                            r"Firefox/(\d+)",
                            r"OPR/(\d+)",
                            r"Version/(\d+).+Safari",
                        ]
                        for p in patterns:
                            m = re.search(p, s)
                            if m:
                                # family derived from pattern name
                                family = p.split("/", maxsplit=1)[0].replace("\\", "")
                                try:
                                    return family, int(m.group(1))
                                except Exception:
                                    return family, None
                        return None, None

                    old_family, old_ver = _find_browser_and_major(old)
                    new_family, new_ver = _find_browser_and_major(new)
                    if old_family and new_family and old_family == new_family:
                        if old_ver is None or new_ver is None:
                            return True
                        try:
                            return abs(old_ver - new_ver) <= 1
                        except Exception:
                            return True

                    # Fallback: require that both strings contain a shared token
                    # like 'Chrome' or 'Safari'
                    tokens = ["Chrome", "Safari", "Edg", "Firefox", "OPR", "Android"]
                    shared = any(tok in old and tok in new for tok in tokens)
                    return bool(shared)

                # If we have a list of allowed UAs, accept if the incoming one is
                # already known or compatible with an existing one. Otherwise,
                # record it (keeping a short history) or block.
                if user_agents:
                    # exact match
                    if user_agent in user_agents:
                        # incoming UA already allowed — refresh history cap
                        session["user_agents"] = user_agents[-5:]
                    else:
                        # check compatibility with any existing UA
                        compatible = any(_ua_compatible(str(ua), user_agent) for ua in user_agents)
                        if compatible:
                            # add this UA to the allowed list (cap history to 5)
                            user_agents.append(user_agent)
                            session["user_agents"] = user_agents[-5:]
                        else:
                            if self.logger:
                                stored_display = user_agents[0] if user_agents else ""
                                self.logger.warning(
                                    "API route access denied: UA changed - "
                                    "stored='%s' curr='%s' from %s",
                                    stored_display,
                                    user_agent,
                                    request.remote_addr,
                                )
                            return jsonify({"error": "Session validation failed"}), 403
                else:
                    # No UA recorded yet; initialize list with current UA
                    session["user_agents"] = [user_agent]

                if self.logger:
                    self.logger.debug("API route access granted: valid CSRF token")
                return f(*args, **kwargs)

            if self.logger:
                self.logger.warning(
                    "API route access denied: no valid API key or CSRF token from %s",
                    request.remote_addr,
                )
            return (
                jsonify({"error": "Unauthorized. Use API key or access via the web interface."}),
                401,
            )

        return decorated_function

    def require_admin_auth(self, f):  # NOSONAR
        """
        Decorator to require admin authentication via session or admin API key.
        Enforces 5-minute session timeout for security.
        Invalidates all sessions created before server startup.
        Refreshes session timestamp on each successful validation (sliding session).
        Also accepts admin API keys for programmatic access.
        """

        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check for admin API key first
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                api_key = auth_header[7:]  # Remove "Bearer " prefix
                if self.check_api_key_in_db(api_key):
                    # Check if this is an admin key
                    if getattr(g, "is_admin_key", False):
                        if self.logger:
                            self.logger.info(
                                "Admin route access granted via admin API key (ID: %s)",
                                g.api_key_id,
                            )
                        return f(*args, **kwargs)
                    elif self.logger:
                        self.logger.warning(
                            "Admin route access denied: API key is not an admin key from %s",
                            request.remote_addr,
                        )
                    return jsonify({"error": "Admin access required"}), 403
                elif self.logger:
                    self.logger.warning(
                        "Admin route access denied: invalid API key from %s",
                        request.remote_addr,
                    )
                return jsonify({"error": "Invalid API key"}), 401

            # Check for session-based admin auth
            if not session.get("admin_authenticated"):
                # Only log warning for non-GET requests (actual access attempts)
                if request.method != "GET" and self.logger:
                    self.logger.warning(
                        "Admin route access denied: not authenticated from %s",
                        request.remote_addr,
                    )
                return jsonify({"error": "Unauthorized"}), 401

            # Invalidate sessions created before server startup
            admin_login_time = session.get("admin_login_time", 0)
            if admin_login_time < self.server_start_time:
                if self.logger:
                    self.logger.warning(
                        "Admin session invalidated: created before server startup from %s",
                        request.remote_addr,
                    )
                session.pop("admin_authenticated", None)
                session.pop("admin_login_time", None)
                return jsonify({"error": "Session invalidated. Please log in again."}), 401

            # Check session timeout (5 minutes)
            current_time = int(time.time())
            session_age = current_time - admin_login_time

            if session_age > 300:  # 5 minutes = 300 seconds
                if self.logger:
                    self.logger.warning(
                        "Admin session expired (%d seconds old) from %s",
                        session_age,
                        request.remote_addr,
                    )
                session.pop("admin_authenticated", None)
                session.pop("admin_login_time", None)
                return jsonify({"error": "Session expired"}), 401

            # Refresh session timestamp (sliding session)
            session["admin_login_time"] = current_time
            session.modified = True

            if self.logger:
                self.logger.debug("Admin route access granted via session")
            return f(*args, **kwargs)

        return decorated_function
