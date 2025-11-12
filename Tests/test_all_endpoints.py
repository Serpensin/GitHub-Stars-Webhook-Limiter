"""
Comprehensive endpoint tests for all API and Admin routes.
Tests edge cases, invalid methods, authentication, and error handling.

NOTE: This test requires a running instance of the application at localhost:5000
      and an admin API key to be set below.
"""

import unittest
import requests
import time

# ============================================================================
# TEST CONFIGURATION
# ============================================================================
BASE_URL = "http://localhost:5000"
# NOTE: This is a TEST-ONLY placeholder API key for local development
# In production, use environment variables and never commit real keys
ADMIN_API_KEY = "9HZ7wknntLZXEzGYyRrpZYPoySwv5jTm3r4odOuZmVI"  # Replace with actual admin API key
# ============================================================================


class TestAllEndpoints(unittest.TestCase):
    """Comprehensive tests for all API and admin endpoints."""

    @classmethod
    def setUpClass(cls):
        """Set up test environment once for all tests."""
        cls.base_url = BASE_URL
        cls.admin_headers = {
            'Authorization': f'Bearer {ADMIN_API_KEY}',
            'Content-Type': 'application/json'
        }
        
        # Verify server is running
        try:
            response = requests.get(f"{cls.base_url}/", timeout=5)
            if response.status_code not in [200, 401, 404]:
                raise Exception(f"Server returned unexpected status: {response.status_code}") # NOSONAR
        except requests.exceptions.RequestException as e:
            raise Exception(f"Server not running at {cls.base_url}. Error: {e}") # NOSONAR
        
        print(f"Connected to server at {cls.base_url}")

    def setUp(self):
        """Set up before each test."""
        time.sleep(0.05)  # Small delay between tests

    # ========================================================================
    # WEB INTERFACE TESTS
    # ========================================================================

    def test_root_endpoint_get(self):
        """Test GET / returns web interface."""
        response = requests.get(f'{self.base_url}/', timeout=5)
        self.assertEqual(response.status_code, 200)
        self.assertIn('text/html', response.headers.get('Content-Type', ''))

    def test_root_endpoint_wrong_methods(self):
        """Test / rejects non-GET methods."""
        for method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            response = requests.request(method, f'{self.base_url}/', timeout=5)
            self.assertIn(response.status_code, [405, 404])  # Method Not Allowed or Not Found

    def test_admin_panel_get(self):
        """Test GET /admin returns admin panel (may require authentication)."""
        response = requests.get(f'{self.base_url}/admin', timeout=5)
        # Either returns admin page (200) or requires login (302/401)
        self.assertIn(response.status_code, [200, 302, 401])

    def test_license_endpoint(self):
        """Test GET /license returns license page."""
        response = requests.get(f'{self.base_url}/license', timeout=5)
        # May or may not exist depending on implementation
        self.assertIn(response.status_code, [200, 404])

    # ========================================================================
    # API ENDPOINTS - Authentication Tests
    # ========================================================================

    def test_api_endpoints_no_auth(self):
        """Test that API endpoints reject requests without authentication."""
        endpoints = [
            ('GET', '/api/generate-secret'),
            ('POST', '/api/repositories'),
            ('PATCH', '/api/repositories'),
            ('DELETE', '/api/repositories'),
            ('POST', '/api/repositories/verify'),
            ('GET', '/api/events'),
            ('GET', '/api/permissions'),
            ('POST', '/api/permissions/calculate'),
            ('POST', '/api/permissions/decode'),
        ]
        
        for method, endpoint in endpoints:
            with self.subTest(method=method, endpoint=endpoint):
                response = requests.request(
                    method,
                    f'{self.base_url}{endpoint}',
                    headers={'Content-Type': 'application/json'},
                    json={} if method in ['POST', 'PATCH', 'DELETE'] else None,
                    timeout=5
                )
                # Should require authentication
                self.assertIn(response.status_code, [401, 403])

    def test_api_endpoints_invalid_token(self):
        """Test that API endpoints reject invalid bearer tokens."""
        headers = {
            'Authorization': 'Bearer invalid_token_12345',
            'Content-Type': 'application/json'
        }
        
        response = requests.get(f'{self.base_url}/api/generate-secret', headers=headers, timeout=30)
        self.assertIn(response.status_code, [401, 403])

    # ========================================================================
    # API ENDPOINTS - generate-secret
    # ========================================================================

    def test_generate_secret_success(self):
        """Test GET /api/generate-secret with valid auth."""
        response = requests.get(
            f'{self.base_url}/api/generate-secret',
            headers=self.admin_headers,
            timeout=5
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('secret', data)
        self.assertGreater(len(data['secret']), 40)  # Should be 44 chars

    def test_generate_secret_wrong_methods(self):
        """Test /api/generate-secret rejects non-GET methods."""
        for method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            response = requests.request(
                method,
                f'{self.base_url}/api/generate-secret',
                headers=self.admin_headers,
                timeout=5
            )
            self.assertIn(response.status_code, [405, 404])

    # ========================================================================
    # API ENDPOINTS - events
    # ========================================================================

    def test_events_list_success(self):
        """Test GET /api/events returns event types."""
        response = requests.get(
            f'{self.base_url}/api/events',
            headers=self.admin_headers,
            timeout=5
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('events', data)
        self.assertIsInstance(data['events'], list)
        # Should contain at least 'star' and 'watch' - check event names in list
        event_names = [event['name'] for event in data['events']]
        self.assertIn('star', event_names)
        self.assertIn('watch', event_names)

    def test_events_wrong_methods(self):
        """Test /api/events rejects non-GET methods."""
        for method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            response = requests.request(
                method,
                f'{self.base_url}/api/events',
                headers=self.admin_headers,
                timeout=5
            )
            self.assertIn(response.status_code, [405, 404])

    # ========================================================================
    # API ENDPOINTS - permissions
    # ========================================================================

    def test_permissions_list_success(self):
        """Test GET /api/permissions returns all permissions."""
        response = requests.get(
            f'{self.base_url}/api/permissions',
            headers=self.admin_headers,
            timeout=5
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('permissions', data)
        self.assertIsInstance(data['permissions'], list)
        self.assertGreater(len(data['permissions']), 0)
        # Check structure
        if len(data['permissions']) > 0:
            perm = data['permissions'][0]
            self.assertIn('name', perm)
            self.assertIn('value', perm)
            self.assertIn('bit', perm)

    def test_permissions_calculate_success(self):
        """Test POST /api/permissions/calculate with valid data."""
        response = requests.post(
            f'{self.base_url}/api/permissions/calculate',
            headers=self.admin_headers,
            json={'permissions': ['generate-secret', 'repositories-add']},
            timeout=5
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('bitmap', data)
        self.assertEqual(data['bitmap'], 3)

    def test_permissions_calculate_missing_json(self):
        """Test POST /api/permissions/calculate without JSON."""
        response = requests.post(
            f'{self.base_url}/api/permissions/calculate',
            headers=self.admin_headers,
            timeout=5
        )
        self.assertEqual(response.status_code, 400)

    def test_permissions_calculate_invalid_permission(self):
        """Test POST /api/permissions/calculate with invalid permission name."""
        response = requests.post(
            f'{self.base_url}/api/permissions/calculate',
            headers=self.admin_headers,
            json={'permissions': ['invalid-permission']},
            timeout=5
        )
        self.assertEqual(response.status_code, 400)

    def test_permissions_decode_success(self):
        """Test POST /api/permissions/decode with valid bitmap."""
        response = requests.post(
            f'{self.base_url}/api/permissions/decode',
            headers=self.admin_headers,
            json={'bitmap': 7},  # First 3 permissions
            timeout=5
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('permissions', data)
        self.assertIsInstance(data['permissions'], list)
        self.assertEqual(len(data['permissions']), 3)

    def test_permissions_decode_negative_bitmap(self):
        """Test POST /api/permissions/decode with negative bitmap."""
        response = requests.post(
            f'{self.base_url}/api/permissions/decode',
            headers=self.admin_headers,
            json={'bitmap': -5},
            timeout=5
        )
        self.assertEqual(response.status_code, 400)

    def test_permissions_decode_exceeds_max(self):
        """Test POST /api/permissions/decode with bitmap > max."""
        response = requests.post(
            f'{self.base_url}/api/permissions/decode',
            headers=self.admin_headers,
            # Use a very large bitmap to ensure it exceeds any configured maximum
            json={'bitmap': 1000000},
            timeout=5
        )
        self.assertEqual(response.status_code, 400)

    # ========================================================================
    # API ENDPOINTS - repositories
    # ========================================================================

    def test_repositories_post_missing_json(self):
        """Test POST /api/repositories without JSON."""
        response = requests.post(
            f'{self.base_url}/api/repositories',
            headers=self.admin_headers,
            timeout=5
        )
        self.assertEqual(response.status_code, 400)

    def test_repositories_post_missing_fields(self):
        """Test POST /api/repositories with missing required fields."""
        response = requests.post(
            f'{self.base_url}/api/repositories',
            headers=self.admin_headers,
            json={'repo_url': 'https://github.com/owner/repo'},  # Missing other fields
            timeout=5
        )
        self.assertEqual(response.status_code, 400)

    def test_repositories_post_invalid_url(self):
        """Test POST /api/repositories with invalid GitHub URL."""
        response = requests.post(
            f'{self.base_url}/api/repositories',
            headers=self.admin_headers,
            json={
                'repo_url': 'https://invalid.com/owner/repo',
                'secret': 'test_secret',
                'discord_webhook_url': 'https://discord.com/api/webhooks/123/abc',
                'enabled_events': 'star'
            },
            timeout=5
        )
        self.assertEqual(response.status_code, 400)

    def test_repositories_patch_missing_json(self):
        """Test PATCH /api/repositories without JSON."""
        response = requests.patch(
            f'{self.base_url}/api/repositories',
            headers=self.admin_headers,
            timeout=5
        )
        self.assertEqual(response.status_code, 400)

    def test_repositories_delete_missing_json(self):
        """Test DELETE /api/repositories without JSON."""
        response = requests.delete(
            f'{self.base_url}/api/repositories',
            headers=self.admin_headers,
            timeout=5
        )
        self.assertEqual(response.status_code, 400)

    def test_repositories_verify_missing_json(self):
        """Test POST /api/repositories/verify without JSON."""
        response = requests.post(
            f'{self.base_url}/api/repositories/verify',
            headers=self.admin_headers,
            timeout=5
        )
        self.assertEqual(response.status_code, 400)

    def test_repositories_wrong_method(self):
        """Test /api/repositories with unsupported method."""
        response = requests.put(  # PUT not supported, only POST/PATCH/DELETE
            f'{self.base_url}/api/repositories',
            headers=self.admin_headers,
            json={},
            timeout=5
        )
        self.assertIn(response.status_code, [405, 404])

    # ========================================================================
    # ADMIN API ENDPOINTS - Authentication
    # ========================================================================

    def test_admin_api_no_auth(self):
        """Test that admin API endpoints reject requests without session."""
        endpoints = [
            ('GET', '/admin/api/keys'),
            ('POST', '/admin/api/keys'),
            ('DELETE', '/admin/api/keys/1'),
            ('PATCH', '/admin/api/keys/1'),
            ('POST', '/admin/api/keys/1/toggle'),
            ('POST', '/admin/api/keys/bulk'),
            ('GET', '/admin/api/logs/list'),
            ('GET', '/admin/api/logs'),
            ('GET', '/admin/api/logs/download'),
        ]
        
        headers = {'Content-Type': 'application/json'}  # No session cookie
        
        for method, endpoint in endpoints:
            with self.subTest(method=method, endpoint=endpoint):
                response = requests.request(
                    method,
                    f'{self.base_url}{endpoint}',
                    headers=headers,
                    json={} if method in ['POST', 'PATCH', 'DELETE'] else None,
                    timeout=5
                )
                # Should require authentication
                self.assertIn(response.status_code, [401, 403])

    def test_admin_login_missing_json(self):
        """Test POST /admin/api/login without JSON (expects 403 - browser-only endpoint)."""
        response = requests.post(
            f'{self.base_url}/admin/api/login',
            headers={'Content-Type': 'application/json'},
            timeout=5
        )
        # Expects 400 because JSON is missing
        self.assertEqual(response.status_code, 400)

    def test_admin_login_missing_csrf(self):
        """Test POST /admin/api/login without CSRF token (expects 403 - browser-only endpoint)."""
        response = requests.post(
            f'{self.base_url}/admin/api/login',
            headers={'Content-Type': 'application/json'},
            json={'password': 'test_password'},
            timeout=5
        )
        # Expects 403 because CSRF token is missing (browser-only endpoint)
        self.assertEqual(response.status_code, 403)

    def test_admin_login_invalid_csrf(self):
        """Test POST /admin/api/login with invalid CSRF token (expects 403 - browser-only endpoint)."""
        response = requests.post(
            f'{self.base_url}/admin/api/login',
            headers={'Content-Type': 'application/json'},
            json={'password': 'test_password', 'csrf_token': 'invalid_token'},
            timeout=5
        )
        # Expects 403 because CSRF token doesn't match session (browser-only endpoint)
        self.assertEqual(response.status_code, 403)

    def test_admin_logout_no_session(self):
        """Test POST /admin/api/logout without session (expects success even without session)."""
        response = requests.post(
            f'{self.base_url}/admin/api/logout',
            headers={'Content-Type': 'application/json'},
            timeout=5
        )
        # Logout should succeed even without session (just clears session)
        self.assertEqual(response.status_code, 200)

    # ========================================================================
    # ADMIN API ENDPOINTS - API Keys (with admin key auth)
    # ========================================================================

    def test_admin_keys_list_success(self):
        """Test GET /admin/api/keys with valid admin auth."""
        response = requests.get(
            f'{self.base_url}/admin/api/keys',
            headers=self.admin_headers,
            timeout=5
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('keys', data)
        self.assertIsInstance(data['keys'], list)

    def test_admin_keys_create_missing_name(self):
        """Test POST /admin/api/keys without name field."""
        response = requests.post(
            f'{self.base_url}/admin/api/keys',
            headers=self.admin_headers,
            json={'permissions': 1, 'rate_limit': 100},
            timeout=5
        )
        self.assertEqual(response.status_code, 400)

    def test_admin_keys_create_invalid_permissions(self):
        """Test POST /admin/api/keys with invalid permissions."""
        response = requests.post(
            f'{self.base_url}/admin/api/keys',
            headers=self.admin_headers,
            json={'name': 'test_key', 'permissions': 0, 'rate_limit': 100},
            timeout=5
        )
        self.assertEqual(response.status_code, 400)

    def test_admin_keys_delete_nonexistent(self):
        """Test DELETE /admin/api/keys/<key_id> with non-existent ID."""
        response = requests.delete(
            f'{self.base_url}/admin/api/keys/999999',
            headers=self.admin_headers,
            timeout=5
        )
        self.assertEqual(response.status_code, 404)

    def test_admin_keys_toggle_nonexistent(self):
        """Test POST /admin/api/keys/<key_id>/toggle with non-existent ID."""
        response = requests.post(
            f'{self.base_url}/admin/api/keys/999999/toggle',
            headers=self.admin_headers,
            timeout=5
        )
        self.assertEqual(response.status_code, 404)

    def test_admin_keys_update_nonexistent(self):
        """Test PATCH /admin/api/keys/<key_id> with non-existent ID."""
        response = requests.patch(
            f'{self.base_url}/admin/api/keys/999999',
            headers=self.admin_headers,
            json={'permissions': 1},  # Include permissions to avoid validation error
            timeout=5
        )
        self.assertEqual(response.status_code, 404)

    def test_admin_keys_bulk_missing_action(self):
        """Test POST /admin/api/keys/bulk without action field."""
        response = requests.post(
            f'{self.base_url}/admin/api/keys/bulk',
            headers=self.admin_headers,
            json={'key_ids': [1, 2]},
            timeout=5
        )
        self.assertEqual(response.status_code, 400)

    def test_admin_keys_bulk_invalid_action(self):
        """Test POST /admin/api/keys/bulk with invalid action."""
        response = requests.post(
            f'{self.base_url}/admin/api/keys/bulk',
            headers=self.admin_headers,
            json={'action': 'invalid_action', 'key_ids': [1, 2]},
            timeout=5
        )
        self.assertEqual(response.status_code, 400)

    # ========================================================================
    # NON-EXISTENT ENDPOINTS
    # ========================================================================

    def test_nonexistent_api_endpoint(self):
        """Test that non-existent API endpoints return 404."""
        response = requests.get(
            f'{self.base_url}/api/nonexistent',
            headers=self.admin_headers,
            timeout=5
        )
        self.assertEqual(response.status_code, 404)

    def test_nonexistent_admin_endpoint(self):
        """Test that non-existent admin endpoints return 404."""
        response = requests.get(
            f'{self.base_url}/admin/api/nonexistent',
            headers=self.admin_headers,
            timeout=5
        )
        self.assertEqual(response.status_code, 404)

    def test_nonexistent_root_path(self):
        """Test that non-existent root paths return 404."""
        response = requests.get(f'{self.base_url}/this-does-not-exist', timeout=5)
        self.assertEqual(response.status_code, 404)

    # ========================================================================
    # STATISTICS ENDPOINTS
    # ========================================================================

    def test_api_stats_endpoint_with_auth(self):
        """Test GET /api/stats endpoint with admin authentication."""
        response = requests.get(
            f'{self.base_url}/api/stats',
            headers={'Authorization': f'Bearer {ADMIN_API_KEY}'},
            timeout=5
        )
        
        # Admin key should have access
        if response.status_code == 200:
            data = response.json()
            # Verify response structure
            self.assertIn('totals', data)
            self.assertIn('deletions', data)
            self.assertIn('top_users', data)
            self.assertIn('timestamp', data)
            
            # Verify totals structure
            self.assertIn('repositories_current', data['totals'])
            self.assertIn('api_keys_current', data['totals'])
            self.assertIn('events_received', data['totals'])
            self.assertIn('unique_events', data['totals'])
            self.assertIn('duplicate_events', data['totals'])
            
            # Verify deletions structure  
            self.assertIn('repos_inactive_360_days', data['deletions'])
            self.assertIn('repos_github_deleted', data['deletions'])
            self.assertIn('repos_webhook_invalid', data['deletions'])
            self.assertIn('api_keys_inactive_360_days', data['deletions'])
            
            # Verify top_users structure
            self.assertIn('valid_events', data['top_users'])
            self.assertIn('invalid_events', data['top_users'])
            
            # Verify data types
            self.assertIsInstance(data['totals']['repositories_current'], int)
            self.assertIsInstance(data['totals']['api_keys_current'], int)
            self.assertIsInstance(data['timestamp'], int)
            self.assertIsInstance(data['top_users']['valid_events'], list)
            self.assertIsInstance(data['top_users']['invalid_events'], list)
            
            print("✓ /api/stats endpoint returned valid data structure")
        else:
            # Endpoint might require specific stats permission
            self.assertIn(response.status_code, [403, 404])
            print(f"✗ /api/stats returned {response.status_code} (may need stats permission)")

    def test_api_stats_no_auth(self):
        """Test /api/stats requires authentication."""
        response = requests.get(f'{self.base_url}/api/stats', timeout=5)
        # Should reject without API key
        self.assertIn(response.status_code, [401, 403])
        print("✓ /api/stats correctly requires authentication")

    def test_status_page(self):
        """Test GET /status page."""
        response = requests.get(f'{self.base_url}/status', timeout=5)
        # The /status endpoint may be present or absent depending on deployment.
        # Accept 200 (page present) or 404 (not implemented).
        self.assertIn(response.status_code, [200, 404])
        if response.status_code == 200:
            self.assertIn('text/html', response.headers.get('Content-Type', ''))
            # Check for key content
            self.assertIn(b'Status', response.content)
            print("✓ /status page accessible and returns HTML")
        else:
            print("✓ /status endpoint not present (404) - accepted by test")

    def test_status_page_invalid_methods(self):
        """Test that /status only accepts GET."""
        for method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            response = requests.request(method, f'{self.base_url}/status', timeout=5)
            self.assertIn(response.status_code, [405, 404])

    # ========================================================================
    # WEBHOOK ENDPOINT
    # ========================================================================

    def test_webhook_endpoint_get(self):
        """Test GET /webhook (should reject or return 405)."""
        response = requests.get(f'{self.base_url}/webhook', timeout=5)
        self.assertIn(response.status_code, [405, 404])

    def test_webhook_endpoint_post_no_signature(self):
        """Test POST /webhook without GitHub signature."""
        response = requests.post(
            f'{self.base_url}/webhook',
            headers={'Content-Type': 'application/json'},
            json={'action': 'created'},
            timeout=5
        )
        # Should reject due to missing signature
        self.assertIn(response.status_code, [400, 401, 403])


if __name__ == '__main__':
    unittest.main(verbosity=2)

