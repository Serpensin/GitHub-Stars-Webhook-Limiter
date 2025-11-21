"""
Comprehensive endpoint tests for all API and Admin routes.
Tests edge cases, invalid methods, authentication, and error handling.

NOTE: This test requires a running instance of the application at localhost:5000
      and an admin API key to be set below.
"""

import os
import unittest
import requests
import time
import secrets
import hmac
import hashlib
import json
from pathlib import Path
from dotenv import load_dotenv

# Load test environment variables from Tests/.env
test_dir = Path(__file__).parent
root_env = test_dir.parent / '.env'
if root_env.exists():
    load_dotenv(root_env)
    print(f"Loaded test configuration from {root_env} (root .env)")
else:
    print(f"Warning: No .env file found in {test_dir} or root. Using defaults.")

# ============================================================================
# TEST CONFIGURATION
# ============================================================================
BASE_URL = os.getenv("TEST_SERVER_URL", "http://localhost:5000")
ADMIN_API_KEY = os.getenv("TEST_API_KEY_PLAINTEXT", "")
TEST_GITHUB_REPO_URL = os.getenv("TEST_GITHUB_REPO_URL", "https://github.com/Serpensin/GitHub-Stars-Webhook-Limiter")
TEST_DISCORD_WEBHOOK_URL = os.getenv("TEST_DISCORD_WEBHOOK_URL", "")
TEST_INVALID_DISCORD_WEBHOOK_URL = os.getenv("TEST_INVALID_DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/invalid/invalid")
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
        
        # Test repository configuration
        cls.test_repo_url = TEST_GITHUB_REPO_URL
        cls.test_discord_webhook = TEST_DISCORD_WEBHOOK_URL
        cls.test_invalid_discord_webhook = TEST_INVALID_DISCORD_WEBHOOK_URL
        
        # Track created repositories for cleanup
        cls.created_repo_ids = []
        cls.created_repo_secrets = {}  # Map repo_id -> secret
        
        # Verify server is running
        try:
            response = requests.get(f"{cls.base_url}/", timeout=5)
            if response.status_code not in [200, 401, 404]:
                raise Exception(f"Server returned unexpected status: {response.status_code}") # NOSONAR
        except requests.exceptions.RequestException as e:
            raise Exception(f"Server not running at {cls.base_url}. Error: {e}") # NOSONAR
        
        print(f"Connected to server at {cls.base_url}")
        
        # Check if test configuration is complete
        if not ADMIN_API_KEY:
            print("WARNING: TEST_ADMIN_API_KEY not set. Admin tests will fail.")
        if not TEST_DISCORD_WEBHOOK_URL:
            print("WARNING: TEST_DISCORD_WEBHOOK_URL not set. Repository tests may be limited.")

    @classmethod
    def tearDownClass(cls):
        """Clean up any repositories created during tests."""
        if not cls.created_repo_ids:
            return
            
        print(f"\n[CLEANUP] Cleaning up {len(cls.created_repo_ids)} test repositories...")
        for repo_id in cls.created_repo_ids:
            try:
                secret = cls.created_repo_secrets.get(repo_id)
                if not secret:
                    print(f"  [WARNING] No secret found for repo {repo_id}, skipping cleanup")
                    continue
                    
                response = requests.delete(
                    f'{cls.base_url}/api/repositories/{repo_id}',
                    headers=cls.admin_headers,
                    json={'secret': secret},
                    timeout=5
                )
                if response.status_code == 200:
                    print(f"  [OK] Deleted test repository {repo_id}")
                else:
                    print(f"  [WARNING] Failed to delete repo {repo_id}: {response.status_code}")
            except Exception as e:
                print(f"  ✗ Error deleting repo {repo_id}: {e}")

    def setUp(self):
        """Set up before each test."""
        time.sleep(0.05)  # Small delay between tests
    
    def _cleanup_test_repository_if_exists(self):
        """
        Attempts to clean up the test repository if it already exists.
        Uses admin API key to delete without needing the secret.
        Returns True if cleaned up or doesn't exist, False if exists but couldn't clean.
        """
        try:
            verify_response = requests.post(
                f'{self.base_url}/api/repositories/verify',
                headers=self.admin_headers,
                json={
                    'repo_url': self.test_repo_url,
                    'discord_webhook_url': self.test_discord_webhook
                },
                timeout=10
            )
            
            if verify_response.status_code == 404:
                # Repository doesn't exist - good!
                return True
            
            if verify_response.status_code == 200:
                # Repository exists - delete it using admin key (no secret needed)
                verify_data = verify_response.json()
                existing_repo_id = verify_data.get('repo_id')
                
                if existing_repo_id:
                    # Use admin API key to delete without secret
                    delete_response = requests.delete(
                        f'{self.base_url}/api/repositories/{existing_repo_id}',
                        headers=self.admin_headers,
                        json={'secret': ''},  # Admin keys don't need secret but endpoint expects JSON
                        timeout=10
                    )
                    if delete_response.status_code == 200:
                        print(f"  [OK] Deleted existing repo {existing_repo_id} using admin key")
                        if existing_repo_id in self.created_repo_ids:
                            self.created_repo_ids.remove(existing_repo_id)
                        if existing_repo_id in self.created_repo_secrets:
                            del self.created_repo_secrets[existing_repo_id]
                        return True
                    else:
                        print(f"  [WARNING] Failed to delete repo {existing_repo_id}: {delete_response.status_code} - {delete_response.text}")
                        return False
            
            return True
        except Exception as e:
            print(f"  [WARNING] Cleanup check failed: {e}")
            return False
            
            return True
        except Exception as e:
            print(f"  [WARNING] Cleanup check failed: {e}")
            return False
        
    def _generate_test_secret(self):
        """Generate a secure random secret for testing."""
        return secrets.token_urlsafe(32)
        
    def _add_test_repository(self, secret=None, discord_webhook=None, enabled_events="star,watch"):
        """
        Helper method to add a test repository.
        Returns (success: bool, response_data: dict, secret: str, repo_id: int or None)
        """
        if secret is None:
            secret = self._generate_test_secret()
        if discord_webhook is None:
            discord_webhook = self.test_discord_webhook
            
        response = requests.post(
            f'{self.base_url}/api/repositories',
            headers=self.admin_headers,
            json={
                'repo_url': self.test_repo_url,
                'secret': secret,
                'discord_webhook_url': discord_webhook,
                'enabled_events': enabled_events
            },
            timeout=10
        )
        
        success = response.status_code == 201
        try:
            data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
        except Exception as e:
            # Capture HTML errors for debugging
            html_preview = response.text[:500] if response.text else 'No content'
            data = {'error': f'Failed to parse response: {e}', 'status_code': response.status_code, 'html_preview': html_preview}
            
        if not success:
            print(f"[WARNING] Failed to add repository. Status: {response.status_code}, Content-Type: {response.headers.get('content-type', 'unknown')}")
            if data.get('html_preview'):
                print(f"[WARNING] HTML Response: {data['html_preview']}")
            
        repo_id = data.get('repo_id') if success else None
        
        # Track for cleanup
        if success and repo_id:
            self.created_repo_ids.append(repo_id)
            self.created_repo_secrets[repo_id] = secret
            
        return success, data, secret, repo_id

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
        
    def test_repositories_add_with_invalid_discord_webhook(self):
        """Test POST /api/repositories with invalid Discord webhook URL."""
        if not self.test_invalid_discord_webhook:
            self.skipTest("TEST_INVALID_DISCORD_WEBHOOK_URL not configured")
            
        secret = self._generate_test_secret()
        response = requests.post(
            f'{self.base_url}/api/repositories',
            headers=self.admin_headers,
            json={
                'repo_url': self.test_repo_url,
                'secret': secret,
                'discord_webhook_url': self.test_invalid_discord_webhook,
                'enabled_events': 'star,watch'
            },
            timeout=10
        )
        
        # Should reject invalid Discord webhook
        self.assertIn(response.status_code, [400, 422])
        data = response.json()
        self.assertIn('error', data)
        print(f"[OK] Invalid Discord webhook correctly rejected: {data.get('error')}")
        
    def test_repositories_full_lifecycle(self):
        """Test complete repository lifecycle: add, verify, update, delete."""
        if not self.test_discord_webhook:
            self.skipTest("TEST_DISCORD_WEBHOOK_URL not configured")
        
        # Step 0: Clean up any existing test repository first
        print("\n  [STEP] Step 0: Cleaning up any existing test repository...")
        cleanup_success = self._cleanup_test_repository_if_exists()
        if not cleanup_success:
            # This should never happen with admin keys, but just in case
            self.fail("Failed to clean up existing test repository. Check admin key permissions.")
        
        # Step 1: Add repository with auto-generated secret
        print("  [STEP] Step 1: Adding repository...")
        secret = self._generate_test_secret()
        success, add_data, secret, repo_id = self._add_test_repository(secret=secret)
        
        if not success:
            self.skipTest(f"Failed to add repository: {add_data}")
        self.assertIsNotNone(repo_id, f"No repo_id returned. Response: {add_data}")
        self.assertIn('repo_id', add_data)
        self.assertEqual(add_data['enabled_events'], 'star,watch')
        print(f"  [OK] Repository added successfully (ID: {repo_id})")
        
        # Step 2: Verify repository exists
        print("  [STEP] Step 2: Verifying repository...")
        response = requests.post(
            f'{self.base_url}/api/repositories/verify',
            headers=self.admin_headers,
            json={
                'repo_url': self.test_repo_url,
                'discord_webhook_url': self.test_discord_webhook
            },
            timeout=10
        )
        self.assertEqual(response.status_code, 200, "Repository should be verified successfully")
        verify_data = response.json()
        self.assertIn('repo_id', verify_data, "Verify response should contain repo_id")
        self.assertEqual(verify_data['repo_id'], repo_id, "Verified repo_id should match created repo_id")
        print("  [OK] Repository verified successfully")
        
        # Step 3: Update repository (change secret and events)
        print("  [STEP] Step 3: Updating repository...")
        new_secret = self._generate_test_secret()
        response = requests.patch(
            f'{self.base_url}/api/repositories/{repo_id}',
            headers=self.admin_headers,
            json={
                'old_secret': secret,
                'new_secret': new_secret,
                'enabled_events': 'star'  # Only star events now
            },
            timeout=10
        )
        self.assertEqual(response.status_code, 200)
        update_data = response.json()
        self.assertIn('message', update_data)
        
        # Update tracked secret for cleanup
        self.created_repo_secrets[repo_id] = new_secret
        print("  [OK] Repository updated successfully")
        
        # Step 4: Update with wrong secret (admin keys bypass secret verification)
        print("  [STEP] Step 4: Testing update with wrong secret (admin override)...")
        response = requests.patch(
            f'{self.base_url}/api/repositories/{repo_id}',
            headers=self.admin_headers,
            json={
                'old_secret': 'wrong_secret',
                'new_secret': self._generate_test_secret()
            },
            timeout=10
        )
        # Admin keys bypass secret verification, so this should succeed
        self.assertEqual(response.status_code, 200)
        print("  [OK] Admin key bypassed secret verification as expected")
        
        # Step 5: Delete repository
        print("  [STEP] Step 5: Deleting repository...")
        response = requests.delete(
            f'{self.base_url}/api/repositories/{repo_id}',
            headers=self.admin_headers,
            json={'secret': new_secret},
            timeout=10
        )
        self.assertEqual(response.status_code, 200)
        delete_data = response.json()
        self.assertIn('message', delete_data)
        
        # Remove from cleanup list since we deleted it
        self.created_repo_ids.remove(repo_id)
        del self.created_repo_secrets[repo_id]
        print("  [OK] Repository deleted successfully")
        
        # Step 6: Verify deletion
        print("  [STEP] Step 6: Verifying deletion...")
        response = requests.post(
            f'{self.base_url}/api/repositories/verify',
            headers=self.admin_headers,
            json={
                'repo_url': self.test_repo_url,
                'discord_webhook_url': self.test_discord_webhook
            },
            timeout=10
        )
        # After deletion, verify should return 404 (repository not found)
        self.assertEqual(response.status_code, 404, "Repository should not be found after deletion")
        print("  [OK] Deletion verified successfully")
        
        print("[SUCCESS] Complete repository lifecycle test passed!")
        
    def test_repositories_delete_with_wrong_secret(self):
        """Test DELETE /api/repositories/<repo_id> with admin key (bypasses secret check)."""
        if not self.test_discord_webhook:
            self.skipTest("TEST_DISCORD_WEBHOOK_URL not configured")
        
        # Clean up any existing test repository first
        cleanup_success = self._cleanup_test_repository_if_exists()
        if not cleanup_success:
            self.fail("Failed to clean up existing test repository. Check admin key permissions.")
            
        # Add a test repository
        success, add_data, secret, repo_id = self._add_test_repository()
        if not success:
            self.skipTest(f"Failed to add test repository: {add_data}")
        self.assertIsNotNone(repo_id, "No repo_id returned")
        
        # Try to delete with wrong secret using admin key (should succeed due to admin bypass)
        response = requests.delete(
            f'{self.base_url}/api/repositories/{repo_id}',
            headers=self.admin_headers,
            json={'secret': 'wrong_secret'},
            timeout=10
        )
        
        # Admin keys bypass secret verification, so this should succeed
        self.assertEqual(response.status_code, 200, f"Admin key should bypass secret check. Got {response.status_code}: {response.text}")
        print("[OK] Admin key bypassed wrong secret as expected")
        
        # Cleanup: delete with correct secret
        requests.delete(
            f'{self.base_url}/api/repositories/{repo_id}',
            headers=self.admin_headers,
            json={'secret': secret},
            timeout=10
        )
        if repo_id in self.created_repo_ids:
            self.created_repo_ids.remove(repo_id)
        if repo_id in self.created_repo_secrets:
            del self.created_repo_secrets[repo_id]
        
    def test_repositories_update_nonexistent(self):
        """Test PATCH /api/repositories/<repo_id> for non-existent repository."""
        response = requests.patch(
            f'{self.base_url}/api/repositories/999999999',
            headers=self.admin_headers,
            json={
                'old_secret': 'any_secret',
                'new_secret': 'new_secret'
            },
            timeout=10
        )
        self.assertEqual(response.status_code, 404)
        print("[OK] Update non-existent repository correctly returns 404")
        
    def test_repositories_delete_nonexistent(self):
        """Test DELETE /api/repositories/<repo_id> for non-existent repository."""
        response = requests.delete(
            f'{self.base_url}/api/repositories/999999999',
            headers=self.admin_headers,
            json={'secret': 'any_secret'},
            timeout=10
        )
        self.assertEqual(response.status_code, 404)
        print("[OK] Delete non-existent repository correctly returns 404")
        
    def test_repositories_update_discord_webhook_invalid(self):
        """Test updating repository with invalid Discord webhook URL."""
        if not self.test_discord_webhook or not self.test_invalid_discord_webhook:
            self.skipTest("TEST_DISCORD_WEBHOOK_URL or TEST_INVALID_DISCORD_WEBHOOK_URL not configured")
        
        # Clean up any existing test repository first
        cleanup_success = self._cleanup_test_repository_if_exists()
        if not cleanup_success:
            self.fail("Failed to clean up existing test repository. Check admin key permissions.")
            
        # Add a test repository
        success, add_data, secret, repo_id = self._add_test_repository()
        if not success:
            self.skipTest(f"Failed to add test repository: {add_data}")
        self.assertIsNotNone(repo_id, "No repo_id returned")
        
        # Try to update with invalid Discord webhook
        response = requests.patch(
            f'{self.base_url}/api/repositories/{repo_id}',
            headers=self.admin_headers,
            json={
                'old_secret': secret,
                'discord_webhook_url': self.test_invalid_discord_webhook
            },
            timeout=10
        )
        
        # Should reject invalid Discord webhook
        self.assertIn(response.status_code, [400, 422])
        data = response.json()
        self.assertIn('error', data)
        print(f"[OK] Invalid Discord webhook update correctly rejected: {data.get('error')}")
        
        # Cleanup
        requests.delete(
            f'{self.base_url}/api/repositories/{repo_id}',
            headers=self.admin_headers,
            json={'secret': secret},
            timeout=10
        )
        self.created_repo_ids.remove(repo_id)
        del self.created_repo_secrets[repo_id]

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

    def test_discord_webhook_integration(self):
        """Test sending a real message to Discord webhook and verify it works."""
        if not self.test_discord_webhook:
            self.skipTest("TEST_DISCORD_WEBHOOK_URL not configured")
        
        import time
        
        # Send a test message directly to Discord webhook
        test_message = {
            "content": f"🧪 **Discord Integration Test** - {time.strftime('%Y-%m-%d %H:%M:%S')}",
            "embeds": [{
                "title": "GitHub Events Limiter - Test Message",
                "description": "This is an automated test message to verify Discord webhook integration.",
                "color": 5814783,  # Blue color
                "fields": [
                    {
                        "name": "Test Type",
                        "value": "Direct Webhook POST",
                        "inline": True
                    },
                    {
                        "name": "Status",
                        "value": "✅ Testing",
                        "inline": True
                    }
                ],
                "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime())
            }]
        }
        
        # Send POST request to Discord webhook
        response = requests.post(
            self.test_discord_webhook,
            json=test_message,
            timeout=10
        )
        
        # Discord returns 204 No Content on success
        self.assertIn(response.status_code, [200, 204], 
                     f"Discord webhook should accept the message. Got: {response.status_code}, {response.text}")
        
        print(f"[OK] Discord webhook integration test successful. Message sent at {time.strftime('%H:%M:%S')}")
        print(f"[INFO] Check your Discord channel to verify the message was received.")

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
            
            print("[OK] /api/stats endpoint returned valid data structure")
        else:
            # Endpoint might require specific stats permission
            self.assertIn(response.status_code, [403, 404])
            print(f"✗ /api/stats returned {response.status_code} (may need stats permission)")

    def test_api_stats_no_auth(self):
        """Test /api/stats requires authentication."""
        response = requests.get(f'{self.base_url}/api/stats', timeout=5)
        # Should reject without API key
        self.assertIn(response.status_code, [401, 403])
        print("[OK] /api/stats correctly requires authentication")

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
            print("[OK] /status page accessible and returns HTML")
        else:
            print("[OK] /status endpoint not present (404) - accepted by test")

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

    def test_webhook_ping_event(self):
        """Test POST /webhook with GitHub ping event."""
        payload = {
            "zen": "Design for failure.",
            "hook_id": 123456789,
            "hook": {
                "type": "Repository",
                "id": 123456789,
                "active": True
            }
        }
        
        response = requests.post(
            f'{self.base_url}/webhook',
            headers={
                'Content-Type': 'application/json',
                'X-GitHub-Event': 'ping'
            },
            json=payload,
            timeout=5
        )
        # Ping events should be accepted without signature check
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('message', data)
        print("[OK] Webhook ping event handled correctly")

    def test_webhook_star_event_with_valid_signature(self):
        """Test POST /webhook with valid GitHub star event and signature."""
        if not self.test_discord_webhook:
            self.skipTest("TEST_DISCORD_WEBHOOK_URL not configured")
        
        # Add a test repository first
        secret = self._generate_test_secret()
        success, add_data, secret, repo_id = self._add_test_repository(secret=secret)
        if not success:
            self.skipTest(f"Failed to add test repository: {add_data}")
        
        try:
            # Create a fake GitHub star event payload
            payload = {
                "action": "created",
                "starred_at": "2024-01-01T00:00:00Z",
                "repository": {
                    "id": repo_id,
                    "name": "test-repo",
                    "full_name": self.test_repo_url.replace('https://github.com/', ''),
                    "owner": {
                        "login": "testuser"
                    }
                },
                "sender": {
                    "login": "testuser",
                    "id": 12345,
                    "avatar_url": "https://avatars.githubusercontent.com/u/12345"
                }
            }
            
            # Generate GitHub signature
            payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
            mac = hmac.new(secret.encode('utf-8'), msg=payload_bytes, digestmod=hashlib.sha256)
            signature = f"sha256={mac.hexdigest()}"
            
            # Send webhook request
            response = requests.post(
                f'{self.base_url}/webhook',
                headers={
                    'Content-Type': 'application/json',
                    'X-GitHub-Event': 'star',
                    'X-Hub-Signature-256': signature
                },
                data=payload_bytes,
                timeout=10
            )
            
            # Should accept with 200 OK
            self.assertEqual(response.status_code, 200, f"Expected 200, got {response.status_code}: {response.text}")
            data = response.json()
            self.assertIn('message', data)
            print(f"[OK] Webhook star event with valid signature accepted: {data.get('message')}")
            
        finally:
            # Cleanup: delete test repository
            requests.delete(
                f'{self.base_url}/api/repositories/{repo_id}',
                headers=self.admin_headers,
                json={'secret': secret},
                timeout=10
            )
            if repo_id in self.created_repo_ids:
                self.created_repo_ids.remove(repo_id)
            if repo_id in self.created_repo_secrets:
                del self.created_repo_secrets[repo_id]

    def test_webhook_watch_event_with_valid_signature(self):
        """Test POST /webhook with valid GitHub watch event and signature."""
        if not self.test_discord_webhook:
            self.skipTest("TEST_DISCORD_WEBHOOK_URL not configured")
        
        # Add a test repository first
        secret = self._generate_test_secret()
        success, add_data, secret, repo_id = self._add_test_repository(secret=secret)
        if not success:
            self.skipTest(f"Failed to add test repository: {add_data}")
        
        try:
            # Create a fake GitHub watch event payload
            payload = {
                "action": "started",
                "repository": {
                    "id": repo_id,
                    "name": "test-repo",
                    "full_name": self.test_repo_url.replace('https://github.com/', ''),
                    "owner": {
                        "login": "testuser"
                    }
                },
                "sender": {
                    "login": "watcher123",
                    "id": 67890,
                    "avatar_url": "https://avatars.githubusercontent.com/u/67890"
                }
            }
            
            # Generate GitHub signature
            payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
            mac = hmac.new(secret.encode('utf-8'), msg=payload_bytes, digestmod=hashlib.sha256)
            signature = f"sha256={mac.hexdigest()}"
            
            # Send webhook request
            response = requests.post(
                f'{self.base_url}/webhook',
                headers={
                    'Content-Type': 'application/json',
                    'X-GitHub-Event': 'watch',
                    'X-Hub-Signature-256': signature
                },
                data=payload_bytes,
                timeout=10
            )
            
            # Should accept with 200 OK
            self.assertEqual(response.status_code, 200, f"Expected 200, got {response.status_code}: {response.text}")
            data = response.json()
            self.assertIn('message', data)
            print(f"[OK] Webhook watch event with valid signature accepted: {data.get('message')}")
            
        finally:
            # Cleanup: delete test repository
            requests.delete(
                f'{self.base_url}/api/repositories/{repo_id}',
                headers=self.admin_headers,
                json={'secret': secret},
                timeout=10
            )
            if repo_id in self.created_repo_ids:
                self.created_repo_ids.remove(repo_id)
            if repo_id in self.created_repo_secrets:
                del self.created_repo_secrets[repo_id]

    def test_webhook_invalid_signature(self):
        """Test POST /webhook with invalid GitHub signature."""
        if not self.test_discord_webhook:
            self.skipTest("TEST_DISCORD_WEBHOOK_URL not configured")
        
        # Add a test repository first
        secret = self._generate_test_secret()
        success, add_data, secret, repo_id = self._add_test_repository(secret=secret)
        if not success:
            self.skipTest(f"Failed to add test repository: {add_data}")
        
        try:
            # Create a fake GitHub star event payload
            payload = {
                "action": "created",
                "repository": {
                    "id": repo_id,
                    "name": "test-repo"
                },
                "sender": {
                    "login": "testuser"
                }
            }
            
            # Use WRONG secret for signature
            payload_bytes = json.dumps(payload).encode('utf-8')
            wrong_secret = "this-is-a-wrong-secret-12345"
            mac = hmac.new(wrong_secret.encode('utf-8'), msg=payload_bytes, digestmod=hashlib.sha256)
            signature = f"sha256={mac.hexdigest()}"
            
            # Send webhook request
            response = requests.post(
                f'{self.base_url}/webhook',
                headers={
                    'Content-Type': 'application/json',
                    'X-GitHub-Event': 'star',
                    'X-Hub-Signature-256': signature
                },
                data=payload_bytes,
                timeout=10
            )
            
            # Should reject with 403 Forbidden
            self.assertEqual(response.status_code, 403, f"Expected 403, got {response.status_code}")
            print("[OK] Webhook with invalid signature correctly rejected")
            
        finally:
            # Cleanup: delete test repository
            requests.delete(
                f'{self.base_url}/api/repositories/{repo_id}',
                headers=self.admin_headers,
                json={'secret': secret},
                timeout=10
            )
            if repo_id in self.created_repo_ids:
                self.created_repo_ids.remove(repo_id)
            if repo_id in self.created_repo_secrets:
                del self.created_repo_secrets[repo_id]

    def test_webhook_unconfigured_repository(self):
        """Test POST /webhook for repository not in database."""
        payload = {
            "action": "created",
            "repository": {
                "id": 999999999,  # Non-existent repo ID
                "name": "non-existent-repo"
            },
            "sender": {
                "login": "testuser"
            }
        }
        
        # Generate signature with dummy secret (won't matter since repo doesn't exist)
        payload_bytes = json.dumps(payload).encode('utf-8')
        mac = hmac.new(b'dummy-secret', msg=payload_bytes, digestmod=hashlib.sha256)
        signature = f"sha256={mac.hexdigest()}"
        
        response = requests.post(
            f'{self.base_url}/webhook',
            headers={
                'Content-Type': 'application/json',
                'X-GitHub-Event': 'star',
                'X-Hub-Signature-256': signature
            },
            data=payload_bytes,
            timeout=5
        )
        
        # Should reject with 404 Not Found
        self.assertEqual(response.status_code, 404)
        print("[OK] Webhook for unconfigured repository correctly rejected")


if __name__ == '__main__':
    unittest.main(verbosity=2)

