"""
Test API Authentication

This script tests the API authentication system to ensure:
1. Direct API access without authentication is blocked
2. API key authentication works
3. Admin panel authentication works
"""

import json
import re
import unittest

import requests

BASE_URL = "http://127.0.0.1:5000"
TEST_PASSWORD = "1234" # NOSONAR


class TestAuthentication(unittest.TestCase):
    """Test suite for API authentication"""

    @classmethod
    def setUpClass(cls):
        """Set up test fixtures that are shared across all tests"""
        cls.base_url = BASE_URL
        cls.admin_password = TEST_PASSWORD
        cls.session = None
        cls.test_api_key = None
        cls.internal_secret = None
        
        # Get the internal secret from the admin page
        try:
            response = requests.get(f"{cls.base_url}/admin")
            if response.status_code == 200:
                # Extract the internal secret from the JavaScript in the HTML
                match = re.search(r'window\.INTERNAL_SECRET = "([^"]+)"', response.text)
                if match:
                    cls.internal_secret = match.group(1)
                    print("Retrieved internal secret for admin authentication")
        except Exception as e:
            print(f"Warning: Could not retrieve internal secret: {e}")

    def test_01_api_without_auth(self):
        """Test that API endpoints are blocked without authentication"""
        print("\n" + "="*70)
        print("TEST 1: API access without authentication (should fail)")
        print("="*70)

        response = requests.get(f"{self.base_url}/api/generate-secret")
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")

        self.assertEqual(
            response.status_code, 401,
            "API should return 401 Unauthorized without authentication"
        )
        print("PASS: API correctly blocked without authentication")

    def test_02_admin_login(self):
        """Test admin login"""
        print("\n" + "="*70)
        print("TEST 2: Admin login")
        print("="*70)

        self.__class__.session = requests.Session()

        headers = {"Content-Type": "application/json"}
        if self.__class__.internal_secret:
            headers["X-Internal-Secret"] = self.__class__.internal_secret

        response = self.__class__.session.post(
            f"{self.base_url}/admin/api/login",
            json={"password": self.admin_password},
            headers=headers
        )
        print(f"Login Status: {response.status_code}")
        print(f"Response: {response.json()}")

        self.assertEqual(response.status_code, 200, "Admin login should succeed")
        print("PASS: Admin login successful")

    def test_03_api_key_creation(self):
        """Test creating an API key"""
        print("\n" + "="*70)
        print("TEST 3: Create API key (requires admin session)")
        print("="*70)

        self.assertIsNotNone(self.__class__.session, "Admin session must exist")

        response = self.__class__.session.post(
            f"{self.base_url}/admin/api/keys",
            json={
                "name": "Test API Key",
                "permissions": 1,
                "rate_limit": 100
            }
        )
        print(f"Status: {response.status_code}")
        data = response.json()
        print(f"Response: {json.dumps(data, indent=2)}")

        self.assertEqual(response.status_code, 201, "API key creation should succeed")
        self.assertIn("api_key", data, "Response should contain api_key")

        self.__class__.test_api_key = data["api_key"]
        print("PASS: API key created successfully")

    def test_04_api_with_key(self):
        """Test API access with API key"""
        print("\n" + "="*70)
        print("TEST 4: API access with API key (should work)")
        print("="*70)

        self.assertIsNotNone(self.__class__.test_api_key, "API key must exist")

        response = requests.get(
            f"{self.base_url}/api/generate-secret",
            headers={"Authorization": f"Bearer {self.__class__.test_api_key}"}
        )
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")

        self.assertEqual(
            response.status_code, 200,
            "API should work with valid API key"
        )
        print("PASS: API key authentication works")

    def test_05_list_api_keys(self):
        """Test listing API keys"""
        print("\n" + "="*70)
        print("TEST 5: List API keys (requires admin session)")
        print("="*70)

        self.assertIsNotNone(self.__class__.session, "Admin session must exist")

        response = self.__class__.session.get(f"{self.base_url}/admin/api/keys")
        print(f"Status: {response.status_code}")
        data = response.json()
        print(f"Found {len(data.get('keys', []))} API key(s)")

        self.assertEqual(response.status_code, 200, "List API keys should succeed")
        print("PASS: Successfully listed API keys")

    def test_06_invalid_api_key(self):
        """Test that invalid API keys are rejected"""
        print("\n" + "="*70)
        print("TEST 6: API access with invalid key (should fail)")
        print("="*70)

        response = requests.get(
            f"{self.base_url}/api/generate-secret",
            headers={"Authorization": "Bearer invalid_key_12345"}
        )
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")

        self.assertEqual(
            response.status_code, 401,
            "Invalid API key should be rejected"
        )
        print("PASS: Invalid API key correctly rejected")


if __name__ == "__main__":
    unittest.main(verbosity=2)
