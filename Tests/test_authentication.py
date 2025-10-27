"""
Test API Authentication

This script tests the API authentication system to ensure:
1. Direct API access without authentication is blocked
2. API key authentication works
3. Admin panel authentication works
"""

import requests
import json

BASE_URL = "http://127.0.0.1:5000"
TEST_PASSWORD = "1234"  # Should match the ADMIN_PASSWORD_HASH in .env

def test_api_without_auth():
    """Test that API endpoints are blocked without authentication"""
    print("\n" + "="*70)
    print("TEST 1: API access without authentication (should fail)")
    print("="*70)
    
    response = requests.get(f"{BASE_URL}/api/generate-secret")
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    
    if response.status_code == 401:
        print("✅ PASS: API correctly blocked without authentication")
        return True
    else:
        print("❌ FAIL: API should be blocked!")
        return False


def test_admin_login():
    """Test admin login"""
    print("\n" + "="*70)
    print("TEST 2: Admin login")
    print("="*70)
    
    session = requests.Session()
    
    # Try to login
    response = session.post(
        f"{BASE_URL}/admin/api/login",
        json={"password": TEST_PASSWORD}
    )
    print(f"Login Status: {response.status_code}")
    print(f"Response: {response.json()}")
    
    if response.status_code == 200:
        print("✅ PASS: Admin login successful")
        return session
    else:
        print("❌ FAIL: Admin login failed")
        return None


def test_api_key_creation(session):
    """Test creating an API key"""
    print("\n" + "="*70)
    print("TEST 3: Create API key (requires admin session)")
    print("="*70)
    
    response = session.post(
        f"{BASE_URL}/admin/api/keys",
        json={
            "name": "Test API Key",
            "permissions": 1,  # At least one permission is required
            "rate_limit": 100
        }
    )
    print(f"Status: {response.status_code}")
    data = response.json()
    print(f"Response: {json.dumps(data, indent=2)}")
    
    if response.status_code == 201 and "api_key" in data:
        print("✅ PASS: API key created successfully")
        return data["api_key"]
    else:
        print("❌ FAIL: API key creation failed")
        return None


def test_api_with_key(api_key):
    """Test API access with API key"""
    print("\n" + "="*70)
    print("TEST 4: API access with API key (should work)")
    print("="*70)
    
    response = requests.get(
        f"{BASE_URL}/api/generate-secret",
        headers={"Authorization": f"Bearer {api_key}"}
    )
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    
    if response.status_code == 200:
        print("✅ PASS: API key authentication works")
        return True
    else:
        print("❌ FAIL: API key authentication failed")
        return False


def test_list_api_keys(session):
    """Test listing API keys"""
    print("\n" + "="*70)
    print("TEST 5: List API keys (requires admin session)")
    print("="*70)
    
    response = session.get(f"{BASE_URL}/admin/api/keys")
    print(f"Status: {response.status_code}")
    data = response.json()
    print(f"Found {len(data.get('keys', []))} API key(s)")
    
    if response.status_code == 200:
        print("✅ PASS: Successfully listed API keys")
        return True
    else:
        print("❌ FAIL: Failed to list API keys")
        return False


def test_invalid_api_key():
    """Test that invalid API keys are rejected"""
    print("\n" + "="*70)
    print("TEST 6: API access with invalid key (should fail)")
    print("="*70)
    
    # NOTE: Using a fake/invalid API key for testing invalid authentication
    response = requests.get(
        f"{BASE_URL}/api/generate-secret",
        headers={"Authorization": "Bearer invalid_key_12345"}  # Test-only invalid key
    )
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    
    if response.status_code == 401:
        print("✅ PASS: Invalid API key correctly rejected")
        return True
    else:
        print("❌ FAIL: Invalid API key should be rejected!")
        return False


def main():
    print("=" * 70)
    print("GitHub Events Limiter - API Authentication Test Suite")
    print("=" * 70)
    print(f"\nTesting against: {BASE_URL}")
    print(f"Admin password: {TEST_PASSWORD}")
    
    results = []
    
    # Test 1: No auth should fail
    results.append(test_api_without_auth())
    
    # Test 2: Admin login
    session = test_admin_login()
    if not session:
        print("\n❌ Cannot continue tests without admin session")
        return
    
    # Test 3: Create API key
    api_key = test_api_key_creation(session)
    if not api_key:
        print("\n❌ Cannot continue tests without API key")
        return
    
    # Test 4: Use API key
    results.append(test_api_with_key(api_key))
    
    # Test 5: List API keys
    results.append(test_list_api_keys(session))
    
    # Test 6: Invalid API key
    results.append(test_invalid_api_key())
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    passed = sum(results)
    total = len(results)
    print(f"Passed: {passed}/{total}")
    
    if passed == total:
        print("\n🎉 All tests passed!")
    else:
        print(f"\n⚠️  {total - passed} test(s) failed")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
    except Exception as e:
        print(f"\n❌ Test error: {e}")
        import traceback
        traceback.print_exc()
