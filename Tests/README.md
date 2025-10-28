# Tests

Comprehensive test suite for the GitHub Events Limiter application.

## Overview

This directory contains integration tests that validate the application's API endpoints, authentication system, and business logic. All tests are implemented using Python's `unittest` framework and require a running instance of the application.

## Test Files

### test_authentication.py
Tests the authentication and authorization system:
- ✅ API access without authentication (should be blocked)
- ✅ Admin login with password
- ✅ API key creation through admin panel
- ✅ API access with valid API keys
- ✅ API key listing
- ✅ Invalid API key rejection

**Run:** `python -m unittest Tests.test_authentication -v`

### test_all_endpoints.py
Tests all API endpoints for proper behavior:
- ✅ All API routes (GET, POST, PATCH, DELETE)
- ✅ Admin panel endpoints
- ✅ Web interface endpoints
- ✅ Webhook endpoint
- ✅ Permission endpoints (list, calculate, decode)
- ✅ Error handling (404, 400, 401, 403, 405)
- ✅ Input validation
- ✅ Method validation (reject unsupported HTTP methods)

**Run:** `python -m unittest Tests.test_all_endpoints -v`

## Prerequisites

### 1. Running Application
The tests require a running instance of the application:

**Using Docker (Recommended):**
```bash
docker-compose up -d
```

**Manual:**
```bash
python main.py
```

The application should be accessible at `http://localhost:5000` (or update `BASE_URL` in test files).

### 2. Admin Password
Ensure the admin password in the tests matches your configured password:

```python
TEST_PASSWORD = "1234"  # Update this in test files if needed
```

### 3. Dependencies
Install test dependencies:
```bash
pip install requests
```

## Running Tests

### Run All Tests
```bash
python -m unittest discover Tests -v
```

### Run Specific Test File
```bash
python -m unittest Tests.test_authentication -v
python -m unittest Tests.test_all_endpoints -v
```

### Run Specific Test Class
```bash
python -m unittest Tests.test_authentication.TestAuthentication -v
```

### Run Specific Test Method
```bash
python -m unittest Tests.test_authentication.TestAuthentication.test_01_api_without_auth -v
```

## Test Configuration

### Base URL
Default: `http://127.0.0.1:5000`

To test against a different server:
```python
BASE_URL = "https://your-domain.com"
```

### Admin Password
Default: `"1234"`

Update in test files to match your environment:
```python
TEST_PASSWORD = "your-admin-password"
```

## Test Execution Order

Tests are designed to run independently, but some test files use sequential naming for logical flow:

**test_authentication.py:**
1. `test_01_api_without_auth` - Verify API is protected
2. `test_02_admin_login` - Log in as admin
3. `test_03_api_key_creation` - Create API key
4. `test_04_api_with_key` - Use API key
5. `test_05_list_api_keys` - List keys
6. `test_06_invalid_api_key` - Reject invalid keys

## Expected Behavior

### Successful Test Run
```
test_01_api_without_auth ... ok
test_02_admin_login ... ok
test_03_api_key_creation ... ok
...
----------------------------------------------------------------------
Ran 6 tests in 2.345s

OK
```

### Failed Tests
Tests will show detailed failure information:
```
FAIL: test_api_with_key (Tests.test_authentication.TestAuthentication)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "...", line 95, in test_api_with_key
    self.assertEqual(response.status_code, 200)
AssertionError: 403 != 200
```

## Common Issues

### Connection Refused
```
ConnectionError: HTTPConnectionPool(...): Max retries exceeded
```
**Solution:** Ensure the application is running on the specified `BASE_URL`.

### Authentication Failures
```
AssertionError: 401 != 200
```
**Solution:** 
- Verify `TEST_PASSWORD` matches the admin password in `.env`
- Check that `ADMIN_PASSWORD_HASH` in `.env` is valid

### Permission Errors
```
AssertionError: 403 != 200
```
**Solution:** Ensure API keys have the required permissions for the endpoint being tested.

## Test Coverage

The test suite covers:
- **Authentication:** Password hashing, API key validation, session management
- **Authorization:** Permission bitmaps, role-based access control
- **Rate Limiting:** Per-key rate limits, concurrent request handling
- **Input Validation:** Missing fields, invalid data types, boundary conditions
- **Error Handling:** 400, 401, 403, 404, 405 responses
- **Business Logic:** Repository management, event tracking, webhook validation

## Performance Tests

**test_api_keys.py** includes performance tests for rate limiting:
- Creates API keys with different rate limits
- Makes concurrent requests to test enforcement
- Validates that rate limits are respected

**Note:** These tests can take several minutes to complete due to concurrent request simulation.

## CI/CD Integration

Run tests in CI/CD pipelines:

```yaml
# Example GitHub Actions
- name: Run tests
  run: |
    docker-compose up -d
    sleep 5  # Wait for application to start
    python -m unittest discover Tests -v
    docker-compose down
```

## Debugging Tests

### Verbose Output
```bash
python -m unittest Tests.test_authentication -v
```

### Print Response Data
Uncomment `print()` statements in test files to see detailed response information.

### Interactive Testing
Use the test files as examples for manual API testing with `curl` or Postman.

## Contributing

When adding new tests:
1. Follow the existing naming convention (`test_*`)
2. Use descriptive test names
3. Add docstrings explaining what is being tested
4. Clean up created resources (API keys, repositories) after tests
5. Use `self.subTest()` for parameterized tests
6. Test both success and failure cases
