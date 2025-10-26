# Testing Guide

## Running Tests

### Prerequisites
1. Start the server (locally or in Docker):
   ```bash
   # Local
   python main.py
   
   # Docker
   .\debug_docker.ps1
   ```

2. Ensure you have an admin API key set in `test_api_keys.py` (line 17)

### Run All Tests
```bash
# Authentication tests (simpler, good for quick checks)
python .\Tests\test_authentication.py

# Full API key tests
python -m unittest .\Tests\test_api_keys.py
```

### Run Specific Test
```bash
# Run a single test
python -m unittest Tests.test_api_keys.TestAPIKeys.test_admin_key_creation -v

# Run rate limit test (takes longer)
python -m unittest Tests.test_api_keys.TestAPIKeys.test_rate_limit_enforcement -v
```

## Cleanup Test Data

After running tests, you may want to clean up test API keys:

```bash
# Delete all test keys (names starting with 'test_' or 'stress_test_')
python .\Tests\test_api_keys.py --cleanup
```

Or manually via Python:
```python
from Tests.test_api_keys import cleanup_test_keys
cleanup_test_keys()
```

## Test Configuration

Edit these values in `test_api_keys.py`:
- `BASE_URL`: Server URL (default: http://localhost:5000)
- `ADMIN_API_KEY`: Your admin API key for testing

Edit `test_authentication.py`:
- `BASE_URL`: Server URL (default: http://127.0.0.1:5000)
- `TEST_PASSWORD`: Admin password (default: 1234)

## Notes

- Tests create temporary API keys with names starting with `test_`
- Rate limit tests may take several minutes to complete
- Use `--cleanup` to remove test keys after testing
- Tests require the server to be running and accessible
