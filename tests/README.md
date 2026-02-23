# UI Toolkit Tests

This directory contains comprehensive test coverage for the UI Toolkit project.

## Test Structure

```
tests/
├── conftest.py          # Pytest configuration and shared fixtures
├── test_auth.py         # Authentication tests (23 tests)
├── test_cache.py        # Caching system tests (19 tests)
├── test_config.py       # Configuration management tests (13 tests)
└── test_crypto.py       # Encryption utilities tests (14 tests)
```

## Running Tests

### Install Test Dependencies

```bash
pip install -r requirements-dev.txt
```

Or install directly:
```bash
pip install pytest pytest-asyncio pytest-mock httpx
```

### Run All Tests

```bash
pytest tests/
```

### Run with Verbose Output

```bash
pytest tests/ -v
```

### Run Specific Test File

```bash
pytest tests/test_auth.py
```

### Run Specific Test Class

```bash
pytest tests/test_auth.py::TestSessionManagement
```

### Run Specific Test

```bash
pytest tests/test_auth.py::TestSessionManagement::test_create_session_returns_token
```

### Show Test Coverage

```bash
pytest tests/ --cov=app --cov=shared --cov=tools
```

## Test Coverage Summary

### Authentication (test_auth.py) - 23 tests
- **Auth enabled check**: Tests for local vs production mode detection
- **Password verification**: bcrypt password hashing and verification
- **Session management**: Token creation, validation, and expiration
- **Rate limiting**: Failed login attempt tracking and IP-based blocking

### Caching (test_cache.py) - 19 tests
- **Gateway info cache**: Storing and retrieving gateway device information
- **IPS settings cache**: Caching IDS/IPS configuration
- **System status cache**: Full system status caching
- **Cache TTL**: Time-to-live expiration behavior
- **Cache invalidation**: Clearing specific or all cached data
- **Cache age tracking**: Monitoring how old cached data is

### Configuration (test_config.py) - 13 tests
- **Required settings**: Encryption key validation
- **Default values**: Database URL, log level, site ID, etc.
- **Optional fields**: UniFi controller settings, auth credentials
- **Environment overrides**: Loading from .env and environment variables
- **Singleton pattern**: get_settings() returns same instance

### Cryptography (test_crypto.py) - 14 tests
- **Password encryption**: Fernet symmetric encryption for passwords
- **Decryption**: Reversible encryption/decryption cycle
- **Special characters**: Unicode and special character handling
- **API key encryption**: Same mechanism as password encryption
- **Key generation**: Valid Fernet key generation
- **Error handling**: Invalid token detection

## Test Quality Principles

Tests in this project follow these principles:

1. **Test behavior, not implementation**: Focus on what the code does, not how it does it
2. **Descriptive names**: Test names explain what is being tested
3. **Arrange-Act-Assert**: Clear separation of setup, execution, and verification
4. **Independence**: Each test can run standalone
5. **Real scenarios**: Tests reflect actual use cases
6. **Edge cases**: Empty values, special characters, boundary conditions
7. **Error paths**: Invalid inputs and error handling

## Fixtures

### Shared Fixtures (conftest.py)

- **test_db**: Fresh in-memory SQLite database for each test
- **async_client**: AsyncClient for testing FastAPI endpoints
- **sample_unifi_config**: Sample UniFi controller configuration
- **sample_device_data**: Sample Wi-Fi client device from UniFi API

## Environment Variables

Tests use these environment variables (set automatically in conftest.py):

- `ENCRYPTION_KEY`: Auto-generated valid Fernet key for testing
- `DATABASE_URL`: In-memory SQLite database
- `DEPLOYMENT_TYPE`: Set to "local" (no auth required)
- `LOG_LEVEL`: Set to "ERROR" to reduce test output noise

## Adding New Tests

When adding new tests:

1. Create a new file: `tests/test_<module>.py`
2. Import the module to test and pytest
3. Organize tests into classes by feature area
4. Use descriptive test names starting with `test_`
5. Add docstrings explaining what each test verifies
6. Clean up resources in teardown methods if needed

Example:

```python
class TestNewFeature:
    """Tests for new feature functionality."""

    def test_feature_does_what_expected(self):
        """Should perform expected behavior when conditions are met."""
        # Arrange
        input_data = "test"

        # Act
        result = new_feature(input_data)

        # Assert
        assert result == expected_output
```

## Continuous Integration

These tests can be integrated into CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Run tests
  run: |
    pip install -r requirements-dev.txt
    pytest tests/ -v --cov=app --cov=shared --cov=tools
```

## Troubleshooting

**"Module not found" errors**: Make sure you're running from the project root and the virtual environment is activated.

**Database errors**: Tests use in-memory SQLite, so there should be no persistence issues.

**Encryption errors**: The test suite auto-generates a valid Fernet key in conftest.py.

**Environment variable conflicts**: Tests set their own environment variables. If tests behave unexpectedly, check for conflicting .env values.
