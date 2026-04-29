# Jen Test Suite

Automated tests covering authentication, dashboard, users, reservations,
leases, and settings.

## Setup

### 1. Install pytest
```bash
pip3 install pytest --break-system-packages
```

### 2. Create the test database
Run this once on your MySQL server (`10.10.11.250`):
```sql
CREATE DATABASE jen_test;
GRANT ALL PRIVILEGES ON jen_test.* TO 'jen'@'%';
FLUSH PRIVILEGES;
```

The test suite reads credentials from `/etc/jen/jen.config` automatically.
It always uses `jen_test` — your production `jen` database is never touched.

### 3. Run the tests
From the `jen/` directory:
```bash
pytest tests/ -v
```

Or run a specific file:
```bash
pytest tests/test_auth.py -v
```

Or a specific test:
```bash
pytest tests/test_auth.py::TestLogin::test_login_success -v
```

## What's tested

| File | Coverage |
|---|---|
| `test_auth.py` | Login, logout, auth required, rate limiting |
| `test_dashboard.py` | Dashboard load, api/stats JSON, Kea down graceful |
| `test_users.py` | Password hashing, create user, change password, session timeout |
| `test_reservations.py` | Add/delete reservation, validation, settings pages |
| `test_leases.py` | Lease list, search, IP map |
| `test_settings.py` | Settings cache, save branding/session/ports, audit log |

## How it works

- Tests use a Flask test client — no real server runs
- Kea API calls are mocked — no real Kea server needed
- Each test starts with clean state (tables wiped between tests)
- The admin user is reset to `admin/admin` before each test
- The test database schema is created at session start and dropped at end

## CI / automated runs

Set environment variables if `/etc/jen/jen.config` is not available:
```bash
JEN_DB_HOST=10.10.11.250 JEN_DB_USER=jen JEN_DB_PASS=yourpass pytest tests/ -v
```
