# EthioSec Scanner - Database Setup & Management

This guide explains how to set up the local PostgreSQL database, apply schema migrations, seed demonstration records, and run database verification tests on a fresh machine.

---

## 1. Install & Start PostgreSQL

### On Fedora / RHEL
```bash
sudo dnf install -y postgresql-server postgresql-contrib
sudo postgresql-setup --initdb
sudo systemctl enable --now postgresql
```

### On Ubuntu / Debian
```bash
sudo apt update && sudo apt install -y postgresql postgresql-contrib
sudo systemctl enable --now postgresql
```

### On macOS (Homebrew)
```bash
brew install postgresql@15
brew services start postgresql@15
```

---

## 2. Create User and Databases

Run the following commands as the `postgres` system user:

```bash
sudo -u postgres psql
```

Inside the `psql` prompt, run:

```sql
-- 1. Create the application user with a password
CREATE USER ethiosec_user WITH PASSWORD 'ethiosec_password';

-- 2. Create the development and test databases owned by ethiosec_user
CREATE DATABASE ethiosec OWNER ethiosec_user;
CREATE DATABASE ethiosec_test OWNER ethiosec_user;

-- 3. Grant schema permissions
GRANT ALL PRIVILEGES ON DATABASE ethiosec TO ethiosec_user;
GRANT ALL PRIVILEGES ON DATABASE ethiosec_test TO ethiosec_user;

\q
```

---

## 3. Configure `.env`

From the project root:

```bash
cp .env.example .env
```

Ensure the database connection URLs match your credentials:

```ini
DATABASE_URL=postgresql+psycopg2://ethiosec_user:ethiosec_password@localhost:5432/ethiosec
TEST_DATABASE_URL=postgresql+psycopg2://ethiosec_user:ethiosec_password@localhost:5432/ethiosec_test
```

---

## 4. Run Migrations

Activate the virtual environment and apply migrations to build the tables:

```bash
source venv/bin/activate
alembic upgrade head
```

To roll back migrations to base:
```bash
alembic downgrade base
```

---

## 5. Seed Demonstration Data

Populate the database with a demonstration user, settings, verified target, completed scan, and findings covering every severity level (Critical, High, Medium, Low, Info):

```bash
python database/seed/seed.py
```

*Note: The seed script is idempotent and safe to run multiple times without creating duplicate records.*

---

## 6. Run Database Tests

Execute the automated test suite to verify table existence, CHECK constraints, UNIQUE constraints, cascade deletion, and single-transaction integrity:

```bash
pytest -v backend/tests/test_database.py
```

All tests execute strictly against `TEST_DATABASE_URL` (`ethiosec_test`) and never modify the development database.

---

## 7. Schema Architecture Notes

* **Single Source of Truth**: The SQLAlchemy models in `backend/app/models/` and Alembic migrations in `database/migrations/` define the schema.
* **`database/schema.sql`**: An exported copy generated via `pg_dump --schema-only` for reference and documentation only. Do not edit it manually.
* **Adding Allowed Values**: Alembic autogenerate does not detect altered `CheckConstraint` expressions. When adding values to `backend/app/utils/vocabulary.py`, write a dedicated Alembic migration using `op.drop_constraint` and `op.create_check_constraint`.
