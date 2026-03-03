# OWASP FinBot CTF

See Collaborator Hub for details on this project: https://github.com/OWASP-ASI/FinBot-CTF-workstream


## Dev Guide (Temporary)

** Warning: `main` branch is potentially unstable **

Please follow below instructions to test drive the current branch

### Prerequisites

Check if you have the required tools:
```bash
python scripts/check_prerequisites.py
```

### Setup

```bash
# Install dependencies
uv sync

# Setup database (defaults to sqlite)
uv run python scripts/setup_database.py

# Or specify database type explicitly
uv run python scripts/setup_database.py --db-type sqlite

# For PostgreSQL and Redis: start the services first
docker compose up -d postgres redis
uv run python scripts/setup_database.py --db-type postgresql

# Start the platform
uv run python run.py
```

Platform runs at http://localhost:8000
