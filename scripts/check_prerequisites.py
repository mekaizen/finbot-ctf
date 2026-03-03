"""
Check prerequisites for running FinBot CTF
"""

import shutil
import subprocess
import sys


def check_command(command: str, name: str, install_hint: str) -> bool:
    """Check if a command is available"""
    if shutil.which(command):
        print(f"✅ {name} is installed")
        return True
    else:
        print(f"❌ {name} is not installed")
        print(f"   Install: {install_hint}")
        return False


def check_docker_running() -> bool:
    """Check if Docker daemon is running"""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            check=False,
            timeout=5,
        )
        if result.returncode == 0:
            print("✅ Docker daemon is running")
            return True
        else:
            print("❌ Docker daemon is not running")
            print("   Start Docker Desktop or run: sudo systemctl start docker")
            return False
    except subprocess.TimeoutExpired:
        print("❌ Docker command timed out")
        return False
    except FileNotFoundError:
        print("❌ Docker is not installed")
        return False


def main():
    """Check all prerequisites"""
    print("🔍 Checking FinBot CTF Prerequisites\n")

    checks = []

    # Check Python
    checks.append(check_command("python3", "Python 3", "https://www.python.org/downloads/"))

    # Check uv
    checks.append(check_command("uv", "uv", "curl -LsSf https://astral.sh/uv/install.sh | sh"))

    # Check Docker
    has_docker = check_command("docker", "Docker", "https://docs.docker.com/get-docker/")
    checks.append(has_docker)

    # Check if Docker daemon is running (only if Docker is installed)
    if has_docker:
        checks.append(check_docker_running())

    # Check for Redis (local or docker)
    has_redis = shutil.which("redis-cli") or shutil.which("redis-server")
    if not has_redis and has_docker:
        # Check if redis container is running
        try:
            result = subprocess.run(
                ["docker", "ps", "--filter", "name=redis", "--format", "{{.Names}}"],
                capture_output=True,
                text=True,
                check=False
            )
            if "redis" in result.stdout.lower():
                has_redis = True
    
        except Exception:
            has_redis = False
    
    if has_redis:
        print("✅ Redis is available")
    else:
        print("❌ Redis is not installed or running")
        print("   Run: docker compose up -d redis")
        checks.append(False)

    print("\n" + "=" * 50)
    if all(checks):
        print("✅ All prerequisites are met!")
        print("\nYou can now run:")
        print("  uv sync")
        print("  docker compose up -d postgres  # If using PostgreSQL")
        print("  uv run python scripts/setup_database.py")
        sys.exit(0)
    else:
        print("❌ Some prerequisites are missing")
        print("\nFor SQLite-only development, you only need Python and uv.")
        print("For PostgreSQL, you also need Docker.")
        sys.exit(1)


if __name__ == "__main__":
    main()
