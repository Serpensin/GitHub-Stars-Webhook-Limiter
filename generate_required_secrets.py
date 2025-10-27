"""
Generate Required Secrets for Environment Variables

This script generates all required secrets for the application:
- ENCRYPTION_KEY: Fernet key for encrypting sensitive data
- ADMIN_PASSWORD_HASH: Argon2id hash for admin authentication
- FLASK_SECRET_KEY: Secret key for Flask session management

The script checks if these are already set in the environment and exits
immediately if any are missing, preventing the application from starting
with incomplete configuration.
"""

import os
import re
import secrets
import sys

from argon2 import PasswordHasher
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# Load .env file (won't override existing environment variables)
load_dotenv()

# Placeholder values that should NOT be used in production
INVALID_PLACEHOLDERS = {
    "ENCRYPTION_KEY": [
        "your-encryption-key-here",
        "your-fernet-key-here",
        "",
    ],
    "ADMIN_PASSWORD_HASH": [
        "your-argon2-hash-here",
        "your-admin-password-hash-here",
        "",
    ],
    "FLASK_SECRET_KEY": [
        "your-flask-secret-key-here",
        "your-secret-key-here",
        "",
    ],
}


def validate_argon2_hash(hash_string: str) -> bool:
    """
    Validate that a string is a valid Argon2 hash.

    Args:
        hash_string: The hash string to validate

    Returns:
        True if valid Argon2 hash, False otherwise
    """
    if not hash_string:
        return False

    # Check format: $argon2id$v=19$m=...,t=...,p=...$...$...
    pattern = r"^\$argon2id?\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$"
    if not re.match(pattern, hash_string):
        return False

    # Additional validation: verify it starts with correct prefix
    return hash_string.startswith("$argon2")


def check_required_env_vars():
    """
    Check if all required environment variables are set and valid.
    Exit immediately if any are missing or contain placeholder values.
    """
    required_vars = ["ENCRYPTION_KEY", "ADMIN_PASSWORD_HASH", "FLASK_SECRET_KEY"]

    missing_vars = []
    invalid_vars = []

    for var in required_vars:
        value = os.environ.get(var)

        if not value:
            missing_vars.append(var)
            continue

        # Check if value is a placeholder
        if value in INVALID_PLACEHOLDERS.get(var, []):
            invalid_vars.append((var, "placeholder value detected"))
            continue

        # Special validation for ADMIN_PASSWORD_HASH
        if var == "ADMIN_PASSWORD_HASH":
            if not validate_argon2_hash(value):
                invalid_vars.append((var, "not a valid Argon2 hash"))

    if missing_vars or invalid_vars:
        print("[X] ERROR: Environment configuration is invalid!")
        print("=" * 70)

        if missing_vars:
            print("\n[!] Missing variables:")
            for var in missing_vars:
                print(f"  - {var}")

        if invalid_vars:
            print("\n[!] Invalid variables:")
            for var, reason in invalid_vars:
                print(f"  - {var}: {reason}")

        print("\n" + "=" * 70)
        print("The application cannot start with invalid configuration.")
        print("Run this script to generate valid secrets:")
        print("  python generate_required_secrets.py")
        print("\nThen add the generated values to your .env file.")
        print("=" * 70)
        print("\nExiting immediately...")
        sys.exit(1)

    print("[OK] All required environment variables are set and valid!")
    return True


def generate_all_secrets():
    """Generate all required secrets for the application."""
    print("=" * 70)
    print("GitHub Events Limiter - Required Secrets Generator")
    print("=" * 70)
    print()

    # Generate ENCRYPTION_KEY
    encryption_key = Fernet.generate_key().decode()
    print("[*] Generated ENCRYPTION_KEY (Fernet)")

    # Generate FLASK_SECRET_KEY
    flask_secret = secrets.token_hex(32)
    print("[*] Generated FLASK_SECRET_KEY (64-character hex)")

    # Generate ADMIN_PASSWORD_HASH
    password = input("\n[>] Enter admin password: ")
    confirm = input("[>] Confirm admin password: ")

    if password != confirm:
        print("\n[X] Passwords do not match!")
        sys.exit(1)

    if len(password) < 8:
        print("\n[!] Warning: Password is less than 8 characters.")
        print("    Consider using a stronger password for better security.")

    ph = PasswordHasher()
    password_hash = ph.hash(password)
    print("[*] Generated ADMIN_PASSWORD_HASH (Argon2id)")

    # Display results
    print("\n" + "=" * 70)
    print("[OK] All secrets generated successfully!")
    print("=" * 70)
    print("\n[INFO] Add these to your .env file:\n")
    print(f"ENCRYPTION_KEY={encryption_key}")
    print(f"FLASK_SECRET_KEY={flask_secret}")
    print(f"ADMIN_PASSWORD_HASH={password_hash}")

    print("\n" + "=" * 70)
    print("[INFO] Or add to docker-compose.yml environment section:\n")
    print(f"      ENCRYPTION_KEY: {encryption_key}")
    print(f"      FLASK_SECRET_KEY: {flask_secret}")
    print(f"      ADMIN_PASSWORD_HASH: {password_hash}")

    print("\n" + "=" * 70)
    print("[!] IMPORTANT SECURITY NOTES:")
    print("=" * 70)
    print("1. Keep these secrets safe and never commit them to version control")
    print("2. Use different secrets for development and production")
    print("3. If any secret is compromised, regenerate ALL secrets")
    print("4. Store production secrets in a secure secret manager")
    print("=" * 70)


def main():
    """Main entry point - check env vars or generate secrets."""
    if len(sys.argv) > 1 and sys.argv[1] == "--check":
        # Check mode: verify all required env vars are set
        check_required_env_vars()
    else:
        # Generate mode: create new secrets
        generate_all_secrets()


if __name__ == "__main__":
    main()
