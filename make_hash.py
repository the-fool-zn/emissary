"""Create the three login lines for your .env file.   python make_hash.py"""
import getpass
import secrets
import sys

from app.auth import hash_password

user = input("Admin username [admin]: ").strip() or "admin"
pw = getpass.getpass("Admin password (12+ characters): ")
if len(pw) < 12:
    sys.exit("Password too short. Use at least 12 characters.")
if pw != getpass.getpass("Repeat password: "):
    sys.exit("Passwords do not match.")
print("\nAdd these three lines to .env (replace any old ones):\n")
print(f"ADMIN_USER={user}")
print(f"ADMIN_PASSWORD_HASH={hash_password(pw)}")
print(f"SESSION_SECRET={secrets.token_urlsafe(48)}")
