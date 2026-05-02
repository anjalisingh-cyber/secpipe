"""A safe file with no hardcoded secrets for testing."""

import os

# Correct way to handle credentials
AWS_ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY_ID")
DATABASE_URL = os.environ.get("DATABASE_URL")
API_KEY = os.environ.get("API_KEY")

APP_NAME = "SecureApp"
DEBUG = False
PORT = 8080
