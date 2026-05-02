"""Deliberately insecure file for testing SecPipe's secrets scanner.

DO NOT use any of these values. They are fake examples.
"""

# AWS Access Key (fake)
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

# Database connection string with password
DATABASE_URL = "postgresql://admin:s3cretP@ss@localhost:5432/mydb"

# GitHub token (fake)
GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"

# This is safe — no secrets here
APP_NAME = "MyApp"
DEBUG = True
PORT = 8080
