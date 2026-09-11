"""Configuration that reads its credentials from the environment."""

import os

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
DATABASE_PASSWORD = os.environ.get("DATABASE_PASSWORD", "")
API_ENDPOINT = "https://example.invalid/api"
