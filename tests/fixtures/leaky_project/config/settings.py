"""Application settings. DELIBERATELY LEAKY TEST FIXTURE - values are fake."""

import os

AWS_ACCESS_KEY_ID = "{{AWS_ACCESS_KEY_ID}}"
AWS_SECRET_ACCESS_KEY = "{{AWS_SECRET_ACCESS_KEY}}"
GITHUB_TOKEN = "{{GITHUB_TOKEN}}"
STRIPE_KEY = "{{STRIPE_LIVE_KEY}}"
api_key = "{{API_KEY}}"
DATABASE_URL = "postgres://app_user:{{DSN_PASSWORD}}@db.internal:5432/app"
session_salt = "{{SESSION_SALT}}"

# Things that must NOT be reported:
LEGACY_TOKEN = "{{GITHUB_TOKEN}}"  # leakhound:allow (rotated, kept for a migration test)
ADMIN_PASSWORD = "changeme123"
REGION_KEY = os.environ["AWS_ACCESS_KEY_ID"]
