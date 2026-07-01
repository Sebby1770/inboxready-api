from __future__ import annotations

import os
from pathlib import Path
import sys


ROOT_DIR = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT_DIR / "API" / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# Vercel functions have an ephemeral filesystem, so default launch storage to /tmp.
os.environ.setdefault("INBOXREADY_DATABASE_PATH", "/tmp/inboxready.sqlite3")
os.environ.setdefault("INBOXREADY_OBJECT_STORE_PATH", "/tmp/inboxready-object-store")
os.environ.setdefault("INBOXREADY_SESSION_HTTPS_ONLY", "true")

from inboxready_api.main import app  # noqa: E402
