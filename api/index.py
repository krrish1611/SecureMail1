import sys
import os

# Ensure project directories are in sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
PARENT_ROOT = os.path.dirname(PROJECT_ROOT)
SIH_DIR = os.path.join(PARENT_ROOT, "sih159")

for p in [PROJECT_ROOT, CURRENT_DIR, PARENT_ROOT, SIH_DIR]:
    if os.path.isdir(p) and p not in sys.path:
        sys.path.insert(0, p)

try:
    from backend.app.main import app
except ImportError:
    from sih159.backend.app.main import app
