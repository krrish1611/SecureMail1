import sys
import os
import traceback

# Ensure project directories are in sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
SIH_DIR = os.path.join(PROJECT_ROOT, "sih159")

for p in [SIH_DIR, PROJECT_ROOT, CURRENT_DIR]:
    abs_p = os.path.abspath(p)
    if os.path.isdir(abs_p) and abs_p not in sys.path:
        sys.path.insert(0, abs_p)

# Resolve FastAPI instance
try:
    from backend.app.main import app as _resolved_app
except Exception as e:
    try:
        from sih159.backend.app.main import app as _resolved_app
    except Exception as e2:
        from fastapi import FastAPI

        err_msg = traceback.format_exc()
        _resolved_app = FastAPI(title="SecureMailScope Diagnostics")

        @_resolved_app.get("/")
        @_resolved_app.get("/api")
        @_resolved_app.get("/api/")
        @_resolved_app.get("/api/index")
        @_resolved_app.get("/api/health")
        @_resolved_app.get("/{full_path:path}")
        def debug_fallback(full_path: str = ""):
            return {
                "status": "error",
                "message": "Failed to import FastAPI backend app",
                "error_direct": str(e),
                "error_sih159": str(e2),
                "traceback": err_msg,
                "sys_path": sys.path,
                "cwd": os.getcwd()
            }

# Top-level ASGI entrypoint for Vercel Serverless Function detection
app = _resolved_app
application = app
