import sys
import os
import traceback

# Ensure project directories are in sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
SIH_DIR = os.path.join(CURRENT_DIR, "sih159")

for p in [CURRENT_DIR, SIH_DIR]:
    abs_p = os.path.abspath(p)
    if os.path.isdir(abs_p) and abs_p not in sys.path:
        sys.path.insert(0, abs_p)

# Resolve FastAPI instance
err_direct = None
err_sih159 = None
err_traceback = None

try:
    from backend.app.main import app as _resolved_app
except Exception as exc:
    err_direct = f"{type(exc).__name__}: {exc}"
    err_traceback = traceback.format_exc()
    try:
        from sih159.backend.app.main import app as _resolved_app
    except Exception as exc2:
        err_sih159 = f"{type(exc2).__name__}: {exc2}"
        from fastapi import FastAPI

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
                "error_direct": str(err_direct),
                "error_sih159": str(err_sih159),
                "traceback": str(err_traceback),
                "sys_path": sys.path,
                "cwd": os.getcwd()
            }

# Top-level ASGI entrypoint for Vercel Serverless Function detection
app = _resolved_app
application = app
