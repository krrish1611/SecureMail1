"""FastAPI application entry point for SecureMailScope backend."""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

app = FastAPI(
    title="SecureMailScope API",
    description="AI-Assisted Cryptographic Security Posture Assessment for Email",
    version="0.1.0",
)

from fastapi.responses import JSONResponse
import traceback
from fastapi import Request

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal Server Error", "error_type": type(exc).__name__, "error_msg": str(exc), "traceback": traceback.format_exc()}
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://securermail.netlify.app",
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "*",
    ],
    allow_origin_regex=r"https://.*\.netlify\.app",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

from .routers.analyze import router as analyze_router
app.include_router(analyze_router)

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "dist")


@app.get("/api/health")
@app.head("/api/health")
@app.get("/health")
@app.head("/health")
@app.get("/ping")
@app.head("/ping")
def health():
    return {"status": "ok", "tool": "SecureMailScope", "version": "0.1.0"}

from core.history import DB_DIR
@app.get("/api/debug")
def debug():
    return {"db_dir": DB_DIR}


@app.get("/")
@app.get("/api")
@app.get("/api/")
@app.get("/api/index")
def root():
    return {
        "status": "online",
        "service": "SecureMailScope API",
        "version": "0.1.0",
        "health": "/api/health",
        "docs": "/docs"
    }



# Serve React build if it exists
if os.path.isdir(FRONTEND_DIR):
    app.mount("/assets", StaticFiles(directory=os.path.join(FRONTEND_DIR, "assets")), name="assets")

    @app.get("/{full_path:path}")
    @app.head("/{full_path:path}")
    async def serve_spa(full_path: str):
        # Never return index.html for API endpoints
        if full_path.startswith("api/") or full_path == "api":
            raise HTTPException(status_code=404, detail=f"API endpoint not found: /{full_path}")
        file_path = os.path.join(FRONTEND_DIR, full_path)
        if os.path.isfile(file_path):
            return FileResponse(file_path)
        return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))
