"""Serving the built React app (frontend/dist) from FastAPI: one container, one origin.

- /api/...           the API (unknown API paths stay JSON 404s, never the HTML app)
- /assets/<hash>.js  build output; names change when content changes -> cached for a year
- any other path     index.html (SPA fallback: React Router handles the path in the browser,
                     so refreshing /uploads/7?tab=events works); never cached, so deploys show up
"""

from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.responses import FileResponse

IMMUTABLE = "public, max-age=31536000, immutable"
NO_CACHE = "no-cache"

# Content Security Policy for the app. script-src 'self': no inline or third-party scripts can run,
# so even attacker-controlled log text that somehow became HTML could not execute JavaScript.
# style-src allows inline styles: React sets style attributes (bar widths, chart positions);
# inline styles can't run code. frame-ancestors 'none' blocks clickjacking.
CSP = "; ".join([
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
])
# Swagger UI / ReDoc load their scripts from a CDN; they're read-only developer docs, so exempt.
CSP_EXEMPT_PREFIXES = ("/docs", "/redoc")


def add_security_headers(app: FastAPI) -> None:
    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        if not request.url.path.startswith(CSP_EXEMPT_PREFIXES):
            response.headers["Content-Security-Policy"] = CSP
        return response


def mount_frontend(app: FastAPI, static_dir: Path) -> None:
    """Serve the built frontend. Call AFTER all API routes are registered (the catch-all is last)."""
    root = static_dir.resolve()
    index = root / "index.html"

    # include_in_schema=False: not an API endpoint (and keeps it out of the route-protection test).
    @app.get("/{full_path:path}", include_in_schema=False)
    def frontend(full_path: str) -> FileResponse:
        if full_path == "api" or full_path.startswith("api/"):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
        candidate = (root / full_path).resolve()
        if full_path and candidate.is_file() and candidate.is_relative_to(root):  # no ../ escapes
            cache = IMMUTABLE if full_path.startswith("assets/") else NO_CACHE
            return FileResponse(candidate, headers={"Cache-Control": cache})
        return FileResponse(index, headers={"Cache-Control": NO_CACHE})
