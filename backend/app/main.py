from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from app.api import analysis, auth, dashboard, investigations, rules, uploads, users
from app.config import get_settings
from app.web import add_security_headers, mount_frontend

app = FastAPI(title="SOC Analyzer")
add_security_headers(app)
app.include_router(auth.router)
app.include_router(uploads.router)
app.include_router(analysis.router)
app.include_router(dashboard.router)
app.include_router(investigations.router)
app.include_router(rules.router)
app.include_router(users.router)


@app.middleware("http")
async def reject_oversized_uploads(request: Request, call_next):
    """Answer 413 from the Content-Length header BEFORE the body is read.

    Starlette spools a multipart body to a temp file before our route runs, so a size check
    inside the route would come too late to protect the server's disk.
    (Clients that omit Content-Length are still caught while copying, in the route.)
    """
    if request.method == "POST" and request.url.path == "/api/uploads":
        length = request.headers.get("content-length")
        limit = get_settings().max_upload_mb * 1024 * 1024
        if length is not None and length.isdigit() and int(length) > limit:
            return JSONResponse(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                content={"detail": f"File is larger than {get_settings().max_upload_mb} MB"},
            )
    return await call_next(request)


@app.get("/api/health")
def health() -> dict[str, str]:
    """Liveness check for Docker Compose and Cloud Run. Needs no auth or DB."""
    return {"status": "ok"}


# Last: the frontend's catch-all route must come after every API route.
_static_dir = get_settings().static_dir
if _static_dir is not None:
    mount_frontend(app, _static_dir)
