from fastapi import FastAPI

app = FastAPI(title="SOC Analyzer")


@app.get("/api/health")
def health() -> dict[str, str]:
    """Liveness check for Docker Compose and Cloud Run. Needs no auth or DB."""
    return {"status": "ok"}
