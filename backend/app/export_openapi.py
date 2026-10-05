"""Print the API's OpenAPI schema as JSON (used by the frontend's `npm run gen:api`).

Usage:  uv run python -m app.export_openapi > openapi.json
No server needs to run; importing the app does not connect to the database.
"""

import json

from app.main import app

if __name__ == "__main__":
    print(json.dumps(app.openapi(), indent=2))
