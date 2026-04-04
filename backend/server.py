"""Compatibility shim for the dashboard launcher.

The canonical FastAPI app now lives in the project-root server module.
"""

from server import app


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("server:app", host="0.0.0.0", port=7860, reload=True)
