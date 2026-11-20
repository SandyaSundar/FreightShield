"""Shared exceptions and handlers so every error returns the same JSON shape."""
import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


class UpstreamError(Exception):
    """Raised when Wazuh (or another upstream) is unreachable or returns an error."""

    def __init__(self, service: str, detail: str, status_code: int = 502):
        self.service, self.detail, self.status_code = service, detail, status_code


class NotConfiguredError(Exception):
    """Raised when required environment variables for a service are missing."""

    def __init__(self, service: str):
        self.service = service


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(UpstreamError)
    async def _upstream(_: Request, exc: UpstreamError):
        # Message is deliberately generic: never leak URLs or credentials to the client.
        return JSONResponse(status_code=exc.status_code,
                            content={"error": "upstream_error", "service": exc.service, "detail": exc.detail})

    @app.exception_handler(NotConfiguredError)
    async def _nc(_: Request, exc: NotConfiguredError):
        return JSONResponse(status_code=503,
                            content={"error": "not_configured", "service": exc.service,
                                     "detail": f"{exc.service} is not configured on the server."})

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError):
        # Never echo submitted values back (they may contain credentials or attacker-controlled markup).
        errs = [{"loc": [str(x) for x in e.get("loc", ())][:6], "msg": str(e.get("msg", ""))[:200], "type": e.get("type")}
                for e in exc.errors()[:20]]
        return JSONResponse(status_code=422, content={"error": "validation_error", "detail": errs})

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception):
        logging.getLogger("freightshield").error("unhandled error: %s", type(exc).__name__)
        return JSONResponse(status_code=500, content={"error": "internal_error", "detail": "Unexpected server error."})
