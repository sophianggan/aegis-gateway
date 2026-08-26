from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from aegis.api.routes import router
from aegis.config import Settings, get_settings
from aegis.container import Container
from aegis.errors import AegisError


def create_app(*, settings: Settings | None = None, container: Container | None = None) -> FastAPI:
    runtime_settings = settings or get_settings()
    runtime_container = container or Container.build(runtime_settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
        app.state.container = runtime_container
        yield
        close = getattr(runtime_container.model, "close", None)
        if close is not None:
            await close()

    app = FastAPI(
        title="Aegis Gateway",
        version="0.1.0",
        description="Policy-enforced access to model-assisted analysis.",
        lifespan=lifespan,
    )
    app.state.container = runtime_container
    app.include_router(router)

    @app.exception_handler(AegisError)
    async def handle_aegis_error(request: Request, exc: AegisError) -> JSONResponse:
        del request
        content: dict[str, Any] = {
            "error": {"code": exc.code, "message": exc.message, "details": exc.details}
        }
        return JSONResponse(status_code=exc.status_code, content=content)

    return app


app = create_app()

