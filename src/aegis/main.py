from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from aegis.api.routes import router
from aegis.config import Settings, get_settings
from aegis.container import Container
from aegis.errors import AegisError
from aegis.observability import RequestContextMiddleware, configure_logging
from aegis.services.metrics import MetricsRegistry


def create_app(*, settings: Settings | None = None, container: Container | None = None) -> FastAPI:
    runtime_settings = settings or get_settings()
    configure_logging(runtime_settings.log_level)

    @asynccontextmanager
    async def lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
        runtime_container = container
        if runtime_container is None:
            if runtime_settings.persistence == "postgres":
                runtime_container = await Container.build_postgres(runtime_settings)
            else:
                runtime_container = Container.build(runtime_settings)
        app.state.container = runtime_container
        yield
        await runtime_container.close()

    app = FastAPI(
        title="Aegis Gateway",
        version="0.1.0",
        description="Policy-enforced access to model-assisted analysis.",
        lifespan=lifespan,
    )
    if container is not None:
        app.state.container = container
    app.state.metrics = MetricsRegistry() if runtime_settings.metrics_enabled else None
    app.add_middleware(RequestContextMiddleware)
    app.include_router(router)

    @app.get("/metrics", include_in_schema=False)
    async def metrics() -> PlainTextResponse:
        if app.state.metrics is None:
            return PlainTextResponse("metrics disabled\n", status_code=404)
        return PlainTextResponse(
            app.state.metrics.render(),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    @app.exception_handler(AegisError)
    async def handle_aegis_error(request: Request, exc: AegisError) -> JSONResponse:
        del request
        content: dict[str, Any] = {
            "error": {"code": exc.code, "message": exc.message, "details": exc.details}
        }
        headers: dict[str, str] = {}
        retry_after = exc.details.get("retry_after_seconds")
        if exc.status_code == 429 and isinstance(retry_after, int):
            headers["Retry-After"] = str(retry_after)
        return JSONResponse(status_code=exc.status_code, content=content, headers=headers)

    return app


app = create_app()
