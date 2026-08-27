from typing import Annotated

from fastapi import Header, Request

from aegis.container import Container
from aegis.domain.models import Principal


def get_container(request: Request) -> Container:
    return request.app.state.container  # type: ignore[no-any-return]


def get_principal(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> Principal:
    container = get_container(request)
    return container.authenticator.authenticate(authorization)
