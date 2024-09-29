"""Request Handler Dependencies."""

from fastapi import Header, HTTPException
from typing_extensions import Annotated

from scan_compute.utils.config import settings


async def validate_token_header(
    x_token: Annotated[str, Header()],
) -> None:
    """Validate token header."""
    if x_token != settings.API_KEY:
        raise HTTPException(
            status_code=400,
            detail="X-Token header invalid",
        )
