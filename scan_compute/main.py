"""Entry point for scan compute."""

from fastapi import Depends, FastAPI

from scan_compute.dependencies import validate_token_header
from scan_compute.routers import scan

app = FastAPI(
    dependencies=[Depends(validate_token_header)],
)
app.include_router(scan.router)
