"""Scan Routes."""

from fastapi import APIRouter
from starlette.responses import JSONResponse
import ujson

from scan_compute.types.scan import ScanStartPayload
from scan_compute.utils.cache import cache

STREAM_NAME = "scan_tasks"

router = APIRouter(
    prefix="/scan",
    tags=["scan"],
    responses={404: {"description": "Not found"}},
)


@router.post(
    "/start",
    responses={403: {"description": "Operation forbidden"}},
)
async def handle_scan_start(payload: ScanStartPayload) -> JSONResponse:
    """Scan Start endpoint."""
    await cache.xadd(
        STREAM_NAME,
        {
            # NOTE: later on we can add more keys apart from
            # payload to attach metadata that can then be attached to the consumers
            # processing this scan
            "payload": ujson.dumps(
                {
                    "bucket_name": payload.bucket_name,
                    "schema_name": payload.schema_name,
                    "account_id": payload.account_id,
                    "scan_id": payload.scan_id,
                    "scan_type": payload.scan_type,
                    "cloud_provider": payload.cloud_provider,
                }
            )
        },
    )
    return JSONResponse(
        content={"message": "scan request received"},
        status_code=200,
    )
