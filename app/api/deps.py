import os
from fastapi import Security, HTTPException, status
from fastapi.security.api_key import APIKeyHeader

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

_PULSE_API_KEY = os.getenv("PULSE_API_KEY", "")


async def verify_api_key(api_key: str = Security(_api_key_header)) -> str:
    """
    Validates X-API-Key header against PULSE_API_KEY env var.
    If PULSE_API_KEY is not configured, all requests are allowed (dev mode).
    """
    if not _PULSE_API_KEY:
        return ""
    if api_key != _PULSE_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing API key. Set X-API-Key header.",
        )
    return api_key
