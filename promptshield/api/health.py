from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import Dict, Any

from promptshield.db.session import get_db
from promptshield.config import settings

router = APIRouter(tags=["Health"])


@router.get("/health", status_code=status.HTTP_200_OK)
def health_check(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Health check endpoint validating database connectivity and system status."""
    db_status = "unhealthy"
    try:
        # Parameterized connectivity ping
        db.execute(text("SELECT 1"))
        db_status = "healthy"
    except Exception as e:
        db_status = f"error: {str(e)}"

    return {
        "status": "UP" if db_status == "healthy" else "DEGRADED",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "database": db_status,
        "fail_secure_mode": settings.FAIL_SECURE_MODE,
    }
