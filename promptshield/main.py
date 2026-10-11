from contextlib import asynccontextmanager
import logging
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.exc import SQLAlchemyError

from promptshield.config import settings
from promptshield.api.router import api_router
from promptshield.db.session import create_all_tables

# Configure structured logging
logging.basicConfig(
    level=logging.INFO if not settings.DEBUG else logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("promptshield")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Safe database initialization
    logger.info("Initializing PromptShield database schemas...")
    try:
        create_all_tables()
        logger.info("PromptShield schema initialization completed successfully.")
        from promptshield.db.session import SessionLocal
        from promptshield.db.seed import seed_default_data
        with SessionLocal() as db:
            seed_default_data(db)
    except Exception as e:
        logger.error(f"Failed to auto-initialize schemas: {e}")
    yield
    logger.info("PromptShield application shutting down.")


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        description="PromptShield: Trusted Policy Management and Data Persistence Layer for Prompt Injection & Data-Exfiltration Defense",
        lifespan=lifespan,
    )

    # CORS configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Security Headers Middleware
    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    # Global Exception Handler for Database Errors
    # Requirement: "Return consistent success and error responses. Do not expose database exceptions or internal stack traces."
    @app.exception_handler(SQLAlchemyError)
    async def sqlalchemy_exception_handler(request: Request, exc: SQLAlchemyError):
        logger.error(f"Database error during request {request.method} {request.url.path}: {exc}", exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "DatabaseOperationError",
                "detail": "A database persistence error occurred. The incident has been logged safely."
            }
        )

    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception):
        logger.error(f"Unhandled server exception during request {request.method} {request.url.path}: {exc}", exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "InternalServerError",
                "detail": "An internal server error occurred. Please contact the administrator."
            }
        )

    # Mount API v1 router
    app.include_router(api_router, prefix=settings.API_V1_STR)

    @app.get("/health", include_in_schema=False)
    async def root_health():
        return {
            "status": "UP",
            "service": settings.PROJECT_NAME,
            "version": settings.VERSION,
            "environment": settings.ENVIRONMENT,
        }

    return app


app = create_app()
