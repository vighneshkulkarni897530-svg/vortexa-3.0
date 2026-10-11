from fastapi import APIRouter

from promptshield.api.health import router as health_router
from promptshield.api.auth import router as auth_router
from promptshield.api.policies import router as policies_router
from promptshield.api.enforcement import router as enforce_router
from promptshield.api.review_queue import router as review_router
from promptshield.api.audit_events import router as audit_router
from promptshield.api.evaluations import router as eval_router
from promptshield.api.stats import router as stats_router

api_router = APIRouter()

# Mount all endpoint groups
api_router.include_router(health_router)
api_router.include_router(auth_router)
api_router.include_router(policies_router)
api_router.include_router(enforce_router)
api_router.include_router(review_router)
api_router.include_router(audit_router)
api_router.include_router(eval_router)
api_router.include_router(stats_router)
