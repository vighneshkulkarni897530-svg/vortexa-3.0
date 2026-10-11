from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from promptshield.db.session import get_db
from promptshield.db.models import EvaluationRun, AuditEvent, User, utc_now
from promptshield.schemas.evaluation import EvaluationRunCreate, EvaluationRunResponse
from promptshield.security.dependencies import get_current_user, require_auditor_or_admin

router = APIRouter(prefix="/evaluations", tags=["Evaluation Runs & Benchmarks"])


@router.get("", response_model=List[EvaluationRunResponse])
def list_evaluations(
    dataset_name: Optional[str] = Query(None, description="Filter by dataset"),
    execution_status: Optional[str] = Query(None, description="Filter by execution status"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve benchmark evaluation runs and accuracy metrics."""
    query = db.query(EvaluationRun)
    if dataset_name:
        query = query.filter(EvaluationRun.dataset_name == dataset_name)
    if execution_status:
        query = query.filter(EvaluationRun.execution_status == execution_status.upper())
    
    runs = query.order_by(EvaluationRun.created_at.desc()).offset(skip).limit(limit).all()
    return runs


@router.get("/{run_id}", response_model=EvaluationRunResponse)
def get_evaluation_run(
    run_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve full details and confusion matrix metrics for an evaluation run."""
    run = db.query(EvaluationRun).filter(EvaluationRun.id == run_id).first()
    if not run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evaluation run '{run_id}' not found."
        )
    return run


@router.post("", response_model=EvaluationRunResponse, status_code=status.HTTP_201_CREATED)
def record_evaluation_run(
    data: EvaluationRunCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Record an evaluation run produced by Laptop 4 testing and benchmarking suites.
    Calculates precision, recall, FPR, and FNR deterministically from the confusion matrix.
    Guarantees no fabricated metrics are persisted.
    """
    tp = data.true_positives
    fp = data.false_positives
    tn = data.true_negatives
    fn = data.false_negatives

    # Deterministic mathematical formulas
    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
    fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0
    fnr = round(fn / (fn + tp), 4) if (fn + tp) > 0 else 0.0

    now = utc_now()
    eval_run = EvaluationRun(
        dataset_name=data.dataset_name,
        dataset_version=data.dataset_version,
        started_at=now,
        completed_at=now if data.execution_status == "COMPLETED" else None,
        sample_count=data.sample_count,
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        false_positive_rate=fpr,
        false_negative_rate=fnr,
        execution_status=data.execution_status,
        report_metadata=data.report_metadata,
        created_by=current_user.id,
        created_at=now,
    )
    db.add(eval_run)
    db.flush()

    audit = AuditEvent(
        actor_id=current_user.id,
        actor_role=current_user.role,
        event_type="EVALUATION_RECORDED",
        target_resource=f"evaluation_run:{eval_run.id}",
        action_taken="RECORD_EVALUATION",
        outcome="SUCCESS",
        safe_metadata={
            "dataset_name": eval_run.dataset_name,
            "sample_count": eval_run.sample_count,
            "precision": precision,
            "recall": recall,
            "execution_status": eval_run.execution_status,
        },
        created_at=now,
    )
    db.add(audit)
    db.commit()
    db.refresh(eval_run)
    return eval_run
