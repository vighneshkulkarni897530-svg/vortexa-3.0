from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict, model_validator


class EvaluationRunCreate(BaseModel):
    dataset_name: str = Field(..., min_length=2, max_length=128)
    dataset_version: str = Field(..., min_length=1, max_length=32)
    sample_count: int = Field(..., ge=0)
    true_positives: int = Field(..., ge=0)
    false_positives: int = Field(..., ge=0)
    true_negatives: int = Field(..., ge=0)
    false_negatives: int = Field(..., ge=0)
    execution_status: str = Field(default="COMPLETED", pattern="^(PENDING|RUNNING|COMPLETED|FAILED)$")
    report_metadata: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_confusion_matrix(self):
        total = self.true_positives + self.false_positives + self.true_negatives + self.false_negatives
        if self.execution_status == "COMPLETED" and self.sample_count > 0 and total != self.sample_count:
            raise ValueError(
                f"Sample count ({self.sample_count}) must equal sum of confusion matrix cells "
                f"TP({self.true_positives}) + FP({self.false_positives}) + TN({self.true_negatives}) + FN({self.false_negatives}) = {total}"
            )
        return self


class EvaluationRunResponse(BaseModel):
    id: str
    dataset_name: str
    dataset_version: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    sample_count: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    false_positive_rate: float
    false_negative_rate: float
    execution_status: str
    report_metadata: Dict[str, Any]
    created_by: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
