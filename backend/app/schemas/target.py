"""
Target Pydantic Schemas (SRS Section 4.2, TGT-1 to TGT-8).
"""

import datetime
from typing import Optional
import uuid

from pydantic import BaseModel, ConfigDict, field_validator

from app.utils.vocabulary import VERIFICATION_METHOD_VALUES


class TargetCreateRequest(BaseModel):
    """Payload to register a new target URL for scanning."""
    url: str
    verification_method: Optional[str] = "meta_tag"

    @field_validator("verification_method")
    @classmethod
    def validate_method(cls, v: Optional[str]) -> str:
        if v is None:
            return "meta_tag"
        method = v.strip().lower()
        if method not in VERIFICATION_METHOD_VALUES:
            raise ValueError(
                f"Invalid verification_method '{v}'. Must be one of: {', '.join(VERIFICATION_METHOD_VALUES)}"
            )
        return method


class VerificationInstructions(BaseModel):
    """Actionable human-readable instructions for verifying domain/site ownership."""
    method: str
    token: str
    summary: str
    meta_tag: Optional[str] = None
    file_url: Optional[str] = None
    file_content: Optional[str] = None
    dns_record_name: Optional[str] = None
    dns_record_value: Optional[str] = None


class TargetResponse(BaseModel):
    """Detailed target representation returned to API clients."""
    id: uuid.UUID
    url: str
    normalized_url: str
    verification_method: str
    verification_token: str
    is_verified: bool
    verified_at: Optional[datetime.datetime] = None
    last_checked_at: Optional[datetime.datetime] = None
    created_at: datetime.datetime
    updated_at: datetime.datetime
    instructions: Optional[VerificationInstructions] = None

    model_config = ConfigDict(from_attributes=True)


class TargetVerifyResponse(BaseModel):
    """Outcome of an ownership verification check."""
    id: uuid.UUID
    url: str
    normalized_url: str
    verification_method: str
    verification_token: str
    is_verified: bool
    verified_at: Optional[datetime.datetime] = None
    last_checked_at: Optional[datetime.datetime] = None
    message: str
    details: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class TargetDeleteResponse(BaseModel):
    """Confirmation payload after deleting a target."""
    message: str
    target_id: uuid.UUID

