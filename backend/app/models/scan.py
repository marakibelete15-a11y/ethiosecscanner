"""
Scan Model with Change-Tracked JSONB Progress Telemetry.
"""

import datetime
import uuid
from sqlalchemy import (
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.ext.mutable import MutableDict, MutableList
from sqlalchemy.orm import relationship

from app.core.database import Base
from app.utils.vocabulary import SCAN_DEPTH_VALUES, SCAN_STATUS_VALUES


class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_id = Column(
        UUID(as_uuid=True),
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_url = Column(Text, nullable=False)
    depth = Column(String(20), nullable=False, default="standard")

    # Change-tracked JSONB columns
    selected_modules = Column(
        MutableList.as_mutable(JSONB),
        nullable=False,
        default=list,
    )
    module_progress = Column(
        MutableDict.as_mutable(JSONB),
        nullable=False,
        default=dict,
    )

    status = Column(String(20), nullable=False, default="queued")
    progress = Column(Integer, nullable=False, default=0)
    current_module = Column(String(50), nullable=True)
    security_score = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)

    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
        onupdate=lambda: datetime.datetime.now(datetime.timezone.utc),
    )

    __table_args__ = (
        Index("idx_scans_user_status", "user_id", "status"),
        Index("idx_scans_target_created", "target_id", "created_at"),
        CheckConstraint(
            f"status IN {SCAN_STATUS_VALUES}",
            name="chk_scans_status",
        ),
        CheckConstraint(
            f"depth IN {SCAN_DEPTH_VALUES}",
            name="chk_scans_depth",
        ),
        CheckConstraint(
            "progress >= 0 AND progress <= 100",
            name="chk_scans_progress",
        ),
        CheckConstraint(
            "security_score IS NULL OR (security_score >= 0 AND security_score <= 100)",
            name="chk_scans_security_score",
        ),
    )

    user = relationship("User", back_populates="scans")
    target = relationship("Target", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")
