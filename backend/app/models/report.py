"""
Report Model with On-Demand Generation and Cached Summary.
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
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.orm import relationship

from app.core.database import Base
from app.utils.vocabulary import REPORT_FORMAT_VALUES


class Report(Base):
    __tablename__ = "reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    report_format = Column(String(10), nullable=False)

    # Change-tracked summary snapshot
    summary = Column(
        MutableDict.as_mutable(JSONB),
        nullable=False,
        default=dict,
    )

    # Nullable for on-demand generation
    file_path = Column(String(1024), nullable=True)
    file_size_bytes = Column(Integer, nullable=True)

    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
    )

    __table_args__ = (
        UniqueConstraint("scan_id", "report_format", name="uq_reports_scan_format"),
        Index("idx_reports_user_created", "user_id", "created_at"),
        CheckConstraint(
            f"report_format IN {REPORT_FORMAT_VALUES}",
            name="chk_reports_format",
        ),
    )

    scan = relationship("Scan", back_populates="reports")
    user = relationship("User", back_populates="reports")
