"""
Finding Model.
"""

import datetime
import uuid
from sqlalchemy import (
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.core.database import Base
from app.utils.vocabulary import (
    CONFIDENCE_VALUES,
    FINDING_STATUS_VALUES,
    SCANNER_MODULE_KEYS,
    SEVERITY_VALUES,
)


class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_id = Column(
        UUID(as_uuid=True),
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    module = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)
    status = Column(String(30), nullable=False, default="open")
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    evidence = Column(Text, nullable=True)
    remediation = Column(Text, nullable=False)
    affected_url = Column(Text, nullable=False)
    parameter = Column(String(255), nullable=True)
    owasp_category = Column(String(100), nullable=True)
    cwe_id = Column(String(50), nullable=True)
    confidence = Column(String(20), nullable=False, default="high")
    http_method = Column(String(10), nullable=True)

    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
    )

    __table_args__ = (
        Index("idx_findings_scan_severity", "scan_id", "severity"),
        Index("idx_findings_target_status", "target_id", "status"),
        Index("idx_findings_module", "module"),
        CheckConstraint(
            f"severity IN {SEVERITY_VALUES}",
            name="chk_findings_severity",
        ),
        CheckConstraint(
            f"status IN {FINDING_STATUS_VALUES}",
            name="chk_findings_status",
        ),
        CheckConstraint(
            f"confidence IN {CONFIDENCE_VALUES}",
            name="chk_findings_confidence",
        ),
        CheckConstraint(
            f"module IN {SCANNER_MODULE_KEYS}",
            name="chk_findings_module",
        ),
    )

    scan = relationship("Scan", back_populates="findings")
    target = relationship("Target", back_populates="findings")
