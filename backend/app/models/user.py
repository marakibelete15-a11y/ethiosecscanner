"""
User and UserSettings Models.
"""

import datetime
import uuid
from sqlalchemy import Boolean, CheckConstraint, Column, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.core.database import Base
from app.utils.vocabulary import SCAN_DEPTH_VALUES, USER_ROLE_VALUES


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(150), nullable=True)
    role = Column(String(50), nullable=False, default="user")
    is_active = Column(Boolean, nullable=False, default=True)

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
        CheckConstraint(
            f"role IN {USER_ROLE_VALUES}",
            name="chk_users_role",
        ),
    )

    # Relationships
    settings = relationship(
        "UserSettings",
        uselist=False,
        back_populates="user",
        cascade="all, delete-orphan",
    )
    targets = relationship(
        "Target",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    scans = relationship(
        "Scan",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    reports = relationship(
        "Report",
        back_populates="user",
        cascade="all, delete-orphan",
    )


class UserSettings(Base):
    __tablename__ = "user_settings"

    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    default_scan_depth = Column(String(20), nullable=False, default="standard")
    notify_scan_completed = Column(Boolean, nullable=False, default=True)
    notify_scan_failed = Column(Boolean, nullable=False, default=True)
    notify_critical_finding = Column(Boolean, nullable=False, default=True)

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
        CheckConstraint(
            f"default_scan_depth IN {SCAN_DEPTH_VALUES}",
            name="chk_user_settings_depth",
        ),
    )

    user = relationship("User", back_populates="settings")
