"""FinBot Data Models"""

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from finbot.core.data.database import Base


class User(Base):
    """User Model"""

    __tablename__ = "users"

    id = Column[int](Integer, primary_key=True, index=True)
    user_id = Column[str](String(32), unique=True, nullable=False, index=True)
    email = Column[str](String(255), unique=True, nullable=True, index=True)
    display_name = Column[str](String(100), nullable=True)
    namespace = Column[str](String(64), nullable=False, index=True)

    created_at = Column[datetime](DateTime, default=datetime.now(UTC), nullable=False)
    last_login = Column[datetime](DateTime, nullable=True)
    is_active = Column[bool](Boolean, default=True)

    __table_args__ = (
        Index("idx_users_namespace", "namespace"),
        Index("idx_users_email", "email"),
    )

    def __repr__(self) -> str:
        """Return string representation of User for __str__"""
        return f"<User(user_id='{self.user_id}', namespace='{self.namespace}')>"


class UserSession(Base):
    """User Session Model
    - HMAC signatures
    - Namespace isolation for multi-user environments
    """

    __tablename__ = "user_sessions"

    session_id = Column[str](String(64), primary_key=True, index=True)
    namespace = Column[str](String(64), nullable=False, index=True)

    # User ID
    user_id = Column[str](String(32), nullable=False, index=True)
    email = Column[str](String(255), nullable=True, index=True)
    is_temporary = Column[bool](Boolean, default=True)

    # Session data
    session_data = Column[str](Text, nullable=False)  # JSON
    signature = Column[str](String(64), nullable=False)  # HMAC signature
    user_agent = Column[str](String(500), nullable=True)
    last_rotation = Column[datetime](DateTime, default=datetime.now(UTC))
    rotation_count = Column[int](Integer, default=0)
    strict_fingerprint = Column[str](String(32), nullable=True)
    loose_fingerprint = Column[str](String(32), nullable=True)
    original_ip = Column[str](String(45), nullable=True)
    current_ip = Column[str](String(45), nullable=True)
    current_vendor_id = Column[int](
        Integer, ForeignKey("vendors.id"), nullable=True, index=True
    )

    created_at = Column[datetime](DateTime, default=datetime.now(UTC), nullable=False)
    last_accessed = Column[datetime](
        DateTime, default=datetime.now(UTC), nullable=False
    )
    expires_at = Column[datetime](DateTime, nullable=False)

    current_vendor = relationship(
        "Vendor", foreign_keys=[current_vendor_id], back_populates="user_sessions"
    )

    __table_args__ = (
        Index("idx_user_sessions_namespace", "namespace"),
        Index("idx_user_sessions_user_id", "user_id"),
        Index("idx_user_sessions_expires", "expires_at"),
        Index("idx_user_sessions_rotation", "last_rotation"),
        Index("idx_user_sessions_vendor", "namespace", "current_vendor_id"),
    )

    def __repr__(self) -> str:
        """Return string representation of UserSession for __str__"""
        return f"<UserSession(session_id='{self.session_id}', namespace='{self.namespace}')>"

    def is_expired(self) -> bool:
        """Check if session is expired"""
        now = datetime.now(UTC)
        # Ensure expires_at is timezone-aware
        expires_at = (
            self.expires_at
            if self.expires_at.tzinfo
            else self.expires_at.replace(tzinfo=UTC)
        )
        return now > expires_at

    def to_dict(self) -> dict:
        """Convert session to dictionary"""
        return {
            "session_id": self.session_id,
            "user_id": self.user_id,
            "email": self.email,
            "is_temporary": self.is_temporary,
            "namespace": self.namespace,
            "created_at": self.created_at.isoformat().replace("+00:00", "Z"),
            "last_accessed": self.last_accessed.isoformat().replace("+00:00", "Z"),
            "expires_at": self.expires_at.isoformat().replace("+00:00", "Z"),
        }


class Vendor(Base):
    """Vendor Model"""

    __tablename__ = "vendors"

    id = Column[int](Integer, primary_key=True)
    namespace = Column[str](String(64), nullable=False, index=True)

    # Company Information
    company_name = Column[str](String(255), nullable=False)
    vendor_category = Column[str](String(100), nullable=False)
    industry = Column[str](String(100), nullable=False)
    services = Column[str](Text, nullable=False)

    # Contact Information
    contact_name = Column[str](String(255), nullable=False)
    email = Column[str](String(255), nullable=False)
    phone = Column[str](String(50), nullable=True)

    # Financial Information
    tin = Column[str](String(20), nullable=False)  # Tax ID/EIN
    bank_account_number = Column[str](String(50), nullable=False)
    bank_name = Column[str](String(255), nullable=False)
    bank_routing_number = Column[str](String(20), nullable=False)
    bank_account_holder_name = Column[str](String(255), nullable=False)

    # Metadata
    status = Column[Literal["pending", "active", "inactive"]](
        String(50), default="pending"
    )
    trust_level = Column[Literal["low", "standard", "high"]](String(20), default="low")
    risk_level = Column[Literal["low", "medium", "high"]](String(20), default="high")

    # agent_notes are notes from the agent that processed the vendor
    # Notes are contributed by both AI agents and Human agents
    agent_notes = Column[str](Text, nullable=True)
    created_at = Column[datetime](DateTime, default=datetime.now(UTC))
    updated_at = Column[datetime](
        DateTime, default=datetime.now(UTC), onupdate=datetime.now(UTC)
    )

    # relationships
    invoices = relationship("Invoice", back_populates="vendor")
    user_sessions = relationship(
        "UserSession",
        foreign_keys="UserSession.current_vendor_id",
        back_populates="current_vendor",
    )

    __table_args__ = (
        Index("idx_vendors_namespace", "namespace"),
        Index("idx_vendors_namespace_status", "namespace", "status"),
        Index("idx_vendors_email", "email"),
        Index("idx_vendors_category", "vendor_category"),
    )

    def to_dict(self) -> dict:
        """Convert vendor to dictionary"""
        return {
            "id": self.id,
            "company_name": self.company_name,
            "namespace": self.namespace,
            "vendor_category": self.vendor_category,
            "industry": self.industry,
            "services": self.services,
            "contact_name": self.contact_name,
            "email": self.email,
            "phone": self.phone,
            "tin": self.tin,
            "bank_account_number": self.bank_account_number,
            "bank_name": self.bank_name,
            "bank_routing_number": self.bank_routing_number,
            "bank_account_holder_name": self.bank_account_holder_name,
            "status": self.status,
            "agent_notes": self.agent_notes,
            "trust_level": self.trust_level,
            "risk_level": self.risk_level,
            "created_at": self.created_at.isoformat().replace("+00:00", "Z"),
            "updated_at": self.updated_at.isoformat().replace("+00:00", "Z"),
        }

    def __repr__(self) -> str:
        return f"<Vendor(id='{self.id}', company_name='{self.company_name}', namespace='{self.namespace}')>"


class Invoice(Base):
    """Invoice Model"""

    __tablename__ = "invoices"

    id = Column[int](Integer, primary_key=True)
    namespace = Column[str](String(64), nullable=False, index=True)

    # Invoice data
    vendor_id = Column[int](Integer, ForeignKey("vendors.id"), nullable=False)
    invoice_number = Column[str](String(100), nullable=True)
    amount = Column[Float](Float, nullable=False)
    description = Column[str](Text, nullable=True)
    invoice_date = Column[datetime](DateTime, nullable=False)
    due_date = Column[datetime](DateTime, nullable=False)
    # status is one of: submitted, processing, approved, rejected, paid
    status = Column[Literal["submitted", "processing", "approved", "rejected", "paid"]](
        String(50), default="submitted"
    )
    # agent_notes are notes from the agent that processed the invoice
    # Notes are contributed by both AI agents and Human agents
    agent_notes = Column[str](Text, nullable=True)

    created_at = Column[datetime](DateTime, default=datetime.now(UTC))
    updated_at = Column[datetime](
        DateTime, default=datetime.now(UTC), onupdate=datetime.now(UTC)
    )

    vendor = relationship("Vendor", back_populates="invoices")

    __table_args__ = (
        Index("idx_invoices_namespace", "namespace"),
        Index("idx_invoices_namespace_vendor", "namespace", "vendor_id"),
        Index("idx_invoices_namespace_status", "namespace", "status"),
    )

    def __repr__(self) -> str:
        """Return string representation of Invoice for __str__"""
        return f"<Invoice(id={self.id}, amount={self.amount}, namespace='{self.namespace}')>"

    def to_dict(self) -> dict:
        """Convert invoice to dictionary"""
        return {
            "id": self.id,
            "namespace": self.namespace,
            "vendor_id": self.vendor_id,
            "invoice_number": self.invoice_number,
            "amount": self.amount,
            "description": self.description,
            "invoice_date": self.invoice_date.isoformat().replace("+00:00", "Z"),
            "due_date": self.due_date.isoformat().replace("+00:00", "Z"),
            "status": self.status,
            "agent_notes": self.agent_notes,
            "created_at": self.created_at.isoformat().replace("+00:00", "Z"),
            "updated_at": self.updated_at.isoformat().replace("+00:00", "Z"),
        }


class UserActivity(Base):
    """User Activity Model
    - Useful for auditing, compliance and CTF purposes
    """

    __tablename__ = "user_activities"

    id = Column[int](Integer, primary_key=True)
    namespace = Column[str](String(64), nullable=False, index=True)

    # activity data
    user_id = Column[str](String(32), nullable=False)
    activity_type = Column[str](String(100), nullable=False)
    description = Column[str](Text, nullable=True)
    activity_metadata = Column[str](Text, nullable=True)  # JSON

    created_at = Column[datetime](DateTime, default=datetime.now(UTC))
    __table_args__ = (
        Index("idx_activities_namespace", "namespace"),
        Index("idx_activities_namespace_user", "namespace", "user_id"),
        Index("idx_activities_namespace_type", "namespace", "activity_type"),
    )


# Non DB Models: Pydantic Models

LLMProviderType = Literal["openai", "http", "mock","ollama"]


class LLMRequest(BaseModel):
    """LLM Request Model
    - LLM requests are normalized to this internal representation to facilitate multiple providers
    """

    messages: list[dict[str, str]] | None = None  # input conversation messages
    model: str | None = None  # model to use for the request
    temperature: float | None = None  # temperature to use
    tools: list[dict[str, Any]] | None = None
    provider: LLMProviderType | None = None
    metadata: dict | None = None  # provider specific metadata
    previous_response_id: str | None = None  # stateful chaining where appropriate
    output_json_schema: dict[str, Any] | None = None  # required fields: name, schema


class LLMResponse(BaseModel):
    """LLM Response Model
    - LLM responses are normalized to this internal representation to facilitate multiple providers
    """

    content: str | None = None  # the text output from the model if any
    tool_calls: list[dict] | None = None  # dict of functions and arguments to pass
    success: bool = True  # whether the request was successful
    provider: LLMProviderType | None = None
    metadata: dict | None = None  # provider specific metadata
    messages: list[dict[str, str]] | None = None  # message history
