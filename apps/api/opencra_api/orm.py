from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import JSON


def _uuid() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String)
    slug: Mapped[str] = mapped_column(String, unique=True)
    main_establishment_ms: Mapped[str | None] = mapped_column(String, nullable=True)
    designated_csirt: Mapped[str | None] = mapped_column(String, nullable=True)
    sso_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class Membership(Base):
    __tablename__ = "memberships"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"))
    user_id: Mapped[str] = mapped_column(String)
    email: Mapped[str | None] = mapped_column(String, nullable=True)
    role: Mapped[str] = mapped_column(String, default="engineer")


class Product(Base):
    __tablename__ = "products"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"))
    name: Mapped[str] = mapped_column(String)
    version: Mapped[str | None] = mapped_column(String, nullable=True)
    market_member_states: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    sboms: Mapped[list[Sbom]] = relationship(back_populates="product")
    cases: Mapped[list[CraCase]] = relationship(back_populates="product")


class Sbom(Base):
    __tablename__ = "sboms"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    product_id: Mapped[str] = mapped_column(ForeignKey("products.id"))
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"))
    document: Mapped[dict] = mapped_column(JSON)
    git_sha: Mapped[str | None] = mapped_column(String, nullable=True)
    source: Mapped[str] = mapped_column(String, default="cli")
    serial_number: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    product: Mapped[Product] = relationship(back_populates="sboms")


class ComponentRow(Base):
    __tablename__ = "components"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    sbom_id: Mapped[str] = mapped_column(ForeignKey("sboms.id"))
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"))
    purl: Mapped[str | None] = mapped_column(String, nullable=True)
    name: Mapped[str] = mapped_column(String)
    version: Mapped[str | None] = mapped_column(String, nullable=True)


class VulnMatchRow(Base):
    __tablename__ = "vuln_matches"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    component_id: Mapped[str | None] = mapped_column(ForeignKey("components.id"), nullable=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"))
    product_id: Mapped[str | None] = mapped_column(ForeignKey("products.id"), nullable=True)
    purl: Mapped[str] = mapped_column(String)
    osv_id: Mapped[str | None] = mapped_column(String, nullable=True)
    cve_id: Mapped[str | None] = mapped_column(String, nullable=True)
    severity: Mapped[str | None] = mapped_column(String, nullable=True)
    cvss_v3: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss: Mapped[float | None] = mapped_column(Float, nullable=True)
    in_kev: Mapped[bool] = mapped_column(Boolean, default=False)
    kev_added_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String, default="open")
    vex_status: Mapped[str | None] = mapped_column(String, nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class CraCase(Base):
    __tablename__ = "cra_cases"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"))
    product_id: Mapped[str] = mapped_column(ForeignKey("products.id"))
    match_id: Mapped[str | None] = mapped_column(ForeignKey("vuln_matches.id"), nullable=True)
    case_type: Mapped[str] = mapped_column(String, default="actively_exploited_vuln")
    status: Mapped[str] = mapped_column(String, default="candidate")
    awareness_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    fix_available_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    early_warning_submitted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    notification_submitted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    final_submitted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    srp_reference_id: Mapped[str | None] = mapped_column(String, nullable=True)
    sensitivity: Mapped[str | None] = mapped_column(String, nullable=True)
    exploit_nature: Mapped[str | None] = mapped_column(Text, nullable=True)
    corrective_measures: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    product: Mapped[Product] = relationship(back_populates="cases")


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"))
    case_id: Mapped[str | None] = mapped_column(ForeignKey("cra_cases.id"), nullable=True)
    actor_id: Mapped[str] = mapped_column(String)
    action: Mapped[str] = mapped_column(String)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    event_hash: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class VexRow(Base):
    __tablename__ = "vex_statements"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"))
    product_id: Mapped[str | None] = mapped_column(ForeignKey("products.id"), nullable=True)
    document: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class Subscription(Base):
    __tablename__ = "subscriptions"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), unique=True)
    tier: Mapped[str] = mapped_column(String, default="community")
    status: Mapped[str] = mapped_column(String, default="active")
    seat_limit: Mapped[int] = mapped_column(Integer, default=1)
    product_limit: Mapped[int] = mapped_column(Integer, default=1)
    stripe_customer_id: Mapped[str | None] = mapped_column(String, nullable=True)
    stripe_subscription_id: Mapped[str | None] = mapped_column(String, nullable=True)
    retention_days: Mapped[int] = mapped_column(Integer, default=7)


class ApiKey(Base):
    __tablename__ = "api_keys"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"))
    name: Mapped[str] = mapped_column(String, default="cli")
    token_hash: Mapped[str] = mapped_column(String, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
