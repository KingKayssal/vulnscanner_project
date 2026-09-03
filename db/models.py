"""
Database models for the vulnerability scanner.
Uses SQLite for local/demo use; swap the engine URL for Postgres in production
(see db/session.py).
"""
import uuid
from datetime import datetime, date

from sqlalchemy import (
    Column, String, Text, Boolean, ForeignKey, DateTime, Date,
    Numeric, JSON, CheckConstraint, Integer
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def gen_uuid() -> str:
    return str(uuid.uuid4())


class Organization(Base):
    __tablename__ = "organizations"
    id = Column(String, primary_key=True, default=gen_uuid)
    name = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    targets = relationship("AuthorizedTarget", back_populates="organization")


class AuthorizedTarget(Base):
    """
    Hard authorization gate. No scan may run against a domain that
    does not have an active, non-expired row here.
    """
    __tablename__ = "authorized_targets"
    id = Column(String, primary_key=True, default=gen_uuid)
    organization_id = Column(String, ForeignKey("organizations.id"))
    domain = Column(String, nullable=False)
    authorized_by = Column(String, nullable=False)
    authorization_doc_url = Column(String, nullable=True)
    valid_from = Column(Date, nullable=False)
    valid_until = Column(Date, nullable=False)
    excluded_paths = Column(JSON, default=list)
    created_at = Column(DateTime, default=datetime.utcnow)

    organization = relationship("Organization", back_populates="targets")

    def is_currently_authorized(self) -> bool:
        today = date.today()
        return self.valid_from <= today <= self.valid_until


class Scan(Base):
    __tablename__ = "scans"
    id = Column(String, primary_key=True, default=gen_uuid)
    organization_id = Column(String, ForeignKey("organizations.id"))
    target_id = Column(String, ForeignKey("authorized_targets.id"))
    status = Column(String, default="queued")
    crawl_depth = Column(Integer, default=3)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    initiated_by = Column(String, nullable=False)
    config = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        CheckConstraint(
            "status in ('queued','crawling','scanning','completed','failed','cancelled')"
        ),
    )

    assets = relationship("Asset", back_populates="scan")
    findings = relationship("Finding", back_populates="scan")


class Asset(Base):
    __tablename__ = "assets"
    id = Column(String, primary_key=True, default=gen_uuid)
    scan_id = Column(String, ForeignKey("scans.id"))
    url = Column(String, nullable=False)
    method = Column(String, default="GET")
    params = Column(JSON, default=dict)
    discovered_via = Column(String, default="crawl")
    response_status = Column(Integer, nullable=True)
    response_headers = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="assets")


class Template(Base):
    __tablename__ = "templates"
    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    description = Column(Text)
    severity_default = Column(String)
    category = Column(String)
    cwe_id = Column(String)
    cvss_vector_template = Column(String)
    yaml_definition = Column(JSON, nullable=False)
    is_active = Column(Boolean, default=True)
    author = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)


class Finding(Base):
    __tablename__ = "findings"
    id = Column(String, primary_key=True, default=gen_uuid)
    scan_id = Column(String, ForeignKey("scans.id"))
    asset_id = Column(String, ForeignKey("assets.id"))
    template_id = Column(String, ForeignKey("templates.id"))
    title = Column(String, nullable=False)
    severity = Column(String)
    cvss_vector = Column(String)
    cvss_score = Column(Numeric(3, 1))
    description = Column(Text)
    remediation = Column(Text)
    evidence_request = Column(Text)
    evidence_response = Column(Text)
    screenshot_url = Column(String, nullable=True)
    confirmed = Column(Boolean, default=False)
    false_positive = Column(Boolean, default=False)
    status = Column(String, default="open")
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        CheckConstraint("severity in ('critical','high','medium','low','info')"),
        CheckConstraint(
            "status in ('open','triaged','fixed','accepted_risk','false_positive')"
        ),
    )

    scan = relationship("Scan", back_populates="findings")


class Report(Base):
    __tablename__ = "reports"
    id = Column(String, primary_key=True, default=gen_uuid)
    scan_id = Column(String, ForeignKey("scans.id"))
    file_url = Column(String, nullable=False)
    generated_at = Column(DateTime, default=datetime.utcnow)
    summary = Column(JSON, default=dict)
