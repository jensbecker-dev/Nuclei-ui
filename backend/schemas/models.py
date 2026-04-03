from __future__ import annotations

from datetime import UTC, datetime

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from backend.utils.extensions import db, login_manager


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(32), default="admin", nullable=False, index=True)
    tenant_id = db.Column(db.String(64), default="default", nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)

    scans = db.relationship("Scan", back_populates="user", lazy=True)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(512), nullable=False, index=True)
    template = db.Column(db.String(512), nullable=True)
    severity = db.Column(db.String(128), nullable=True)
    tags = db.Column(db.String(256), nullable=True)
    advanced_args = db.Column(db.String(1024), nullable=True)
    command = db.Column(db.String(2048), nullable=False)
    status = db.Column(db.String(32), default="queued", nullable=False, index=True)
    findings_count = db.Column(db.Integer, default=0, nullable=False)
    critical_count = db.Column(db.Integer, default=0, nullable=False)
    high_count = db.Column(db.Integer, default=0, nullable=False)
    medium_count = db.Column(db.Integer, default=0, nullable=False)
    low_count = db.Column(db.Integer, default=0, nullable=False)
    info_count = db.Column(db.Integer, default=0, nullable=False)
    promoted_findings_count = db.Column(db.Integer, default=0, nullable=False)
    error_message = db.Column(db.Text, nullable=True)
    raw_output = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False, index=True)
    updated_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    user = db.relationship("User", back_populates="scans")

    findings = db.relationship("Finding", back_populates="scan", cascade="all, delete-orphan", lazy=True)


class Finding(db.Model):
    __tablename__ = "findings"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False, index=True)
    template_id = db.Column(db.String(256), nullable=True)
    template_name = db.Column(db.String(256), nullable=True)
    matcher_name = db.Column(db.String(256), nullable=True)
    host = db.Column(db.String(512), nullable=True)
    matched_at = db.Column(db.String(1024), nullable=True)
    severity = db.Column(db.String(32), nullable=True, index=True)
    status = db.Column(db.String(32), default="open", nullable=False, index=True)
    owner = db.Column(db.String(64), nullable=True, index=True)
    triage_note = db.Column(db.Text, nullable=True)
    risk_acceptance_reason = db.Column(db.Text, nullable=True)
    due_at = db.Column(db.DateTime(timezone=True), nullable=True, index=True)
    resolved_at = db.Column(db.DateTime(timezone=True), nullable=True, index=True)
    first_seen_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)
    last_seen_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)
    payload = db.Column(db.Text, nullable=False)

    scan = db.relationship("Scan", back_populates="findings")


@login_manager.user_loader
def load_user(user_id: str) -> User | None:
    return db.session.get(User, int(user_id))
