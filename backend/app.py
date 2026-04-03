from __future__ import annotations

import os
from collections.abc import Iterable

from dotenv import load_dotenv
from flask import Flask
from sqlalchemy import text

from backend.routes.api import api_bp
from backend.routes.auth import auth_bp
from backend.routes.ui import ui_bp
from backend.schemas.models import User
from backend.utils.extensions import db, login_manager
from backend.utils.nuclei_service import NucleiService


def create_app(test_config: dict | None = None) -> Flask:
	load_dotenv()

	app = Flask(
		__name__,
		template_folder="templates",
		static_folder="static",
	)

	app.config.update(
		SECRET_KEY=os.getenv("SECRET_KEY", "dev-secret-change-me"),
		SQLALCHEMY_DATABASE_URI=os.getenv("DATABASE_URL", "sqlite:///nuclei_webui.db"),
		SQLALCHEMY_TRACK_MODIFICATIONS=False,
	)

	if test_config:
		app.config.update(test_config)

	db.init_app(app)
	login_manager.init_app(app)

	app.config["NUCLEI_SERVICE"] = app.config.get("NUCLEI_SERVICE") or NucleiService(
		binary=os.getenv("NUCLEI_BINARY", "nuclei")
	)

	app.register_blueprint(ui_bp)
	app.register_blueprint(auth_bp)
	app.register_blueprint(api_bp)

	with app.app_context():
		db.create_all()
		_apply_compat_schema_updates()
		_ensure_default_user()

	return app


def _ensure_default_user() -> None:
	username = os.getenv("DEFAULT_ADMIN_USERNAME", "Developer")
	password = os.getenv("DEFAULT_ADMIN_PASSWORD", "Nucl31-ui")
	tenant_id = os.getenv("DEFAULT_TENANT_ID", "default")

	existing = User.query.filter_by(username=username).first()
	if existing:
		if not existing.tenant_id:
			existing.tenant_id = tenant_id
		if existing.role == "developer":
			existing.role = "admin"
		db.session.commit()
		return

	user = User(username=username, role="admin", tenant_id=tenant_id)
	user.set_password(password)
	db.session.add(user)
	db.session.commit()


def _apply_compat_schema_updates() -> None:
	uri = db.engine.url.drivername
	if "sqlite" not in uri:
		return

	_ensure_columns(
		"users",
		[
			("role", "ALTER TABLE users ADD COLUMN role VARCHAR(32) DEFAULT 'admin' NOT NULL"),
			("tenant_id", "ALTER TABLE users ADD COLUMN tenant_id VARCHAR(64) DEFAULT 'default' NOT NULL"),
		],
	)

	_ensure_columns(
		"scans",
		[
			("promoted_findings_count", "ALTER TABLE scans ADD COLUMN promoted_findings_count INTEGER DEFAULT 0 NOT NULL"),
		],
	)

	_ensure_columns(
		"findings",
		[
			("status", "ALTER TABLE findings ADD COLUMN status VARCHAR(32) DEFAULT 'open' NOT NULL"),
			("owner", "ALTER TABLE findings ADD COLUMN owner VARCHAR(64)"),
			("triage_note", "ALTER TABLE findings ADD COLUMN triage_note TEXT"),
			("risk_acceptance_reason", "ALTER TABLE findings ADD COLUMN risk_acceptance_reason TEXT"),
			("due_at", "ALTER TABLE findings ADD COLUMN due_at DATETIME"),
			("resolved_at", "ALTER TABLE findings ADD COLUMN resolved_at DATETIME"),
			("first_seen_at", "ALTER TABLE findings ADD COLUMN first_seen_at DATETIME"),
			("last_seen_at", "ALTER TABLE findings ADD COLUMN last_seen_at DATETIME"),
		],
	)


def _ensure_columns(table: str, column_statements: Iterable[tuple[str, str]]) -> None:
	result = db.session.execute(text(f"PRAGMA table_info({table})"))
	existing_columns = {row[1] for row in result.fetchall()}

	for column_name, statement in column_statements:
		if column_name in existing_columns:
			continue
		db.session.execute(text(statement))

	db.session.commit()
