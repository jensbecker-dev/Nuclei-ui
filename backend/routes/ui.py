from flask import Blueprint, redirect, render_template, url_for
from flask_login import current_user, login_required


ui_bp = Blueprint("ui", __name__)


@ui_bp.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("ui.dashboard"))
    return redirect(url_for("auth.login"))


@ui_bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", current_user=current_user, active_page="dashboard")


@ui_bp.route("/scans")
@login_required
def scans_page():
    return render_template("scans.html", current_user=current_user, active_page="scans")


@ui_bp.route("/findings")
@login_required
def findings_page():
    return render_template("findings.html", current_user=current_user, active_page="findings")


@ui_bp.route("/workflow")
@login_required
def workflow_page():
    return render_template("workflow.html", current_user=current_user, active_page="workflow")
