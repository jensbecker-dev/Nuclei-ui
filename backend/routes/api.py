from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
import csv
import io
import json

from flask import Blueprint, Response, current_app, jsonify, request
from flask_login import current_user, login_required

from backend.schemas.models import Finding, Scan, User
from backend.utils.authz import require_roles
from backend.utils.extensions import db
from backend.utils.nuclei_service import summarize_by_severity


api_bp = Blueprint("api", __name__, url_prefix="/api")
executor = ThreadPoolExecutor(max_workers=2)


def _serialize_scan(scan: Scan) -> dict:
    return {
        "id": scan.id,
        "target": scan.target,
        "template": scan.template,
        "severity": scan.severity,
        "tags": scan.tags,
        "advancedArgs": scan.advanced_args,
        "status": scan.status,
        "findingsCount": scan.findings_count,
        "criticalCount": scan.critical_count,
        "highCount": scan.high_count,
        "mediumCount": scan.medium_count,
        "lowCount": scan.low_count,
        "infoCount": scan.info_count,
        "promotedFindingsCount": scan.promoted_findings_count,
        "errorMessage": scan.error_message,
        "command": scan.command,
        "createdAt": scan.created_at.isoformat(),
        "updatedAt": scan.updated_at.isoformat(),
    }


def _serialize_finding(finding: Finding) -> dict:
    intelligence = _extract_finding_intelligence(finding.payload)

    return {
        "id": finding.id,
        "scanId": finding.scan_id,
        "templateId": finding.template_id,
        "templateName": finding.template_name,
        "matcherName": finding.matcher_name,
        "host": finding.host,
        "matchedAt": finding.matched_at,
        "severity": finding.severity,
        "status": finding.status,
        "owner": finding.owner,
        "triageNote": finding.triage_note,
        "riskAcceptanceReason": finding.risk_acceptance_reason,
        "dueAt": finding.due_at.isoformat() if finding.due_at else None,
        "resolvedAt": finding.resolved_at.isoformat() if finding.resolved_at else None,
        "firstSeenAt": finding.first_seen_at.isoformat() if finding.first_seen_at else None,
        "lastSeenAt": finding.last_seen_at.isoformat() if finding.last_seen_at else None,
        "cveIds": intelligence["cveIds"],
        "cweIds": intelligence["cweIds"],
        "cvssScore": intelligence["cvssScore"],
        "cvssMetrics": intelligence["cvssMetrics"],
        "epssScore": intelligence["epssScore"],
        "description": intelligence["description"],
        "references": intelligence["references"],
        "tags": intelligence["tags"],
        "matchedUrl": intelligence["matchedUrl"],
        "curlCommand": intelligence["curlCommand"],
        "metadata": intelligence["metadata"],
        "extractedResults": intelligence["extractedResults"],
    }


def _safe_parse_payload(payload: str | None) -> dict:
    if not payload:
        return {}

    text = payload.strip()
    if not text:
        return {}

    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        pass

    try:
        parsed = ast.literal_eval(text)
        return parsed if isinstance(parsed, dict) else {}
    except (ValueError, SyntaxError):
        return {}


def _to_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return []
        if "," in stripped:
            return [v.strip() for v in stripped.split(",") if v.strip()]
        return [stripped]
    return [str(value).strip()]


def _extract_finding_intelligence(payload: str | None) -> dict:
    parsed = _safe_parse_payload(payload)
    info = parsed.get("info", {}) if isinstance(parsed.get("info"), dict) else {}
    classification = info.get("classification", {}) if isinstance(info.get("classification"), dict) else {}

    cve_ids = _to_list(classification.get("cve-id") or classification.get("cve") or parsed.get("cve-id"))
    cwe_ids = _to_list(classification.get("cwe-id") or classification.get("cwe"))
    references = _to_list(info.get("reference") or parsed.get("reference"))
    tags = _to_list(info.get("tags") or parsed.get("tags"))
    extracted_results = _to_list(parsed.get("extracted-results"))

    return {
        "cveIds": cve_ids,
        "cweIds": cwe_ids,
        "cvssScore": classification.get("cvss-score"),
        "cvssMetrics": classification.get("cvss-metrics"),
        "epssScore": classification.get("epss-score"),
        "description": info.get("description"),
        "references": references,
        "tags": tags,
        "matchedUrl": parsed.get("matched-at"),
        "curlCommand": parsed.get("curl-command"),
        "metadata": info.get("metadata") if isinstance(info.get("metadata"), dict) else {},
        "extractedResults": extracted_results,
        "raw": parsed,
    }


def _parse_scan_raw_output(raw_output: str | None) -> list[dict]:
    if not raw_output:
        return []

    findings: list[dict] = []
    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
            if isinstance(parsed, dict):
                findings.append(parsed)
        except json.JSONDecodeError:
            continue
    return findings


def _serialize_scan_result_item(item: dict, index: int) -> dict:
    payload = json.dumps(item, ensure_ascii=False)
    intelligence = _extract_finding_intelligence(payload)
    info = item.get("info", {}) if isinstance(item.get("info"), dict) else {}

    return {
        "resultId": index,
        "templateId": item.get("template-id"),
        "templateName": info.get("name"),
        "severity": (info.get("severity") or "info").lower(),
        "host": item.get("host"),
        "matchedAt": item.get("matched-at"),
        "matcherName": item.get("matcher-name"),
        "cveIds": intelligence["cveIds"],
        "cweIds": intelligence["cweIds"],
        "cvssScore": intelligence["cvssScore"],
        "cvssMetrics": intelligence["cvssMetrics"],
        "epssScore": intelligence["epssScore"],
        "description": intelligence["description"],
        "references": intelligence["references"],
        "tags": intelligence["tags"],
        "metadata": intelligence["metadata"],
        "extractedResults": intelligence["extractedResults"],
        "raw": item,
    }


def _scan_query_for_current_user():
    return (
        db.session.query(Scan)
        .join(User, User.id == Scan.user_id)
        .filter(User.tenant_id == current_user.tenant_id)
    )


def _finding_query_for_current_user():
    return (
        db.session.query(Finding)
        .join(Scan, Scan.id == Finding.scan_id)
        .join(User, User.id == Scan.user_id)
        .filter(User.tenant_id == current_user.tenant_id)
    )


def _parse_iso_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    clean = value.strip()
    if not clean:
        return None
    clean = clean.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(clean)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


@api_bp.route("/health", methods=["GET"])
def health():
    nuclei_service = current_app.config["NUCLEI_SERVICE"]
    installed = nuclei_service.is_installed()
    return jsonify(
        {
            "ok": True,
            "nucleiInstalled": installed,
            "nucleiVersion": nuclei_service.get_version() if installed else "n/a",
        }
    )


@api_bp.route("/templates", methods=["GET"])
@login_required
def templates():
    nuclei_service = current_app.config["NUCLEI_SERVICE"]
    templates_list = nuclei_service.list_templates(limit=300)
    return jsonify({"templates": templates_list, "count": len(templates_list)})


@api_bp.route("/scans", methods=["GET"])
@login_required
def get_scans():
    limit = min(int(request.args.get("limit", 20)), 100)
    scans = _scan_query_for_current_user().order_by(Scan.created_at.desc()).limit(limit).all()
    return jsonify({"scans": [_serialize_scan(scan) for scan in scans]})


@api_bp.route("/scans/<int:scan_id>", methods=["GET"])
@login_required
def get_scan(scan_id: int):
    scan = _scan_query_for_current_user().filter(Scan.id == scan_id).first_or_404()
    findings = [
        {
            "id": finding.id,
            "templateId": finding.template_id,
            "templateName": finding.template_name,
            "matcherName": finding.matcher_name,
            "host": finding.host,
            "matchedAt": finding.matched_at,
            "severity": finding.severity,
            "payload": finding.payload,
        }
        for finding in scan.findings
    ]
    return jsonify({"scan": _serialize_scan(scan), "findings": findings})


@api_bp.route("/scans/<int:scan_id>/results", methods=["GET"])
@login_required
def get_scan_results(scan_id: int):
    scan = _scan_query_for_current_user().filter(Scan.id == scan_id).first_or_404()
    results = _parse_scan_raw_output(scan.raw_output)
    payload = [_serialize_scan_result_item(item, idx) for idx, item in enumerate(results)]
    return jsonify({"scan": _serialize_scan(scan), "results": payload, "count": len(payload)})


@api_bp.route("/scans", methods=["POST"])
@login_required
@require_roles("admin", "analyst")
def create_scan():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    template = (data.get("template") or "").strip() or None
    severity = (data.get("severity") or "").strip() or None
    tags = (data.get("tags") or "").strip() or None
    advanced_args = (data.get("advancedArgs") or "").strip() or None

    if not target:
        return jsonify({"error": "target is required"}), 400

    nuclei_service = current_app.config["NUCLEI_SERVICE"]
    command = nuclei_service.build_command(target, template, severity, tags, advanced_args)

    scan = Scan(
        target=target,
        template=template,
        severity=severity,
        tags=tags,
        advanced_args=advanced_args,
        command=" ".join(command),
        status="queued",
        user_id=current_user.id,
    )
    db.session.add(scan)
    db.session.commit()

    app = current_app._get_current_object()
    if current_app.config.get("TESTING"):
        _run_scan_task(app, scan.id)
    else:
        executor.submit(_run_scan_task, app, scan.id)

    return jsonify({"scan": _serialize_scan(scan)}), 202


@api_bp.route("/scans/<int:scan_id>/promote-findings", methods=["POST"])
@login_required
@require_roles("admin", "analyst")
def promote_scan_findings(scan_id: int):
    scan = _scan_query_for_current_user().filter(Scan.id == scan_id).first_or_404()
    if scan.status != "completed":
        return jsonify({"error": "scan must be completed before promotion"}), 400

    data = request.get_json(silent=True) or {}
    selected_result_ids = data.get("selectedResultIds")
    selected_ids_set = (
        {int(v) for v in selected_result_ids}
        if isinstance(selected_result_ids, list) and selected_result_ids
        else None
    )

    results = _parse_scan_raw_output(scan.raw_output)
    promoted = 0

    existing_findings = Finding.query.filter_by(scan_id=scan.id).all()
    existing_count = len(existing_findings)
    existing_keys = {
        (f.template_id or "", f.host or "", f.matched_at or "")
        for f in existing_findings
    }

    for idx, result in enumerate(results):
        if selected_ids_set is not None and idx not in selected_ids_set:
            continue

        info = result.get("info", {}) if isinstance(result.get("info"), dict) else {}
        key = (
            str(result.get("template-id") or ""),
            str(result.get("host") or ""),
            str(result.get("matched-at") or ""),
        )
        if key in existing_keys:
            continue

        db.session.add(
            Finding(
                scan_id=scan.id,
                template_id=result.get("template-id"),
                template_name=info.get("name"),
                matcher_name=result.get("matcher-name"),
                host=result.get("host"),
                matched_at=result.get("matched-at"),
                severity=(info.get("severity") or "info").lower(),
                status="open",
                owner=None,
                triage_note=None,
                risk_acceptance_reason=None,
                first_seen_at=datetime.now(UTC),
                last_seen_at=datetime.now(UTC),
                payload=json.dumps(result, ensure_ascii=False),
            )
        )
        existing_keys.add(key)
        promoted += 1

    scan.promoted_findings_count = existing_count + promoted

    db.session.commit()
    return jsonify({"scan": _serialize_scan(scan), "promoted": promoted})


@api_bp.route("/dashboard/summary", methods=["GET"])
@login_required
def dashboard_summary():
    recent_scans = _scan_query_for_current_user().order_by(Scan.created_at.desc()).limit(12).all()
    total_scans = _scan_query_for_current_user().count()
    running_scans = _scan_query_for_current_user().filter(Scan.status == "running").count()
    failed_scans = _scan_query_for_current_user().filter(Scan.status == "failed").count()

    severity_totals = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for scan in recent_scans:
        severity_totals["critical"] += scan.critical_count
        severity_totals["high"] += scan.high_count
        severity_totals["medium"] += scan.medium_count
        severity_totals["low"] += scan.low_count
        severity_totals["info"] += scan.info_count

    lifecycle = {"open": 0, "in_progress": 0, "accepted_risk": 0, "resolved": 0}
    all_findings = _finding_query_for_current_user().all()
    overdue_open = 0
    now = datetime.now(UTC)

    for finding in all_findings:
        status = (finding.status or "open").lower()
        if status not in lifecycle:
            status = "open"
        lifecycle[status] += 1

        if status != "resolved" and finding.due_at and finding.due_at < now:
            overdue_open += 1

    sla_compliance = 100
    total_unresolved = len([f for f in all_findings if (f.status or "open") != "resolved"])
    if total_unresolved > 0:
        sla_compliance = round(((total_unresolved - overdue_open) / total_unresolved) * 100)

    return jsonify(
        {
            "totalScans": total_scans,
            "runningScans": running_scans,
            "failedScans": failed_scans,
            "severityTotals": severity_totals,
            "lifecycleTotals": lifecycle,
            "overdueOpenFindings": overdue_open,
            "slaCompliancePct": sla_compliance,
            "recentScans": [_serialize_scan(scan) for scan in recent_scans],
        }
    )


@api_bp.route("/me", methods=["GET"])
@login_required
def me():
    return jsonify(
        {
            "id": current_user.id,
            "username": current_user.username,
            "role": current_user.role,
            "tenantId": current_user.tenant_id,
        }
    )


@api_bp.route("/findings", methods=["GET"])
@login_required
def list_findings():
    status = (request.args.get("status") or "").strip().lower()
    severity = (request.args.get("severity") or "").strip().lower()
    limit = min(int(request.args.get("limit", 100)), 500)

    query = _finding_query_for_current_user()
    if status:
        query = query.filter(Finding.status == status)
    if severity:
        query = query.filter(Finding.severity == severity)

    findings = query.order_by(Finding.id.desc()).limit(limit).all()
    return jsonify({"findings": [_serialize_finding(f) for f in findings], "count": len(findings)})


@api_bp.route("/findings/<int:finding_id>", methods=["GET"])
@login_required
def get_finding(finding_id: int):
    finding = _finding_query_for_current_user().filter(Finding.id == finding_id).first_or_404()
    data = _serialize_finding(finding)
    intelligence = _extract_finding_intelligence(finding.payload)

    return jsonify(
        {
            "finding": {
                **data,
                "rawPayload": intelligence["raw"],
                "scan": _serialize_scan(finding.scan),
            }
        }
    )


@api_bp.route("/findings/<int:finding_id>", methods=["PATCH"])
@login_required
@require_roles("admin", "analyst")
def update_finding(finding_id: int):
    finding = _finding_query_for_current_user().filter(Finding.id == finding_id).first_or_404()
    data = request.get_json(silent=True) or {}

    new_status = (data.get("status") or "").strip().lower()
    allowed_status = {"open", "in_progress", "accepted_risk", "resolved"}
    if new_status:
        if new_status not in allowed_status:
            return jsonify({"error": "invalid status"}), 400
        finding.status = new_status
        if new_status == "resolved":
            finding.resolved_at = datetime.now(UTC)

    if "owner" in data:
        finding.owner = (data.get("owner") or "").strip() or None
    if "triageNote" in data:
        finding.triage_note = (data.get("triageNote") or "").strip() or None
    if "riskAcceptanceReason" in data:
        finding.risk_acceptance_reason = (data.get("riskAcceptanceReason") or "").strip() or None
    if "dueAt" in data:
        finding.due_at = _parse_iso_datetime(data.get("dueAt"))

    db.session.commit()
    return jsonify({"finding": _serialize_finding(finding)})


@api_bp.route("/export/findings.csv", methods=["GET"])
@login_required
def export_findings_csv():
    findings = _finding_query_for_current_user().order_by(Finding.id.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "scan_id", "severity", "status", "owner", "due_at", "resolved_at", "host", "template_name"])

    for finding in findings:
        writer.writerow(
            [
                finding.id,
                finding.scan_id,
                finding.severity,
                finding.status,
                finding.owner,
                finding.due_at.isoformat() if finding.due_at else "",
                finding.resolved_at.isoformat() if finding.resolved_at else "",
                finding.host,
                finding.template_name,
            ]
        )

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=findings_export.csv"},
    )


@api_bp.route("/export/findings.json", methods=["GET"])
@login_required
def export_findings_json():
    findings = _finding_query_for_current_user().order_by(Finding.id.desc()).all()
    payload = [
        {
            **_serialize_finding(finding),
            "scan": _serialize_scan(finding.scan),
        }
        for finding in findings
    ]
    return Response(
        json.dumps(payload, ensure_ascii=False, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=findings_export.json"},
    )


@api_bp.route("/admin/purge/scans", methods=["DELETE"])
@login_required
@require_roles("admin")
def purge_scans():
    scans = _scan_query_for_current_user().all()
    deleted_scans = len(scans)

    for scan in scans:
        db.session.delete(scan)

    db.session.commit()
    return jsonify({"ok": True, "scope": "scans", "deletedScans": deleted_scans})


@api_bp.route("/admin/purge/findings", methods=["DELETE"])
@login_required
@require_roles("admin")
def purge_findings():
    findings = _finding_query_for_current_user().all()
    deleted_findings = len(findings)

    for finding in findings:
        db.session.delete(finding)

    scans = _scan_query_for_current_user().all()
    for scan in scans:
        scan.promoted_findings_count = 0

    db.session.commit()
    return jsonify({"ok": True, "scope": "findings", "deletedFindings": deleted_findings})


@api_bp.route("/admin/purge/database", methods=["DELETE"])
@login_required
@require_roles("admin")
def purge_database_values():
    scans = _scan_query_for_current_user().all()
    findings_count = _finding_query_for_current_user().count()
    scans_count = len(scans)

    for scan in scans:
        db.session.delete(scan)

    db.session.commit()
    return jsonify(
        {
            "ok": True,
            "scope": "database",
            "deletedScans": scans_count,
            "deletedFindings": findings_count,
            "message": "All tenant data values were deleted successfully.",
        }
    )


def _run_scan_task(app, scan_id: int) -> None:
    with app.app_context():
        scan = db.session.get(Scan, scan_id)
        if scan is None:
            return

        nuclei_service = current_app.config["NUCLEI_SERVICE"]

        scan.status = "running"
        scan.updated_at = datetime.now(UTC)
        db.session.commit()

        result = nuclei_service.run_scan(
            target=scan.target,
            template=scan.template,
            severity=scan.severity,
            tags=scan.tags,
            advanced_args=scan.advanced_args,
        )

        summary = summarize_by_severity(result.findings)

        scan.raw_output = result.raw_output
        scan.findings_count = len(result.findings)
        scan.critical_count = summary["critical"]
        scan.high_count = summary["high"]
        scan.medium_count = summary["medium"]
        scan.low_count = summary["low"]
        scan.info_count = summary["info"]
        scan.updated_at = datetime.now(UTC)

        if result.return_code == 0:
            scan.status = "completed"
            scan.error_message = None
        else:
            scan.status = "failed"
            scan.error_message = result.stderr.strip() or "Nuclei scan failed"

        scan.promoted_findings_count = Finding.query.filter_by(scan_id=scan.id).count()

        db.session.commit()
