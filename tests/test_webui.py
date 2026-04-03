from backend.app import create_app
from backend.schemas.models import User
from backend.utils.extensions import db
import time


class DummyNucleiService:
    def is_installed(self):
        return True

    def get_version(self):
        return "nuclei v3.x"

    def list_templates(self, limit=300):
        return ["/tmp/template.yaml"]

    def build_command(self, target, template=None, severity=None, tags=None, advanced_args=None):
        return ["nuclei", "-u", target]

    def run_scan(self, target, template=None, severity=None, tags=None, advanced_args=None):
        class Result:
            command = ["nuclei", "-u", target]
            raw_output = '{"template-id":"test","info":{"name":"Test Finding","severity":"high"},"host":"example.com"}'
            findings = [
                {
                    "template-id": "test",
                    "info": {"name": "Test Finding", "severity": "high"},
                    "host": "example.com",
                    "matcher-name": "body",
                    "matched-at": "https://example.com",
                }
            ]
            stderr = ""
            return_code = 0

        return Result()


def build_test_app():
    return create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "WTF_CSRF_ENABLED": False,
            "NUCLEI_SERVICE": DummyNucleiService(),
        }
    )


def login(client):
    return client.post(
        "/login",
        data={"username": "Developer", "password": "Nucl31-ui"},
        follow_redirects=True,
    )


def test_login_and_dashboard_access():
    app = build_test_app()
    with app.app_context():
        db.create_all()

    client = app.test_client()
    response = login(client)
    assert response.status_code == 200
    assert b"Vulnerability Management Command Center" in response.data
    assert b"severityChart" in response.data


def test_start_scan_and_summary():
    app = build_test_app()
    with app.app_context():
        db.create_all()

    client = app.test_client()
    login(client)

    create_response = client.post(
        "/api/scans",
        json={"target": "https://example.com"},
    )
    assert create_response.status_code == 202
    data = create_response.get_json()
    assert data["scan"]["target"] == "https://example.com"

    summary_response = client.get("/api/dashboard/summary")
    assert summary_response.status_code == 200
    summary_data = summary_response.get_json()
    assert "recentScans" in summary_data


def test_me_endpoint_and_export_endpoints():
    app = build_test_app()
    with app.app_context():
        db.create_all()

    client = app.test_client()
    login(client)

    me_response = client.get("/api/me")
    assert me_response.status_code == 200
    me_data = me_response.get_json()
    assert me_data["username"] == "Developer"
    assert me_data["role"] == "admin"

    csv_response = client.get("/api/export/findings.csv")
    assert csv_response.status_code == 200
    assert csv_response.mimetype == "text/csv"

    json_response = client.get("/api/export/findings.json")
    assert json_response.status_code == 200
    assert json_response.mimetype == "application/json"


def test_finding_lifecycle_patch_and_viewer_forbidden():
    app = build_test_app()
    with app.app_context():
        db.create_all()
        viewer = User(username="viewer", role="viewer", tenant_id="default")
        viewer.set_password("ViewerPass123")
        db.session.add(viewer)
        db.session.commit()

    client = app.test_client()
    login(client)

    create_response = client.post("/api/scans", json={"target": "https://example.com"})
    assert create_response.status_code == 202
    scan_id = create_response.get_json()["scan"]["id"]

    scan_results = None
    for _ in range(60):
        scan_state_response = client.get(f"/api/scans/{scan_id}")
        assert scan_state_response.status_code == 200
        scan_state = scan_state_response.get_json().get("scan", {})

        scan_results_response = client.get(f"/api/scans/{scan_id}/results")
        if scan_results_response.status_code == 200:
            scan_results = scan_results_response.get_json()
            if scan_state.get("status") == "completed" and scan_results.get("results"):
                break
        time.sleep(0.05)

    assert scan_results is not None
    assert len(scan_results.get("results", [])) >= 1

    promote_response = client.post(f"/api/scans/{scan_id}/promote-findings", json={})
    assert promote_response.status_code == 200
    promoted = promote_response.get_json()
    assert promoted["promoted"] >= 1

    findings = []
    for _ in range(20):
        findings_response = client.get("/api/findings")
        assert findings_response.status_code == 200
        findings = findings_response.get_json()["findings"]
        if findings:
            break
        time.sleep(0.05)

    assert len(findings) >= 1
    finding_id = findings[0]["id"]

    patch_response = client.patch(
        f"/api/findings/{finding_id}",
        json={"status": "in_progress", "owner": "analyst-a"},
    )
    assert patch_response.status_code == 200
    updated = patch_response.get_json()["finding"]
    assert updated["status"] == "in_progress"
    assert updated["owner"] == "analyst-a"

    client.post("/logout")
    client.post("/login", data={"username": "viewer", "password": "ViewerPass123"}, follow_redirects=True)

    forbidden_scan = client.post("/api/scans", json={"target": "https://forbidden.example"})
    assert forbidden_scan.status_code == 403

    forbidden_patch = client.patch(f"/api/findings/{finding_id}", json={"status": "resolved"})
    assert forbidden_patch.status_code == 403
