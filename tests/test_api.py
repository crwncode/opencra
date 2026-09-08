from fastapi.testclient import TestClient
from opencra_api.db import engine
from opencra_api.main import app
from opencra_api.orm import Base

Base.metadata.create_all(bind=engine)
client = TestClient(app)
HEADERS = {"X-Dev-User-Id": "user-1", "X-Dev-Org-Id": "org-1"}


def test_health() -> None:
    assert client.get("/health").json()["ok"] is True


def test_ingest_creates_candidate_not_awareness() -> None:
    response = client.post(
        "/v1/ingest",
        headers=HEADERS,
        json={
            "target": ".",
            "product_name": "acme-app",
            "sbom": {
                "serialNumber": "urn:uuid:test",
                "metadata": {"component": {"name": "acme-app"}},
                "components": [],
            },
            "matches": [
                {
                    "purl": "pkg:pypi/demo@1.0.0",
                    "cve_id": "CVE-2021-44228",
                    "in_kev": True,
                    "severity": "CRITICAL",
                }
            ],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["candidates"] == 1
    case_id = body["case_ids"][0]

    cases = client.get("/cases", headers=HEADERS).json()
    case = next(c for c in cases if c["id"] == case_id)
    assert case["status"] == "candidate"
    assert case["awareness_at"] is None
    assert case["early_warning_due_at"] is None

    acked = client.patch(
        f"/cases/{case_id}",
        headers=HEADERS,
        json={"acknowledge": True},
    ).json()
    assert acked["awareness_at"] is not None
    assert acked["early_warning_due_at"] is not None
