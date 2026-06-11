from io import BytesIO

from fastapi.testclient import TestClient

from app.main import app
from app.db.database import Base, engine


from app.api.auth import get_current_user
from app.models.user import User

Base.metadata.create_all(bind=engine)

def override_get_current_user():
    return User(id=1, username="test_user")

app.dependency_overrides[get_current_user] = override_get_current_user

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_train_and_benchmark_flow():
    response = client.post(
        "/api/v1/train",
        json={
            "csv_path": "data/network_traffic_sample.csv",
            "target_column": "label",
            "dataset_profile": "sample",
        },
    )
    assert response.status_code == 200
    benchmark = client.get("/api/v1/benchmark")
    assert benchmark.status_code == 200
    assert "selected_model" in benchmark.json()


def test_predict_endpoint():
    payload = {
        "records": [
            {
                "duration": 0,
                "src_bytes": 0,
                "dst_bytes": 0,
                "count": 240,
                "srv_count": 12,
                "same_srv_rate": 0.05,
                "diff_srv_rate": 0.87,
                "dst_host_count": 255,
                "dst_host_srv_count": 17,
                "protocol_type": "tcp",
                "service": "smtp",
                "flag": "S0",
            }
        ],
        "explain": True,
    }
    response = client.post("/api/v1/predict", json=payload)
    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["total_records"] == 1
    assert "dashboard" in body


def test_analysis_state_persists_and_clears_per_user():
    client.delete("/api/v1/analysis/state")
    initial = client.get("/api/v1/analysis/state")
    assert initial.status_code == 200
    assert initial.json()["has_data"] is False

    payload = {
        "records": [
            {
                "duration": 0,
                "src_bytes": 0,
                "dst_bytes": 0,
                "count": 240,
                "srv_count": 12,
                "same_srv_rate": 0.05,
                "diff_srv_rate": 0.87,
                "dst_host_count": 255,
                "dst_host_srv_count": 17,
                "protocol_type": "tcp",
                "service": "smtp",
                "flag": "S0",
            }
        ],
        "explain": True,
    }
    prediction = client.post("/api/v1/predict", json=payload)
    assert prediction.status_code == 200

    saved = client.get("/api/v1/analysis/state")
    assert saved.status_code == 200
    body = saved.json()
    assert body["has_data"] is True
    assert body["state"]["summary"]["total_records"] == 1
    assert len(body["state"]["predictions"]) == 1

    cleared = client.delete("/api/v1/analysis/state")
    assert cleared.status_code == 200
    assert client.get("/api/v1/analysis/state").json()["has_data"] is False


def test_predict_csv_rejects_invalid_columns():
    csv_content = b"name,value\ninvalid,1\n"
    response = client.post(
        "/api/v1/predict/csv",
        files={"file": ("bad.csv", BytesIO(csv_content), "text/csv")},
    )
    assert response.status_code == 400


def test_chat_endpoint():
    response = client.post(
        "/api/v1/chat",
        json={"message": "What is a DoS attack?", "history": [], "latest_summary": None},
    )
    assert response.status_code == 200
    assert "reply" in response.json()
