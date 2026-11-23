import pytest
from fastapi.testclient import TestClient
from fastapi import Depends, BackgroundTasks
from sqlalchemy.orm import Session
from unittest.mock import MagicMock, patch

# Import the router and dependencies
from Backend.Routes.upishing_route import domain_router, get_current_user, get_db
from Backend.Routes.upishing_route import analyze_url, send_email
from Backend.Routes.upishing_route import Domain

# Create a minimal FastAPI app for testing
from fastapi import FastAPI
app = FastAPI()
app.include_router(domain_router)

# Helper to create a fake DB session
class FakeSession:
    def __init__(self):
        self._data = []

    def query(self, model):
        return self

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self._data[0] if self._data else None

    def add(self, obj):
        self._data.append(obj)

    def commit(self):
        pass

    def refresh(self, obj):
        pass

# Override dependencies
@pytest.fixture
def client():
    with patch('Backend.Routes.upishing_route.get_db', return_value=FakeSession()), \
         patch('Backend.Routes.upishing_route.get_current_user', return_value=MagicMock(email='user@example.com')), \
         patch('Backend.Routes.upishing_route.analyze_url') as mock_analyze, \
         patch('Backend.Routes.upishing_route.send_email') as mock_send:
        mock_analyze.side_effect = lambda url: {
            "url": url,
            "is_phishing": "phish" in url,
            "reason": "This is a phishing site" if "phish" in url else "Safe"
        }
        client = TestClient(app)
        yield client, mock_analyze, mock_send

def test_new_phishing_url_triggers_email(client):
    client, mock_analyze, mock_send = client
    response = client.post("/pishing-url/check", json={"url": "http://phish.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["is_phishing"] is True
    assert data["reason"] == "This is a phishing site"
    # Email should be queued via background task
    mock_send.assert_called_once_with(
        to_email='user@example.com',
        subject="⚠️ Phishing Alert",
        body=pytest.approx("The URL you checked is identified as PHISHING.")
    )

def test_new_safe_url_no_email(client):
    client, mock_analyze, mock_send = client
    response = client.post("/pishing-url/check", json={"url": "http://safe.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["is_phishing"] is False
    assert data["reason"] == "Safe"
    mock_send.assert_not_called()

def test_existing_domain_returns_cached_result(client):
    client, mock_analyze, mock_send = client
    # First call to create entry
    client.post("/pishing-url/check", json={"url": "http://existing.com"})
    # Second call should return cached result without calling analyze_url again
    mock_analyze.reset_mock()
    response = client.post("/pishing-url/check", json={"url": "http://existing.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["is_phishing"] is False  # safe by default
    assert data["reason"] == "Safe"
    mock_analyze.assert_not_called()
    mock_send.assert_not_called()

def test_brittle_reason_logic_fixed(client):
    client, mock_analyze, mock_send = client
    # Simulate a reason that does not contain the word 'phishing'
    mock_analyze.side_effect = lambda url: {
        "url": url,
        "is_phishing": True,
        "reason": "Malicious activity detected"
    }
    response = client.post("/pishing-url/check", json={"url": "http://malicious.com"})
    assert response.status_code == 200
    data = response.json()
    # The endpoint should still report phishing based on is_phishing flag
    assert data["is_phishing"] is True
    assert data["reason"] == "Malicious activity detected"
    mock_send.assert_called_once()

def test_error_handling_returns_500(client):
    client, mock_analyze, mock_send = client
    # Force analyze_url to raise an exception
    mock_analyze.side_effect = Exception("Analysis failed")
    response = client.post("/pishing-url/check", json={"url": "http://error.com"})
    assert response.status_code == 500
    assert response.json()["detail"] == "Analysis failed"