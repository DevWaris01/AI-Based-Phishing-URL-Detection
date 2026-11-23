import os
import pytest
from fastapi import FastAPI, Depends, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from unittest.mock import MagicMock

# Import the module under test
import Backend.Routes.auth_route as auth_route

# Helper to override get_db dependency
def override_get_db():
    db = MagicMock(spec=Session)
    yield db

# Helper to create a FastAPI app with the auth router
def get_app():
    app = FastAPI()
    app.include_router(auth_route.auth_router)
    app.dependency_overrides[auth_route.get_db] = override_get_db
    return app

@pytest.fixture
def client():
    app = get_app()
    return TestClient(app)

def test_signup_success(client, monkeypatch):
    # Mock DB behavior
    db = next(override_get_db())
    db.query.return_value.filter.return_value.first.return_value = None
    # Perform signup
    response = client.post(
        "/auth/signup",
        json={"user_name": "alice", "email": "alice@example.com", "password": "secret"}
    )
    assert response.status_code == 200
    assert response.json() == {"message": "User created successfully"}
    # Ensure user was added and committed
    db.add.assert_called_once()
    db.commit.assert_called_once()
    db.refresh.assert_called_once()

def test_signup_duplicate_email(client, monkeypatch):
    db = next(override_get_db())
    # Simulate existing user
    db.query.return_value.filter.return_value.first.return_value = MagicMock()
    response = client.post(
        "/auth/signup",
        json={"user_name": "bob", "email": "bob@example.com", "password": "secret"}
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Email already registered"

def test_login_success(client, monkeypatch):
    db = next(override_get_db())
    # Mock user in DB
    mock_user = MagicMock()
    mock_user.id = 42
    mock_user.password = auth_route.hash_password("mypassword")
    db.query.return_value.filter.return_value.first.return_value = mock_user
    # Perform login
    response = client.post(
        "/auth/login",
        data={"username": "bob@example.com", "password": "mypassword"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["token_type"] == "bearer"
    assert "access_token" in data

def test_login_invalid_credentials(client, monkeypatch):
    db = next(override_get_db())
    db.query.return_value.filter.return_value.first.return_value = None
    response = client.post(
        "/auth/login",
        data={"username": "unknown@example.com", "password": "nopass"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"

def test_create_access_token_expiration(monkeypatch):
    # Set a short expiry for test
    monkeypatch.setenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1")
    # Re-import to apply new env var
    import importlib
    importlib.reload(auth_route)
    token = auth_route.create_access_token({"sub": "test"})
    # Decode token to check exp
    decoded = auth_route.jwt.decode(token, auth_route.SECRET_KEY, algorithms=[auth_route.ALGORITHM])
    exp_timestamp = decoded["exp"]
    # exp should be roughly 60 seconds from now
    now = int(auth_route.datetime.utcnow().timestamp())
    assert exp_timestamp - now <= 65
    assert exp_timestamp - now >= 55

def test_missing_env_vars(monkeypatch):
    # Remove critical env vars
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.delenv("ALGORITHM", raising=False)
    monkeypatch.delenv("ACCESS_TOKEN_EXPIRE_MINUTES", raising=False)
    with pytest.raises(RuntimeError) as exc:
        import importlib
        importlib.reload(auth_route)
    assert "Missing required environment variable" in str(exc.value)

def test_invalid_access_token_minutes(monkeypatch):
    monkeypatch.setenv("ACCESS_TOKEN_EXPIRE_MINUTES", "not_an_int")
    with pytest.raises(RuntimeError) as exc:
        import importlib
        importlib.reload(auth_route)
    assert "must be an integer" in str(exc.value)