import os
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from Database.database import Base, get_db
from Backend.Routes.auth_route import auth_router, hash_password, verify_password, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES, SECRET_KEY, ALGORITHM
from models.user_Schema import UserCreate
from Database.tables import User

# Setup an in-memory SQLite database for testing
DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create tables
Base.metadata.create_all(bind=engine)

# Override get_db dependency to use the test session
def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

auth_router.dependency_overrides[get_db] = override_get_db

client = TestClient(auth_router)

@pytest.fixture(autouse=True)
def clear_env(monkeypatch):
    """Ensure environment variables are set for each test."""
    monkeypatch.setenv("SECRET_KEY", "testsecret")
    monkeypatch.setenv("ALGORITHM", "HS256")
    monkeypatch.setenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")
    # Re-import to apply env checks
    global ACCESS_TOKEN_EXPIRE_MINUTES, SECRET_KEY, ALGORITHM
    ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))
    SECRET_KEY = os.getenv("SECRET_KEY")
    ALGORITHM = os.getenv("ALGORITHM")

def test_env_variables_present():
    """Test that missing env vars raise RuntimeError."""
    with pytest.raises(RuntimeError, match="Missing required environment variable: SECRET_KEY"):
        os.environ.pop("SECRET_KEY")
        from Backend.Routes import auth_route  # re-import to trigger check

def test_hash_and_verify_password():
    pwd = "mysecret"
    hashed = hash_password(pwd)
    assert hashed != pwd
    assert verify_password(pwd, hashed)
    assert not verify_password("wrong", hashed)

def test_create_access_token_and_expiration():
    token = create_access_token({"sub": "123"})
    # Decode without verification to check payload
    from jose import jwt
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    assert payload["sub"] == "123"
    assert "exp" in payload
    # exp should be in the future
    assert payload["exp"] > int(datetime.utcnow().timestamp())

def test_signup_and_duplicate_email():
    user_data = {"user_name": "alice", "email": "alice@example.com", "password": "pass123"}
    response = client.post("/auth/signup", json=user_data)
    assert response.status_code == 200
    assert response.json() == {"message": "User created successfully"}

    # Attempt duplicate signup
    dup_response = client.post("/auth/signup", json=user_data)
    assert dup_response.status_code == 400
    assert dup_response.json()["detail"] == "Email already registered"

def test_login_success_and_token_return():
    # First create user
    user_data = {"user_name": "bob", "email": "bob@example.com", "password": "mypassword"}
    client.post("/auth/signup", json=user_data)

    # Login using form data
    login_response = client.post(
        "/auth/login",
        data={"username": "bob@example.com", "password": "mypassword"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert login_response.status_code == 200
    data = login_response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

def test_login_invalid_credentials():
    # Ensure user exists
    client.post("/auth/signup", json={"user_name": "charlie", "email": "charlie@example.com", "password": "secret"})

    # Wrong password
    resp = client.post(
        "/auth/login",
        data={"username": "charlie@example.com", "password": "wrong"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid credentials"

def test_get_me_endpoint(monkeypatch):
    # Create user and login to get token
    client.post("/auth/signup", json={"user_name": "dave", "email": "dave@example.com", "password": "pwd"})
    login_resp = client.post(
        "/auth/login",
        data={"username": "dave@example.com", "password": "pwd"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    token = login_resp.json()["access_token"]

    # Access protected route
    me_resp = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == "dave@example.com"

def test_missing_env_var_raises_on_import(monkeypatch):
    """Simulate missing SECRET_KEY during import."""
    monkeypatch.setenv("SECRET_KEY", "")
    with pytest.raises(RuntimeError, match="Missing required environment variable: SECRET_KEY"):
        import importlib
        importlib.reload(auth_router)