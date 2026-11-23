import pytest
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from Database.database import Base
from Backend.Database.tables import User, OTP

# Create an in‑memory SQLite database for testing
engine = create_engine("sqlite:///:memory:", echo=False)
Session = sessionmaker(bind=engine)

@pytest.fixture(scope="module", autouse=True)
def setup_database():
    Base.metadata.create_all(engine)
    yield
    Base.metadata.drop_all(engine)

@pytest.fixture
def session():
    sess = Session()
    yield sess
    sess.close()

@pytest.fixture
def user(session):
    u = User(user_name="alice", email="alice@example.com", password="secret")
    session.add(u)
    session.commit()
    return u

def test_otp_hashing_and_verification(session, user):
    otp = OTP(user_id=user.id)
    plain = "123456"
    otp.set_otp(plain)
    session.add(otp)
    session.commit()

    # The stored value should not be the plain text
    assert otp.otp_hash != plain
    # Verify with correct OTP
    assert otp.verify_otp(plain) is True
    # Verify with incorrect OTP
    assert otp.verify_otp("654321") is False

def test_otp_expiry(session, user, monkeypatch):
    # Create OTP with a short expiry (1 second)
    otp = OTP(user_id=user.id)
    otp.set_otp("999999")
    otp.expiry_at = datetime.utcnow() + timedelta(seconds=1)
    session.add(otp)
    session.commit()

    # Immediately verify should succeed
    assert otp.verify_otp("999999") is True

    # Fast‑forward time beyond expiry
    future_time = datetime.utcnow() + timedelta(seconds=2)
    monkeypatch.setattr("datetime.datetime", type("MockDateTime", (datetime,), {"utcnow": staticmethod(lambda: future_time)}))
    # After expiry, verification should fail
    assert otp.verify_otp("999999") is False

def test_default_expiry_is_five_minutes(session, user):
    otp = OTP(user_id=user.id)
    otp.set_otp("555555")
    session.add(otp)
    session.commit()

    # The default expiry should be roughly 5 minutes after creation
    delta = otp.expiry_at - otp.created_at
    assert timedelta(minutes=4, seconds=59) <= delta <= timedelta(minutes=5, seconds=1)

def test_otp_relationship(session, user):
    otp = OTP(user_id=user.id)
    otp.set_otp("111111")
    session.add(otp)
    session.commit()

    # Retrieve OTP via user relationship
    retrieved_user = session.query(User).filter_by(id=user.id).one()
    assert len(retrieved_user.transactions) == 0  # No transactions
    # OTP has a direct relationship to user
    assert otp.user.id == user.id
    assert otp.user.email == user.email