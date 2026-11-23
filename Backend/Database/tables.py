from sqlalchemy import Column, String, Float, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta
import uuid
import bcrypt
from Database.database import Base


class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)
    transactions = relationship("Transaction", back_populates="user")


class Domain(Base):
    __tablename__ = "domains"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    url = Column(String, unique=True, index=True, nullable=False)
    reason = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)


class Transaction(Base):
    __tablename__ = "transactions"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    amount = Column(Float, nullable=False)
    status = Column(String, default="pending")
    risk_level = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="transactions")


class OTP(Base):
    __tablename__ = "otps"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    otp_hash = Column(String, nullable=False)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    user = relationship("User")

    def set_otp(self, plain_otp: str, validity_minutes: int = 5):
        """
        Hashes the provided plain OTP and stores it in the database.
        Also sets an expiration timestamp based on the provided validity period.
        """
        # Generate a bcrypt hash of the OTP
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(plain_otp.encode("utf-8"), salt)
        self.otp_hash = hashed.decode("utf-8")
        # Set expiration time
        self.expires_at = datetime.utcnow() + timedelta(minutes=validity_minutes)

    def verify_otp(self, plain_otp: str) -> bool:
        """
        Verifies a plain OTP against the stored hash and checks expiration.
        Returns True if the OTP is correct and not expired; otherwise False.
        """
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False
        try:
            return bcrypt.checkpw(plain_otp.encode("utf-8"), self.otp_hash.encode("utf-8"))
        except Exception:
            return False