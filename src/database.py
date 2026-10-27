import os
from datetime import datetime, timezone
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker

os.makedirs("data", exist_ok=True)

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///data/sdn_security.db")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def utc_now():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    email = Column(String(120), unique=True, index=True, nullable=False)
    full_name = Column(String(120), nullable=False)
    password_hash = Column(String(256), nullable=False)
    role = Column(String(32), default="analyst", nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utc_now)


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(Float, nullable=False)
    time_str = Column(String(32), nullable=False)
    src_ip = Column(String(64), index=True, nullable=False)
    dst_ip = Column(String(64), nullable=False)
    flow_count = Column(Integer, nullable=False)
    pkt_rate = Column(Float, nullable=False)
    byte_rate = Column(Float, nullable=False)
    mean_pkt_size = Column(Float, default=0.0)
    unique_dst_ports = Column(Integer, nullable=False)
    syn_ratio = Column(Float, nullable=False)
    active_model = Column(String(64), default="Random Forest")
    rf_prediction = Column(Integer, nullable=False)
    rf_confidence = Column(Float, nullable=False)
    iso_prediction = Column(Integer, default=0)
    threat_type = Column(String(64), nullable=False)
    explanation = Column(Text, default="")
    action = Column(String(32), nullable=False)
    inference_latency_ms = Column(Float, nullable=False)


class PolicyRule(Base):
    __tablename__ = "policy_rules"

    id = Column(Integer, primary_key=True, index=True)
    target_ip = Column(String(64), index=True, nullable=False)
    rule_type = Column(String(32), nullable=False)
    rate_kbps = Column(Integer, default=0)
    priority = Column(Integer, default=100)
    status = Column(String(32), default="active")
    reason = Column(String(256), default="Automated ML Policy Enforcement")
    created_by = Column(String(64), default="system")
    created_at = Column(DateTime, default=utc_now)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=utc_now)
    username = Column(String(64), nullable=False)
    role = Column(String(32), nullable=False)
    action = Column(String(128), nullable=False)
    details = Column(Text, default="")


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
