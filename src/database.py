import os
import time
from datetime import datetime
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    Float,
    String,
    Boolean,
    Text,
    DateTime,
)
from sqlalchemy.orm import sessionmaker, declarative_base

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IS_VERCEL = bool(os.getenv("VERCEL"))

if os.getenv("DATABASE_URL"):
    DATABASE_URL = os.getenv("DATABASE_URL")
elif IS_VERCEL:
    DATABASE_URL = "sqlite:////tmp/sdn_soc.db"
else:
    os.makedirs(os.path.join(BASE_DIR, "data"), exist_ok=True)
    DATABASE_URL = f"sqlite:///{os.path.join(BASE_DIR, 'data', 'sdn_soc.db')}"

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    email = Column(String(128), unique=True, index=True, nullable=False)
    full_name = Column(String(128), nullable=False)
    password_hash = Column(String(256), nullable=False)
    role = Column(String(32), default="analyst", nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(Float, default=time.time, index=True)
    time_str = Column(String(32), nullable=False)
    src_ip = Column(String(64), index=True, nullable=False)
    dst_ip = Column(String(64), nullable=False)
    flow_count = Column(Integer, default=1)
    pkt_rate = Column(Float, default=0.0)
    byte_rate = Column(Float, default=0.0)
    mean_pkt_size = Column(Float, default=0.0)
    unique_dst_ports = Column(Integer, default=1)
    syn_ratio = Column(Float, default=0.0)
    active_model = Column(String(64), default="Ensemble Voting (All 5 Models)")
    rf_prediction = Column(Integer, default=0)
    rf_confidence = Column(Float, default=0.0)
    iso_prediction = Column(Integer, default=0)
    threat_type = Column(String(64), default="benign")
    explanation = Column(Text, default="")
    action = Column(String(32), default="allow")
    inference_latency_ms = Column(Float, default=0.0)


class PolicyRule(Base):
    __tablename__ = "policy_rules"

    id = Column(Integer, primary_key=True, index=True)
    target_ip = Column(String(64), index=True, nullable=False)
    rule_type = Column(String(32), nullable=False)
    rate_kbps = Column(Integer, default=0)
    priority = Column(Integer, default=100)
    status = Column(String(32), default="active")
    reason = Column(Text, default="")
    created_by = Column(String(64), default="system")
    created_at = Column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    username = Column(String(64), nullable=False)
    role = Column(String(32), nullable=False)
    action = Column(String(64), nullable=False)
    details = Column(Text, default="")


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


init_db()