import os
from datetime import datetime, timedelta, timezone
from typing import Optional
import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from src.database import SessionLocal, User, AuditLog, PolicyRule, get_db, init_db

SECRET_KEY = os.environ.get("SDN_JWT_SECRET", "rifat-sdn-enterprise-secret-key-2026-nsu")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24

security_scheme = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except Exception:
        return None


def log_audit(db: Session, username: str, role: str, action: str, details: str = ""):
    entry = AuditLog(username=username, role=role, action=action, details=details)
    db.add(entry)
    db.commit()


def seed_default_accounts():
    init_db()
    db = SessionLocal()
    try:
        if not db.query(User).filter(User.username == "admin").first():
            admin_user = User(
                username="admin",
                email="rifat.admin@sdnlab.local",
                full_name="Rifat Khan (SOC Admin)",
                password_hash=hash_password("Admin@SDN2026"),
                role="admin",
            )
            db.add(admin_user)

        if not db.query(User).filter(User.username == "analyst").first():
            analyst_user = User(
                username="analyst",
                email="analyst@sdnlab.local",
                full_name="SOC Security Analyst",
                password_hash=hash_password("Analyst@SDN2026"),
                role="analyst",
            )
            db.add(analyst_user)

        for vip_ip, desc in [
            ("10.0.0.1", "Protected Web Server h1"),
            ("10.0.0.4", "Protected Database/iperf Server h4"),
            ("10.10.10.1", "Ubuntu SDN-Core Controller"),
        ]:
            exists = db.query(PolicyRule).filter(PolicyRule.target_ip == vip_ip, PolicyRule.rule_type == "whitelist").first()
            if not exists:
                db.add(PolicyRule(
                    target_ip=vip_ip,
                    rule_type="whitelist",
                    priority=200,
                    status="active",
                    reason=desc,
                    created_by="system",
                ))
        db.commit()
    finally:
        db.close()


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    payload = decode_access_token(credentials.credentials)
    if not payload or "sub" not in payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    user = db.query(User).filter(User.username == payload["sub"], User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")
    return user


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator privileges required")
    return current_user


if __name__ == "__main__":
    seed_default_accounts()
    db = SessionLocal()
    users = db.query(User).all()
    rules = db.query(PolicyRule).all()
    tkn = create_access_token({"sub": "admin", "role": "admin"})
    decoded = decode_access_token(tkn)
    print("[+] Database initialized at data/sdn_security.db")
    print(f"[+] Seeded Users ({len(users)}): " + ", ".join([f"{u.username} ({u.role})" for u in users]))
    print(f"[+] Seeded Protected Whitelist IPs ({len(rules)}): " + ", ".join([r.target_ip for r in rules]))
    print(f"[+] JWT Self-Test Verified: user={decoded['sub']} | role={decoded['role']}")
    db.close()
