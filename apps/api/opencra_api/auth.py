from __future__ import annotations

import hashlib
from dataclasses import dataclass

import jwt
from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from opencra_api.config import settings
from opencra_api.db import get_db
from opencra_api.orm import ApiKey, Membership, Organization, Subscription


@dataclass
class Principal:
    user_id: str
    org_id: str
    role: str
    email: str | None
    tier: str


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def get_principal(
    authorization: str | None = Header(default=None),
    x_dev_user_id: str | None = Header(default=None),
    x_dev_org_id: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> Principal:
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        key = db.query(ApiKey).filter(ApiKey.token_hash == _hash_token(token)).one_or_none()
        if key:
            sub = db.query(Subscription).filter(Subscription.org_id == key.org_id).one_or_none()
            return Principal(
                user_id="api-key",
                org_id=key.org_id,
                role="engineer",
                email=None,
                tier=sub.tier if sub else "community",
            )
        try:
            payload = jwt.decode(
                token,
                settings.supabase_jwt_secret,
                algorithms=["HS256"],
                options={"verify_aud": False},
            )
        except jwt.PyJWTError as exc:
            raise HTTPException(status_code=401, detail="Invalid token") from exc
        user_id = str(payload.get("sub") or "")
        org_id = str(payload.get("org_id") or payload.get("app_org_id") or "")
        membership = None
        if user_id:
            q = db.query(Membership).filter(Membership.user_id == user_id)
            if org_id:
                q = q.filter(Membership.org_id == org_id)
            membership = q.first()
        if not membership:
            raise HTTPException(status_code=403, detail="No organization membership")
        sub = db.query(Subscription).filter(Subscription.org_id == membership.org_id).one_or_none()
        return Principal(
            user_id=membership.user_id,
            org_id=membership.org_id,
            role=membership.role,
            email=membership.email,
            tier=sub.tier if sub else "community",
        )

    if settings.dev_auth and x_dev_user_id and x_dev_org_id:
        _ensure_dev_org(db, x_dev_org_id, x_dev_user_id)
        sub = db.query(Subscription).filter(Subscription.org_id == x_dev_org_id).one_or_none()
        return Principal(
            user_id=x_dev_user_id,
            org_id=x_dev_org_id,
            role="owner",
            email=None,
            tier=sub.tier if sub else "community",
        )

    raise HTTPException(status_code=401, detail="Missing credentials")


def _ensure_dev_org(db: Session, org_id: str, user_id: str) -> None:
    if db.get(Organization, org_id) is None:
        db.add(Organization(id=org_id, name="Dev Org", slug=f"dev-{org_id[:8]}"))
        db.add(Membership(org_id=org_id, user_id=user_id, role="owner", email="dev@local"))
        db.add(Subscription(org_id=org_id, tier="pro_plus", product_limit=15, seat_limit=25, retention_days=365))
        db.commit()


def require_tier(*allowed: str):
    def checker(principal: Principal = Depends(get_principal)) -> Principal:
        if principal.tier not in allowed:
            raise HTTPException(
                status_code=402,
                detail=f"This feature requires one of: {', '.join(allowed)}",
            )
        return principal

    return checker
