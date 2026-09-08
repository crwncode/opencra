from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from opencra_api.auth import Principal, get_principal
from opencra_api.config import settings
from opencra_api.db import get_db
from opencra_api.orm import Subscription

router = APIRouter()

TIER_LIMITS = {
    "community": {"seat_limit": 1, "product_limit": 1, "retention_days": 7},
    "pro": {"seat_limit": 10, "product_limit": 5, "retention_days": 365},
    "pro_plus": {"seat_limit": 25, "product_limit": 15, "retention_days": 365},
    "enterprise": {"seat_limit": 9999, "product_limit": 9999, "retention_days": 2555},
}


class CheckoutIn(BaseModel):
    tier: str = "pro"


@router.post("/billing/checkout")
def checkout(
    body: CheckoutIn,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> dict:
    if body.tier not in {"pro", "pro_plus"}:
        raise HTTPException(400, "Use sales for enterprise annual contracts")
    price = settings.stripe_price_pro if body.tier == "pro" else settings.stripe_price_pro_plus
    if not settings.stripe_secret_key or not price:
        # Local/dev: upgrade the subscription without Stripe.
        sub = db.query(Subscription).filter(Subscription.org_id == principal.org_id).one_or_none()
        if sub is None:
            sub = Subscription(org_id=principal.org_id)
            db.add(sub)
        sub.tier = body.tier
        limits = TIER_LIMITS[body.tier]
        sub.seat_limit = limits["seat_limit"]
        sub.product_limit = limits["product_limit"]
        sub.retention_days = limits["retention_days"]
        sub.status = "active"
        db.commit()
        return {"ok": True, "mode": "dev", "tier": body.tier}

    import stripe

    stripe.api_key = settings.stripe_secret_key
    session = stripe.checkout.Session.create(
        mode="subscription",
        line_items=[{"price": price, "quantity": 1}],
        success_url=f"{settings.public_app_url}/billing?ok=1",
        cancel_url=f"{settings.public_app_url}/billing?canceled=1",
        client_reference_id=principal.org_id,
        metadata={"org_id": principal.org_id, "tier": body.tier},
    )
    return {"ok": True, "url": session.url}


@router.post("/billing/webhook")
async def stripe_webhook(request: Request, db: Session = Depends(get_db)) -> dict:
    payload = await request.body()
    if not settings.stripe_webhook_secret:
        return {"ok": True, "ignored": True}
    import stripe

    sig = request.headers.get("stripe-signature", "")
    try:
        event = stripe.Webhook.construct_event(payload, sig, settings.stripe_webhook_secret)
    except Exception as exc:
        raise HTTPException(400, f"Invalid Stripe signature: {exc}") from exc

    if event["type"] in {"checkout.session.completed", "customer.subscription.updated"}:
        obj = event["data"]["object"]
        org_id = (obj.get("metadata") or {}).get("org_id") or obj.get("client_reference_id")
        tier = (obj.get("metadata") or {}).get("tier") or "pro"
        if org_id:
            sub = db.query(Subscription).filter(Subscription.org_id == org_id).one_or_none()
            if sub is None:
                sub = Subscription(org_id=org_id)
                db.add(sub)
            sub.tier = tier
            sub.stripe_customer_id = obj.get("customer")
            sub.stripe_subscription_id = obj.get("subscription") or obj.get("id")
            limits = TIER_LIMITS.get(tier, TIER_LIMITS["pro"])
            sub.seat_limit = limits["seat_limit"]
            sub.product_limit = limits["product_limit"]
            sub.retention_days = limits["retention_days"]
            sub.status = "active"
            db.commit()
    return {"ok": True}
