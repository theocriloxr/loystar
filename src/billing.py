"""
Self-serve billing integration for merchant onboarding.

Merchants deploy the server → pick a plan → pay via Stripe →
connect their Loystar account → get their MCP server URL.

All without anyone from the Loystar team touching anything.
"""
from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from starlette.responses import HTMLResponse, RedirectResponse

from src.config import settings
from src.database import get_db_context
from src.models import MerchantSubscription

def require_billing_enabled() -> None:
    if not settings.enable_billing_routes:
        raise HTTPException(status_code=404, detail="Not found.")


router = APIRouter(
    prefix="/onboard",
    tags=["billing"],
    dependencies=[Depends(require_billing_enabled)],
)


# ── Plans ────────────────────────────────────────────────────────────────────

PLANS = {
    "free": {
        "name": "Starter",
        "description": "For testing and small merchants",
        "price_monthly": 0,
        "rate_limit_requests": 30,
        "max_merchants": 1,
        "features": [
            "Up to 30 AI queries per minute",
            "1 merchant account",
            "Standard MCP tools",
            "PII redaction",
            "Audit logging",
        ],
    },
    "pro": {
        "name": "Pro",
        "description": "For growing businesses",
        "price_monthly": 29,
        "rate_limit_requests": 120,
        "max_merchants": 5,
        "features": [
            "Up to 120 AI queries per minute",
            "Up to 5 merchant accounts",
            "All MCP tools + write actions",
            "PII redaction + custom masking rules",
            "Audit logging + export",
            "Priority support",
        ],
    },
    "enterprise": {
        "name": "Enterprise",
        "description": "For large operations and agencies",
        "price_monthly": 99,
        "rate_limit_requests": 500,
        "max_merchants": 50,
        "features": [
            "Up to 500 AI queries per minute",
            "Up to 50 merchant accounts",
            "All MCP tools + write actions + HITL",
            "Custom PII rules + data residency",
            "Full audit trail + SIEM integration",
            "Dedicated support + SLA",
            "Custom domain + white-label",
        ],
    },
}

PRICE_IDS = {
    "free": settings.stripe_price_id_free,
    "pro": settings.stripe_price_id_pro,
    "enterprise": settings.stripe_price_id_enterprise,
}


def _stripe_enabled() -> bool:
    """Return True when Stripe API key is configured."""
    return bool(settings.stripe_secret_key)


def _get_stripe():
    """Lazy-import and return Stripe client."""
    try:
        import stripe
    except ImportError:
        raise HTTPException(status_code=500, detail="Stripe library not installed")
    stripe.api_key = settings.stripe_secret_key
    return stripe


# ── Onboarding page ──────────────────────────────────────────────────────────


@router.get("", response_class=HTMLResponse)
async def onboard_page(request: Request):
    """Render the self-serve onboarding page with plan selection."""
    base_url = settings.server_base_url.rstrip("/")
    stripe_checkout_url = f"{base_url}/onboard/create-checkout" if _stripe_enabled() else None

    cards_html = ""
    for tier, plan in PLANS.items():
        price = f"${plan['price_monthly']}/mo" if plan['price_monthly'] > 0 else "Free"
        features_html = "".join(
            f'<li style="padding:4px 0;color:#475467">✓ {f}</li>' for f in plan["features"]
        )
        cards_html += f"""
<div style="background:white;border:1px solid #e4e7ec;border-radius:12px;padding:24px;
            display:flex;flex-direction:column;transition:box-shadow .2s;
            {('border-color:#155eef;box-shadow:0 0 0 1px #155eef' if tier == 'pro' else '')}">
  <h3 style="margin:0 0 4px;font-size:18px">{plan['name']}</h3>
  <p style="margin:0 0 12px;color:#667085;font-size:14px">{plan['description']}</p>
  <div style="font-size:32px;font-weight:700;margin:8px 0 16px">{price}</div>
  <ul style="list-style:none;padding:0;margin:0 0 20px;flex:1">{features_html}</ul>
  <form action="{stripe_checkout_url or '#'}" method="POST" style="margin-top:auto">
    <input type="hidden" name="plan_tier" value="{tier}" />
    <input type="hidden" name="email" id="email_{tier}" />
    <button type="submit"
      style="width:100%;border:0;border-radius:8px;padding:10px 16px;font-weight:600;
             cursor:pointer;
             background:{'#155eef' if tier != 'enterprise' else '#101828'};color:white;
             {('background:transparent;color:#155eef;border:1px solid #d0d5dd' if tier == 'free' else '')}">
      {('Get Started' if tier != 'free' else 'Start Free')}
    </button>
  </form>
</div>"""

    stripe_section = ""
    if not _stripe_enabled():
        stripe_section = """
<div style="background:#fef3f2;border:1px solid #fecdca;border-radius:8px;padding:16px;margin-bottom:24px">
  <strong>⚠️ Billing not configured.</strong>
  Set <code>STRIPE_SECRET_KEY</code> to enable paid plans. 
  Without it, only manual/local onboarding is available.
</div>"""

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Loystar MCP — Onboard</title>
  <style>
    body {{ margin:0; font-family:Inter,Segoe UI,Arial,sans-serif; background:#f6f7f9; color:#18202f; }}
    .container {{ max-width:1000px; margin:0 auto; padding:40px 24px; }}
    h1 {{ font-size:28px; margin:0 0 8px }}
    .subtitle {{ color:#667085; font-size:16px; margin:0 0 32px }}
    .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:20px }}
    label {{ display:block; font-size:13px; font-weight:600; margin:16px 0 6px }}
    input {{ box-sizing:border-box; width:100%; max-width:400px; border:1px solid #cfd4dc;
             border-radius:6px; padding:10px; font:inherit }}
    footer {{ margin-top:48px; text-align:center; color:#98a2b3; font-size:13px }}
  </style>
</head>
<body>
  <div class="container">
    <h1>🚀 Deploy Loystar for Your AI</h1>
    <p class="subtitle">Choose a plan, connect your Loystar account, and get your MCP server URL — no team needed.</p>
    {stripe_section}
    <div style="margin-bottom:24px">
      <label for="onboard_email">Your email address</label>
      <input id="onboard_email" type="email" placeholder="you@example.com"
             oninput="document.querySelectorAll('[id^=email_]').forEach(e=>e.value=this.value)" />
    </div>
    <div class="grid">{cards_html}</div>
    <footer>
      <p>Already have a subscription? <a href="/onboard/manage" style="color:#155eef">Manage your plan</a></p>
      <p style="margin-top:8px">🔒 Powered by Stripe. Your payment info is processed securely by Stripe.</p>
    </footer>
  </div>
</body>
</html>"""


# ── Stripe Checkout ──────────────────────────────────────────────────────────


@router.post("/create-checkout")
async def create_checkout(
    request: Request,
    plan_tier: str = "pro",
    email: str = "",
):
    """Create a Stripe Checkout Session and redirect the merchant."""
    if not _stripe_enabled():
        raise HTTPException(status_code=400, detail="Stripe billing is not configured")

    if plan_tier not in PLANS:
        raise HTTPException(status_code=400, detail=f"Unknown plan: {plan_tier}")

    stripe = _get_stripe()
    base_url = settings.server_base_url.rstrip("/")

    # For free plan, skip Stripe and create directly
    if plan_tier == "free" or not PRICE_IDS.get(plan_tier):
        return await _create_free_subscription(request, email=email, plan_tier=plan_tier)

    try:
        checkout_session = stripe.checkout.Session.create(
            customer_email=email or None,
            mode="subscription",
            line_items=[{"price": PRICE_IDS[plan_tier], "quantity": 1}],
            success_url=f"{base_url}/onboard/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{base_url}/onboard",
            metadata={"plan_tier": plan_tier, "email": email or ""},
        )
        return RedirectResponse(checkout_session.url, status_code=303)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


async def _create_free_subscription(
    request: Request,
    email: str,
    plan_tier: str = "free",
) -> Dict[str, Any]:
    """Create a free subscription directly without Stripe."""
    plan = PLANS[plan_tier]
    merchant_email = email or f"merchant_{secrets.token_hex(4)}@example.com"

    mcp_url = f"{settings.server_base_url.rstrip('/')}/mcp"

    try:
        async with get_db_context() as db:
            from src.models import MerchantSubscription

            sub = MerchantSubscription(
                merchant_email=merchant_email,
                plan_tier=plan_tier,
                status="active",
                mcp_server_url=mcp_url,
                rate_limit_requests=plan["rate_limit_requests"],
                max_merchants=plan["max_merchants"],
                current_period_start=datetime.now(timezone.utc),
                current_period_end=datetime.now(timezone.utc),
            )
            db.add(sub)
            # get_db_context() auto-commits on clean exit

        return {
            "success": True,
            "plan": plan_tier,
            "mcp_server_url": mcp_url,
            "message": "Free subscription created! Use the MCP URL below to connect any AI platform.",
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to create subscription: {e}")


# ── Stripe Webhook ───────────────────────────────────────────────────────────


@router.post("/stripe-webhook")
async def stripe_webhook(request: Request):
    """Handle Stripe webhook events for subscription lifecycle."""
    if not _stripe_enabled():
        return {"received": True, "ignored": True}
    if not settings.stripe_webhook_secret:
        raise HTTPException(status_code=503, detail="Stripe webhook is not configured")

    stripe = _get_stripe()
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, settings.stripe_webhook_secret
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid signature")

    event_type = event.get("type")
    data = event.get("data", {}).get("object", {})

    if event_type == "checkout.session.completed":
        await _handle_checkout_completed(data)
    elif event_type == "customer.subscription.updated":
        await _handle_subscription_updated(data)
    elif event_type == "customer.subscription.deleted":
        await _handle_subscription_deleted(data)
    elif event_type == "invoice.payment_succeeded":
        await _handle_payment_succeeded(data)
    elif event_type == "invoice.payment_failed":
        await _handle_payment_failed(data)

    return {"received": True, "event": event_type}


async def _handle_checkout_completed(session: Dict[str, Any]) -> None:
    """Process a completed Stripe checkout session."""
    customer_id = session.get("customer")
    subscription_id = session.get("subscription")
    metadata = session.get("metadata", {})
    plan_tier = metadata.get("plan_tier", "pro")
    email = metadata.get("email") or session.get("customer_details", {}).get("email", "")

    plan = PLANS.get(plan_tier, PLANS["pro"])
    mcp_url = f"{settings.server_base_url.rstrip('/')}/mcp"

    async with get_db_context() as db:
        from sqlalchemy import select

        result = await db.execute(
            select(MerchantSubscription).where(MerchantSubscription.merchant_email == email)
        )
        sub = result.scalar_one_or_none()

        if sub:
            sub.stripe_customer_id = customer_id
            sub.stripe_subscription_id = subscription_id
            sub.stripe_price_id = metadata.get("price_id")
            sub.plan_tier = plan_tier
            sub.status = "active"
            sub.mcp_server_url = mcp_url
            sub.rate_limit_requests = plan["rate_limit_requests"]
            sub.max_merchants = plan["max_merchants"]
        else:
            from src.models import MerchantSubscription
            import uuid

            db.add(MerchantSubscription(
                merchant_email=email,
                stripe_customer_id=customer_id,
                stripe_subscription_id=subscription_id,
                plan_tier=plan_tier,
                status="active",
                mcp_server_url=mcp_url,
                rate_limit_requests=plan["rate_limit_requests"],
                max_merchants=plan["max_merchants"],
            ))


async def _handle_subscription_updated(subscription: Dict[str, Any]) -> None:
    """Sync subscription status updates."""
    sub_id = subscription.get("id")
    status = subscription.get("status", "active")
    cancel_at_period_end = subscription.get("cancel_at_period_end", False)

    async with get_db_context() as db:
        from sqlalchemy import select

        result = await db.execute(
            select(MerchantSubscription).where(
                MerchantSubscription.stripe_subscription_id == sub_id
            )
        )
        sub = result.scalar_one_or_none()
        if sub:
            sub.status = status
            sub.cancel_at_period_end = cancel_at_period_end


async def _handle_subscription_deleted(subscription: Dict[str, Any]) -> None:
    """Mark subscription as canceled."""
    sub_id = subscription.get("id")
    async with get_db_context() as db:
        from sqlalchemy import select

        result = await db.execute(
            select(MerchantSubscription).where(
                MerchantSubscription.stripe_subscription_id == sub_id
            )
        )
        sub = result.scalar_one_or_none()
        if sub:
            sub.status = "canceled"
            sub.cancel_at_period_end = False


async def _handle_payment_succeeded(invoice: Dict[str, Any]) -> None:
    """Handle successful payment."""
    sub_id = invoice.get("subscription")
    period_start = invoice.get("period_start")
    period_end = invoice.get("period_end")

    if not sub_id:
        return

    async with get_db_context() as db:
        from sqlalchemy import select

        result = await db.execute(
            select(MerchantSubscription).where(
                MerchantSubscription.stripe_subscription_id == sub_id
            )
        )
        sub = result.scalar_one_or_none()
        if sub:
            sub.status = "active"
            if period_start:
                sub.current_period_start = datetime.fromtimestamp(period_start, tz=timezone.utc)
            if period_end:
                sub.current_period_end = datetime.fromtimestamp(period_end, tz=timezone.utc)


async def _handle_payment_failed(invoice: Dict[str, Any]) -> None:
    """Handle failed payment — mark subscription past_due."""
    sub_id = invoice.get("subscription")
    if not sub_id:
        return

    async with get_db_context() as db:
        from sqlalchemy import select

        result = await db.execute(
            select(MerchantSubscription).where(
                MerchantSubscription.stripe_subscription_id == sub_id
            )
        )
        sub = result.scalar_one_or_none()
        if sub:
            sub.status = "past_due"


# ── Success / Manage Pages ───────────────────────────────────────────────────


@router.get("/success", response_class=HTMLResponse)
async def onboard_success(session_id: str = ""):
    """Show onboarding success page with MCP URL."""
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>🎉 Loystar MCP — Connected!</title>
  <style>
    body {{ margin:0; font-family:Inter,Segoe UI,Arial,sans-serif; background:#f6f7f9; color:#18202f; }}
    .container {{ max-width:600px; margin:10vh auto; padding:40px 24px; text-align:center }}
    .card {{ background:white; border:1px solid #e4e7ec; border-radius:12px; padding:32px }}
    h1 {{ font-size:28px; margin:0 0 8px }}
    .url-box {{ background:#f9fafb; border:1px solid #d0d5dd; border-radius:8px;
               padding:16px; font-family:monospace; font-size:14px; word-break:break-all;
               margin:20px 0; user-select:all }}
    .step {{ background:#f0fdf4; border:1px solid #bbf7d0; border-radius:8px; padding:16px;
            margin:16px 0; text-align:left }}
    code {{ background:#f2f4f7; padding:2px 6px; border-radius:4px; font-size:13px }}
    button {{ border:0; background:#155eef; color:white; border-radius:8px; padding:12px 24px;
             font-weight:600; cursor:pointer; margin-top:16px }}
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <h1>🎉 Your MCP Server is Ready!</h1>
      <p style="color:#667085;margin:0 0 24px">
        Your server is deployed and your subscription is active. Here's how to connect any AI platform:
      </p>

      <div style="text-align:left;margin-bottom:20px">
        <p style="font-size:13px;font-weight:600;margin:0 0 6px">🔗 Your MCP Server URL</p>
        <div class="url-box">{settings.server_base_url}/mcp</div>
      </div>

      <div class="step">
        <strong>Step 1:</strong> Copy the URL above
      </div>
      <div class="step">
        <strong>Step 2:</strong> Open <strong>ChatGPT</strong> → Settings → Developer → MCP Servers → Add Server<br>
        <span style="color:#98a2b3;font-size:13px">Or Claude Desktop → Settings → Developer → MCP Servers</span>
      </div>
      <div class="step">
        <strong>Step 3:</strong> Paste the URL, sign in with your Loystar account when prompted
      </div>
      <div class="step">
        <strong>Step 4:</strong> Start asking questions!<br>
        <span style="color:#98a2b3;font-size:13px">"Show my sales" · "List my customers" · "What's my SMS balance?"</span>
      </div>

      <p style="margin-top:24px">
        <a href="{settings.server_base_url}/demo" style="color:#155eef;font-weight:600">
          Or try the live demo →</a>
      </p>
    </div>
  </div>
</body>
</html>"""


@router.get("/manage", response_class=HTMLResponse)
async def manage_subscription():
    """Placeholder for subscription management page."""
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Manage Subscription — Loystar MCP</title>
  <style>
    body {{ margin:0; font-family:Inter,Segoe UI,Arial,sans-serif; background:#f6f7f9; color:#18202f; }}
    .container {{ max-width:600px; margin:10vh auto; padding:40px 24px; text-align:center }}
    .card {{ background:white; border:1px solid #e4e7ec; border-radius:12px; padding:32px }}
    h1 {{ font-size:24px; margin:0 0 12px }}
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <h1>🔧 Subscription Management</h1>
      <p style="color:#667085">Manage your plan, billing, and Loystar connection.</p>
      <p style="margin-top:16px">
        <em>Subscription management coming soon. For now, contact support to change your plan.</em>
      </p>
    </div>
  </div>
</body>
</html>"""


@router.get("/plans")
async def list_plans():
    """List available plans and pricing."""
    return {
        "plans": {
            tier: {
                "name": plan["name"],
                "description": plan["description"],
                "price_monthly": plan["price_monthly"],
                "rate_limit_requests": plan["rate_limit_requests"],
                "max_merchants": plan["max_merchants"],
            }
            for tier, plan in PLANS.items()
        }
    }
