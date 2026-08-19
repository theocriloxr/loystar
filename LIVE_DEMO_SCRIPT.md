# Live Boss Demo Script

> This presents the development demo, not the production connector. Use
> `README.md` for production deployment and client configuration.

Use this script to present the project as a production-minded Loystar AI connector.

## 1. Start With The Product Statement

Say:

```text
This is a Loystar AI connector. It lets Claude, ChatGPT, Gemini, or any custom agent query a merchant's Loystar business data through controlled tools instead of direct database or raw API access.
```

## 2. Run The Test Suite

```powershell
python -m pytest
```

Expected:

```text
27 passed
```

Say:

```text
The tests cover the demo endpoints, Loystar tool discovery, request-scoped merchant credentials, audit logging, API-key protection, and rate limiting.
```

## 3. Start The Server

```powershell
python -m uvicorn src.main:app --host 127.0.0.1 --port 8000 --reload
```

Open:

```text
http://127.0.0.1:8000/docs
```

Also open the AI host simulator:

```text
http://127.0.0.1:8000/demo
```

## 4. Show The Polished Root Endpoint

Open:

```text
http://127.0.0.1:8000/
```

Say:

```text
The server now exposes a connector landing response instead of a 404.
```

## 4a. Show The AI Host Simulator

Open:

```text
http://127.0.0.1:8000/demo
```

Say:

```text
This page simulates mounting Loystar into ChatGPT, Claude, Gemini, or a custom agent. The user asks in plain English, the host chooses a safe MCP tool, and the gateway calls Loystar through controlled credentials.
```

Try these prompts:

```text
What were my sales this month?
Show my latest customers
List my products and inventory
Show unpaid invoices
Which customers look inactive or at churn risk?
```

If live Loystar credentials are available, paste them into the left panel. If not, explain:

```text
Without merchant session headers, the connector still demonstrates mounting, tool selection, audit logging, and guardrails. Live Loystar data appears once a merchant session is provided.
```

If you have a real test merchant email/password, use the left panel:

```text
Loystar email
Loystar password
Link Loystar Account
```

Say:

```text
For this live demo, the connector exchanges the merchant login for Loystar session headers, clears the password, and uses those headers for the next AI questions. In production this should become OAuth or a secure token-exchange flow instead of long-term password handling.
```

## 5. Show Health And Policy

Run:

```text
GET /health
```

Point out:

```text
connector_auth_required
rate_limit
```

Say:

```text
This shows the gateway has operational policy, not just business endpoints.
```

## 6. Show AI Tool Discovery

Run:

```text
GET /mcp/tools
```

Point out:

```text
loystar_get_customers
loystar_get_sales
loystar_get_orders
loystar_get_products
loystar_get_invoices
loystar_get_loyalty_programs
```

Say:

```text
These are the tools an AI platform sees. We are not giving the AI arbitrary Loystar API access.
```

## 7. Show Request-Scoped Merchant Auth

Use:

```text
POST /mcp/tools/call
```

Body:

```json
{
  "name": "loystar_auth_status",
  "arguments": {}
}
```

Then explain the production headers:

```text
x-loystar-access-token
x-loystar-client
x-loystar-uid
x-loystar-expiry
x-loystar-token-type
```

Say:

```text
In production, the connector injects these headers per merchant session. Merchant A and Merchant B can use the same gateway without sharing data.
```

## 8. Show A Loystar Business Query

Use:

```text
POST /mcp/tools/call
```

Body:

```json
{
  "name": "loystar_get_sales",
  "arguments": {
    "from_date": "2025-01-01",
    "to_date": "2025-01-31",
    "page_number": 1,
    "page_size": 30
  }
}
```

If credentials are not configured, say:

```text
The connector is ready, but live Loystar calls require real merchant session headers. This is intentional because we do not hardcode public/example credentials.
```

## 9. Show Audit Logging

Run:

```text
GET /admin/audit/events
```

Say:

```text
Every AI tool call is recorded with tool name, timestamp, client IP, status, and masked merchant identity. Tokens are never logged.
```

## 10. Show Guardrails

Run:

```text
POST /api/v1/customers/cust_demo/coupon
```

High-risk body:

```json
{
  "discount_percent": 50,
  "expiry_hours": 24,
  "estimated_order_value": 500,
  "max_uses": 2
}
```

Expected:

```text
pending_merchant_approval
```

Say:

```text
For read-only questions, the AI can answer quickly. For risky write actions, the system pauses for human approval.
```

## Closing Line

Say:

```text
This is now more than a demo API. It is the foundation for a hosted Loystar AI connector: merchant-scoped credentials, controlled tools, PII redaction, audit logs, rate limits, and HITL guardrails.
```
