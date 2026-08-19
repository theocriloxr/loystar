# Loystar MCP Server Local Demo

> Local development only. Production startup requires
> `ENABLE_DEMO_ROUTES=false`.

This guide runs the local demo API for a boss/stakeholder walkthrough.

## 1. Install

Use Python from the project root:

```powershell
cd C:\Users\sammm\Desktop\loystar-mcp-server
python -m pip install -r requirements.txt
```

If your global Python packages are messy, use a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## 2. Run Tests

```powershell
python -m pytest
```

Expected result:

```text
27 passed
```

## 3. Start The Server

Run the app as a package from the project root:

```powershell
python -m uvicorn src.main:app --host 127.0.0.1 --port 8000 --reload
```

Do not run `python src/main.py` for the demo. Package mode keeps imports consistent.

Open:

```text
http://127.0.0.1:8000/docs
```

For the boss demo, also open:

```text
http://127.0.0.1:8000/demo
```

That page acts like the AI host screen. Pick ChatGPT, Claude, Gemini, or Custom Agent, link a real test Loystar account, then ask business questions in plain English.

## 3a. Connect Real Loystar Merchant Data

The MCP server can now call read-only Loystar API endpoints from the public Postman documentation.
For the easiest live demo, use the browser page:

```text
http://127.0.0.1:8000/demo
```

Enter a real Loystar test merchant email/password and click:

```text
Link Loystar Account
```

The server exchanges the login for Loystar session headers, clears the password from the page, and uses those headers for the next AI questions. The password is not stored by this project.

For a command-line or fixed local merchant demo, create a `.env` file from `.env.example` and fill in the merchant session headers:

```powershell
Copy-Item .env.example .env
```

Set these values:

```text
LOYSTAR_API_BASE_URL=https://api.loystar.co
LOYSTAR_API_V1_BASE_URL=https://api1.loystar.co
LOYSTAR_ACCESS_TOKEN=...
LOYSTAR_TOKEN_TYPE=Bearer
LOYSTAR_CLIENT=...
LOYSTAR_UID=merchant@example.com
LOYSTAR_EXPIRY=...
LOYSTAR_REDACT_PII=true
```

Restart the server after editing `.env`.

Check credential status without exposing secrets:

```powershell
$body = @{
  name = 'loystar_auth_status'
  arguments = @{}
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Method Post http://127.0.0.1:8000/mcp/tools/call -ContentType 'application/json' -Body $body
```

Available real Loystar query tools:

```text
loystar_get_customers
loystar_search_customers
loystar_get_sales
loystar_get_orders
loystar_get_products
loystar_get_product_categories
loystar_get_loyalty_programs
loystar_get_business_branches
loystar_get_invoices
loystar_get_sms_balance
loystar_get_current_subscription
```

Example: ask for the merchant's latest sales:

```powershell
$body = @{
  name = 'loystar_get_sales'
  arguments = @{
    from_date = '2025-01-01'
    to_date = '2025-01-31'
    page_number = 1
    page_size = 30
  }
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Method Post http://127.0.0.1:8000/mcp/tools/call -ContentType 'application/json' -Body $body
```

By default, PII-like fields such as email and phone are masked before results are returned to the AI layer.

For hosted AI connectors, you can send the Loystar merchant session per request instead of relying on `.env`:

```powershell
$headers = @{
  'x-loystar-access-token' = '...'
  'x-loystar-client' = '...'
  'x-loystar-uid' = 'merchant@example.com'
  'x-loystar-expiry' = '...'
}

$body = @{
  name = 'loystar_auth_status'
  arguments = @{}
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Method Post http://127.0.0.1:8000/mcp/tools/call -Headers $headers -ContentType 'application/json' -Body $body
```

## 4. Demo Story

Use customer ID:

```text
cust_demo
```

### Health Check

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

### Show Customer Profile

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/v1/customers/cust_demo/profile
```

Talking point: the agent reads customer loyalty state through MCP resources.

### Calculate Churn Risk

```powershell
Invoke-RestMethod -Method Post http://127.0.0.1:8000/api/v1/customers/cust_demo/churn-risk
```

Talking point: the agent detects behavior changes and recommends retention action.

### Create A Safe Coupon

```powershell
$body = @{ discount_percent = 10; expiry_hours = 24; estimated_order_value = 100 } | ConvertTo-Json
Invoke-RestMethod -Method Post http://127.0.0.1:8000/api/v1/customers/cust_demo/coupon -ContentType 'application/json' -Body $body
```

Talking point: low-risk actions can execute autonomously.

### Trigger HITL Guardrail

```powershell
$body = @{ discount_percent = 50; expiry_hours = 24; estimated_order_value = 500; max_uses = 2 } | ConvertTo-Json
Invoke-RestMethod -Method Post http://127.0.0.1:8000/api/v1/customers/cust_demo/coupon -ContentType 'application/json' -Body $body
```

Expected status:

```text
pending_merchant_approval
```

Talking point: high-exposure actions pause for human approval instead of issuing risky discounts.

### Queue A WhatsApp Message

```powershell
$body = @{ customer_id = 'cust_demo'; channel = 'WHATSAPP'; message_body = 'Hi Sarah, here is a loyalty reward picked for you.' } | ConvertTo-Json
Invoke-RestMethod -Method Post http://127.0.0.1:8000/api/v1/customers/cust_demo/message -ContentType 'application/json' -Body $body
```

Talking point: outbound messaging is exposed as an MCP tool and can later connect to WhatsApp/Twilio.

## 5. MCP JSON-RPC Example

```powershell
$body = @{
  jsonrpc = '2.0'
  id = 1
  method = 'tools/call'
  params = @{
    name = 'calculate_churn_risk'
    arguments = @{ customer_id = 'cust_demo' }
  }
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Method Post http://127.0.0.1:8000/mcp/rpc -ContentType 'application/json' -Body $body
```
