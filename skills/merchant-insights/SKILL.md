---
name: loystar-merchant-insights
description: Analyze an authorized Loystar merchant's live customers, sales, orders, products, loyalty, branches, invoices, SMS balance, or subscription using the Loystar MCP read tools.
---

Use this skill when the user asks about business information stored in their connected Loystar merchant account.

1. Confirm the Loystar connection with `loystar_auth_status` when authorization state is unclear.
2. Select the narrowest read tool that answers the request. Prefer server-side search/date filters over downloading broad datasets.
3. Use pagination deliberately. Start with a small page unless the user asks for a complete export or a wider analysis.
4. State the period, filters, and scope used when summarizing sales, customers, orders, or invoices.
5. Distinguish returned Loystar facts from calculations or interpretations you derive from them.
6. If required data is unavailable from the exposed tools, say what is missing instead of guessing.
7. Do not request or expose Loystar passwords, session headers, OAuth tokens, or other secrets.
8. Respect the server's PII masking. Do not attempt to reconstruct masked customer information.
9. This production integration is read-only. Never claim that a customer, sale, order, product, loyalty program, invoice, or subscription was modified unless a future write tool actually returns a successful result.
10. For consequential business decisions, present the relevant data and assumptions rather than making an unsupported decision on the user's behalf.
