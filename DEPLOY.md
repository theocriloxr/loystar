# Production deployment

The maintained deployment instructions are in [README.md](README.md#deploying).

Do not deploy using the old demo defaults. Production requires PostgreSQL,
Redis, HTTPS, the full `.env.production.example` safety profile, and the secure
OAuth migration for an existing database.

Release gate:

```bash
python -m pytest -q
```

Then verify `/live`, `/health`, both OAuth discovery documents, one complete
authorization-code/PKCE flow, refresh-token rotation, revocation, and one live
Loystar read from every AI client you intend to support.
