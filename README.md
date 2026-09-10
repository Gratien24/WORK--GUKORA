# WORK GUKORA — Render version

This version uses an Express backend at `/api` and is prepared for Render Web Service deployment.

## Render settings
- Runtime: Node
- Build Command: `npm install`
- Start Command: `npm start`
- Required environment variables: `ADMIN_EMAIL`, `ADMIN_PASSWORD`
- `SESSION_SECRET` can be generated automatically by Render using `render.yaml`.

## Important
The included local JSON data store is suitable for testing/demo deployment. Render free services use an ephemeral filesystem, so production user/transaction data should be moved to a persistent database before real-money use.
