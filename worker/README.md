# NORISKLIFE enquiry API (staged deployment)

This is a separate Cloudflare Worker so the existing public website is not replaced while the backend is prepared.

## What it provides
- D1-backed private enquiry records.
- Public enquiry endpoint: POST /api/enquiries.
- Private admin page: /admin.
- Password-protected admin login with an eight-hour signed session token.
- Admin enquiry listing and status changes (New / Contacted / Closed).
- Basic per-IP rate limits using hashed IP-derived keys; raw IP addresses are not stored.
- Optional Resend email notification to the configured MAIL_TO address.

## Before deployment
1. Create a Cloudflare D1 database named `norisklife-enquiries`.
2. Apply `schema.sql` to that database.
3. Put the resulting database ID in `wrangler.toml`.
4. Set ALLOWED_ORIGIN to the exact HTTPS origin of the preview website (origin only; no trailing slash or path).
5. Set MAIL_FROM to an address on a domain verified with Resend. MAIL_TO is already set to insurdasset@gmail.com.
6. Add these Worker secrets using the Cloudflare dashboard:
   - ADMIN_PASSWORD: a unique, strong password (do not reuse your GitHub password).
   - SESSION_SECRET: a long random secret (at least 32 random characters).
   - RESEND_API_KEY: optional until email sending is configured.
7. Deploy this Worker separately from the existing website and test /health and /admin.

## Important
- Do not activate public enquiry collection until insurer/compliance approvals and the final privacy notice are confirmed.
- Do not enter real personal data during testing until the service is secured and approved.
- The Worker never returns enquiry records from the public endpoint.
- The admin API uses bearer tokens held in sessionStorage in the admin browser tab; sign out when finished and use a private device only.
- Configure a verified sender address before expecting email notifications. The recipient is insurdasset@gmail.com.
