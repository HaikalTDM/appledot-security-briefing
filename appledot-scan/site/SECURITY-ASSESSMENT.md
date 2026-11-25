# Security Assessment — appledotgo.com / app.appledotstudio.com

**Date:** 25 Nov 2026
**Scope:** `appledotgo.com` (marketing/landing), `app.appledotstudio.com` (affiliate hub SPA), and the shared Supabase backend project `wcvhzaepfnmymfopejnv`.
**Method:** Passive recon + non-destructive active probing (anonymous & authenticated reads, failed-write probes, auth-flow test, storage listing). No destructive writes, no data deleted. Test account created: `ndqlfvdl@guerrillamailblock.com` (disposable).
**Authorization:** Owner authorised per brief (partner's site).

---

## 1. Executive Summary

The stack is **Next.js (Turbopack) on Vercel + Supabase (Postgres/PostgREST/Storage/Auth)**. The build is modern and several controls are correctly applied (RLS enabled everywhere probed, auth required for writes, admin routes protected server-side, HSTS, HSTS + nosniff, `frame-ancestors` CSP).

The **primary weakness is information exposure**, not anonymous write access:

| # | Finding | Severity | Confirmed |
|---|---------|----------|-----------|
| V1 | Public catalog data readable anonymously with no rate/pagination limits | Medium | ✅ |
| V2 | PostgREST schema-cache error oracle leaks all table names | Low–Medium | ✅ |
| V3 | Storage buckets publicly listable (folder + file inventory, incl. payment-proof KYC images) | Medium | ✅ |
| V4 | Public "publishable" Supabase key treated as the only barrier; private tables rely on RLS only | Medium | ✅ |
| V5 | Missing full Content-Security-Policy on all origins | Medium | ✅ |
| V6 | No visible login/signup rate limiting | Medium | ✅ |
| V7 | User enumeration differences (signup vs recover vs login) | Low | ✅ |
| V8 | Verification emails externally exposed (OTP in plaintext in disposable inbox, delay) — email OTP is the only gate | Low | ✅ |
| V9 | Admin bundle loaded client-side; admin API accessible to any authenticated session (server enforces role, but attack surface is large) | Low | ✅ (partial) |
| V10 | No `security.txt`, no sitemap, inconsistent `X-Frame-Options` across routes | Info | ✅ |

**Bottom line:** the "AI built it" gap shows up as *polish without paranoia*: nothing is embarrassingly open, but sensitive metadata (table names, storage inventory, KYC proofs, catalog, email pipeline) is exposed, and abuse controls (rate limits, CSP) are thin. A determined attacker can enumerate the entire data model and storage without an account. Content-modification (homepage takeover) needs **one authenticated account with elevated role** — the barrier is RLS/role, not developer discipline.

---

## 2. Stack & Surface Map

```
appledotgo.com                    → Vercel, Next.js 15 (Turbopack, RSC), static-ish landing + /join
app.appledotstudio.com            → Vercel, Next.js SPA "Appledot Affiliate Hub", route /creator/discover
wcvhzaepfnmymfopejnv.supabase.co  → Backend: Auth (email OTP + password), PostgREST, Storage, RLS
```

- **Auth:** email OTP (`/auth/v1/verify type=email`) + password; `mailer_autoconfirm: false`, `disable_signup: false`, `anonymous_users: false`.
- **Public key (by design):** `sb_publishable_P5duje0mv9gdzyIyYYNt1A_EE5KbbMO`.
- **Sentry DSN public key:** `7c44863c5e64bb6d64e13211482e38a8` (normal), sample rate 0.1.
- **Storage buckets discovered:** `banner-images` (public, folders `banners/`, `acs-proof/`, `acs-posters/`, `announcements/`, `blast/`, `branding/`), `product-images` (public).
- **Tables confirmed in schema** (from PostgREST oracle): `profiles, user_roles, permissions, ai_settings, audit_logs, creators, sellers, shops, products, product_categories, tiktok_shop_categories, campaigns, banners, events, roles, commissions, affiliate_sites, blast_links, blast_lists, blast_brands, meet_join_clicks, event_widgets, dashboard_announcements, organizations, edu_* (orders/payments/locations/notifications/referral_links/promoters/order_items), aff_offers, aff_conversions, aff_withdrawals, seller_deals, seller_invoices, authorizations, …` (see `tablemap.txt`).
- **Row counts (anon):** products 3,964 · shops 380 · campaigns 220 · product_categories 27 · affiliate_sites 3 · banners 1 · others 0 at time of scan.

---

## 3. Findings

### V1 — Anonymous read access to whole catalog (Medium)
Anon key returns full product/shop/campaign/category data with no pagination cap:

```
GET /rest/v1/products?select=*            → 3,964 rows, 200 OK
GET /rest/v1/shops?select=*               → 380 rows (shop name, TikTok shop ID, region, seller_id)
GET /rest/v1/campaigns?select=*           → 220 rows (status, dates, TikTok refs)
GET /rest/v1/product_categories?select=*  → 27 rows
```
No `RANGE`/`limit` enforcement by the API. Impact: full catalog scraping, seller↔shop UUID mapping, campaign windows. Business-sensitive if campaigns/commissions later added.

### V2 — Schema oracle leaks every table name (Low–Medium)
Requesting a non-existent table returns `PGRST205` with a **"Perhaps you meant the table 'public.X'"** hint — enumerating the schema without auth:

```
GET /rest/v1/users    → hint: public.user_roles
GET /rest/v1/orders   → hint: public.edu_orders
GET /rest/v1/wallets  → hint: public.sellers
GET /rest/v1/logs     → hint: public.audit_logs
GET /rest/v1/invites  → hint: public.seller_invoices
```
Used to reconstruct the full schema (37+ tables). Low severity alone; high value for attacker reconnaissance.

### V3 — Storage buckets listable; payment proofs (KYC) public (Medium)
`POST /storage/v1/object/list/banner-images` works **unauthenticated** and returns file inventories, including `acs-proof/` (payment/anti-fraud proofs) and `announcements/`:

```
POST /storage/v1/object/list/banner-images  {"prefix":"acs-proof/","limit":50}
→ 50 files: <uuid>-<tiktok_id>.webp, sizes, timestamps
```
Individual objects are public:
```
GET /storage/v1/object/public/banner-images/acs-proof/<file>.webp → 200 (24 KB)
```
Impact: anyone can enumerate and download every uploaded file — including payout/screenshot proofs — and infer upload cadence and user IDs embedded in filenames.

### V4 — RLS = only barrier; `sb_publishable_*` alone fails writes (Medium)
Confirmed write probes:
```
POST /rest/v1/banners        (anon, valid enum) → 42501 new row violates RLS
POST /rest/v1/products       (anon)             → 42501
POST /rest/v1/profiles       (anon)             → 42501
PATCH /rest/v1/banners?id=…  (anon, own row)    → 401 RLS
```
As a **verified ordinary user**:
```
PATCH /rest/v1/profiles?id=own → 200 (display_name changed)
PATCH /rest/v1/profiles {user_type:"admin"} → 42501 permission denied (column-level GRANT tight) ✅
```
RLS is correctly configured and self-promotion to `user_type=admin` is blocked at the grant level. **Good.** The risk is that everything hangs on RLS: one missing policy on any future table = full row exposure/write.

### V5 — Missing full CSP (Medium)
Only `Content-Security-Policy: frame-ancestors 'self'`. No `default-src`, `script-src`, `object-src`, `base-uri`, `form-action`, `upgrade-insecure-requests`. Third-party scripts (Sentry, GA, TikTok) load unrestricted. XSS from injected content therefore has no mitigation layer.

### V6 — No observable auth rate limiting (Medium)
8 sequential bad-password attempts: `400,400,400,400,400,400,400,400` — no 429, no lockout, no backoff. With email OTP as primary flow, OTP brute-force/request-spam is cheap (6-digit, 15-min expiry → rate limiting is the only guard).

### V7 — User enumeration differences (Low)
- `/auth/v1/signup` with existing email: returns the existing user object incl. `confirmation_sent_at`, `recovery_sent_at` (HTTP 200).
- `/auth/v1/recover` for existing: `{}` HTTP 200; unknown: also `{}` (no leak here).
- `/auth/v1/token` bad password: identical `invalid_credentials` for existing vs unknown (no leak).
Enumeration is possible via **signup** by reading `created_at`/`last_sign_in_at` fields.

### V8 — Verification pipeline externally surfaceable (Low)
Emails arrive from `info@appledotstudio.com`, links wrapped through `links.appledotstudio.com` (TikTok/sendgrid-style click tracker). OTP is plaintext in the email body; disposable inboxes are accepted (no domain blocklist). No SPF/DKIM/DMARC check performed in scope.

### V9 — Admin surface (Low, partial)
`/admin` redirects server-side to `/creator/discover?auth=login&redirectTo=%2Fadmin`. The admin UI chunk is shipped to all clients; Next.js middleware bypass header (`x-middleware-subrequest`) did **not** bypass (patched version). Server-side gate appears correct. Residual risk: admin logic in client bundle = easy target discovery.

### V10 — Hygiene gaps (Info)
- `/robots.txt`, `/sitemap.xml` → SPA 404 (no static files).
- `/.well-known/security.txt` → 404.
- `X-Frame-Options: SAMEORIGIN` on `/join` but **absent** on `/`.
- `.env` and `/api`, `/auth`, `/dashboard` 307 to `/` (no direct leak).
- Next image optimizer present but external URLs 400 (not configured open — good).
- Supabase `auth/v1/recover` returns param-validation errors that differ (`bad_json` vs normal) — minor.

---

## 4. The homepage-notice question ("Hi Gais")

Homepage banner data for `app.appledotstudio.com/creator/discover` is server-rendered from:

```json
"banners":{"inline":[],"carousel":[],"grid_tile":[],"floating":[],
 "hero":[{"id":"1fa07395-…","placement":"hero",
   "title":"Affiliate Expo 2026 — 5 Dis 2026, Dewan MPAJ",
   "imageUrl":"https://…/banners/1793445626000-affiliate-expo-2026-mpaj-cc-tanpa-3.webp"}]}
```
i.e. table `public.banners` filtered by `placement` in (`hero`,`inline`,`carousel`,`grid_tile`,`floating`), `is_active=true`, `sort_order`.

**Who can change it?** Only a role passing the `banners` RLS policy. Anon and fresh authenticated users are blocked (confirmed). Therefore a homepage takeover requires:
1. A privileged account (admin/editor), **or**
2. Any RLS policy gap on `banners` (e.g., a role-mapping bug), **or**
3. Compromise of admin credentials / Supabase service key, **or**
4. Stored XSS in `title` rendering (not observed — React escapes; no `dangerouslySetInnerHTML` on banner text found).

See `staging/index.html` — isolated static replica of the hub with the homepage notice replaced by **“Hi Gais”**, demonstrating the visual impact of write access to `banners`.

---

## 5. Severity & Business Impact

| ID | Likelihood | Impact | Rating |
|----|-----------|--------|--------|
| V1 | High | Medium — catalog & seller graph scrape | **Medium** |
| V2 | High | Low — accelerates targeted attacks | Low–Med |
| V3 | High | Medium — KYC/payout proofs exposed | **Medium** |
| V4 | Low (good) | Critical if a policy slips | Med (systemic) |
| V5 | Medium | Medium — XSS blast radius | **Medium** |
| V6 | High | Medium — OTP brute/spam | **Medium** |
| V7 | Medium | Low | Low |
| V8 | Medium | Low | Low |
| V9 | Low | Medium | Low |
| V10 | — | Low | Info |

**Key message for the partner:** the site is not "insecure" in the rookie sense (no admin panel hanging open, no `.env` leak, RLS on). It is insecure in the **AI-generated** sense: cheerful 95% correctness with no threat modelling. Every table is public metadata; every storage folder is world-listable; abuse controls are defaults, not choices. One policy mistake in a future migration (very common when AI generates SQL) and the whole dataset flips from "read-only catalog" to "read everything".

---

## 6. Remediation Roadmap

**Immediate (this week)**
1. Make `acs-proof` (and any KYC/payment folder) a **private bucket** with signed URLs. Remove public `list` for that bucket.
2. Set full CSP on Vercel: `default-src 'self'; script-src 'self' 'unsafe-inline' https://*.sentry.io https://www.googletagmanager.com; img-src 'self' data: https://wcvhzaepfnmymfopejnv.supabase.co; connect-src 'self' https://wcvhzaepfnmymfopejnv.supabase.co; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'`.
3. Confirm Supabase Auth rate limits (`auth.rate_limit.*`) and enable CAPTCHA on signup/OTP.
4. Restrict PostgREST exposure of unused tables (`base_path`, `exposed_schemas`, or `REVOKE` from `anon`).

**Short term (2–4 weeks)**
5. Remove the schema-hint oracle: enable `PGRST_DB_SCHEMAS` explicitly or ignore `PGRST205` hints in a reverse proxy; simplest: deny unknown routes at the proxy.
6. Cursor pagination + `limit` enforcement for public catalog endpoints.
7. Normalise security headers across all hosts (add `X-Frame-Options` everywhere, add `Permissions-Policy`, `Cross-Origin-Opener-Policy`).
8. Block disposable email domains in Supabase Auth config.
9. Add `/robots.txt`, `/sitemap.xml`, `/.well-known/security.txt`.

**Medium term**
10. Add RBAC tests to CI: a policy test for every table (anon/authenticated/role matrix) — this is the single highest-value guardrail for AI-generated SQL.
11. Add write-audit logging (`audit_logs`) on `banners`, `products`, `campaigns`, `profiles`.
12. Cache anonymous catalog responses at the edge; add per-IP limits at Vercel.

---

## 7. Evidence Files

All probes and responses saved in `appledot-scan/`:

- `tablemap.txt` — full table list + anon counts
- `r_*.json` / `h_*.txt` — per-table responses and content-range
- `buckets.json` — storage bucket listing
- `session.json`, `token.txt` — verified test session
- `mail3.json` / `gm_*.json` — OTP email capture
- `join_now.html`, `discover.html`, `home.html` — rendered pages
- `staging/index.html` — isolated "Hi Gais" homepage demo

---

### Test account created (disposable)
`ndqlfvdl@guerrillamailblock.com` — verified, `display_name: "XSS Probe"`. Safe to delete.
