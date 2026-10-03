# TZ Solutions Inventory

## Run locally

1. Install Node.js 20 or newer.
2. Run `npm.cmd install` in this folder.
3. Copy `.env.example` to `.env` and fill in Gmail settings and the role accounts you need.
4. Run `npm.cmd start`.
5. Open `http://127.0.0.1:3000`.

## Gmail setup

Use a Gmail account authorized to send vendor notices. Enable 2-Step Verification on the Google account, then create an App Password in Google Account security settings. Put the generated App Password in `GMAIL_APP_PASSWORD` in the local `.env` file. Never commit or share `.env`.

The server checks synced inventory immediately and then at the configured interval. It sends a vendor email when an in-stock product reaches 15 days or fewer until expiry, and sends a second notice if it becomes expired. Each product, expiry date, and alert state is sent once. Products with missing vendor emails or placeholder `.example` addresses are skipped. Failed sends are retried on the next check.

This is a local role-authenticated app. The server binds only to `127.0.0.1`; do not expose it to a network without HTTPS, secure cookie settings, and deployment security.

## Role-based sign-in

Configure `ADMIN_EMAIL` and `ADMIN_PASSWORD` to enable the Administrator account. Configure `MANAGER_EMAIL`/`MANAGER_PASSWORD` and `STAFF_EMAIL`/`STAFF_PASSWORD` to enable those roles. Each role signs in with its matching email, password, and role selection. Use unique, strong passwords; credentials stay in `.env` and are checked by the local server.

The Administrator can open every module. Managers can access workspace modules except Users & Roles. Staff can access Overview, Products, Stock In, Stock Out, and Sales. Sessions expire after eight hours or when the server restarts. The app requires the localhost URL; the `file://` page does not authenticate or synchronize data.

## Deploy to Netlify

1. Rotate any credentials that have been shared, then connect this repository to Netlify or deploy it with the Netlify CLI.
2. Keep the build command blank. `netlify.toml` sets the publish directory and Functions directory.
3. Add `GMAIL_USER`, `GMAIL_APP_PASSWORD`, `MAIL_FROM`, and the `ADMIN_*`, `MANAGER_*`, and `STAFF_*` account variables in the Netlify site's environment-variable settings. Use new, unique passwords; never upload `.env`.
4. Deploy to production. Netlify Blobs stores inventory, sessions, sent-email deduplication, and authentication audit events. The scheduled function checks expiry alerts hourly on published deploys.

Netlify is a separate deployment: local `data/inventory.json` is excluded and is not migrated automatically. The hosted site starts with its own Netlify Blobs store and browser-local data. Import or recreate production inventory after first sign-in; use the hosted URL for all future edits.
