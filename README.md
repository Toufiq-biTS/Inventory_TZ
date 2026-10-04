# TZ Solutions Inventory

## Run locally

1. Install Node.js 20 or newer.
2. Run `npm.cmd install` in this folder.
3. Create a local `.env` file and add the Gmail settings and role account variables you need. Keep `.env` local; it is ignored by Git and must not be published.
4. Run `npm.cmd start`.
5. Open `http://127.0.0.1:3000`.

## Gmail setup

Use a Gmail account authorized to send vendor notices. Enable 2-Step Verification on the Google account, then create an App Password in Google Account security settings. Put the generated App Password in `GMAIL_APP_PASSWORD` in the local `.env` file. Never commit or share `.env`.

The server checks synced inventory immediately and then at the configured interval. It sends a vendor email when an in-stock product reaches 15 days or fewer until expiry, and sends a second notice if it becomes expired. Each product, expiry date, and alert state is sent once. Products with missing vendor emails or placeholder `.example` addresses are skipped. Failed sends are retried on the next check.

This is a local role-authenticated app. The server binds only to `127.0.0.1`; do not expose it to a network without HTTPS, secure cookie settings, and deployment security.

## Role-based sign-in

Configure `ADMIN_EMAIL` and `ADMIN_PASSWORD` to enable the built-in TZ Solutions Administrator account. Configure `MANAGER_EMAIL`/`MANAGER_PASSWORD` and `STAFF_EMAIL`/`STAFF_PASSWORD` to enable those built-in roles.

Organizations can also be created from the sign-in page. Signup creates a separate inventory workspace and its first Administrator account. Choose the organization on the sign-in page, then enter the matching role, email, and password. Organization Administrators can create additional Administrator, Manager, and Staff accounts in Users & Roles; set a password of at least 12 characters and share it with the user securely. Organization accounts and workspace inventory are stored by the server, with passwords stored as salted scrypt hashes. Browser-held transactions, bills, and activity are namespaced by organization and synchronized for organization accounts.

The built-in TZ Solutions organization remains available for existing environment-configured accounts and existing inventory data. Use unique, strong passwords; environment credentials stay in `.env` and are checked by the local server.

The Administrator can open every module. Managers can access workspace modules except Users & Roles. Staff can access Overview, Products, Stock In, Stock Out, and Sales. Sessions expire after eight hours or when the server restarts. The app requires the localhost URL; the `file://` page does not authenticate or synchronize data.

## Day-end accounting

Administrators and Managers can close the day once per business date from Day-End. Closing creates a saved snapshot of the Day-wise Stock Report, Day-wise Sells Report, Day-wise Transaction Report, and Day's Basic Accounting Report. Each report is available as a formatted PDF download in the generated daily reports list. Local runs store report snapshots in `data/inventory.json`; Netlify deployments store them with the inventory database.

Fresh browser storage starts with no sample products, sales, vendors, or activity. Existing browser data and the ignored local `data/inventory.json` are not cleared automatically.

## Deploy to Netlify

1. Rotate any credentials that have been shared, then connect this repository to Netlify or deploy it with the Netlify CLI.
2. Keep the build command blank. `netlify.toml` sets the publish directory and Functions directory.
3. Add `GMAIL_USER`, `GMAIL_APP_PASSWORD`, `MAIL_FROM`, and any built-in `ADMIN_*`, `MANAGER_*`, and `STAFF_*` account variables in the Netlify site's environment-variable settings. Organizations may self-register from the sign-in page. Use new, unique passwords; never upload `.env`.
4. Deploy to production. Netlify Blobs stores inventory, sessions, sent-email deduplication, and authentication audit events. The scheduled function checks expiry alerts hourly on published deploys.

Netlify is a separate deployment: local `data/inventory.json` is excluded and is not migrated automatically. The hosted site starts with its own Netlify Blobs store and browser-local data. Import or recreate production inventory after first sign-in; use the hosted URL for all future edits.
