import dotenv from 'dotenv';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import nodemailer from 'nodemailer';

dotenv.config();
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const HOST = '127.0.0.1';
const PORT = Number(process.env.PORT || 3000);
const intervalMinutes = Math.max(5, Number(process.env.EXPIRY_CHECK_INTERVAL_MINUTES || 60));
const dataDirectory = path.join(__dirname, 'data');
const inventoryFile = path.join(dataDirectory, 'inventory.json');
const sampleStore = { products: [], vendors: [], sentAlerts: {}, authAudit: [] };
const sessionCookie = 'tz_inventory_session';
const sessionLifetimeMs = 8 * 60 * 60 * 1000;
const sessions = new Map();
const failedLogins = new Map();
const roleAccounts = [
  { role: 'Administrator', email: process.env.ADMIN_EMAIL, password: process.env.ADMIN_PASSWORD, name: process.env.ADMIN_NAME || 'Administrator' },
  { role: 'Manager', email: process.env.MANAGER_EMAIL, password: process.env.MANAGER_PASSWORD, name: process.env.MANAGER_NAME || 'Inventory Manager' },
  { role: 'Staff', email: process.env.STAFF_EMAIL, password: process.env.STAFF_PASSWORD, name: process.env.STAFF_NAME || 'Inventory Staff' }
].filter(account => account.email && account.password);

function readStore() {
  try {
    return { ...sampleStore, ...JSON.parse(fs.readFileSync(inventoryFile, 'utf8')) };
  } catch {
    return { ...sampleStore };
  }
}

let store = readStore();
const gmailConfigured = Boolean(process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD);
const transporter = gmailConfigured ? nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD.replace(/\s/g, '')
  }
}) : null;
let activeCheck;

function persistStore() {
  fs.mkdirSync(dataDirectory, { recursive: true });
  const temporaryFile = `${inventoryFile}.tmp`;
  fs.writeFileSync(temporaryFile, JSON.stringify(store, null, 2), 'utf8');
  fs.renameSync(temporaryFile, inventoryFile);
}

function utcDay(value) {
  const [year, month, day] = value.split('-').map(Number);
  return Date.UTC(year, month - 1, day);
}

function expiryState(product, now = new Date()) {
  if (!product.expiryDate || Number(product.stock) <= 0) return null;
  const remainingDays = Math.floor((utcDay(product.expiryDate) - Date.UTC(now.getFullYear(), now.getMonth(), now.getDate())) / 86400000);
  if (remainingDays < 0) return { name: 'expired', remainingDays };
  if (remainingDays <= 15) return { name: 'upcoming', remainingDays };
  return null;
}

async function checkExpiryAlerts() {
  if (activeCheck) return activeCheck;
  activeCheck = (async () => {
    const result = { configured: gmailConfigured, sent: 0, skipped: 0, failed: 0 };
    if (!transporter) return result;

    for (const product of store.products) {
      const state = expiryState(product);
      if (!state) continue;
      const vendor = store.vendors.find(item => item.name === product.vendor);
      const recipient = String(vendor?.email || '').trim();
      if (!recipient || /\.example$/i.test(recipient)) {
        result.skipped += 1;
        continue;
      }

      const alertKey = `${product.id}:${product.expiryDate}:${state.name}`;
      if (store.sentAlerts[alertKey]) continue;
      const timing = state.name === 'expired'
        ? `expired on ${product.expiryDate}`
        : `expires on ${product.expiryDate} in ${state.remainingDays} day${state.remainingDays === 1 ? '' : 's'}`;
      const contact = vendor.contact ? `Hello ${vendor.contact},` : 'Hello,';
      const text = `${contact}\n\nInventory alert for ${vendor.name}:\n\n${product.name} (${product.id}) has ${timing}. Current stock: ${product.stock}.\n\nPlease review and advise on the appropriate action.\n\nRegards,\nTZ Solutions`;

      try {
        await transporter.sendMail({
          from: process.env.MAIL_FROM || process.env.GMAIL_USER,
          to: recipient,
          subject: `Inventory expiry alert: ${product.name} ${state.name === 'expired' ? 'has expired' : 'expires soon'}`,
          text
        });
        store.sentAlerts[alertKey] = new Date().toISOString();
        persistStore();
        result.sent += 1;
        console.log(`Expiry email sent to ${recipient} for ${product.id} (${state.name}).`);
      } catch (error) {
        result.failed += 1;
        console.error(`Could not send expiry email for ${product.id}: ${error.message}`);
      }
    }
    return result;
  })().finally(() => { activeCheck = null; });
  return activeCheck;
}

function sendJson(response, statusCode, data) {
  response.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  });
  response.end(JSON.stringify(data));
}

function getSession(request) {
  const cookies = String(request.headers.cookie || '').split(';');
  const sessionCookieValue = cookies.map(cookie => cookie.trim()).find(cookie => cookie.startsWith(`${sessionCookie}=`));
  const token = sessionCookieValue?.slice(sessionCookie.length + 1);
  const session = token ? sessions.get(token) : null;
  if (!session) return null;
  if (session.expiresAt <= Date.now()) {
    sessions.delete(token);
    return null;
  }
  return session;
}

function sameSecret(provided, expected) {
  const providedHash = crypto.createHash('sha256').update(String(provided)).digest();
  const expectedHash = crypto.createHash('sha256').update(String(expected)).digest();
  return crypto.timingSafeEqual(providedHash, expectedHash);
}

function setSessionCookie(response, token, maxAge) {
  response.setHeader('Set-Cookie', `${sessionCookie}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}`);
}

function recordAuthEvent(action, user) {
  store.authAudit.unshift({
    id: crypto.randomUUID(),
    action,
    user: user.name,
    role: user.role,
    email: user.email,
    time: new Date().toISOString()
  });
  store.authAudit = store.authAudit.slice(0, 1000);
  persistStore();
}

function readJson(request) {
  return new Promise((resolve, reject) => {
    let body = '';
    request.on('data', chunk => {
      body += chunk;
      if (body.length > 2_000_000) {
        reject(new Error('Inventory payload is too large.'));
        request.destroy();
      }
    });
    request.on('end', () => {
      try { resolve(JSON.parse(body)); } catch { reject(new Error('Invalid JSON payload.')); }
    });
    request.on('error', reject);
  });
}

const server = http.createServer(async (request, response) => {
  const requestUrl = new URL(request.url, `http://${HOST}:${PORT}`);
  if (request.method === 'GET' && requestUrl.pathname === '/api/session') {
    const session = getSession(request);
    return sendJson(response, 200, { authenticated: Boolean(session), user: session?.user || null });
  }
  if (request.method === 'POST' && requestUrl.pathname === '/api/login') {
    try {
      const payload = await readJson(request);
      const address = String(payload.email || '').trim().toLowerCase();
      const requestedRole = String(payload.role || '');
      const attemptKey = request.socket.remoteAddress || 'local';
      const attempt = failedLogins.get(attemptKey);
      if (attempt?.lockedUntil > Date.now()) return sendJson(response, 429, { error: 'Too many failed attempts. Try again in five minutes.' });
      const account = roleAccounts.find(item => item.role === requestedRole && item.email.toLowerCase() === address);
      if (!account || !sameSecret(payload.password || '', account.password)) {
        const previousCount = attempt?.lockedUntil && attempt.lockedUntil <= Date.now() ? 0 : (attempt?.count || 0);
        const count = Math.min(previousCount + 1, 5);
        failedLogins.set(attemptKey, { count, lockedUntil: count >= 5 ? Date.now() + 5 * 60 * 1000 : 0 });
        return sendJson(response, 401, { error: 'Email, password, or role did not match.' });
      }
      failedLogins.delete(attemptKey);
      const token = crypto.randomBytes(32).toString('base64url');
      const user = { name: account.name, email: account.email, role: account.role };
      sessions.set(token, { user, expiresAt: Date.now() + sessionLifetimeMs });
      recordAuthEvent('User logged in', user);
      setSessionCookie(response, token, Math.floor(sessionLifetimeMs / 1000));
      return sendJson(response, 200, { authenticated: true, user });
    } catch (error) {
      return sendJson(response, 400, { error: error.message });
    }
  }
  if (request.method === 'POST' && requestUrl.pathname === '/api/logout') {
    const session = getSession(request);
    if (session) {
      recordAuthEvent('User logged out', session.user);
      const cookies = String(request.headers.cookie || '').split(';');
      const sessionCookieValue = cookies.map(cookie => cookie.trim()).find(cookie => cookie.startsWith(`${sessionCookie}=`));
      if (sessionCookieValue) sessions.delete(sessionCookieValue.slice(sessionCookie.length + 1));
    }
    setSessionCookie(response, '', 0);
    return sendJson(response, 200, { authenticated: false });
  }
  if (request.method === 'GET' && requestUrl.pathname === '/api/audit/auth') {
    const session = getSession(request);
    if (!session) return sendJson(response, 401, { error: 'Sign in to view authentication activity.' });
    if (!['Administrator', 'Manager'].includes(session.user.role)) return sendJson(response, 403, { error: 'You do not have access to authentication activity.' });
    return sendJson(response, 200, { events: store.authAudit });
  }
  if (request.method === 'GET' && requestUrl.pathname === '/api/status') {
    return sendJson(response, 200, { gmailConfigured, intervalMinutes, loginConfigured: roleAccounts.length > 0, availableRoles: roleAccounts.map(account => account.role) });
  }
  if (request.method === 'PUT' && requestUrl.pathname === '/api/inventory') {
    if (!getSession(request)) return sendJson(response, 401, { error: 'Sign in to synchronize inventory.' });
    try {
      const payload = await readJson(request);
      if (!Array.isArray(payload.products) || !Array.isArray(payload.vendors)) {
        return sendJson(response, 400, { error: 'Products and vendors must be arrays.' });
      }
      store.products = payload.products;
      store.vendors = payload.vendors;
      persistStore();
      const check = await checkExpiryAlerts();
      return sendJson(response, 200, { ok: true, ...check });
    } catch (error) {
      return sendJson(response, 400, { error: error.message });
    }
  }
  if (request.method === 'GET' && (requestUrl.pathname === '/' || requestUrl.pathname === '/index.html')) {
    response.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'same-origin'
    });
    return fs.createReadStream(path.join(__dirname, 'index.html')).pipe(response);
  }
  sendJson(response, 404, { error: 'Not found.' });
});

server.listen(PORT, HOST, () => {
  console.log(`TZ Solutions running at http://${HOST}:${PORT}`);
  if (!gmailConfigured) console.warn('Gmail is not configured. Add GMAIL_USER and GMAIL_APP_PASSWORD to .env, then restart.');
  if (!roleAccounts.length) console.warn('No login accounts configured. Add role account credentials to .env before signing in.');
  checkExpiryAlerts().catch(error => console.error(`Expiry check failed: ${error.message}`));
  setInterval(() => checkExpiryAlerts().catch(error => console.error(`Expiry check failed: ${error.message}`)), intervalMinutes * 60 * 1000);
});
