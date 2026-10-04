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
const sampleStore = { products: [], vendors: [], sentAlerts: {}, authAudit: [], dayEndReports: [], organizations: [], workspaces: {} };
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
    const saved = JSON.parse(fs.readFileSync(inventoryFile, 'utf8'));
    return { ...sampleStore, ...saved, organizations: saved.organizations || [], workspaces: saved.workspaces || {} };
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
const activeChecks = new WeakMap();

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

async function checkExpiryAlerts(workspace = store) {
  const activeCheck = activeChecks.get(workspace);
  if (activeCheck) return activeCheck;
  const check = (async () => {
    const result = { configured: gmailConfigured, sent: 0, skipped: 0, failed: 0 };
    if (!transporter) return result;

    workspace.sentAlerts ||= {};
    for (const product of workspace.products || []) {
      const state = expiryState(product);
      if (!state) continue;
      const vendor = (workspace.vendors || []).find(item => item.name === product.vendor);
      const recipient = String(vendor?.email || '').trim();
      if (!recipient || /\.example$/i.test(recipient)) {
        result.skipped += 1;
        continue;
      }

      const alertKey = `${product.id}:${product.expiryDate}:${state.name}`;
      if (workspace.sentAlerts[alertKey]) continue;
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
        workspace.sentAlerts[alertKey] = new Date().toISOString();
        persistStore();
        result.sent += 1;
        console.log(`Expiry email sent to ${recipient} for ${product.id} (${state.name}).`);
      } catch (error) {
        result.failed += 1;
        console.error(`Could not send expiry email for ${product.id}: ${error.message}`);
      }
    }
    return result;
  })();
  activeChecks.set(workspace, check);
  try {
    return await check;
  } finally {
    activeChecks.delete(workspace);
  }
}

async function checkAllExpiryAlerts() {
  const results = await Promise.all([store, ...Object.values(store.workspaces || {})].map(checkExpiryAlerts));
  return results.reduce((summary, result) => ({
    configured: summary.configured || result.configured,
    sent: summary.sent + result.sent,
    skipped: summary.skipped + result.skipped,
    failed: summary.failed + result.failed
  }), { configured: false, sent: 0, skipped: 0, failed: 0 });
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

function passwordRecord(password) {
  const salt = crypto.randomBytes(16).toString('base64url');
  return { salt, hash: crypto.scryptSync(password, salt, 64).toString('base64url') };
}

function passwordRecordMatches(password, record) {
  const expected = Buffer.from(record.hash, 'base64url');
  const provided = crypto.scryptSync(String(password), record.salt, expected.length);
  return expected.length === provided.length && crypto.timingSafeEqual(provided, expected);
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

function organizationList() {
  store.organizations ||= [];
  if (roleAccounts.length && !store.organizations.some(item => item.id === 'legacy')) {
    store.organizations.unshift({ id: 'legacy', name: 'TZ Solutions', users: [] });
  }
  return store.organizations;
}

function organizationWorkspace(organizationId) {
  if (organizationId === 'legacy') return store;
  store.workspaces ||= {};
  store.workspaces[organizationId] ||= { products: [], vendors: [], sentAlerts: {}, authAudit: [], dayEndReports: [] };
  return store.workspaces[organizationId];
}

function organizationRoles(organization) {
  return [...new Set([
    ...(organization.id === 'legacy' ? roleAccounts.map(account => account.role) : []),
    ...(organization.users || []).map(user => user.role)
  ])];
}

function setSessionCookie(response, token, maxAge) {
  response.setHeader('Set-Cookie', `${sessionCookie}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}`);
}

function recordAuthEvent(action, user) {
  const workspace = organizationWorkspace(user.organizationId || 'legacy');
  workspace.authAudit ||= [];
  workspace.authAudit.unshift({
    id: crypto.randomUUID(),
    action,
    user: user.name,
    role: user.role,
    email: user.email,
    time: new Date().toISOString()
  });
  workspace.authAudit = workspace.authAudit.slice(0, 1000);
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

function validDayEndDate(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const date = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === value;
}

function normalizeDayEndReports(payload, date) {
  const definitions = {
    stock: { title: 'Day-wise Stock Report', filename: `${date}-day-wise-stock-report.pdf` },
    sales: { title: 'Day-wise Sells Report', filename: `${date}-day-wise-sells-report.pdf` },
    transactions: { title: 'Day-wise Transaction Report', filename: `${date}-day-wise-transaction-report.pdf` },
    accounting: { title: "Day's Basic Accounting Report", filename: `${date}-days-basic-accounting-report.pdf` }
  };
  if (!Array.isArray(payload) || payload.length !== Object.keys(definitions).length) return null;
  const reports = [];
  for (const item of payload) {
    const definition = definitions[item?.type];
    if (!definition || reports.some(report => report.type === item.type) || !Array.isArray(item.rows)) return null;
    if (!item.rows.every(row => Array.isArray(row) && row.every(value => ['string', 'number'].includes(typeof value) || value === null))) return null;
    reports.push({ type: item.type, ...definition, rows: item.rows });
  }
  return reports.length === Object.keys(definitions).length ? reports : null;
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
      const organization = organizationList().find(item => item.id === String(payload.organizationId || ''));
      const configuredAccount = organization?.id === 'legacy'
        ? roleAccounts.find(item => item.role === requestedRole && item.email.toLowerCase() === address)
        : null;
      const organizationAccount = organization
        ? (organization.users || []).find(item => item.role === requestedRole && item.email.toLowerCase() === address)
        : null;
      const account = configuredAccount || organizationAccount;
      const passwordValid = configuredAccount
        ? sameSecret(payload.password || '', configuredAccount.password)
        : organizationAccount && passwordRecordMatches(payload.password || '', organizationAccount.password);
      if (!account || !passwordValid) {
        const previousCount = attempt?.lockedUntil && attempt.lockedUntil <= Date.now() ? 0 : (attempt?.count || 0);
        const count = Math.min(previousCount + 1, 5);
        failedLogins.set(attemptKey, { count, lockedUntil: count >= 5 ? Date.now() + 5 * 60 * 1000 : 0 });
        return sendJson(response, 401, { error: 'Email, password, or role did not match.' });
      }
      failedLogins.delete(attemptKey);
      const token = crypto.randomBytes(32).toString('base64url');
      const user = { name: account.name, email: account.email, role: account.role, organizationId: organization.id };
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
    const workspace = organizationWorkspace(session.user.organizationId || 'legacy');
    return sendJson(response, 200, { events: workspace.authAudit || [] });
  }
  if (request.method === 'GET' && requestUrl.pathname === '/api/status') {
    const organizations = organizationList().map(organization => ({
      id: organization.id,
      name: organization.name,
      roles: organizationRoles(organization)
    }));
    return sendJson(response, 200, { gmailConfigured, intervalMinutes, loginConfigured: organizations.some(organization => organization.roles.length), organizations });
  }
  if (request.method === 'POST' && requestUrl.pathname === '/api/organizations') {
    try {
      const payload = await readJson(request);
      const name = String(payload.organizationName || '').trim();
      const userName = String(payload.name || '').trim();
      const email = String(payload.email || '').trim().toLowerCase();
      const password = String(payload.password || '');
      if (name.length < 2 || name.length > 80) return sendJson(response, 400, { error: 'Organization name must be between 2 and 80 characters.' });
      if (userName.length < 2 || userName.length > 80) return sendJson(response, 400, { error: 'Administrator name must be between 2 and 80 characters.' });
      if (!validEmail(email)) return sendJson(response, 400, { error: 'Enter a valid email address.' });
      if (password.length < 12 || password.length > 128) return sendJson(response, 400, { error: 'Password must be between 12 and 128 characters.' });
      const organizations = organizationList();
      if (organizations.some(item => item.name.toLowerCase() === name.toLowerCase())) return sendJson(response, 409, { error: 'An organization with that name already exists.' });
      const organization = {
        id: crypto.randomUUID(),
        name,
        users: [{ id: crypto.randomUUID(), name: userName, email, role: 'Administrator', password: passwordRecord(password) }]
      };
      organizations.push(organization);
      organizationWorkspace(organization.id);
      persistStore();
      return sendJson(response, 201, { organization: { id: organization.id, name: organization.name } });
    } catch (error) {
      return sendJson(response, 400, { error: error.message });
    }
  }
  if (requestUrl.pathname === '/api/users') {
    const session = getSession(request);
    if (!session) return sendJson(response, 401, { error: 'Sign in to manage users.' });
    if (session.user.role !== 'Administrator') return sendJson(response, 403, { error: 'Only Administrators can manage users.' });
    const organization = organizationList().find(item => item.id === (session.user.organizationId || 'legacy'));
    if (!organization) return sendJson(response, 404, { error: 'Organization not found.' });
    if (request.method === 'GET') {
      return sendJson(response, 200, { users: (organization.users || []).map(({ id, name, email, role }) => ({ id, name, email, role })) });
    }
    if (request.method === 'POST') {
      try {
        const payload = await readJson(request);
        const name = String(payload.name || '').trim();
        const email = String(payload.email || '').trim().toLowerCase();
        const password = String(payload.password || '');
        const role = String(payload.role || '');
        if (name.length < 2 || name.length > 80) return sendJson(response, 400, { error: 'User name must be between 2 and 80 characters.' });
        if (!validEmail(email)) return sendJson(response, 400, { error: 'Enter a valid email address.' });
        if (password.length < 12 || password.length > 128) return sendJson(response, 400, { error: 'Password must be between 12 and 128 characters.' });
        if (!['Administrator', 'Manager', 'Staff'].includes(role)) return sendJson(response, 400, { error: 'Choose a valid user role.' });
        organization.users ||= [];
        if (organization.id === 'legacy' && roleAccounts.some(account => account.email.toLowerCase() === email)) {
          return sendJson(response, 409, { error: 'That email is already registered in this organization.' });
        }
        if (organization.users.some(user => user.email.toLowerCase() === email)) return sendJson(response, 409, { error: 'That email is already registered in this organization.' });
        const user = { id: crypto.randomUUID(), name, email, role, password: passwordRecord(password) };
        organization.users.push(user);
        persistStore();
        return sendJson(response, 201, { user: { id: user.id, name, email, role } });
      } catch (error) {
        return sendJson(response, 400, { error: error.message });
      }
    }
    return sendJson(response, 405, { error: 'Method not allowed.' });
  }
  if (requestUrl.pathname === '/api/day-end') {
    const session = getSession(request);
    if (!session) return sendJson(response, 401, { error: 'Sign in to access day-end accounting.' });
    if (!['Administrator', 'Manager'].includes(session.user.role)) return sendJson(response, 403, { error: 'You do not have access to day-end accounting.' });
    const workspace = organizationWorkspace(session.user.organizationId || 'legacy');
    workspace.dayEndReports ||= [];
    if (request.method === 'GET') return sendJson(response, 200, { reports: workspace.dayEndReports });
    if (request.method === 'POST') {
      try {
        const payload = await readJson(request);
        if (!validDayEndDate(payload.date)) return sendJson(response, 400, { error: 'A valid business date is required.' });
        const existing = workspace.dayEndReports.find(report => report.date === payload.date);
        if (existing) return sendJson(response, 409, { error: 'Day-end accounting has already been completed for this date.', report: existing });
        const reports = normalizeDayEndReports(payload.reports, payload.date);
        if (!reports) return sendJson(response, 400, { error: 'Exactly four valid daily reports are required.' });
        const report = { date: payload.date, reports, generatedAt: new Date().toISOString(), generatedBy: session.user.name };
        workspace.dayEndReports.push(report);
        workspace.dayEndReports.sort((left, right) => right.date.localeCompare(left.date));
        persistStore();
        return sendJson(response, 201, { report });
      } catch (error) {
        return sendJson(response, 400, { error: error.message });
      }
    }
    return sendJson(response, 405, { error: 'Method not allowed.' });
  }
  if (requestUrl.pathname === '/api/inventory' && request.method === 'GET') {
    const session = getSession(request);
    if (!session) return sendJson(response, 401, { error: 'Sign in to view inventory.' });
    const workspace = organizationWorkspace(session.user.organizationId || 'legacy');
    return sendJson(response, 200, {
      products: workspace.products || [],
      vendors: workspace.vendors || [],
      transactions: workspace.transactions || [],
      bills: workspace.bills || [],
      audit: workspace.audit || []
    });
  }
  if (request.method === 'PUT' && requestUrl.pathname === '/api/inventory') {
    const session = getSession(request);
    if (!session) return sendJson(response, 401, { error: 'Sign in to synchronize inventory.' });
    try {
      const payload = await readJson(request);
      if (!Array.isArray(payload.products) || !Array.isArray(payload.vendors)) {
        return sendJson(response, 400, { error: 'Products and vendors must be arrays.' });
      }
      for (const key of ['transactions', 'bills', 'audit']) {
        if (payload[key] !== undefined) {
          if (!Array.isArray(payload[key])) return sendJson(response, 400, { error: `${key} must be an array.` });
        }
      }
      const workspace = organizationWorkspace(session.user.organizationId || 'legacy');
      workspace.products = payload.products;
      workspace.vendors = payload.vendors;
      for (const key of ['transactions', 'bills', 'audit']) {
        if (payload[key] !== undefined) workspace[key] = payload[key];
      }
      persistStore();
      const check = session.user.organizationId && session.user.organizationId !== 'legacy'
        ? await checkExpiryAlerts(workspace)
        : await checkExpiryAlerts();
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
  checkAllExpiryAlerts().catch(error => console.error(`Expiry check failed: ${error.message}`));
  setInterval(() => checkAllExpiryAlerts().catch(error => console.error(`Expiry check failed: ${error.message}`)), intervalMinutes * 60 * 1000);
});
