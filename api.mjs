import crypto from 'node:crypto';
import {
  createSession,
  deleteSession,
  getSession,
  organizationList,
  organizationRoles,
  organizationWorkspace,
  passwordRecord,
  passwordRecordMatches,
  readDatabase,
  recordAuthentication,
  response,
  roleAccounts,
  sendExpiryEmails,
  sessionCookie,
  validEmail,
  writeDatabase
} from '../lib.mjs';
import { getStore } from '@netlify/blobs';

function routePath(request) {
  const pathname = new URL(request.url).pathname;
  const functionPrefix = '/.netlify/functions/api';
  if (pathname.startsWith(functionPrefix)) return pathname.slice(functionPrefix.length) || '/';
  return pathname.replace(/^\/api(?=\/|$)/, '') || '/';
}

function secureCompare(left, right) {
  const leftHash = crypto.createHash('sha256').update(String(left)).digest();
  const rightHash = crypto.createHash('sha256').update(String(right)).digest();
  return crypto.timingSafeEqual(leftHash, rightHash);
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

async function checkLoginLimit(request) {
  const address = request.headers.get('x-nf-client-connection-ip') || request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown';
  const key = crypto.createHash('sha256').update(address).digest('hex');
  const store = getStore('tz-login-attempts');
  const attempt = await store.get(key, { type: 'json', consistency: 'strong' });
  if (attempt?.lockedUntil > Date.now()) return { blocked: true, key, store, attempt };
  return { blocked: false, key, store, attempt: attempt?.lockedUntil ? null : attempt };
}

export default async request => {
  const route = routePath(request);
  const method = request.method;

  if (method === 'GET' && route === '/status') {
    const database = await readDatabase();
    const organizations = organizationList(database).map(organization => ({
      id: organization.id,
      name: organization.name,
      roles: organizationRoles(organization)
    }));
    return response(200, {
      gmailConfigured: Boolean(process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD),
      loginConfigured: organizations.some(organization => organization.roles.length),
      organizations
    });
  }

  if (method === 'GET' && route === '/session') {
    const session = await getSession(request);
    return response(200, { authenticated: Boolean(session), user: session?.user || null });
  }

  if (method === 'POST' && route === '/login') {
    try {
      const limit = await checkLoginLimit(request);
      if (limit.blocked) return response(429, { error: 'Too many failed attempts. Try again in five minutes.' });
      const payload = await request.json();
      const email = String(payload.email || '').trim().toLowerCase();
      const database = await readDatabase();
      const organization = organizationList(database).find(item => item.id === String(payload.organizationId || ''));
      const role = String(payload.role || '');
      const configuredAccount = organization?.id === 'legacy'
        ? roleAccounts().find(item => item.role === role && item.email.trim().toLowerCase() === email)
        : null;
      const organizationAccount = organization
        ? (organization.users || []).find(item => item.role === role && item.email.toLowerCase() === email)
        : null;
      const account = configuredAccount || organizationAccount;
      const passwordValid = configuredAccount
        ? secureCompare(payload.password || '', configuredAccount.password)
        : organizationAccount && passwordRecordMatches(payload.password || '', organizationAccount.password);
      if (!account || !passwordValid) {
        const count = Math.min((limit.attempt?.count || 0) + 1, 5);
        await limit.store.setJSON(limit.key, { count, lockedUntil: count >= 5 ? Date.now() + 5 * 60 * 1000 : 0 });
        return response(401, { error: 'Email, password, or role did not match.' });
      }
      await limit.store.delete(limit.key);
      const user = { name: account.name, email: account.email, role: account.role, organizationId: organization.id };
      recordAuthentication(database, 'User logged in', user);
      await writeDatabase(database);
      const token = await createSession(user);
      return response(200, { authenticated: true, user }, { 'Set-Cookie': sessionCookie(token, request) });
    } catch (error) {
      console.error(`Login failed: ${error.message}`);
      return response(400, { error: 'Could not complete sign-in.' });
    }
  }

  if (method === 'POST' && route === '/organizations') {
    try {
      const payload = await request.json();
      const name = String(payload.organizationName || '').trim();
      const userName = String(payload.name || '').trim();
      const email = String(payload.email || '').trim().toLowerCase();
      const password = String(payload.password || '');
      if (name.length < 2 || name.length > 80) return response(400, { error: 'Organization name must be between 2 and 80 characters.' });
      if (userName.length < 2 || userName.length > 80) return response(400, { error: 'Administrator name must be between 2 and 80 characters.' });
      if (!validEmail(email)) return response(400, { error: 'Enter a valid email address.' });
      if (password.length < 12 || password.length > 128) return response(400, { error: 'Password must be between 12 and 128 characters.' });
      const database = await readDatabase();
      const organizations = organizationList(database);
      if (organizations.some(item => item.name.toLowerCase() === name.toLowerCase())) return response(409, { error: 'An organization with that name already exists.' });
      const organization = {
        id: crypto.randomUUID(),
        name,
        users: [{ id: crypto.randomUUID(), name: userName, email, role: 'Administrator', password: passwordRecord(password) }]
      };
      organizations.push(organization);
      organizationWorkspace(database, organization.id);
      await writeDatabase(database);
      return response(201, { organization: { id: organization.id, name: organization.name } });
    } catch (error) {
      console.error(`Organization signup failed: ${error.message}`);
      return response(400, { error: 'Could not create organization.' });
    }
  }

  if (route === '/users') {
    const session = await getSession(request);
    if (!session) return response(401, { error: 'Sign in to manage users.' });
    if (session.user.role !== 'Administrator') return response(403, { error: 'Only Administrators can manage users.' });
    const database = await readDatabase();
    const organization = organizationList(database).find(item => item.id === session.user.organizationId);
    if (!organization) return response(404, { error: 'Organization not found.' });
    if (method === 'GET') {
      return response(200, { users: (organization.users || []).map(({ id, name, email, role }) => ({ id, name, email, role })) });
    }
    if (method === 'POST') {
      try {
        const payload = await request.json();
        const name = String(payload.name || '').trim();
        const email = String(payload.email || '').trim().toLowerCase();
        const password = String(payload.password || '');
        const role = String(payload.role || '');
        if (name.length < 2 || name.length > 80) return response(400, { error: 'User name must be between 2 and 80 characters.' });
        if (!validEmail(email)) return response(400, { error: 'Enter a valid email address.' });
        if (password.length < 12 || password.length > 128) return response(400, { error: 'Password must be between 12 and 128 characters.' });
        if (!['Administrator', 'Manager', 'Staff'].includes(role)) return response(400, { error: 'Choose a valid user role.' });
        organization.users ||= [];
        if (organization.id === 'legacy' && roleAccounts().some(account => account.email.trim().toLowerCase() === email)) {
          return response(409, { error: 'That email is already registered in this organization.' });
        }
        if (organization.users.some(user => user.email.toLowerCase() === email)) return response(409, { error: 'That email is already registered in this organization.' });
        const user = { id: crypto.randomUUID(), name, email, role, password: passwordRecord(password) };
        organization.users.push(user);
        await writeDatabase(database);
        return response(201, { user: { id: user.id, name, email, role } });
      } catch (error) {
        console.error(`User creation failed: ${error.message}`);
        return response(400, { error: 'Could not create user.' });
      }
    }
    return response(405, { error: 'Method not allowed.' });
  }

  if (method === 'POST' && route === '/logout') {
    const session = await getSession(request);
    if (session) {
      const database = await readDatabase();
      recordAuthentication(database, 'User logged out', session.user);
      await writeDatabase(database);
      await deleteSession(session.token);
    }
    return response(200, { authenticated: false }, { 'Set-Cookie': sessionCookie('', request, 0) });
  }

  if (method === 'GET' && route === '/audit/auth') {
    const session = await getSession(request);
    if (!session) return response(401, { error: 'Sign in to view authentication activity.' });
    if (!['Administrator', 'Manager'].includes(session.user.role)) return response(403, { error: 'You do not have access to authentication activity.' });
    const database = await readDatabase();
    const workspace = organizationWorkspace(database, session.user.organizationId);
    return response(200, { events: workspace.authAudit || [] });
  }

  if (route === '/day-end') {
    const session = await getSession(request);
    if (!session) return response(401, { error: 'Sign in to access day-end accounting.' });
    if (!['Administrator', 'Manager'].includes(session.user.role)) return response(403, { error: 'You do not have access to day-end accounting.' });
    const database = await readDatabase();
    const workspace = organizationWorkspace(database, session.user.organizationId);
    workspace.dayEndReports ||= [];
    if (method === 'GET') return response(200, { reports: workspace.dayEndReports });
    if (method === 'POST') {
      try {
        const payload = await request.json();
        if (!validDayEndDate(payload.date)) return response(400, { error: 'A valid business date is required.' });
        const existing = workspace.dayEndReports.find(report => report.date === payload.date);
        if (existing) return response(409, { error: 'Day-end accounting has already been completed for this date.', report: existing });
        const reports = normalizeDayEndReports(payload.reports, payload.date);
        if (!reports) return response(400, { error: 'Exactly four valid daily reports are required.' });
        const report = { date: payload.date, reports, generatedAt: new Date().toISOString(), generatedBy: session.user.name };
        workspace.dayEndReports.push(report);
        workspace.dayEndReports.sort((left, right) => right.date.localeCompare(left.date));
        await writeDatabase(database);
        return response(201, { report });
      } catch (error) {
        console.error(`Day-end report generation failed: ${error.message}`);
        return response(400, { error: 'Could not generate day-end reports.' });
      }
    }
    return response(405, { error: 'Method not allowed.' });
  }

  if (method === 'GET' && route === '/inventory') {
    const session = await getSession(request);
    if (!session) return response(401, { error: 'Sign in to view inventory.' });
    const database = await readDatabase();
    const workspace = organizationWorkspace(database, session.user.organizationId);
    return response(200, {
      products: workspace.products || [],
      vendors: workspace.vendors || [],
      transactions: workspace.transactions || [],
      bills: workspace.bills || [],
      audit: workspace.audit || []
    });
  }

  if (method === 'PUT' && route === '/inventory') {
    const session = await getSession(request);
    if (!session) return response(401, { error: 'Sign in to synchronize inventory.' });
    try {
      const payload = await request.json();
      if (!Array.isArray(payload.products) || !Array.isArray(payload.vendors)) return response(400, { error: 'Products and vendors must be arrays.' });
      for (const key of ['transactions', 'bills', 'audit']) {
        if (payload[key] !== undefined && !Array.isArray(payload[key])) return response(400, { error: `${key} must be an array.` });
      }
      const database = await readDatabase();
      const workspace = organizationWorkspace(database, session.user.organizationId);
      workspace.products = payload.products;
      workspace.vendors = payload.vendors;
      for (const key of ['transactions', 'bills', 'audit']) {
        if (payload[key] !== undefined) workspace[key] = payload[key];
      }
      await writeDatabase(database);
      const emailResult = await sendExpiryEmails(workspace);
      await writeDatabase(database);
      return response(200, { ok: true, ...emailResult });
    } catch (error) {
      console.error(`Inventory sync failed: ${error.message}`);
      return response(400, { error: 'Could not synchronize inventory.' });
    }
  }

  return response(404, { error: 'Not found.' });
};
