import crypto from 'node:crypto';
import {
  createSession,
  deleteSession,
  getSession,
  readDatabase,
  recordAuthentication,
  response,
  roleAccounts,
  sendExpiryEmails,
  sessionCookie,
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
    return response(200, {
      gmailConfigured: Boolean(process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD),
      loginConfigured: roleAccounts().length > 0,
      availableRoles: roleAccounts().map(account => account.role)
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
      const account = roleAccounts().find(item => item.role === String(payload.role || '') && item.email.trim().toLowerCase() === email);
      if (!account || !secureCompare(payload.password || '', account.password)) {
        const count = Math.min((limit.attempt?.count || 0) + 1, 5);
        await limit.store.setJSON(limit.key, { count, lockedUntil: count >= 5 ? Date.now() + 5 * 60 * 1000 : 0 });
        return response(401, { error: 'Email, password, or role did not match.' });
      }
      await limit.store.delete(limit.key);
      const user = { name: account.name, email: account.email, role: account.role };
      const database = await readDatabase();
      recordAuthentication(database, 'User logged in', user);
      await writeDatabase(database);
      const token = await createSession(user);
      return response(200, { authenticated: true, user }, { 'Set-Cookie': sessionCookie(token, request) });
    } catch (error) {
      console.error(`Login failed: ${error.message}`);
      return response(400, { error: 'Could not complete sign-in.' });
    }
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
    return response(200, { events: database.authAudit || [] });
  }

  if (method === 'PUT' && route === '/inventory') {
    if (!await getSession(request)) return response(401, { error: 'Sign in to synchronize inventory.' });
    try {
      const payload = await request.json();
      if (!Array.isArray(payload.products) || !Array.isArray(payload.vendors)) return response(400, { error: 'Products and vendors must be arrays.' });
      const database = await readDatabase();
      database.products = payload.products;
      database.vendors = payload.vendors;
      await writeDatabase(database);
      const emailResult = await sendExpiryEmails(database);
      await writeDatabase(database);
      return response(200, { ok: true, ...emailResult });
    } catch (error) {
      console.error(`Inventory sync failed: ${error.message}`);
      return response(400, { error: 'Could not synchronize inventory.' });
    }
  }

  return response(404, { error: 'Not found.' });
};
