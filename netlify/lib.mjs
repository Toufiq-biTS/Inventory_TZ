import crypto from 'node:crypto';
import nodemailer from 'nodemailer';
import { getStore as openStore } from '@netlify/blobs';

const inventoryStoreName = 'tz-solutions-inventory';
const sessionStoreName = 'tz-solutions-sessions';
const sessionLifetimeMs = 8 * 60 * 60 * 1000;
const defaultDatabase = { products: [], vendors: [], sentAlerts: {}, authAudit: [] };
const gmailConfigured = Boolean(process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD);
const mailTransporter = gmailConfigured ? nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD.replace(/\s/g, '')
  }
}) : null;

export function roleAccounts() {
  return [
    { role: 'Administrator', email: process.env.ADMIN_EMAIL, password: process.env.ADMIN_PASSWORD, name: process.env.ADMIN_NAME || 'Administrator' },
    { role: 'Manager', email: process.env.MANAGER_EMAIL, password: process.env.MANAGER_PASSWORD, name: process.env.MANAGER_NAME || 'Inventory Manager' },
    { role: 'Staff', email: process.env.STAFF_EMAIL, password: process.env.STAFF_PASSWORD, name: process.env.STAFF_NAME || 'Inventory Staff' }
  ].filter(account => account.email && account.password);
}

export function response(status, data, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers }
  });
}

export async function readDatabase() {
  const store = openStore(inventoryStoreName);
  const saved = await store.get('state', { type: 'json', consistency: 'strong' });
  return { ...defaultDatabase, ...(saved || {}) };
}

export async function writeDatabase(database) {
  const store = openStore(inventoryStoreName);
  await store.setJSON('state', database);
}

export function recordAuthentication(database, action, user) {
  database.authAudit ||= [];
  database.authAudit.unshift({
    id: crypto.randomUUID(),
    action,
    user: user.name,
    role: user.role,
    email: user.email,
    time: new Date().toISOString()
  });
  database.authAudit = database.authAudit.slice(0, 1000);
}

function passwordMatches(provided, expected) {
  const providedHash = crypto.createHash('sha256').update(String(provided)).digest();
  const expectedHash = crypto.createHash('sha256').update(String(expected)).digest();
  return crypto.timingSafeEqual(providedHash, expectedHash);
}

export async function createSession(user) {
  const token = crypto.randomBytes(32).toString('base64url');
  const store = openStore(sessionStoreName);
  await store.setJSON(token, { user, expiresAt: Date.now() + sessionLifetimeMs });
  return token;
}

export async function getSession(request) {
  const token = String(request.headers.get('cookie') || '').split(';').map(part => part.trim())
    .find(part => part.startsWith('tz_inventory_session='))?.slice('tz_inventory_session='.length);
  if (!token) return null;
  const store = openStore(sessionStoreName);
  const session = await store.get(token, { type: 'json', consistency: 'strong' });
  if (!session) return null;
  if (session.expiresAt <= Date.now()) {
    await store.delete(token);
    return null;
  }
  return { ...session, token };
}

export async function deleteSession(token) {
  if (token) await openStore(sessionStoreName).delete(token);
}

export function sessionCookie(token, request, maxAge = sessionLifetimeMs / 1000) {
  const secure = new URL(request.url).protocol === 'https:' ? '; Secure' : '';
  return `tz_inventory_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(maxAge)}${secure}`;
}

function expiryState(product, now = new Date()) {
  if (!product.expiryDate || Number(product.stock) <= 0 || !/^\d{4}-\d{2}-\d{2}$/.test(product.expiryDate)) return null;
  const [year, month, day] = product.expiryDate.split('-').map(Number);
  const expiry = Date.UTC(year, month - 1, day);
  const today = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  const remainingDays = Math.floor((expiry - today) / 86400000);
  if (remainingDays < 0) return { name: 'expired', remainingDays };
  if (remainingDays <= 15) return { name: 'upcoming', remainingDays };
  return null;
}

export async function sendExpiryEmails(database) {
  const result = { configured: gmailConfigured, sent: 0, skipped: 0, failed: 0 };
  if (!mailTransporter) return result;
  database.sentAlerts ||= {};

  for (const product of database.products) {
    const state = expiryState(product);
    if (!state) continue;
    const vendor = database.vendors.find(item => item.name === product.vendor);
    const recipient = String(vendor?.email || '').trim();
    if (!recipient || /\.example$/i.test(recipient)) {
      result.skipped += 1;
      continue;
    }
    const alertKey = `${product.id}:${product.expiryDate}:${state.name}`;
    if (database.sentAlerts[alertKey]) continue;
    const timing = state.name === 'expired'
      ? `expired on ${product.expiryDate}`
      : `expires on ${product.expiryDate} in ${state.remainingDays} day${state.remainingDays === 1 ? '' : 's'}`;
    const greeting = vendor.contact ? `Hello ${vendor.contact},` : 'Hello,';
    const text = `${greeting}\n\nInventory alert for ${vendor.name}:\n\n${product.name} (${product.id}) has ${timing}. Current stock: ${product.stock}.\n\nPlease review and advise on the appropriate action.\n\nRegards,\nTZ Solutions`;
    try {
      await mailTransporter.sendMail({
        from: process.env.MAIL_FROM || process.env.GMAIL_USER,
        to: recipient,
        subject: `Inventory expiry alert: ${product.name} ${state.name === 'expired' ? 'has expired' : 'expires soon'}`,
        text
      });
      database.sentAlerts[alertKey] = new Date().toISOString();
      result.sent += 1;
    } catch (error) {
      result.failed += 1;
      console.error(`Expiry email failed for ${product.id}: ${error.message}`);
    }
  }
  return result;
}
