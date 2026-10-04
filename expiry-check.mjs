import { readDatabase, sendExpiryEmails, writeDatabase } from '../lib.mjs';

export default async () => {
  const database = await readDatabase();
  const result = { configured: false, sent: 0, skipped: 0, failed: 0 };
  for (const workspace of [database, ...Object.values(database.workspaces || {})]) {
    const workspaceResult = await sendExpiryEmails(workspace);
    result.configured ||= workspaceResult.configured;
    result.sent += workspaceResult.sent;
    result.skipped += workspaceResult.skipped;
    result.failed += workspaceResult.failed;
  }
  await writeDatabase(database);
  console.log(`Expiry check complete: sent=${result.sent}, skipped=${result.skipped}, failed=${result.failed}.`);
};

export const config = { schedule: '@hourly' };
