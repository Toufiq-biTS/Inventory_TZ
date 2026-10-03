import { readDatabase, sendExpiryEmails, writeDatabase } from '../lib.mjs';

export default async () => {
  const database = await readDatabase();
  const result = await sendExpiryEmails(database);
  await writeDatabase(database);
  console.log(`Expiry check complete: sent=${result.sent}, skipped=${result.skipped}, failed=${result.failed}.`);
};

export const config = { schedule: '@hourly' };
