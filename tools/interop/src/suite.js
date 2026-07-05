// Orchestrated end-to-end interop suite. Runs every check in dependency order,
// never aborts early (each step reports independently), always attempts
// interaction cleanup, and writes a JSON report under .state/reports/.

import { BASE_URL } from './config.js';
import { describeServer, health, createAccount, scheduleEphemeralDeletion } from './account.js';
import { verifyIdentity } from './identity.js';
import { crudRoundTrip, deleteRecord } from './records.js';
import { firehoseWriteCheck } from './firehose.js';
import { syncChecks } from './sync.js';
import { networkChecks } from './network.js';
import { resolveTarget, followTarget, likeTargetPost, mentionTarget, cleanupInteractions } from './interact.js';
import { loadState, writeReport } from './state.js';
import { randomSuffix } from './crypto.js';

async function step(report, name, fn) {
  const started = Date.now();
  process.stderr.write(`▶ ${name}\n`);
  try {
    const detail = await fn();
    // Check helpers (verifyIdentity, syncChecks, networkChecks) report logical
    // failures via `ok: false` rather than throwing — treat those as failed.
    if (detail && typeof detail === 'object' && detail.ok === false) {
      const failed = (detail.checks ?? []).filter((c) => !c.ok && !c.informational).map((c) => c.label);
      report.steps.push({ name, ok: false, ms: Date.now() - started, detail, error: `checks failed: ${failed.join(', ') || 'see detail'}` });
      process.stderr.write(`  ✘ ${name}: ${failed.join(', ') || 'ok=false'}\n`);
      return;
    }
    report.steps.push({ name, ok: true, ms: Date.now() - started, detail });
    process.stderr.write(`  ✔ ${name}\n`);
  } catch (err) {
    report.steps.push({ name, ok: false, ms: Date.now() - started, error: err.message });
    process.stderr.write(`  ✘ ${name}: ${err.message}\n`);
  }
}

/**
 * @param {{account: string, interact: boolean, lifecycle: boolean}} opts
 *   account: name of the persistent account to use (created if missing)
 *   interact: include follow/like/mention against the allowlisted identity
 *   lifecycle: include the ephemeral create→deactivate→reap lifecycle test
 */
export async function runSuite({ account = 'primary', interact = true, lifecycle = false } = {}) {
  const report = { startedAt: new Date().toISOString(), baseUrl: BASE_URL, account, steps: [] };

  await step(report, 'server: health', () => health());
  await step(report, 'server: describeServer', async () => {
    const server = await describeServer();
    return { did: server.did, availableUserDomains: server.availableUserDomains, inviteCodeRequired: server.inviteCodeRequired };
  });

  await step(report, `account: ensure persistent "${account}"`, async () => {
    const state = loadState();
    if (state.accounts[account]) return { did: state.accounts[account].did, handle: state.accounts[account].handle, existing: true };
    const created = await createAccount({ name: account, kind: 'persistent' });
    return { did: created.did, handle: created.handle, existing: false };
  });

  await step(report, 'identity: handle/DID/plc.directory agreement', () => verifyIdentity(account));
  await step(report, 'repo: CRUD round-trip', () => crudRoundTrip(account));
  await step(report, 'firehose: write observed on subscribeRepos', async () => {
    const result = await firehoseWriteCheck(account);
    // Cleanup failure must not mask a successful observation — report it
    // alongside the result instead (same separation as "interact: cleanup").
    try {
      await deleteRecord(account, 'app.bsky.feed.post', result.rkey);
    } catch (err) {
      return { ...result, cleanupError: err.message };
    }
    return result;
  });
  await step(report, 'sync: CAR / latestCommit / repoStatus / listRepos', () => syncChecks(account));
  await step(report, 'network: relay + AppView visibility', () => networkChecks(account));

  if (interact) {
    await step(report, 'interact: resolve allowlisted target', () => resolveTarget());
    await step(report, 'interact: follow', () => followTarget(account));
    await step(report, 'interact: like latest post', () => likeTargetPost(account));
    await step(report, 'interact: mention post', () => mentionTarget(account));
    await step(report, 'interact: cleanup', async () => {
      const results = await cleanupInteractions(account);
      const failed = results.filter((r) => !r.deleted);
      if (failed.length) throw new Error(`failed to delete ${failed.length} interaction record(s): ${failed.map((f) => f.uri).join(', ')}`);
      return { deleted: results.length };
    });
  }

  if (lifecycle) {
    const ephemeralName = `ephemeral-${randomSuffix(4)}`;
    await step(report, `lifecycle: ephemeral account ${ephemeralName}`, async () => {
      const created = await createAccount({ name: ephemeralName, kind: 'ephemeral' });
      const identity = await verifyIdentity(ephemeralName);
      // Always schedule teardown, even when the identity check failed — an
      // ephemeral account must never outlive its run.
      const deleteAfter = await scheduleEphemeralDeletion(ephemeralName, { afterMinutes: 5 });
      if (!identity.ok) {
        throw new Error(`ephemeral identity checks failed (teardown still scheduled for ${deleteAfter})`);
      }
      return { did: created.did, handle: created.handle, identityOk: identity.ok, deleteAfter };
    });
  }

  report.finishedAt = new Date().toISOString();
  report.ok = report.steps.every((s) => s.ok);
  const file = writeReport(report);

  const passed = report.steps.filter((s) => s.ok).length;
  console.log(`\n${report.ok ? 'PASS' : 'FAIL'} — ${passed}/${report.steps.length} steps ok`);
  for (const s of report.steps) {
    console.log(` ${s.ok ? '✔' : '✘'} ${s.name} (${s.ms}ms)${s.ok ? '' : ` — ${s.error}`}`);
  }
  console.log(`report: ${file}`);
  return report;
}
