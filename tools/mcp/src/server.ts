// Custos MCP stdio server entry point.
//
// First launch against a PDS runs the auth.md onboarding ceremony: register,
// print the claim code for the human, poll for confirmation in the background
// while the MCP session is already live (whoami reports progress), and
// transition to ready without a restart. A PDS with agent auth disabled makes
// startup fail legibly with a nonzero exit — no retry storm.
//
// stdout belongs to the MCP protocol; every human-facing message goes to
// stderr.

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { AgentSession } from './auth.ts';
import { registerTools } from './tools.ts';
import { pdsUrl, AGENT_NAME } from './config.ts';
import { clearCredentials } from './state.ts';

const log = (message: string) => process.stderr.write(`[custos-mcp] ${message}\n`);

async function main(): Promise<void> {
  const command = process.argv[2];
  if (command === 'reset') {
    // Explicit user action: forget the cached registration so the next start
    // onboards fresh. This is the deliberate step required after a revocation.
    const url = pdsUrl();
    clearCredentials(url);
    log(`cleared cached credentials for ${url}; the next start will re-onboard`);
    return;
  }
  if (command !== undefined) {
    log(`unknown command "${command}" — run with no arguments (stdio server) or "reset"`);
    process.exitCode = 2;
    return;
  }

  const url = pdsUrl();
  const session = new AgentSession(url);

  if (session.status().state === 'revoked') {
    log(
      `the cached registration for ${url} was revoked in Obsign; refusing to re-register ` +
        `automatically. Run \`custos-mcp reset\` and restart to onboard again.`,
    );
  } else if (session.needsOnboarding()) {
    // Registration happens before the MCP handshake so a PDS without agent
    // auth fails the launch legibly (exit nonzero) instead of limping along.
    await session.startOnboarding({
      onWaiting: (reg) => {
        log(`onboarding to ${url} as "${AGENT_NAME}"`);
        log(`ACTION NEEDED — confirm this agent as the account owner:`);
        log(`  claim code:  ${reg.userCode}`);
        log(`  confirm at:  ${reg.verificationUri} (or in the Obsign wallet)`);
        log(`  expires:     ${reg.expiresAt}`);
        log(`waiting for confirmation (the whoami tool reports live status) ...`);
      },
      onReady: (state) => {
        if (state.state === 'ready') {
          log(`claim confirmed — ready as ${state.did} (scopes: ${state.scopes.join(' ')})`);
        }
      },
      onFailed: (err) => log(`onboarding failed: ${err.message}`),
    });
  } else {
    log(`using cached credentials for ${url}`);
  }

  const server = new McpServer({ name: 'custos-mcp', version: '0.1.0' });
  // The stdio server is single-user: every tool call runs as the one onboarded
  // session. (The sidecar instead resolves a per-caller session from the
  // request's authenticated identity.)
  registerTools(server, () => session);
  await server.connect(new StdioServerTransport());
  log(`MCP server connected (PDS: ${url})`);
}

main().catch((err: Error) => {
  log(`fatal: ${err.message}`);
  process.exit(1);
});
