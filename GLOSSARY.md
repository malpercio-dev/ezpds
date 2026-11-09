# ezpds

The domain language shared by Custos (the PDS) and Obsign (the identity wallet). Terms here name concepts, never implementations; module docs and ADRs own the how and the why.

## Language

### Identity wallet

**Create flow**:
The door through which a new identity is created on a Custos PDS: account, DID ceremony, handle.
_Avoid_: signup, onboarding, registration

**DID ceremony**:
The step of the create flow in which the device key signs the identity's genesis and the account is promoted to a DID.
_Avoid_: genesis, promotion

**did:web ceremony**:
The create flow's variant in which the user hosts the DID document on a domain they own.
_Avoid_: custom domain flow

**Import**:
Adopting an existing did:web identity into the wallet with no PDS account created.
_Avoid_: claim (a claim takes over an existing did:plc account's rotation key)

**Share 1**:
The recovery share the wallet keeps for itself, on the device and, where the platform has one, in the cloud slot.
_Avoid_: device share, local share

**Startup reconcile**:
The pass at launch that moves Share 1 and the created-identity record into their current slots.
_Avoid_: migration (reserved for moving an account between PDSes)

### Agents

**Agent claim**:
The owner confirming that an agent is bound to their identity, after which the agent acts under that owner.
_Avoid_: claim (on its own, a claim means taking over an existing did:plc account's rotation key)

**Agent scope grant**:
The set of scopes an owner consented to for one agent, kept with that agent.
_Avoid_: agent scopes, stored scopes

**Scope profile**:
The operator's ceiling on what any agent on the instance may be granted.
_Avoid_: granted scopes (names the setting, not the concept)

**Connector**:
A third-party MCP client that reaches Custos through the hosted MCP sidecar and authenticates with the MCP-spec OAuth handshake, which uses neither PAR nor DPoP.
_Avoid_: MCP client (too broad), agent (an auth.md agent uses the identity-assertion exchange, not this handshake)

**Acts-as-you**:
The attribution model in which a delegate's actions carry the user's own DID and land in the user's repo.
_Avoid_: delegate mode, impersonation

**Sovereign child**:
A separate identity with its own DID, repo and handle, owned by a parent account on the same PDS, whose recovery key the parent's wallet holds.
_Avoid_: sub-account, child agent (a child need not be an agent)
