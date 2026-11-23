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

**Space transfer**:
The step of an account migration that moves the account's permissioned space repos, and the space meta of every space it is the authority of, to the destination PDS.
_Avoid_: space import (import names the wire methods, and on its own means adopting a did:web identity)

### Spaces

**Space**:
A shared context whose records live spread across its writers' space repos, named by a space authority, a space type and a space key. It is the boundary for who may read and sync those records.
_Avoid_: group, community, room (things a space type might model)

**Space authority**:
The DID at the root of a space, which issues its space credentials. It may be a person's own DID or a dedicated one that can pass between people.
_Avoid_: space owner (owner names an agent's or a sovereign child's person), creator, admin

**Space type**:
The NSID naming what kind of space a space is. It is also the boundary a user consents to when granting an app access.
_Avoid_: space kind, modality

**Space key**:
The string that tells apart spaces of one space type under one space authority.
_Avoid_: space name, skey

**Space host**:
The role that answers for a whole space: issuing its space credentials, keeping its writer set and sending its notifications. Custos plays it for every space whose authority it hosts.
_Avoid_: space server, authority server

**Repo host**:
The role that stores and serves accounts' space repos. Custos plays it for every account it hosts.
_Avoid_: PDS (one service that can play the role), space repo server

**Space repo**:
One account's records in one space, kept by that account's repo host.
_Avoid_: space data, member repo

**Space commit**:
The unsigned summary of a space repo's current state, proved to one syncer at a time by a MAC rather than by a signature.
_Avoid_: signed commit (the public repo's commit, which space repos do not have)

**Repo revision**:
A space repo's own revision, advanced by each write to it.
_Avoid_: rev (ambiguous with the space revision)

**Space revision**:
The space host's sequence number for updates across a whole space, so that a gap means a missed notification.
_Avoid_: rev, space rev

**Syncer**:
An app that keeps its own copy of a space by pulling each space repo from its repo host.
_Avoid_: syncing service, subscriber, consumer, reader

**Writer set**:
The accounts the space host records as having written to a space: the starting point a syncer uses to find a space's repos.
_Avoid_: repo list, participants

**Writer**:
An account in a space's writer set. Being allowed to write does not make an account a writer; writing does.
_Avoid_: participant, repo

**Member**:
A DID on a memberspace's member list, allowed to read and/or write. A member is not a writer until it writes.
_Avoid_: membership, subscriber

**Space policy**:
The one object that decides who may read and write a space, and from which apps.
_Avoid_: read policy, write policy, app access

**Baseline policy**:
One of the three space policies every PDS must support: personalspace, memberspace and managedspace.
_Avoid_: default policy, simplespace

**Personalspace**:
The baseline policy under which only the space authority's own account has access.
_Avoid_: personal space, private space

**Memberspace**:
The baseline policy under which access is decided by a member list the space host keeps.
_Avoid_: member space, simplespace

**Managedspace**:
The baseline policy under which access is decided, per request, by an outside managing app.
_Avoid_: managed space, delegated space

**Published policy**:
The authority's copy of its space policy or member list, as records in its own space repo, for readers to see. It is never the authoritative copy.
_Avoid_: policy record

**Space credential**:
The short-lived token, signed by the space authority and bound to one app's key, that lets that app read a space from any repo host.
_Avoid_: space token, read token

**Delegation token**:
The token a user's PDS issues to an app, which the app exchanges with the space host for a space credential.
_Avoid_: space delegation, user token

**Client attestation**:
An app's own proof of its identity, which a space host requires only when the space policy limits which apps may read.
_Avoid_: app attestation, client assertion (the OAuth client-authentication JWT)

**Notification registration**:
A syncer's request, made while getting a space credential, to be told of updates to a space; it lasts while the credential is valid.
_Avoid_: subscription, notify registration

**KEM key**:
An account's dedicated key, published in its DID document, which its repo host uses to answer MAC requests. It never signs.
_Avoid_: space key (that is a space's identifier), space signing key

**Ephemeral key**:
The throwaway public key a syncer sends with one request so that it and the repo host derive a secret only they share.
_Avoid_: key share, session key

**MAC**:
The per-request, per-syncer proof that a space commit or record came from its repo host, which the syncer cannot show to anyone else as proof.
_Avoid_: commit signature, signed commit

**Space meta**:
A space's authority-side state (its policy, member list and writer set), which moves with the authority's account and is never part of any repo.
_Avoid_: space config, space settings

**Deleted space**:
A space its authority has deleted. It answers as deleted from then on, its syncers are told to drop their copies, and it can be created again under the same space key as a new, empty space.
_Avoid_: removed space, purged space

**Suspended space**:
A space whose authority's account is deactivated or taken down. It refuses new credentials with the authority's status but loses nothing, and resumes when the account does.
_Avoid_: frozen space, disabled space

**Space takedown**:
The operator's reversible refusal to serve one space, independent of its authority's account.
_Avoid_: space suspension (that names the authority's account state), takedown label (that is the authority's request to syncers and apps)

**Label record**:
A moderation label on space data, written as an unsigned record into the same space as the data it labels, by a labeler in that space's writer set. A label that points into any other space carries no meaning.
_Avoid_: space label, signed label

**Takedown label**:
A label record with the value `!takedown`, which a space authority publishes by convention to ask syncers and apps to stop showing the labelled data. It is a request, not an operator takedown.
_Avoid_: space takedown (that is the operator's refusal to serve a space)

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
