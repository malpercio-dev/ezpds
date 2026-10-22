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
