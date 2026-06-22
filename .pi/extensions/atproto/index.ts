/**
 * ATProto Extension for Pi
 *
 * Tools for interacting with ezpds provisioning relay and ATProto endpoints.
 * Requires EZPDS_BASE_URL and optionally EZPDS_ADMIN_TOKEN in the environment.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { StringEnum } from "@earendil-works/pi-ai";
import * as crypto from "node:crypto";
import * as dagCbor from "@ipld/dag-cbor";
import { P256Keypair } from "@atproto/crypto";

// ── Types ───────────────────────────────────────────────────────────────────

interface PlcGenesisOp {
  did: string;
  signedOpJson: string;
}

// ── Crypto: P-256 Key Generation ─────────────────────────────────────────────

interface P256KeypairRaw {
  keypair: P256Keypair;
  keyId: string;
}

async function generateP256KeypairRaw(): Promise<P256KeypairRaw> {
  // Use official atproto crypto library for compatibility
  const keypair = await P256Keypair.create({ exportable: true });
  const keyId = keypair.did();

  return {
    keypair,
    keyId,
  };
}

function generateP256Keypair(): Promise<P256Keypair> {
  return P256Keypair.create({ exportable: true });
}

// ── Multibase (base58btc) ───────────────────────────────────────────────────

const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function multibaseEncode(data: Buffer): string {
  // base58btc with 'z' prefix (but we return just the base58 part for did:key)
  return base58Encode(data);
}

function base58Encode(buffer: Buffer): string {
  let num = BigInt("0x" + buffer.toString("hex"));
  let result = "";
  while (num > 0n) {
    const remainder = Number(num % 58n);
    num = num / 58n;
    result = BASE58_ALPHABET[remainder] + result;
  }
  // Handle leading zeros
  for (const byte of buffer) {
    if (byte === 0) result = "1" + result;
    else break;
  }
  return result;
}

// ── DID:plc Genesis Operation ────────────────────────────────────────────────

async function buildDidPlcGenesisOp(
  rotationKeyId: string,
  signingKeyId: string,
  signingKeypair: P256Keypair,
  handle: string,
  publicUrl: string
): Promise<PlcGenesisOp> {
  // Build unsigned operation with DAG-CBOR canonical key ordering
  // Sort by UTF-8 byte length, then alphabetically
  const unsignedOp: Record<string, unknown> = {
    prev: null,
    type: "plc_operation",
    services: {
      atproto_pds: {
        type: "AtprotoPersonalDataServer",
        endpoint: publicUrl,
      },
    },
    alsoKnownAs: [`at://${handle}`],
    rotationKeys: [rotationKeyId, signingKeyId],
    verificationMethods: {
      atproto: signingKeyId,
    },
  };

  // CBOR encode the unsigned op (deterministic, DAG-CBOR canonical ordering)
  const unsignedBytes = dagCbor.encode(unsignedOp);

  // Sign using official atproto crypto library (produces raw 64-byte signature)
  const signature = await signingKeypair.sign(unsignedBytes);
  const signatureBase64url = Buffer.from(signature).toString("base64url");

  // Build signed op (add sig field - comes first in DAG-CBOR order since "sig" is 3 bytes)
  const signedOp: Record<string, unknown> = {
    sig: signatureBase64url,
    ...unsignedOp,
  };

  // CBOR encode the signed op (DAG-CBOR canonical ordering)
  const signedBytes = dagCbor.encode(signedOp);

  // SHA-256 hash of signed CBOR
  const hash = crypto.createHash("sha256").update(signedBytes).digest();

  // Base32-lowercase first 24 chars → DID suffix
  const didSuffix = base32Encode(hash).substring(0, 24).toLowerCase();
  const did = `did:plc:${didSuffix}`;

  return {
    did,
    signedOpJson: JSON.stringify(signedOp),
  };
}

// ── Base32 (RFC 4648, no padding) ───────────────────────────────────────────

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Encode(buffer: Buffer): string {
  let result = "";
  let bits = 0;
  let value = 0;

  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      result += BASE32_ALPHABET[(value >>> (bits - 5)) & 0x1f];
      bits -= 5;
    }
  }

  if (bits > 0) {
    result += BASE32_ALPHABET[(value << (5 - bits)) & 0x1f];
  }

  return result;
}

// ── ATProto HTTP Client ──────────────────────────────────────────────────────

async function relayRequest<T = any>(
  baseUrl: string,
  path: string,
  options: {
    method?: string;
    body?: unknown;
    token?: string;
    adminToken?: string;
  } = {}
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (options.token) {
    headers["Authorization"] = `Bearer ${options.token}`;
  } else if (options.adminToken) {
    headers["Authorization"] = `Bearer ${options.adminToken}`;
  }

  const res = await fetch(`${baseUrl}${path}`, {
    method: options.method || "GET",
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`HTTP ${res.status}: ${text}`);
  }

  return res.json() as Promise<T>;
}

// ── Extension Entry Point ────────────────────────────────────────────────────

export default function (pi: ExtensionAPI) {
  const baseUrl = process.env.EZPDS_BASE_URL;
  const adminToken = process.env.EZPDS_ADMIN_TOKEN;

  if (!baseUrl) {
    pi.on("session_start", (_e, ctx) => {
      ctx.ui.notify(
        "EZPDS_BASE_URL not set — ATProto tools disabled",
        "warning"
      );
    });
    return;
  }

  pi.on("session_start", (_e, ctx) => {
    ctx.ui.notify(
      `ATProto extension loaded — targeting ${baseUrl}`,
      "info"
    );
  });

  // ── atproto_create_claim_code ────────────────────────────────────────────

  pi.registerTool({
    name: "atproto_create_claim_code",
    label: "Create Claim Code",
    description:
      "Create an invite/claim code for account registration. Requires admin token.",
    promptSnippet: "Create a claim code for new account registration",
    promptGuidelines: [
      "Use when you need to create a new account and need an invite code first.",
    ],
    parameters: Type.Object({
      count: Type.Optional(
        Type.Number({ description: "Number of codes to generate (default 1)" })
      ),
      expires_in_hours: Type.Optional(
        Type.Number({ description: "Hours until expiry (default 24)" })
      ),
    }),
    async execute(_id, params) {
      if (!adminToken) {
        throw new Error("EZPDS_ADMIN_TOKEN not set");
      }
      const data = await relayRequest(baseUrl, "/v1/accounts/claim-codes", {
        method: "POST",
        adminToken,
        body: {
          count: params.count ?? 1,
          expiresInHours: params.expires_in_hours ?? 24,
        },
      });
      return {
        content: [
          {
            type: "text",
            text: `Claim codes: ${data.codes.join(", ")}`,
          },
        ],
        details: data,
      };
    },
  });

  // ── atproto_create_mobile_account ────────────────────────────────────────

  pi.registerTool({
    name: "atproto_create_mobile_account",
    label: "Create Mobile Account",
    description:
      "Create an account via the mobile provisioning flow. Returns accountId, deviceId, deviceToken, and sessionToken. Use atproto_complete_did_ceremony next to finish account setup.",
    promptSnippet: "Create a new mobile account with a claim code",
    promptGuidelines: [
      "Use after obtaining a claim code to create an account.",
      "The account will be in 'did_creation' state until atproto_complete_did_ceremony is called.",
    ],
    parameters: Type.Object({
      email: Type.String({ description: "Email address" }),
      handle: Type.String({ description: "Desired handle (e.g. alice.staging.example.com)" }),
      claim_code: Type.String({ description: "Claim code from atproto_create_claim_code" }),
    }),
    async execute(_id, params) {
      // Generate a device keypair
      const deviceKeypair = await generateP256Keypair();

      const data = await relayRequest(baseUrl, "/v1/accounts/mobile", {
        method: "POST",
        body: {
          email: params.email,
          handle: params.handle,
          devicePublicKey: Buffer.from(deviceKeypair.publicKeyBytes()).toString(
            "base64"
          ),
          platform: "ios",
          claimCode: params.claim_code,
        },
      });

      return {
        content: [
          {
            type: "text",
            text: [
              `Account created (state: ${data.nextStep})`,
              `  accountId: ${data.accountId}`,
              `  deviceId: ${data.deviceId}`,
              `  handle: ${params.handle}`,
              `  deviceToken: ${data.deviceToken}`,
              `  sessionToken: ${data.sessionToken}`,
              "",
              "Save these values and call atproto_complete_did_ceremony to finish setup.",
            ].join("\n"),
          },
        ],
        details: {
          ...data,
          handle: params.handle,
          _deviceKeypair: {
            keyId: deviceKeypair.keyId,
            privateKey: Buffer.from(deviceKeypair.privateKey).toString("hex"),
          },
        },
      };
    },
  });

  // ── atproto_complete_did_ceremony ────────────────────────────────────────

  pi.registerTool({
    name: "atproto_complete_did_ceremony",
    label: "Complete DID Ceremony",
    description:
      "Complete the did:plc ceremony for a pending account. Generates rotation key, builds and signs the genesis operation, and registers the DID. Returns the DID, session token, and Shamir shares.",
    promptSnippet: "Complete the DID ceremony for a pending account",
    promptGuidelines: [
      "Use after atproto_create_mobile_account to finish account setup.",
      "The sessionToken from create_mobile_account is required.",
      "The handle must match what was used during account creation.",
    ],
    parameters: Type.Object({
      session_token: Type.String({
        description: "Session token from create_mobile_account",
      }),
      handle: Type.String({
        description: "Handle (must match the one used during account creation)",
      }),
      password: Type.String({
        description: "Account password (min 12 chars)",
      }),
    }),
    async execute(_id, params) {
      // Generate rotation keypair (same key for rotation and signing)
      const rotationKeypair = await generateP256KeypairRaw();

      // Build the genesis operation
      const genesisOp = await buildDidPlcGenesisOp(
        rotationKeypair.keyId,
        rotationKeypair.keyId,
        rotationKeypair.keypair,
        params.handle,
        baseUrl
      );

      const signedOp = JSON.parse(genesisOp.signedOpJson);

      // Submit to relay
      const data = await relayRequest(baseUrl, "/v1/dids", {
        method: "POST",
        token: params.session_token,
        body: {
          rotationKeyPublic: rotationKeypair.keyId,
          signedCreationOp: signedOp,
          password: params.password,
        },
      });

      return {
        content: [
          {
            type: "text",
            text: [
              `DID ceremony complete!`,
              `  DID: ${data.did}`,
              `  Handle: ${params.handle}`,
              `  Status: ${data.status}`,
              `  Session token: ${data.session_token}`,
              `  Shamir share 1: ${data.shamir_share_1}`,
              `  Shamir share 3: ${data.shamir_share_3}`,
            ].join("\n"),
          },
        ],
        details: {
          ...data,
          _rotationKeypair: {
            keyId: rotationKeypair.keyId,
            privateKey: Buffer.from(rotationKeypair.privateKey).toString("hex"),
          },
        },
      };
    },
  });

  // ── atproto_create_full_account ──────────────────────────────────────────

  pi.registerTool({
    name: "atproto_create_full_account",
    label: "Create Full Account",
    description:
      "End-to-end account creation: claim code → mobile account → DID ceremony → handle registration. Returns DID, handle, session tokens, and Shamir shares.",
    promptSnippet: "Create a fully provisioned account in one step",
    promptGuidelines: [
      "Use when you need a complete account without manual steps.",
      "Requires EZPDS_ADMIN_TOKEN for claim code generation.",
    ],
    parameters: Type.Object({
      email: Type.String({ description: "Email address" }),
      handle: Type.String({ description: "Desired handle" }),
      password: Type.String({ description: "Account password (min 12 chars)" }),
    }),
    async execute(_id, params) {
      if (!adminToken) {
        throw new Error("EZPDS_ADMIN_TOKEN not set for claim code creation");
      }

      // Step 1: Create claim code
      const claimData = await relayRequest<{ codes: string[] }>(
        baseUrl,
        "/v1/accounts/claim-codes",
        {
          method: "POST",
          adminToken,
          body: { count: 1, expiresInHours: 1 },
        }
      );
      const claimCode = claimData.codes[0];

      // Step 2: Create mobile account
      const deviceKeypair = await generateP256Keypair();
      const accountData = await relayRequest<{
        accountId: string;
        deviceId: string;
        deviceToken: string;
        sessionToken: string;
      }>(baseUrl, "/v1/accounts/mobile", {
        method: "POST",
        body: {
          email: params.email,
          handle: params.handle,
          devicePublicKey: Buffer.from(deviceKeypair.publicKeyBytes()).toString(
            "base64"
          ),
          platform: "ios",
          claimCode,
        },
      });

      // Step 3: Complete DID ceremony
      const rotationKeypair = await generateP256KeypairRaw();
      const genesisOp = await buildDidPlcGenesisOp(
        rotationKeypair.keyId,
        rotationKeypair.keyId,
        rotationKeypair.keypair,
        params.handle,
        baseUrl
      );
      const signedOp = JSON.parse(genesisOp.signedOpJson);

      const didData = await relayRequest<{
        did: string;
        did_document: unknown;
        status: string;
        session_token: string;
        shamir_share_1: string;
        shamir_share_3: string;
      }>(baseUrl, "/v1/dids", {
        method: "POST",
        token: accountData.sessionToken,
        body: {
          rotationKeyPublic: rotationKeypair.keyId,
          signedCreationOp: signedOp,
          password: params.password,
        },
      });

      // Step 4: Register handle
      let handleResult: string;
      try {
        await relayRequest(baseUrl, "/v1/handles", {
          method: "POST",
          token: didData.session_token,
          body: {
            handle: params.handle,
            accountId: didData.did,
          },
        });
        handleResult = "registered";
      } catch (e) {
        handleResult = `failed: ${e}`;
      }

      // Step 5: Get ATProto session
      const atprotoSession = await relayRequest<{
        accessJwt: string;
        refreshJwt: string;
      }>(baseUrl, "/xrpc/com.atproto.server.createSession", {
        method: "POST",
        body: {
          identifier: didData.did,
          password: params.password,
        },
      });

      return {
        content: [
          {
            type: "text",
            text: [
              `✅ Account created successfully!`,
              ``,
              `DID: ${didData.did}`,
              `Handle: ${params.handle} (${handleResult})`,
              `Email: ${params.email}`,
              `Password: ${params.password}`,
              ``,
              `Session tokens:`,
              `  Provisioning: ${didData.session_token}`,
              `  ATProto access: ${atprotoSession.accessJwt.slice(0, 20)}...`,
              ``,
              `Shamir shares:`,
              `  Share 1: ${didData.shamir_share_1}`,
              `  Share 3: ${didData.shamir_share_3}`,
            ].join("\n"),
          },
        ],
        details: {
          did: didData.did,
          handle: params.handle,
          email: params.email,
          password: params.password,
          provisioning_session_token: didData.session_token,
          atproto_access_jwt: atprotoSession.accessJwt,
          atproto_refresh_jwt: atprotoSession.refreshJwt,
          shamir_share_1: didData.shamir_share_1,
          shamir_share_3: didData.shamir_share_3,
          device_token: accountData.deviceToken,
        },
      };
    },
  });

  // ── atproto_create_session ───────────────────────────────────────────────

  pi.registerTool({
    name: "atproto_create_session",
    label: "Create ATProto Session",
    description:
      "Create an ATProto session using DID/email and password. Returns access and refresh JWTs.",
    promptSnippet: "Authenticate and get ATProto session tokens",
    promptGuidelines: [
      "Use to get a fresh access token for XRPC calls.",
    ],
    parameters: Type.Object({
      identifier: Type.String({
        description: "DID or email",
      }),
      password: Type.String({ description: "Account password" }),
    }),
    async execute(_id, params) {
      const data = await relayRequest<{
        accessJwt: string;
        refreshJwt: string;
        handle: string;
        did: string;
      }>(baseUrl, "/xrpc/com.atproto.server.createSession", {
        method: "POST",
        body: {
          identifier: params.identifier,
          password: params.password,
        },
      });

      return {
        content: [
          {
            type: "text",
            text: [
              `Session created for ${data.did}`,
              `Handle: ${data.handle}`,
              `Access JWT: ${data.accessJwt}`,
              `Refresh JWT: ${data.refreshJwt}`,
            ].join("\n"),
          },
        ],
        details: data,
      };
    },
  });

  // ── atproto_register_handle ──────────────────────────────────────────────

  pi.registerTool({
    name: "atproto_register_handle",
    label: "Register Handle",
    description: "Register a handle for an account using the provisioning API.",
    promptSnippet: "Register a handle for an existing account",
    promptGuidelines: [
      "Use after account creation if the handle wasn't registered automatically.",
    ],
    parameters: Type.Object({
      session_token: Type.String({
        description: "Provisioning session token",
      }),
      handle: Type.String({ description: "Handle to register" }),
      did: Type.String({ description: "Account DID" }),
    }),
    async execute(_id, params) {
      const data = await relayRequest(baseUrl, "/v1/handles", {
        method: "POST",
        token: params.session_token,
        body: {
          handle: params.handle,
          accountId: params.did,
        },
      });

      return {
        content: [
          {
            type: "text",
            text: `Handle registered: ${data.handle} (DNS: ${data.dns_status})`,
          },
        ],
        details: data,
      };
    },
  });

  // ── atproto_get_blob ──────────────────────────────────────────────────────

  pi.registerTool({
    name: "atproto_get_blob",
    label: "Get Blob",
    description:
      "Retrieve a blob by CID from a DID's repo. Returns the blob content as base64 along with its MIME type and size.",
    promptSnippet: "Retrieve blob content by CID",
    promptGuidelines: [
      "Use to fetch blob content from the relay for inspection or verification.",
      "The blob must belong to the specified DID.",
    ],
    parameters: Type.Object({
      did: Type.String({ description: "DID that owns the blob" }),
      cid: Type.String({ description: "Content identifier of the blob" }),
    }),
    async execute(_id, params) {
      const url = new URL(`${baseUrl}/xrpc/com.atproto.sync.getBlob`);
      url.searchParams.set("did", params.did);
      url.searchParams.set("cid", params.cid);

      const res = await fetch(url.toString());

      if (!res.ok) {
        const text = await res.text();
        throw new Error(`HTTP ${res.status}: ${text}`);
      }

      const contentType = res.headers.get("content-type") || "application/octet-stream";
      const arrayBuffer = await res.arrayBuffer();
      const bytes = Buffer.from(arrayBuffer);
      const base64 = bytes.toString("base64");

      return {
        content: [
          {
            type: "text",
            text: [
              `Blob retrieved successfully`,
              `  CID: ${params.cid}`,
              `  DID: ${params.did}`,
              `  Content-Type: ${contentType}`,
              `  Size: ${bytes.length} bytes`,
              `  Base64: ${base64}`,
            ].join("\n"),
          },
        ],
        details: {
          cid: params.cid,
          did: params.did,
          contentType,
          size: bytes.length,
          base64,
        },
      };
    },
  });

  // ── atproto_xrpc ─────────────────────────────────────────────────────────

  pi.registerTool({
    name: "atproto_xrpc",
    label: "XRPC Call",
    description:
      "Make a generic XRPC call to the relay. Supports GET, POST, PUT, DELETE.",
    promptSnippet: "Make an XRPC API call",
    promptGuidelines: [
      "Use for testing any ATProto endpoint not covered by other tools.",
      "Path should start with /xrpc/ (e.g. /xrpc/com.atproto.server.getSession)",
    ],
    parameters: Type.Object({
      path: Type.String({
        description: "XRPC path (e.g. /xrpc/com.atproto.server.getSession)",
      }),
      method: Type.Optional(
        StringEnum(["GET", "POST", "PUT", "DELETE"] as const, {
          description: "HTTP method (default GET)",
        })
      ),
      access_jwt: Type.Optional(
        Type.String({ description: "ATProto access JWT for auth" })
      ),
      body: Type.Optional(
        Type.Any({ description: "Request body (for POST/PUT)" })
      ),
      params: Type.Optional(
        Type.Record(Type.String(), Type.String(), {
          description: "Query parameters",
        })
      ),
    }),
    async execute(_id, options) {
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
      };
      if (options.access_jwt) {
        headers["Authorization"] = `Bearer ${options.access_jwt}`;
      }

      let url = `${baseUrl}${options.path}`;
      if (options.params) {
        const qs = new URLSearchParams(options.params).toString();
        url += `?${qs}`;
      }

      const res = await fetch(url, {
        method: options.method || "GET",
        headers,
        body: options.body ? JSON.stringify(options.body) : undefined,
      });

      const contentType = res.headers.get("content-type") || "";
      let result: unknown;
      if (contentType.includes("json")) {
        result = await res.json();
      } else {
        result = await res.text();
      }

      return {
        content: [
          {
            type: "text",
            text: `HTTP ${res.status}\n\n${
              typeof result === "string"
                ? result
                : JSON.stringify(result, null, 2)
            }`,
          },
        ],
        details: { status: res.status, body: result },
      };
    },
  });

  // ── atproto_describe_server ──────────────────────────────────────────────

  pi.registerTool({
    name: "atproto_describe_server",
    label: "Describe Server",
    description:
      "Get server info including DID, available user domains, and invite requirements.",
    promptSnippet: "Get server information",
    parameters: Type.Object({}),
    async execute() {
      const data = await relayRequest(baseUrl, "/xrpc/com.atproto.server.describeServer");
      return {
        content: [
          {
            type: "text",
            text: [
              `Server DID: ${data.did}`,
              `Available domains: ${data.availableUserDomains?.join(", ")}`,
              `Invite required: ${data.inviteCodeRequired}`,
            ].join("\n"),
          },
        ],
        details: data,
      };
    },
  });

  // ── atproto_generate_keypair ─────────────────────────────────────────────

  pi.registerTool({
    name: "atproto_generate_keypair",
    label: "Generate P-256 Keypair",
    description:
      "Generate a P-256 keypair for ATProto operations. Returns the did:key:z... ID and hex-encoded private key.",
    promptSnippet: "Generate a P-256 keypair",
    parameters: Type.Object({}),
    async execute() {
      const kp = await P256Keypair.create({ exportable: true });
      const did = kp.did();
      const exported = await kp.export();
      const privateKeyBytes = exported instanceof Uint8Array ? exported : (exported as any).bytes || exported;
      return {
        content: [
          {
            type: "text",
            text: [
              `Key ID: ${did}`,
              `Private key (hex): ${Buffer.from(privateKeyBytes).toString("hex")}`,
            ].join("\n"),
          },
        ],
        details: {
          keyId: did,
          privateKeyHex: Buffer.from(privateKeyBytes).toString("hex"),
        },
      };
    },
  });
}
