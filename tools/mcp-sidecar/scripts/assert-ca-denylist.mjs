// Build-time guard: fail if the CA bundle Node will trust still contains a root
// that anchors a known-compromised chain.
//
// The sidecar runs with `--use-openssl-ca` and SSL_CERT_FILE pointing at the
// Alpine bundle (see the Dockerfile), so this bundle is exactly what outbound
// TLS trusts. Roots are matched by SubjectPublicKeyInfo hash, so a re-issued
// certificate over the same key is still caught.
//
// Usage: node assert-ca-denylist.mjs [bundle.pem]   (defaults to $SSL_CERT_FILE)

import { X509Certificate } from "node:crypto";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

// eMudhra intermediate key compromise, October 2026: every affected chain
// anchors at one of these two roots (https://emudhra.we-have-a-problem.com/).
const DENIED_SPKI_SHA256 = new Map([
  ["8d417db2dd8bf5e3084d1e3f196d583849d81bdd4c00c70b9d39369e96b8c782", "emSign ECC Root CA - G3"],
  ["bd153ed7b0434f6886b17bce8bbe84ed340c7132d702a8f4fa318f756ecbd6f3", "AAA Certificate Services"],
]);

const bundlePath = process.argv[2] ?? process.env.SSL_CERT_FILE;
if (!bundlePath) {
  console.error("✗ no CA bundle given and SSL_CERT_FILE is unset");
  process.exit(1);
}

const pems = readFileSync(bundlePath, "utf8").match(
  /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g,
) ?? [];
// An empty or unreadable bundle would pass a denylist trivially.
if (pems.length < 50) {
  console.error(`✗ ${bundlePath} holds only ${pems.length} certificates; refusing to vouch for it`);
  process.exit(1);
}

const hits = [];
for (const pem of pems) {
  const spki = new X509Certificate(pem).publicKey.export({ type: "spki", format: "der" });
  const name = DENIED_SPKI_SHA256.get(createHash("sha256").update(spki).digest("hex"));
  if (name) hits.push(name);
}

if (hits.length > 0) {
  console.error(`✗ ${bundlePath} still trusts denied root(s): ${hits.join(", ")}`);
  process.exit(1);
}
console.log(`✓ ${bundlePath}: ${pems.length} roots, none denied`);
