import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import { canonicalize } from "./canonical-json.mjs";

// Control point: contract authorization against a base-authoritative trust
// root. A contract's authorization signature is NEVER trusted merely because
// it is internally self-consistent; the authorizing key must appear in the
// selected profile's trusted-authorizer set (which lives in the trusted base,
// outside the contract), and the contract's claimed identity must match that
// key. Under an UNSIGNED_PERSONAL profile mode, unsigned contracts are an
// explicit, profile-authorized policy — not authenticated provenance.
export const CONTROL_POINTS = Object.freeze(["contract-authorization"]);

function integrityValid(workContract, signature) {
  const unsigned = { ...workContract, authorization: { ...workContract.authorization, signature: null } };
  const message = Buffer.from(canonicalize(unsigned), "utf8");
  try {
    const key = createPublicKey({
      key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(signature.publicKey, "hex").toString("base64url") },
      format: "jwk"
    });
    return cryptoVerify(null, message, key, Buffer.from(signature.signature, "hex"));
  } catch {
    return false;
  }
}

// authorizationPolicy is the selected profile's authorization block:
//   { mode: "SIGNED" | "UNSIGNED_PERSONAL", trustedAuthorizers: [{identity, publicKey}] }
export function verifyContractAuthorization(workContract, authorizationPolicy) {
  const signature = workContract.authorization.signature;
  const mode = authorizationPolicy?.mode ?? "UNSIGNED_PERSONAL";
  const trusted = authorizationPolicy?.trustedAuthorizers ?? [];

  if (signature === null) {
    if (mode === "SIGNED") {
      return { ok: false, reasonCode: "AUTHORIZATION_INVALID", message: "profile requires a signed contract, but the contract is unsigned" };
    }
    // Explicit unsigned-personal policy: allowed, but not authenticated.
    return { ok: true, authenticated: false, mode };
  }

  // A present signature must be structurally valid regardless of mode: the
  // field is load-bearing, never inert.
  if (!integrityValid(workContract, signature)) {
    return { ok: false, reasonCode: "AUTHORIZATION_INVALID", message: "contract authorization signature does not verify over the contract body" };
  }

  if (mode === "UNSIGNED_PERSONAL") {
    // Personal mode does not authenticate provenance even for a valid
    // self-signature; the signature only proves body integrity.
    return { ok: true, authenticated: false, mode, publicKey: signature.publicKey };
  }

  // SIGNED mode: the key must be a trusted authorizer AND the claimed identity
  // must match that authorizer.
  const authorizer = trusted.find((a) => a.publicKey === signature.publicKey);
  if (!authorizer) {
    return { ok: false, reasonCode: "AUTHORIZATION_INVALID", message: "contract is signed by a key that is not a trusted authorizer for this profile" };
  }
  if (workContract.authorization.identity !== authorizer.identity) {
    return { ok: false, reasonCode: "AUTHORIZATION_INVALID", message: `contract identity ${JSON.stringify(workContract.authorization.identity)} does not match the trusted authorizer for its signing key` };
  }
  return { ok: true, authenticated: true, mode, identity: authorizer.identity, publicKey: signature.publicKey };
}
