import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import { canonicalize } from "./canonical-json.mjs";

// Control point: contract authorization. The work-contract's
// authorization.signature is mechanically load-bearing — when present it must
// be a valid Ed25519 signature by the embedded public key over the canonical
// contract with the signature field nulled. A contract carrying a malformed
// or non-matching signature is rejected (AUTHORIZATION_INVALID) rather than
// accepted with an inert field. Absence of a signature is allowed (the
// identity + issuance time still bind provenance); presence is enforced.
export const CONTROL_POINTS = Object.freeze(["contract-authorization"]);

export function verifyContractAuthorization(workContract) {
  const signature = workContract.authorization.signature;
  if (signature === null) {
    return { ok: true, signed: false };
  }
  const unsigned = {
    ...workContract,
    authorization: { ...workContract.authorization, signature: null }
  };
  const message = Buffer.from(canonicalize(unsigned), "utf8");
  try {
    const key = createPublicKey({
      key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(signature.publicKey, "hex").toString("base64url") },
      format: "jwk"
    });
    const valid = cryptoVerify(null, message, key, Buffer.from(signature.signature, "hex"));
    if (!valid) {
      return { ok: false, reasonCode: "AUTHORIZATION_INVALID", message: "contract authorization signature does not verify" };
    }
    return { ok: true, signed: true, publicKey: signature.publicKey };
  } catch {
    return { ok: false, reasonCode: "AUTHORIZATION_INVALID", message: "contract authorization signature is malformed" };
  }
}
