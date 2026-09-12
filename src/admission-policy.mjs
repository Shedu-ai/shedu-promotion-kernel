// Derived admission defaults. Hygiene (UNSIGNED_PERSONAL) may evaluate a
// fixture repository. A SIGNED profile is a promotion gate: the subject must
// be a real commit graph, the issuer must be authenticated, and declared
// authorities may not be silently null.

export const CONTRACT_ISSUERS = Object.freeze(["SUBMITTER", "CI", "MAINTAINER"]);

export function subjectBindingOf(authorizationPolicy) {
  if (authorizationPolicy?.subjectBinding === "REPOSITORY" || authorizationPolicy?.subjectBinding === "FIXTURE") {
    return authorizationPolicy.subjectBinding;
  }
  return authorizationPolicy?.mode === "SIGNED" ? "REPOSITORY" : "FIXTURE";
}

export function allowedIssuersOf(authorizationPolicy) {
  const allowed = authorizationPolicy?.allowedIssuers;
  if (Array.isArray(allowed) && allowed.length > 0) return allowed;
  return authorizationPolicy?.mode === "SIGNED" ? ["CI", "MAINTAINER"] : ["SUBMITTER"];
}

export function claimedIssuerOf(workContract, authenticated) {
  const claimed = workContract?.authorization?.issuer;
  if (CONTRACT_ISSUERS.includes(claimed)) return claimed;
  return authenticated ? "MAINTAINER" : "SUBMITTER";
}
