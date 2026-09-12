// Derived admission defaults. Hygiene (UNSIGNED_PERSONAL) may evaluate a
// fixture repository. A SIGNED profile is a promotion gate: the subject must
// be a real commit graph, the issuer must be authenticated, and declared
// authorities may not be silently null.

export function subjectBindingOf(authorizationPolicy) {
  if (authorizationPolicy?.subjectBinding === "REPOSITORY" || authorizationPolicy?.subjectBinding === "FIXTURE") {
    return authorizationPolicy.subjectBinding;
  }
  return authorizationPolicy?.mode === "SIGNED" ? "REPOSITORY" : "FIXTURE";
}
