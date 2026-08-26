// Closed registry of builtin validator identifiers reserved for the four
// mandatory kernel packs. None is implemented yet: implementations arrive in
// a later phase, and the orphan census keys off `implemented` so a reserved
// id can never be claimed as live before its executable exists.
export const BUILTIN_VALIDATORS = Object.freeze({
  "candidate-identity-verify@1": Object.freeze({
    packId: "candidate-identity",
    implemented: false,
    outputSchemaId: "check-result@1"
  }),
  "scope-boundary-classify@1": Object.freeze({
    packId: "scope-boundary",
    implemented: false,
    outputSchemaId: "check-result@1"
  }),
  "validation-plan-execute@1": Object.freeze({
    packId: "validation-plan",
    implemented: false,
    outputSchemaId: "check-result@1"
  }),
  "evidence-binding-index@1": Object.freeze({
    packId: "evidence-binding",
    implemented: false,
    outputSchemaId: "check-result@1"
  })
});

export function knownBuiltinValidatorIds() {
  return new Set(Object.keys(BUILTIN_VALIDATORS));
}

export function implementedBuiltinValidatorIds() {
  return new Set(
    Object.entries(BUILTIN_VALIDATORS)
      .filter(([, descriptor]) => descriptor.implemented)
      .map(([id]) => id)
  );
}
