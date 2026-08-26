import { candidateIdentityVerify, candidateTreeStability } from "./validators/candidate-identity.mjs";
import { scopeBoundaryClassify } from "./validators/scope-boundary.mjs";
import { validationPlanExecute } from "./validators/validation-plan.mjs";
import { evidenceBindingIndex } from "./validators/evidence-binding.mjs";

// Closed registry of builtin validators. `implemented` is derived from the
// presence of an executable `run` function — a registry row can never claim
// an implementation that does not exist, and an implementation cannot ship
// without a registry row (the dispatcher only resolves through this table).
// `sourceFile` names the module whose bytes are the validator identity
// digest bound into receipts.
const definitions = {
  "candidate-identity-verify@1": {
    packId: "candidate-identity",
    outputSchemaId: "check-result@1",
    sourceFile: "validators/candidate-identity.mjs",
    run: candidateIdentityVerify
  },
  "candidate-tree-stability@1": {
    packId: "candidate-identity",
    outputSchemaId: "check-result@1",
    sourceFile: "validators/candidate-identity.mjs",
    run: candidateTreeStability
  },
  "scope-boundary-classify@1": {
    packId: "scope-boundary",
    outputSchemaId: "check-result@1",
    sourceFile: "validators/scope-boundary.mjs",
    run: scopeBoundaryClassify
  },
  "validation-plan-execute@1": {
    packId: "validation-plan",
    outputSchemaId: "check-result@1",
    sourceFile: "validators/validation-plan.mjs",
    run: validationPlanExecute
  },
  "evidence-binding-index@1": {
    packId: "evidence-binding",
    outputSchemaId: "check-result@1",
    sourceFile: "validators/evidence-binding.mjs",
    run: evidenceBindingIndex
  }
};

export const BUILTIN_VALIDATORS = Object.freeze(
  Object.fromEntries(
    Object.entries(definitions).map(([id, def]) => [
      id,
      Object.freeze({ ...def, implemented: typeof def.run === "function" })
    ])
  )
);

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

export function resolveBuiltinValidator(builtinId) {
  const descriptor = BUILTIN_VALIDATORS[builtinId];
  if (!descriptor) throw new Error(`unknown builtin validator ${builtinId}`);
  if (!descriptor.implemented) throw new Error(`builtin validator ${builtinId} is not implemented`);
  return descriptor.run;
}
