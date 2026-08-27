// A closed, typed control-runtime ledger. Every admission- or
// disposition-affecting control event flows through this ledger. Recording an
// event for a control that is NOT in the registered set throws: a control
// omitted from the registry cannot emit an admissible event. The ledger is
// the runtime evidence the control-surface census consumes for invocation,
// evidence, and consumption — replacing string occurrence with execution.

export class ControlLedgerError extends Error {
  constructor(message) {
    super(message);
    this.name = "ControlLedgerError";
    this.reasonCode = "CONTROL_UNREGISTERED";
  }
}

export function createControlLedger(registeredIds) {
  const registered = new Set(registeredIds);
  const events = [];
  return {
    // Record one control event. `evidence` is the machine artifact the
    // control produced; `consumed` marks that a consumer acted on it.
    record({ controlId, invocation, inputDigest = null, outcome, evidence = null, consumer = null, dispositionEffect = false, proven = false }) {
      if (!registered.has(controlId)) {
        throw new ControlLedgerError(`control ${JSON.stringify(controlId)} is not registered and cannot emit an admissible event`);
      }
      const event = { controlId, invocation, inputDigest, outcome, evidence, consumer, dispositionEffect, proven };
      events.push(event);
      return event;
    },
    events() {
      return events.map((e) => ({ ...e }));
    },
    invoked() {
      return new Set(events.map((e) => e.controlId));
    },
    proven() {
      return new Set(events.filter((e) => e.proven).map((e) => e.controlId));
    }
  };
}
