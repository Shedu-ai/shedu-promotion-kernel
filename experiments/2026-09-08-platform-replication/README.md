# Frozen platform replication

This package preserves the exact inputs and harnesses of the second independent Astra experiment. It compares the merged baseline e82010f0c6ae13fb59f62710e26ad2bdf49a7dc8 with the workflow's exact corrected commit on macOS and Linux. The source experiment's original `subjectCommit` identifies its historical discovery baseline; each new run records its actual source identity separately.

The input manifest and replication manifest are checked before execution. The 12 cases run three times each; all 36 receipts must verify offline. All 54 activation-pair checks must execute on Linux; macOS retains 18 unsupported bounded checks as NOT_EXECUTED and requires the other 36 to match. Another 24 signature checks must match. Synthetic signing keys are generated in memory and provide no release authority.

The runner constructs an explicit environment without provider credentials or GitHub tokens. Checkout does not persist authentication. The Linux container image is pinned by digest in the kernel source. Raw receipts, plans, evidence, verifier streams, mutation inputs, execution identity and timing are retained in downloadable workflow artifacts. Git target checkouts are excluded from the archive and are reproducible from the frozen bundles.

Run `node experiments/2026-09-08-platform-replication/replicate.mjs /absolute/kernel/check-out unique-label /absolute/disposable/tmp` after pulling the pinned image on Linux. Use a new label for every attempt; outputs are never overwritten.

This is replication of a previously source-aware assessment, not a blinded trial or an external certification. Hosted runner images and artifact retention are mutable; the downloaded archive digest supports integrity checking, not WORM storage or reproducible performance claims.
