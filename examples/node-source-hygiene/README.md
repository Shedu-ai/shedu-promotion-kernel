# Node source-hygiene policy pack

This is a runnable example of target-owned policy authority. It is deliberately small:
the blocking check rejects `TODO` and `FIXME` markers in JavaScript and TypeScript source
files in the immutable candidate.

```text
.shedu/
├── policy/
│   ├── node-source-hygiene.json  policy-pack@1
│   └── profile.json              policy-profile@1 with an exact raw-byte pack digest
└── validators/
    └── source-hygiene.mjs        base-owned validator named by an exact argv array
```

The pack itself is declarative. Executable policy lives in the separately declared
validator, and `inputManifest` grants the sandbox read access to exactly that base-owned
file. The kernel injects `KERNEL_CANDIDATE_DIR`; the validator reads the candidate, writes
nothing, opens no network connection, and spawns no child process. Its JSON stdout and
exit status become evidence. Exit `0` passes; exit `1` fires the blocking check.

## Verify before copying

From the kernel repository root:

```sh
npm run verify:sample-policy
```

The verifier performs all of these checks without a provider:

1. strict schema and semantic validation of the pack and profile;
2. equality of the profile's pack pin and the SHA-256 digest of the exact pack bytes;
3. a conforming validator fixture that must pass;
4. a planted marker fixture that must block; and
5. a real immutable-base CLI compilation that must include the sample check and the
   kernel's mandatory integrity packs.

Any pack/profile drift makes this command and the repository test suite fail.

## Copy into a target repository

```sh
cp -R examples/node-source-hygiene/.shedu /absolute/path/to/target-repository/
```

Commit the copied files before creating the work contract. The contract's
`policyProfile` reference must use:

```json
{
  "profileId": "node-personal",
  "path": ".shedu/policy/profile.json",
  "digest": "sha256:<RAW_PROFILE_FILE_DIGEST>"
}
```

Compute the raw-byte digest mechanically from a pinned kernel checkout:

```sh
node scripts/digest-authority.mjs /absolute/path/to/target-repository/.shedu/policy/profile.json
```

If you edit the pack, first compute its new raw-byte digest with the same command and put
that value in `.shedu/policy/profile.json`; then compute the profile digest for the work
contract. The digests bind exact file bytes, including whitespace and the final newline.

`UNSIGNED_PERSONAL` is appropriate only when the repository owner is the sole authority.
Organizations should change the profile to `SIGNED`, register their trusted authorizer
public keys, and supply a correctly signed work contract. The sample does not weaken or
replace the four mandatory kernel packs; those are injected by the compiler independently.
