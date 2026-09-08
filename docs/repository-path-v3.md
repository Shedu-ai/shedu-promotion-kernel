# Repository paths in version 3

`work-contract@3`, `compiled-policy-plan@3` and `promotion-receipt@3` add explicit support for repository filenames containing spaces, well-formed Unicode and punctuation such as `%`, `#` and quotes. A version 3 work contract produces a version 3 plan and receipt. Existing version 1 and 2 schemas remain unchanged.

Only repository scope entries and receipt changed-file paths use the broader representation. Authority-document paths and output-artifact paths retain their original restricted alphabet. Version 3 uses `policy-profile@2` and `policy-pack@2`, with the same explicit execution requirements, task limits, compiled authority and receipt execution reports as version 2. A new filename format grants no additional execution capability.

Names retain their exact Git UTF-8 spelling in scope matching, receipts and digests. Percent sequences are literal filename characters. The kernel does not normalize or URL-decode identity. Git filename transport rejects malformed UTF-8 instead of substituting replacement characters. Candidate names that collide after NFC normalization and lowercase comparison are rejected by the scope control because they can alias on supported filesystems.

Both schema and semantic validation are required. Repository paths must contain 1–512 UTF-16 code units and reject absolute paths, a leading dash, backslashes, colons, control or format characters, empty segments, `.` or `..` segments and `.git` segments (case-insensitive). Only scope prefixes may end with `/`. The Git and filesystem limits of the execution host still apply; this is not support for arbitrary byte filenames or every operating system.

For example, `src/a valid name.mjs` may appear in `scope.allowed` or beneath an allowed `src/` prefix in a version 3 contract. An identical version 2 contract still rejects that changed-file representation. Read-only and forbidden scopes retain their precedence rules, and a rename remains independently classified as a deletion and an addition.

The closed format mapping in `src/contracts.mjs` is shared by compilation, evaluation, supervision, offline receipt verification and published-evidence consumers. Changing a document's declared version does not migrate its authority or repair its digests. Produce a fresh evaluation from the intended work-contract version.

Run `node scripts/generate-repository-path-schemas.mjs` to reproduce the three new schemas from the frozen version 2 definitions. This change does not recertify the public launcher; a new external certificate must bind the selected source commit before the launcher can advance.
