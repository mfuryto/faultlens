# Phase 2: select a stable journal boot identity

Diagnose accepts `--boot-id` for repeatable selection of an exact boot identity even
when relative indices change after a reboot. Existing `--boot`, `--previous-boot`
and default previous-visible-boot behavior remain available. These selectors are
mutually exclusive and valid only for diagnose.

```sh
./bin/faultlens history --system-journal
```

Copy an ID from the listing in the intended scope. The following is an invented ID;
replace it with the exact identity observed in that listing:

```sh
./bin/faultlens diagnose --boot-id 0123456789abcdef0123456789abcdef --system-journal --search-events --json
```

Only exactly 32 lowercase hexadecimal characters are accepted. Abbreviations,
uppercase variants, hyphenated UUIDs, paths, control characters and extra arguments
are rejected before collection. The programmatic diagnose interface uses a null
index to indicate the default selector, and rejects supplying both an explicit
index and an ID. Without an ID or index it still selects index -1.

## Scope and failure behavior

The identity must occur in the existing bounded, validated boot listing for the
requested visible/system journal scope. Matching an ID in another scope does not
grant access. An unavailable, empty or malformed listing prevents selection. An ID
missing from that listing is unavailable; no direct out-of-list query, alternate
scope, current boot or other index is substituted. Permissions, rotation and the
listing limit still restrict which identities can be selected. An absent ID is not
proof that the boot never occurred.

Once resolved, both targeted queries and ordinary tail collection use the same
immutable ID. Selected-boot output retains the current listing index as context;
it does not reinterpret the request as that index on later runs. Existing mixed-
boot response rejection remains in place. A selected ID identifies the scoped
journal evidence, not authenticated machine identity, complete history or the boot
of independent Atop/pstore evidence.

## Report and validation

Diagnose adds `boot_selection` with method (id/index), normalized requested selector
and state: unresolved, listing_unavailable, not_visible or resolved. A resolved
selection does not imply collection or diagnosis succeeded; inspect journal_collection
and each source state independently. Text output also shows the selection metadata.
No collection command, privilege, dependency or raw-log output is added, and existing
resource limits and Unknown root-cause/shutdown semantics remain unchanged.

Synthetic tests cover IDs moving between relative indices, default/index compatibility,
missing IDs, failed/invalid listings, scope-local membership, consistent search/tail
identity, mixed-boot responses, malformed inputs and conflicting selectors. The
existing system-scope resource benchmark now exercises exact-ID selection with 500
retained records; other diagnostic modes retain index selection. A local read-only
visible-scope smoke resolved an exact listed identity and returned the same selected
identity without printing raw records or boot identifiers. This does not establish
complete system access or full incident reconstruction. Phase 2 remains incomplete.
