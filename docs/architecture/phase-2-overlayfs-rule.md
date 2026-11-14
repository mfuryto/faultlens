# Phase 2: reported OverlayFS layer reuse

Diagnose adds `kernel.overlay_layer_reuse` for the two complete kernel warning
formats reporting upperdir or workdir already in use as an upper/work directory of
another mount, followed by the undefined-behavior warning. The message structure
was checked against Linux v6.12's `ovl_report_in_use` implementation. Only kernel
transport and an exact supported message, optionally ending in one newline, match.
Application quotations, embedded mentions, path-bearing variants, trailing content,
other roles and different error/protection messages remain unsupported.

## Finding semantics

The finding confirms a recorded warning with warning severity and retains its
normalized evidence reference. The observation identifies only the fixed role label
upperdir/workdir; raw message text and mount paths are not emitted. Root cause and
shutdown conclusions remain Unknown. This does not establish an active present-day
conflict, data corruption, container failure, OOM, whole-system freeze or responsibility
for an unexpected reboot.

The warning does not identify the relevant mount paths, namespaces, owning container
or responsible service. A current mount snapshot can differ from historical state.
Distinct path strings do not prove distinct underlying directories, and a visible
namespace does not necessarily include other namespaces. Paired upperdir/workdir
reports may reflect the same mount operation; two findings are not two independent
incidents. Nearby Docker/container activity is temporal context only.

Recommendations ask for local evidence review and comparison with relevant mount
and lifecycle state before identifying an owning workload. Faultlens does not run
findmnt, Docker or namespace commands, add them as dependencies, change mount options,
unmount filesystems, delete layers, restart services or disable protection. Docker
stop timeout/exit-code interpretation remains outside this rule; exit 137 is not
converted into an OOM diagnosis.

## Existing search and coverage behavior

The rule runs within the ordinary bounded selected-boot tail and existing targeted
kernel warning/error query. No new flag, collector, command, permission or dependency
is introduced. Targeted matches become supported findings and are counted as matched
candidates; other unknown reports remain in candidate_review. The filtered result
still does not change main-tail coverage, shutdown assessment or Atop window scope.
Optional Atop overlap remains Possible and uses the journal report time only.

## Verification and limits

Synthetic tests cover both role variants, exact formatting, provenance, unsupported
protection/path variants, control/private suffix rejection, text/JSON redaction,
targeted-review transitions, equal references without cursors and uncertain Atop
pairing. A fresh-process benchmark verifies 500 retained OverlayFS findings from 501
invented reports. No real paths, container identifiers, diagnostic fixtures, mounts
or service operations are used in CI. Owner-supplied historical warnings motivated
the rule; live root-session revalidation remains an owner-run compatibility check.
Supported formats are intentionally narrow and do not detect every OverlayFS problem.
Kernel/root compromise can falsify local evidence. Phase 2 remains incomplete.

Primary references: [Linux v6.12 OverlayFS warning implementation](https://github.com/torvalds/linux/blob/v6.12/fs/overlayfs/super.c),
[OverlayFS layer-sharing documentation](https://www.kernel.org/doc/html/latest/filesystems/overlayfs.html).
