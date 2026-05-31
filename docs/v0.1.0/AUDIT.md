# Linx v0.1.0 — Phase-1 Release-Consistency Audit

This document is the Phase-1 deliverable of the v0.1.0 release-consistency audit. It records, with `file:line` citations, every site in the Linx codebase that must change to satisfy the four locked release decisions. It is an audit, not a fix: nothing here was edited, and the findings below are the actionable checklist for the fixup phase.

The decisions are **locked** — this document records what to change to satisfy them, not whether to adopt them:

- **D1** — Collapse the four post-terminal atoms (`:already_terminated`, `:ended`, `:session_terminated`, `:session_ended`) to a single `{:error, :no_process}` across Process + Tty.
- **D2** — Error shape by context-richness: `%Linx.X.Error{}` (defexception + `message/1` + uniform core `operation`/`errno`/`code`, with honest extras `path`/`message`/subsystem-specifics only where non-nil) for kernel failures; bare atoms for context-free conditions; `{:error, {:bad_*, reason}}` tuples for caller validation. Add `Linx.Process.Error` + `Linx.Tty.Error`. Add `:operation` to `Linx.Netlink.Error`.
- **D3** — Minimal SUMMARY `Inspect` on Netfilter containers + `Seccomp.Builder`; leaf structs unchanged.
- **D4** — (Referenced by the plan's commit structure; covered transitively by the dimension findings below.)

## Summary

| metric | count |
|---|---|
| total | 114 |
| inconsistency | 35 |
| gap | 36 |
| nit | 9 |
| verified-ok | 34 |

State of the library: Linx is in good shape for v0.1.0. The bulk of the design — validation-tuple conventions, forward-compat strategies, `@spec` coverage of public APIs, `Inspect` on leaf types, and moduledoc shape across nine of ten subsystems — is already consistent and verified. The actionable work clusters into a small number of well-defined seams: (1) the **D1 atom unification** ripples through Process, Tty, Capabilities, Seccomp specs, every relevant test file, and the docs; (2) the **D2 error-shape work** is mostly the two missing structs (`Linx.Process.Error`, `Linx.Tty.Error`) plus adding `:operation` to `Linx.Netlink.Error`, the only existing error struct missing it; (3) the **D3 Inspect work** is five Netfilter container structs plus `Seccomp.Builder`, following the already-established `Patch`/`Filter` summary pattern. Beyond the locked decisions, the two recurring polish themes are the **Netlink subsystem tree** (sparse moduledocs, no examples/status, the lone documentation laggard) and **forward-compat strategy documentation** (the behavior is correct everywhere but undocumented). The `cgroup_test.exs` `@moduletag :integration`-in-a-mixed-file bug is the one test-hygiene defect that silently excludes unit tests from the default run.

## Findings by dimension

### 1. Error struct shapes & D2 conformance

| id | subsystems | sev | current (file:line) | should be | fix locations | D# |
|---|---|---|---|---|---|---|
| netlink-missing-operation | Netlink | inconsistency | `lib/linx/netlink/error.ex:19-20` defines `[:errno, :code, :message]`, no `:operation`; only error struct in either family lacking it | Add `:operation` atom to fields + `@enforce_keys`; update `from_errno/2` to track the failing operation (`:open`/`:send`/`:recv`) | `lib/linx/netlink/error.ex` | D2 |
| netlink-impl-true-nit | Netlink | nit | `lib/linx/netlink/error.ex:88` uses `@impl true`; all other structs use `@impl Exception` | Standardize to `@impl Exception` | `lib/linx/netlink/error.ex` | D2 |
| message-wording-inconsistency-path-suffix | Netlink, Seccomp, Netfilter | nit | Message wording differs by family; Netlink (no `:operation`) reads `"netlink <format_errno()>[: <msg>]"` | After `:operation` added, Netlink uses Family-B pattern `"<subsys> <op> failed: <errno>[: extra]"`; verify Seccomp/Netfilter parallel | `lib/linx/netlink/error.ex` | D2 |
| process-no-error-struct-d2-gap | Process | gap | No error struct; errors are `:no_pty` or `{:linx_process, :error, errno, stage}` tuples | Create `Linx.Process.Error` (Family B): `@enforce_keys [:operation, :errno]`, fields `[:operation, :errno, :code]`; `from_posix(stage, errno)`; `message/1` = `"process <stage> failed: <errno>(code)"` | `lib/linx/process/error.ex` (new) | D2 |
| tty-no-error-struct-d2-gap | Tty | gap | No error struct; errors are bare atoms or `{:error, {stage, errno}}` | Create `Linx.Tty.Error` (Family B): `@enforce_keys [:operation, :errno]`, fields `[:operation, :errno, :code]`; `from_posix(stage, errno)`; `message/1` = `"tty <stage> failed: <errno>(code)"` | `lib/linx/tty/error.ex` (new) | D2 |
| process-tty-atom-consolidation-d1 | Process, Tty | inconsistency | Process `:no_pty` at `lib/linx/process.ex:929,941,954`; Tty post-terminal atoms documented at `lib/linx/tty.ex:254` | Per D1, standardize post-terminal/context-free returns to `{:error, :no_process}` (Process) and consolidated atoms for Tty | `lib/linx/process.ex`, `lib/linx/tty.ex` | D1 |

Verified-ok in this dimension:
- **family-a-from-posix-arity-inconsistency** (Cgroup, Mount, User, Capabilities, Sysctl) — Sysctl's `from_posix/4` adds `:key` as honest-extra at `lib/linx/sysctl/error.ex:103`; intentional, not a bug.
- **netfilter-subsys-extras-d2-honest** (Netfilter) — `lib/linx/netfilter/error.ex:85-96`; uniform core + nil-when-absent honest extras (`subsys`/`msg_type`/`batch_seq`/`attr_offset`/`ruleset_gen`) conform to D2.
- **message-impl-consistency-all-six** (all eight existing structs) — all implement `Exception` + `message/1` (only the `@impl true` nit on Netlink remains).
- **family-b-no-path-consistent** (Seccomp, Netfilter) — both lack `:path`, operation-first arity, parallel `message/1`; the model for new Process/Tty structs.
- **enforce-keys-consistency** (all eight) — `@enforce_keys` correct everywhere; add `:operation` to Netlink's once the field lands.

### 2. Post-terminal atom unification (D1)

| id | subsystems | sev | current (file:line) | should be | fix locations | D# |
|---|---|---|---|---|---|---|
| already-terminated-process-proceed | Process | inconsistency | `process.ex:284,301,347,353` docs; `:721,:736` return `{:error, :already_terminated}` from `handle_call(:proceed)` | Return `{:error, :no_process}`; update docstrings/specs | `process.ex:284,301,347,353,721,736` | D1 |
| already-terminated-process-abort | Process | inconsistency | `process.ex:353` `@spec`; `:736` returns `{:error, :already_terminated}` from `handle_call(:abort)` | Return `{:error, :no_process}`; update `@spec`/docstring | `process.ex:353,736` | D1 |
| already-terminated-cap-commands | Process, Capabilities | inconsistency | `process.ex:769,774,839` return `{:error, :already_terminated}`; `capabilities.ex:262,283,327,369` document it | Return `{:error, :no_process}`; update Capabilities specs/docstrings | `process.ex:769,774,839`; `capabilities.ex:262,283,327,369` | D1 |
| ended-process-signal | Process | inconsistency | `process.ex:301` docstring; `:887` `signal/2` returns `{:error, :ended}` (only `:ended` site) | Return `{:error, :no_process}`; update docstring | `process.ex:301,887` | D1 |
| session-ended-process-wait | Process | inconsistency | `process.ex:414` `@spec`; `:429` (`:wait` catch), `:455` (`:info` catch), `:1108` (`terminate/2` waiter reply) return `:session_ended` | Return `:no_process` at all three; update `@spec`/docstring | `process.ex:414,429,455,1108` | D1 |
| session-ended-process-pty | Process | inconsistency | `process.ex:463,491` docstrings; `:919,933,950,958` return `{:error, :session_ended}` for pty ops | Return `{:error, :no_process}`; update docstrings | `process.ex:463,491,919,933,950,958` | D1 |
| session-terminated-tty-attach | Tty | inconsistency | `tty.ex:74-76` moduledoc, `:340` `@spec`, `:417` `ensure_session_running/1` returns `{:error, :session_terminated}` | Return `{:error, :no_process}`; update moduledoc + `@spec` | `tty.ex:74,340,417` | D1 |
| session-ended-tty-attach | Tty | inconsistency | `tty.ex:340` `@spec`, `:422-423` returns `{:error, :session_ended}`, `:452-455` `format_error/1` case | Return `{:error, :no_process}`; collapse `format_error/1` case to `:no_process` | `tty.ex:340,422,452` | D1 |
| seccomp-already-terminated | Seccomp | inconsistency | `seccomp.ex:384,408` document `:already_terminated` for `install/2` (handled by `process.ex:837-839`) | Update `@spec`/docstring to `:no_process` | `seccomp.ex:384,408` | D1 |
| process-test-already-terminated | Process | inconsistency | `process_test.exs:262,268,279` expect `{:error, :already_terminated}` | Update `:268,:279` to `{:error, :no_process}` | `process_test.exs:262,268,279` | D1 |
| process-test-ended | Process | inconsistency | `process_test.exs:141,148` expect `{:error, :ended}` | Update `:148` to `{:error, :no_process}` | `process_test.exs:141,148` | D1 |
| process-test-session-ended | Process | inconsistency | `process_test.exs:442,450,453,459,663` expect `{:error, :session_ended}` | Update `:450,:459,:663` to `{:error, :no_process}` | `process_test.exs:442,450,453,459,663` | D1 |
| capabilities-test-already-terminated | Capabilities | inconsistency | `capabilities_test.exs:519,525,529,535,543,549` expect `{:error, :already_terminated}` | Update `:525,:535,:549` to `{:error, :no_process}` | `capabilities_test.exs:519,525,529,535,543,549` | D1 |
| seccomp-test-already-terminated | Seccomp | inconsistency | `seccomp_test.exs:648,655` expect `{:error, :already_terminated}` | Update `:655` to `{:error, :no_process}` | `seccomp_test.exs:648,655` | D1 |
| tty-test-session-terminated | Tty | inconsistency | `tty_test.exs:88,97,98,112-117` expect `{:error, :session_terminated}`; `format_error/1` case at `tty.ex:444-450` | Update `:97,:98` to `{:error, :no_process}`; update `format_error/1`/docstring | `tty_test.exs:88,97,98,112`; `tty.ex:444` | D1 |
| tty-test-session-ended | Tty | inconsistency | `tty_test.exs:101,108,109,119-123` expect `{:error, :session_ended}`; `format_error/1` at `tty.ex:452-455` | Update `:108,:109` to `{:error, :no_process}`; merge `format_error/1` case into main `:no_process` handler | `tty_test.exs:101,108,109,119`; `tty.ex:452` | D1 |
| doc-readme-already-terminated | Documentation | inconsistency | `README.md:740,809`; `docs/capabilities/EXAMPLES.md:257`; `docs/process/EXAMPLES.md:250`; `docs/seccomp/COVERAGE.md:66`; `docs/process/PLAN.md:162,181` mention `:already_terminated` | Replace all with `:no_process` | (as listed) | D1 |
| doc-v0.1.0-plan-post-terminal | Documentation | inconsistency | `docs/v0.1.0/PLAN.md:66-68` lists all four atoms as design points | Update to reflect D1 unification to `:no_process` with rationale | `docs/v0.1.0/PLAN.md:66` | D1 |
| generated-docs-already-terminated | Documentation | inconsistency | `_build/docs/` (`Linx.Capabilities.md:117,133,190,226`; `Linx.Process.md:143,179`; `Linx.Seccomp.md:272,299`) reference the atoms | Regenerate via `mix docs` after source updates (auto-derived artifacts) | `_build/docs/` | D1 |

### 3. Inspect protocol coverage (D3)

| id | subsystems | sev | current (file:line) | should be | fix locations | D# |
|---|---|---|---|---|---|---|
| netfilter-table-missing-summary-inspect | Netfilter | gap | `table.ex:53` defstruct, no `Inspect`; default dumps all chains/sets/maps/objects/flowtables | Add summary `Inspect`: `#Linx.Netfilter.Table<inet mytable: N chains, M sets, K rules>` | `lib/linx/netfilter/table.ex` | D3 |
| netfilter-chain-missing-summary-inspect | Netfilter | gap | `chain.ex:69` defstruct, no `Inspect`; default dumps all rules | Add summary `Inspect`: `#Linx.Netfilter.Chain<mychain: N rules>` | `lib/linx/netfilter/chain.ex` | D3 |
| netfilter-set-missing-summary-inspect | Netfilter | gap | `set.ex:51` defstruct, no `Inspect`; default dumps all elements | Add summary `Inspect`: `#Linx.Netfilter.Set<blocklist(ipv4_addr): N elements>` | `lib/linx/netfilter/set.ex` | D3 |
| netfilter-map-missing-summary-inspect | Netfilter | gap | `map.ex:38` defstruct, no `Inspect`; default dumps all key-value pairs | Add summary `Inspect`: `#Linx.Netfilter.Map<port_to_chain(inet_service→verdict): N elements>` | `lib/linx/netfilter/map.ex` | D3 |
| netfilter-ruleset-missing-summary-inspect | Netfilter | gap | `ruleset.ex:72` defstruct, no `Inspect`; default dumps all tables | Add summary `Inspect`: `#Linx.Netfilter.Ruleset<2 tables, 8 chains, 240 rules>` | `lib/linx/netfilter/ruleset.ex` | D3 |
| seccomp-builder-missing-summary-inspect | Seccomp | gap | `builder.ex:32` defstruct, no `Inspect`; default dumps rules list | Add summary `Inspect`: `#Linx.Seccomp.Builder<N rules>` (mirror `Seccomp.Filter`) | `lib/linx/seccomp/builder.ex` | D3 |
| netfilter-flowtable-no-custom-inspect | Netfilter | nit | `flowtable.ex:38` defstruct, no `Inspect`; flat fields | Leaf type; default acceptable. Optional: `#Linx.Netfilter.Flowtable<ft1: ingress, [eth0, eth1]>` | `lib/linx/netfilter/flowtable.ex` | D3 |
| netfilter-object-no-custom-inspect | Netfilter | nit | `object.ex:51` defstruct, no `Inspect`; flat fields | Leaf type; default acceptable. Optional: `#Linx.Netfilter.Object<:counter ssh_attempts>` | `lib/linx/netfilter/object.ex` | D3 |

Verified-ok in this dimension:
- **rtnl-codec-custom-inspect-confirmed** (Netlink) — Link (`link.ex:337`), Address (`address.ex:129`), Route (`route.ex:187`), Neighbour (`neighbour.ex:129`), Rule (`rule.ex:185`), Stats (`stats.ex:81`) all have custom `Inspect`.
- **leaf-types-inspect-confirmed** (IP, Tty, Cgroup, Mount, User, Capabilities, Process, Sysctl) — all leaf types (IP `ip.ex:110`, Subnet `:99`, MAC `mac.ex:90`, Tty.Saved/WindowSize, Cgroup.Stats, Mount.Entry, User.Map, Capabilities.State, Process.Info, Sysctl.Entry) have custom `Inspect`.
- **netfilter-expression-and-verdict-inspect-confirmed** (Netfilter) — `Expr` (`expr.ex:614`), `Verdict` (`verdict.ex:163`), `Rule` (`rule.ex:180`) render compactly.
- **container-summary-inspect-established** (Netfilter, Seccomp) — `Patch` (`patch.ex:119`) and `Seccomp.Filter` (`filter.ex:79`) are the summary-Inspect pattern the missing containers should follow.

### 4. Public verb naming consistency

| id | subsystems | sev | current (file:line) | should be | fix locations | D# |
|---|---|---|---|---|---|---|
| create-vs-add-collision | Netlink.Rtnl.Link, Cgroup, Netfilter.Ruleset | inconsistency | `Rtnl.Link` uses `create_*` (`link.ex:44-74`); Cgroup `create/1` (`cgroup.ex:103`); `Ruleset` uses `add_table/add_chain/add_rule` (`ruleset.ex:40-120`) | Adopt single create pattern: rename `Ruleset.add_table→create_table` etc. to align `create` = materialize, `add` = membership insertion under existing parent | `lib/linx/netfilter/ruleset.ex`; docs/examples | — |
| supported-parity-gap | Process, Tty, Mount | gap | `supported?/0` present in Cgroup (`:88`), User (`:107`), Capabilities (`:148`), Seccomp (`:124`), Sysctl (`:176`), Netfilter (`:172`); absent in Process, Tty, Mount | Add `supported?/0` to Process (clone usable), Tty (`/dev/tty` accessible), Mount (mount(2) family available) | `lib/linx/process.ex`, `lib/linx/tty.ex`, `lib/linx/mount.ex` | — |
| missing-operation-on-netlink-error | Netlink | gap | `lib/linx/netlink/error.ex` lacks `:operation` | Add `:operation`, populate at all error sites for `{subsystem, operation}` matching | `lib/linx/netlink/error.ex`; `lib/linx/netlink.ex` + sites | D2 |
| netfilter-ruleset-put-vs-add | Netfilter.Ruleset | inconsistency | `put_chain/put_chain!` (`ruleset.ex:140-160`) vs `add_table/add_chain` (`:40-120`) | Rename `put_chain/put_chain!→create_chain/create_chain!`; pick one verb for the op type | `lib/linx/netfilter/ruleset.ex`; docstrings/call sites | — |
| tty-window-query-verb-asymmetry | Tty | nit | `window_size/1` (`tty.ex:208`) + `set_window_size/2` (`:229`); others pair `read`/`write` | Rename `set_window_size→write_window_size`, or document deliberate ioctl `get/set` naming | `lib/linx/tty.ex` | — |

Verified-ok in this dimension:
- **rtnl-delete-naming-inconsistency** (Netlink.Rtnl) — `Address/Route/Neighbour/Rule.delete(entity, opts)` is consistent; Netfilter's `delete_*` is encoder-internal, no user-facing conflict. Documentation-level clarification only.
- **netfilter-builder-construction-verbs** (Seccomp, Netfilter) — `allow_list/deny_list/builder` (`seccomp.ex:179-259`) vs Netfilter's pipeline DSL are intentionally subsystem-appropriate.
- **process-checkpoint-verb-clarity** (Process) — `proceed/1` (`process.ex:290`) and `abort/1` (`:354`) are semantically named; correct trade-off over wire-protocol names.

### 5. Validation-vs-kernel error split (D2 lane 3)

| id | subsystems | sev | current (file:line) | should be | fix locations | D# |
|---|---|---|---|---|---|---|
| process-validation-bare-atoms | Process | inconsistency | Bare atoms: `:bad_argv` (`process.ex:582`), `:bad_env` (`:627,630`), `:bad_stdio` (`:643,656,669`), `:bad_no_new_privs` (`:573`) | Uniform tagged tuples `{:error, {:bad_*, reason}}` to match Mount/User/Sysctl/Capabilities | `lib/linx/process.ex` | D2 |
| process-inconsistent-namespaces-tuple | Process | inconsistency | Both bare `:bad_namespaces` (`:597,615`) and tuple `{:bad_namespaces, invalid_list}` (`:594,612`) for same failure | Return tagged tuple consistently; bare atom only for non-list input | `lib/linx/process.ex` | D2 |
| netlink-error-missing-operation | Netlink | gap | `error.ex:20` has `[:errno, :code, :message]`, no `:operation` | Add `:operation` to type + `@enforce_keys`; track failing op | `lib/linx/netlink/error.ex` | D2 |
| process-no-error-struct | Process | gap | No `Linx.Process.Error`; kernel failures arrive as `{:linx_process, :error, errno, stage}` (`process.ex:39-40`) | Define struct (`operation`/`errno`/`code`); map stage atoms to `:operation` | `lib/linx/process.ex` | D2 |
| tty-no-error-struct | Tty | gap | No `Linx.Tty.Error`; errors are `{:error, {:open, :enxio}}` / bare atoms (`tty.ex:38-39,76-77`) | Define struct; convert e.g. `{:open, :enxio}` to `%Linx.Tty.Error{operation: :open, errno: :enxio, code: 6}` | `lib/linx/tty.ex` | D2 |
| seccomp-bad-action-vs-unknown-syscall | Seccomp | nit | `{:unknown_syscall, atom}` (`seccomp.ex:436`) vs `{:bad_action, action}` (`:433,457`) | Rename `:unknown_syscall→:bad_syscall` for `:bad_*` convention | `lib/linx/seccomp.ex` | D2 |
| seccomp-bad-rules-arg | Seccomp | inconsistency | `from_rules/1` returns `{:bad_rules_arg, other}` (`seccomp.ex:331`) vs per-rule `{:bad_action,_}`/`{:bad_rule,_}` | Use `{:bad_rule, {:not_a_rules_tuple, other}}` (or `%Error{operation: :build}` struct) consistently | `lib/linx/seccomp.ex` | D2 |
| user-bad-entry-vs-bad-map | User | nit | `validate_entry/1` returns `{:bad_entry, tuple}` (`user.ex:217`) always re-wrapped as `{:bad_map, reason}` by `render_map/1` (`:199`) | Either nest as `{:bad_map, {:bad_entry, tuple}}` or expose `:bad_entry` unwrapped | `lib/linx/user.ex` | D2 |

Verified-ok in this dimension:
- **mount-bad-flag-format** (Mount) — `{:bad_flag, _}` for both unknown flag and non-list (`mount.ex:427,432`).
- **capabilities-validation-tuple-shape** (Capabilities) — `{:bad_capability, cap}` (`:386,389`), `{:bad_thread_sets, {:missing, key}}` (`:404`).
- **sysctl-validation-tuple-shapes** (Sysctl) — `{:bad_key,_}` (`:375`), `{:bad_value,_}` (`:258,290,383-384,393,397`), `{:bad_in,_}` (`:425`).
- **netfilter-validation-tuples** (Netfilter) — all sub-modules return `{:bad_table/chain/rule/set/map/object/verdict/flowtable, _}`.
- **ip-and-mac-validation-tuples** (IP, MAC) — `{:bad_address,_}` (`ip.ex:59`), `{:bad_subnet,_}` (`subnet.ex:44`), `{:bad_mac,_}` (`mac.ex:41,50`).

### 6. Unknown-value / forward-compat handling

| id | subsystems | sev | current (file:line) | should be | fix locations | D# |
|---|---|---|---|---|---|---|
| netlink-unknown-attributes-silent-drop | Netlink | inconsistency | `Attr.decode/1` (`attr.ex:59-87`) + per-message codecs silently drop unknown attrs (`:170-177`) | Document the silent-drop choice (or collect into `:_unknown_attrs`) | `lib/linx/netlink/attr.ex` | — |
| mount-unknown-flags-caller-error | Mount | inconsistency | `pack_flags/2` returns `{:bad_flag, flag}` for unknown flags (strict, not forward-compat) | Document the intentional strict-at-syscall-boundary choice in moduledoc | `lib/linx/mount.ex` | — |
| cgroup-parse-keyed-forward-compat-drop | Cgroup | gap | `parse_keyed/1` (`cgroup.ex:363-370`) silently drops unparseable `cpu.stat` lines | Document in `stats/1` verb docstring that unknown counters are omitted, struct always valid with nil fields | `lib/linx/cgroup.ex` | — |
| forward-compat-strategy-undocumented | all ten | gap | No subsystem moduledoc documents its forward-compat strategy; five distinct strategies coexist | Add a "Forward compatibility" `@moduledoc` section to each subsystem (which sources grow, drop vs log vs raw vs reject, why safe) | all ten `lib/linx/*.ex` entry modules | — |
| process-error-stages-unknown-not-mentioned | Process | gap | `@error_stages` (`process.ex:148-175`) hardcoded; new C-side stages would fail `:safe` decode (BadArg) | Document version-lock requirement (or add `:unknown` fallback handled in `handle_agent_frame/2`) | `lib/linx/process.ex` | — |
| tty-error-stages-unknown-not-mentioned | Tty | gap | `@error_stages` (`tty.ex:158`) hardcoded; moduledoc (`:155-157`) only brief | Add explicit `@moduledoc` statement on `:safe`-decode stage pre-declaration + version-lock (or fallback) | `lib/linx/tty.ex` | — |
| netlink-attr-codec-dispatch-error-shape | Netlink | gap | `decode_attr_value/3`: encode raises `ArgumentError` on unknown (`codec.ex:219-220`), decode returns raw bytes (`:233`) — asymmetric | Document the intentional encode-strict / decode-lenient asymmetry in Codec | `lib/linx/netlink/codec.ex` | — |

Verified-ok in this dimension:
- **netlink-unknown-errno-sentinel** — `from_errno/2` maps unknown to `:unknown`, preserves int in `:code` (`error.ex:84-85`); the model pattern.
- **netlink-linkinfo-unknown-kind-raw-bytes** — unknown LinkInfo kind keeps raw bytes (`codec.ex:226-238`).
- **capabilities-unknown-bits-log-once-drop** — `maybe_warn_unknown_bits/2` logs once then drops (`capabilities.ex:213-214,232-246`).
- **seccomp-unknown-syscall-build-time-reject** — `do_validate_rules/3` rejects unknown syscalls at build time (`seccomp.ex:435-436`); correct for static filters.
- **mount-malformed-mountinfo-silent-drop** — `parse_line/1` drops malformed lines (`mount.ex:161-188`).
- **mount-unknown-optional-fields-skip** — `parse_propagation/1` returns `:skip` for unknown tags (`mount.ex:209-220`).
- **user-unparseable-map-lines-silent-drop** — `parse_map/1` drops non-three-integer lines (`user.ex:275-284`).
- **process-unrecognized-agent-frame-log-and-drop** — `handle_agent_frame/2` fallthrough logs+drops (`process.ex:1098-1101`).
- **tty-unrecognized-error-stage-log-and-drop** — `:safe`-mode decode + unmatched-message drop (`tty.ex:158,975-1002`).
- **sysctl-unknown-errno-integer-sentinel** — `native_error/4` maps unknown to `:unknown` + raw `:code` (`sysctl.ex:457-459`).
- **netfilter-push-mode-strict-validation** — closed-set `push_mode` validated strictly; correct.

### 7. Test tagging & async conventions

| id | subsystems | sev | current (file:line) | should be | fix locations | D# |
|---|---|---|---|---|---|---|
| cgroup-moduletag-in-mixed-file | Cgroup | inconsistency | `cgroup_test.exs:2` `async: true` mixes unit + integration but uses `@moduletag :integration` at `:266,348,371,426,472`, excluding unit tests from default runs | Use `@describetag :integration` per integration describe block (see `capabilities_test.exs:556` rationale) | `cgroup_test.exs:266,348,371,426,472` | — |
| process-kernel-tests-untagged | Process | gap | `process_test.exs:2` `async: true`; only 4 tests `@tag :integration` (`:168,298,517,540`); spawn/signal/stdio/PTY describes touch the kernel untagged | Decide + apply consistent policy: tag kernel-touching describes `@describetag :integration` or document why they run unprivileged | `process_test.exs` | — |
| tty-kernel-tests-untagged | Tty | gap | `tty_test.exs:2` `async: true`; no integration tagging; ioctl/open tests (`:160-202,136-146`) degrade gracefully | Tag kernel-touching describes `@describetag :integration` (per `mount_test.exs`) or document environment-tolerance | `tty_test.exs:160,136,148` | — |

Verified-ok in this dimension:
- **mount-user-capabilities-seccomp-sysctl-describetag-correct** (Mount, User, Capabilities, Seccomp, Sysctl, Netfilter) — correct `@describetag :integration` in mixed files (`mount_test.exs:121,157,206,331,517,738`; `user_test.exs:283,357`; `capabilities_test.exs:555`; `seccomp_test.exs:1011,1084`; `sysctl_test.exs:210,254,321,420`; `netfilter_test.exs:187`).
- **netlink-rtnl-netfilter-dedicated-integration-correct** (Netlink, Netfilter) — dedicated files correctly use `@moduletag :integration` + `async: false` (`netlink/rtnl/integration_test.exs:10,17`; `netfilter/integration_test.exs:2,4`).

### 8. @spec / @type coverage & internal boundary

| id | subsystems | sev | current (file:line) | should be | fix locations | D# |
|---|---|---|---|---|---|---|
| missing-moduledoc-false-codec-modules | Netfilter, NFT | gap | `Netfilter.Decoder` (`decoder.ex:1-2`), `Encoder` (`encoder.ex:1-2`), `Wire` (`wire.ex:1-2`) have full `@moduledoc` but are internal | Add `@moduledoc false` | `lib/linx/netfilter/{decoder,encoder,wire}.ex` | — |
| missing-moduledoc-false-nft-implementation | NFT | gap | `NFT.Formatter` (`formatter.ex:2-10`), `NFT.Runtime` (`runtime.ex:2-16`) documented but internal | Add `@moduledoc false` (keep `NFT.ParseError` public) | `lib/linx/nft/{formatter,runtime}.ex` | — |
| missing-moduledoc-false-nfnl-codec | Netlink | gap | `Netlink.Nfnl.Codec` (`codec.ex:1-36`) documented but used only internally by Netfilter | Add `@moduledoc false` | `lib/linx/netlink/nfnl/codec.ex` | — |
| missing-spec-netfilter-pull-clause | Netfilter | gap | `pull/2` second clause `def pull(%Socket{}, {family, name})` (`netfilter.ex:374`) has no `@spec`; first spec at `:359` | Add `@spec` for the `{family, name}` overload (or consolidate) | `lib/linx/netfilter.ex:374` | — |
| missing-spec-mount-module-public-funcs | Mount | gap | `list({:path, p})` (`mount.ex:138`) no `@spec`; `unescape/1` (`:246`) `@doc false` but public, no `@spec` | Add `@spec` to both clauses | `lib/linx/mount.ex:138,246` | — |
| missing-spec-process-clauses-internal | Process | inconsistency | GenServer callbacks `init/1` (`process.ex:674`), `handle_call/3` (`:719+`) lack `@spec` | No action — internal machinery; verify public verbs all have `@spec` (sampling confirms) | — | — |
| missing-spec-tty-format-error-clauses | Tty | gap | `format_error/1` four clauses (`tty.ex:345-351`) no `@spec` | Add `@spec format_error(term()) :: binary()` | `lib/linx/tty.ex:344` | — |
| missing-spec-capabilities-read-clause | Capabilities | gap | `read(:self)` (`capabilities.ex:186`) and `read(pid)` (`:188`) both lack `@spec` | Add `@spec read(:self | pos_integer()) :: {:ok, map()} | {:error, Error.t()}` | `lib/linx/capabilities.ex:186` | — |
| missing-spec-seccomp-error-clauses | Seccomp | gap | `from_rules(other)` (`seccomp.ex:330`), `to_rules(%Filter{...})` (`:357`) lack `@spec`; first `from_rules` spec at `:314` | Verify/extend specs to cover all clauses | `lib/linx/seccomp.ex:330,357` | — |
| missing-spec-sysctl-list-clause | Sysctl | gap | `list(prefix)` (`sysctl.ex:532`) delegating to `list/2` lacks `@spec` | Add `@spec list(binary()) :: {:ok, [{binary(), binary()}]} | {:error, term()}` | `lib/linx/sysctl.ex:532` | — |

Verified-ok in this dimension:
- **missing-spec-tty-attach-clause** (Tty) — `attach(:group_leader, session)` (`tty.ex:404`) covered by the union `@spec` at `:338-340`.
- **missing-spec-cgroup-set-clauses** (Cgroup) — `set_memory_max/2` (`:224-228`), `set_pids_max/2` (`:238-242`), `set_cpu_max/2` (`:258-264`) covered by single union `@spec` per Elixir multi-clause rules.
- **native-modules-documented-not-false** (Mount, Tty, Sysctl, Netlink) — `*.Native` NIF wrappers correctly carry public `@moduledoc` + `@spec`.
- **constants-modules-correctly-internal** (Capabilities, Seccomp) — `constants.ex`, `syscalls.ex` correctly `@moduledoc false`.
- **type-definitions-sparse-but-adequate** (Process, User, Netfilter, Mount, Tty) — domain `@type`s present where needed; coverage matches complexity.

### 9. Moduledoc shape (what/why/example/status)

| id | subsystems | sev | current (file:line) | should be | fix locations | D# |
|---|---|---|---|---|---|---|
| netlink-top-module-sparse | Netlink | gap | `netlink.ex:2-26` has what+why+architecture but no example, no status | Add `## Example` (open + simple Rtnl call) and `## Status` (milestones + roadmap pointer) | `lib/linx/netlink.ex` | — |
| rtnl-entry-module-minimal | Netlink | gap | `rtnl.ex:2-9` 8-line what+why, no example/status | Add `## Example` (socket + `Link.list/1`) and `## Status` (shipped resource modules) | `lib/linx/netlink/rtnl.ex` | — |
| nfnl-entry-module-minimal | Netlink | gap | `nfnl.ex:2-27` what+why+subsys table, no example, no status | Add `## Example` and `## Status` ("N0 scaffolding; N1+ for verbs") | `lib/linx/netlink/nfnl.ex` | — |
| rtnl-resource-modules-no-examples | Netlink | gap | `link.ex:2-36`, `address.ex:2-16`, `route.ex:2-16`, `neighbour.ex:2-15`, `rule.ex:2-31` have what+why but no examples | Add `## Examples` (list/create/delete snippets) matching Cgroup/Mount compact style | the five `lib/linx/netlink/rtnl/*.ex` | — |
| netlink-inconsistent-structure | Netlink | inconsistency | The whole Netlink tree lacks the what/why/example/status pattern every peer subsystem follows; reader can't see a working snippet or milestone status | Uniform the Netlink tree to the established pattern at all levels (top, Rtnl, Nfnl, resource modules) | `netlink.ex` + `rtnl.ex` + `nfnl.ex` + the five resource modules | — |

Verified-ok in this dimension:
- **all-other-subsystems-complete** (Process, Tty, Cgroup, Mount, User, Capabilities, Seccomp, Sysctl, Netfilter, NFT) — all hit the full what/why/example/status shape; these are the remediation model for Netlink.

### 10. Shared idioms (cross-namespace `:in` option and atom-set patterns)

| id | subsystems | sev | current (file:line) | should be | fix locations | D# |
|---|---|---|---|---|---|---|
| in-option-netlink-socket-type-name-divergence | Netlink | nit | `socket.ex:46` `@type netns :: :host | {:pid,_} | {:path,_}`; default `:host` (`:62`) not `:self` | Same concept as Mount/Sysctl `:in`; alias or document the naming divergence (`netns`/`:host` vs `in_target`/`:self`) | `lib/linx/netlink/socket.ex:46` | — |
| capabilities-enumerable-vs-mapset-semantic-ambiguity | Capabilities | inconsistency | `@type cap_set :: MapSet.t(cap())` (`capabilities.ex:137`); verbs accept `Enumerable.t()` (`:278,322,364`); returns always MapSet (`:217-223`) | Acceptable for UX; add docstring note that Enumerable is for caller convenience, canonical/returned form is MapSet | `lib/linx/capabilities.ex:133-137,278,322,364` | — |
| netlink-error-missing-operation-field | Netlink | inconsistency | `error.ex:19-26` `@enforce_keys [:errno, :code]`, no `:operation`; every other error struct enforces `:operation` | Add `:operation` (`:socket`/`:bind`/`:send`/`:recv`/`:request`); update type + `from_errno/2` | `lib/linx/netlink/error.ex:19-26,79-86` | D2 |
| process-and-tty-no-error-structs-yet | Process, Tty | gap | No `Linx.Process.Error`/`Linx.Tty.Error`; errors are message tuples / `{:stage, errno}` (`process.ex:39-40`) | Add both structs (`operation`/`errno`/`code`); collapse post-terminal atoms to `{:error, :no_process}` per D1 | `lib/linx/process.ex`, `lib/linx/tty.ex` | D1, D2 |

Verified-ok in this dimension:
- **in-option-consistent-mount-sysctl** (Mount, Sysctl) — `resolve_in/1` identical shape (`mount.ex:407-418`, `sysctl.ex:410-427`).
- **seccomp-rules-list-not-mapset** (Seccomp) — list-based rules are correct for ordered sequences (`seccomp.ex:218,314`; `builder.ex:59`; internal MapSet only for dup detection `:424`).
- **inspect-summary-minimal-netfilter-seccomp** (Netfilter, Seccomp) — current default Inspect on `Ruleset`/`Table`/`Chain`/`Builder` is compliant; when summaries are added they must stay minimal (overlaps with D3 dimension findings).

## Findings by subsystem

### Netlink
- **netlink-missing-operation** / **missing-operation-on-netlink-error** / **netlink-error-missing-operation** / **netlink-error-missing-operation-field**: add `:operation` to `Linx.Netlink.Error` (fields, `@enforce_keys`, `from_errno/2`, all call sites) — D2. The single most-cited Netlink change.
- **netlink-impl-true-nit**: change `@impl true` → `@impl Exception` at `error.ex:88`.
- **message-wording-inconsistency-path-suffix**: align `message/1` to Family-B wording once `:operation` lands.
- **netlink-unknown-attributes-silent-drop**: document the unknown-attr silent-drop in `attr.ex`.
- **netlink-attr-codec-dispatch-error-shape**: document encode-strict / decode-lenient asymmetry in `codec.ex`.
- **in-option-netlink-socket-type-name-divergence**: document `netns`/`:host` vs Mount/Sysctl `:in`/`:self`.
- **netlink-top-module-sparse / rtnl-entry-module-minimal / nfnl-entry-module-minimal / rtnl-resource-modules-no-examples / netlink-inconsistent-structure**: bring the whole Netlink moduledoc tree up to the what/why/example/status pattern.
- **forward-compat-strategy-undocumented**: add forward-compat moduledoc section.
- Verified-ok: errno sentinel, LinkInfo raw-bytes, Rtnl custom Inspect, dedicated integration test tagging.

### Process
- **process-no-error-struct-d2-gap / process-no-error-struct / process-and-tty-no-error-structs-yet**: create `Linx.Process.Error` (Family B, stage→operation) — D2.
- **D1 atom unification** (`already-terminated-process-proceed`, `already-terminated-process-abort`, `already-terminated-cap-commands`, `ended-process-signal`, `session-ended-process-wait`, `session-ended-process-pty`, `process-tty-atom-consolidation-d1`): replace `:already_terminated`/`:ended`/`:session_ended`/`:no_pty` returns with `{:error, :no_process}` across the cited `process.ex` lines; update specs/docstrings.
- **process-test-already-terminated / process-test-ended / process-test-session-ended**: update test expectations to `{:error, :no_process}`.
- **process-validation-bare-atoms / process-inconsistent-namespaces-tuple**: convert validation errors to uniform `{:error, {:bad_*, reason}}` tuples — D2.
- **supported-parity-gap**: add `Process.supported?/0`.
- **process-kernel-tests-untagged**: decide/apply integration tagging policy.
- **process-error-stages-unknown-not-mentioned / forward-compat-strategy-undocumented**: document stage version-lock and forward-compat.
- Verified-ok: `proceed/1`/`abort/1` verb clarity, internal GenServer clauses unspecified by design, agent-frame log-and-drop, Process.Info Inspect, domain types.

### Tty
- **tty-no-error-struct-d2-gap / tty-no-error-struct / process-and-tty-no-error-structs-yet**: create `Linx.Tty.Error` (Family B) — D2.
- **D1 atom unification** (`session-terminated-tty-attach`, `session-ended-tty-attach`, `tty-test-session-terminated`, `tty-test-session-ended`, `process-tty-atom-consolidation-d1`): collapse `:session_terminated`/`:session_ended` to `{:error, :no_process}` in `ensure_session_running/1`, `format_error/1`, moduledoc, `@spec`, and tests.
- **supported-parity-gap**: add `Tty.supported?/0`.
- **tty-window-query-verb-asymmetry**: rename `set_window_size→write_window_size` or document ioctl naming.
- **missing-spec-tty-format-error-clauses**: add `@spec` to `format_error/1`.
- **tty-kernel-tests-untagged**: integration-tag or document environment-tolerance.
- **tty-error-stages-unknown-not-mentioned / forward-compat-strategy-undocumented**: document stage pre-declaration + version-lock.
- Verified-ok: `attach/2` union `@spec`, Saved/WindowSize Inspect, `:safe`-decode log-and-drop.

### Cgroup
- **cgroup-moduletag-in-mixed-file**: switch `@moduletag :integration` → `@describetag :integration` at `cgroup_test.exs:266,348,371,426,472` (silently-excluded-unit-tests bug).
- **cgroup-parse-keyed-forward-compat-drop / forward-compat-strategy-undocumented**: document unknown-counter omission in `stats/1` and add a forward-compat moduledoc section.
- **already-terminated-cap-commands**: indirectly affected — its cap verbs route through `process.ex` guards (no Cgroup code change here).
- Verified-ok: `create/1` verb, `set_*` union specs, Stats Inspect, validation tuples (within Cgroup's scope).

### Mount
- **supported-parity-gap**: add `Mount.supported?/0`.
- **mount-unknown-flags-caller-error / forward-compat-strategy-undocumented**: document the strict-flag-at-boundary choice and forward-compat strategy.
- **missing-spec-mount-module-public-funcs**: add `@spec` to `list({:path,_})` (`:138`) and `unescape/1` (`:246`).
- Verified-ok: `:in` option shape, `{:bad_flag, _}` validation, Entry Inspect, mountinfo/optional-field silent-drop, `@describetag` tagging.

### User
- **user-bad-entry-vs-bad-map**: resolve the `:bad_entry`→`:bad_map` re-wrap (`user.ex:199,217`).
- **forward-compat-strategy-undocumented**: add forward-compat moduledoc section.
- Verified-ok: `supported?/0`, map-line silent-drop, validation tuples, User.Map Inspect, `@describetag` tagging, domain types.

### Capabilities
- **already-terminated-cap-commands**: update `:already_terminated` references in specs/docstrings (`capabilities.ex:262,283,327,369`) to `:no_process` — D1.
- **capabilities-test-already-terminated**: update test expectations (`capabilities_test.exs`).
- **capabilities-enumerable-vs-mapset-semantic-ambiguity**: add docstring note that Enumerable is convenience, MapSet is canonical/returned.
- **missing-spec-capabilities-read-clause**: add `@spec` to `read/1` (`:186`).
- **forward-compat-strategy-undocumented**: add forward-compat moduledoc section.
- Verified-ok: `supported?/0`, validation tuples, State Inspect, log-once-drop unknown bits, `@describetag` tagging (`:555-556`), constants `@moduledoc false`.

### Seccomp
- **seccomp-already-terminated**: update `:already_terminated` in `install/2` spec/docstring (`seccomp.ex:384,408`) to `:no_process` — D1.
- **seccomp-test-already-terminated**: update test expectation (`seccomp_test.exs:655`).
- **seccomp-builder-missing-summary-inspect**: add summary `Inspect` to `Seccomp.Builder` (`builder.ex:32`) — D3.
- **seccomp-bad-action-vs-unknown-syscall**: rename `:unknown_syscall→:bad_syscall` (`:436`).
- **seccomp-bad-rules-arg**: normalize `{:bad_rules_arg, other}` (`:331`) to the `{:bad_rule, ...}` shape.
- **missing-spec-seccomp-error-clauses**: cover `from_rules/to_rules` clauses with `@spec`.
- **forward-compat-strategy-undocumented**: add forward-compat moduledoc section.
- Verified-ok: `supported?/0`, builder verbs, list-based rules idiom, `Filter` summary Inspect, build-time syscall reject, `@describetag` tagging, constants `@moduledoc false`.

### Sysctl
- **missing-spec-sysctl-list-clause**: add `@spec` to `list(prefix)` (`sysctl.ex:532`).
- **forward-compat-strategy-undocumented**: add forward-compat moduledoc section.
- Verified-ok: `supported?/0`, `from_posix/4` `:key` extra (intentional), validation tuples, Entry Inspect, errno `:unknown` sentinel, `:in` shape, `@describetag` tagging.

### Netfilter
- **D3 container Inspect** (`netfilter-table/chain/set/map/ruleset-missing-summary-inspect`): add summary `Inspect` to Table (`:53`), Chain (`:69`), Set (`:51`), Map (`:38`), Ruleset (`:72`).
- **netfilter-flowtable/object-no-custom-inspect**: optional summary Inspect (leaf-ish; default acceptable).
- **create-vs-add-collision / netfilter-ruleset-put-vs-add**: rename `Ruleset.add_*→create_*` and `put_chain→create_chain` for verb consistency.
- **missing-spec-netfilter-pull-clause**: add `@spec` to `pull/2` `{family, name}` overload (`netfilter.ex:374`).
- **missing-moduledoc-false-codec-modules**: `@moduledoc false` on Decoder/Encoder/Wire.
- **forward-compat-strategy-undocumented**: add forward-compat moduledoc section.
- Verified-ok: `supported?/0`, `Patch` summary Inspect, Expr/Verdict/Rule Inspect, validation tuples, honest-extras error struct, strict `push_mode`, `@describetag` + dedicated integration tagging.

### NFT (and shared value types IP / IP.Subnet / MAC)
- **missing-moduledoc-false-nft-implementation**: `@moduledoc false` on `NFT.Formatter`, `NFT.Runtime` (keep `NFT.ParseError` public).
- Shared value types verified-ok: IP/Subnet/MAC validation tuples and custom Inspect.

## Suggested fixup-commit plan

Small, single-concern commits, ordered so non-breaking polish lands first and the two breaking-change groups are isolated and clearly marked. Per the project convention, commit + push after each milestone.

1. **`error: standardize @impl Exception + parallel message/1`** — closes `netlink-impl-true-nit`, `message-wording-inconsistency-path-suffix` (wording portion deferred until commit 7). Non-breaking.
2. **`inspect: summary Inspect for Netfilter containers + Seccomp.Builder` (D3)** — closes `netfilter-table-missing-summary-inspect`, `netfilter-chain-missing-summary-inspect`, `netfilter-set-missing-summary-inspect`, `netfilter-map-missing-summary-inspect`, `netfilter-ruleset-missing-summary-inspect`, `seccomp-builder-missing-summary-inspect`; optionally `netfilter-flowtable-no-custom-inspect`, `netfilter-object-no-custom-inspect`. Non-breaking.
3. **`docs: @moduledoc false on internal codec/DSL modules`** — closes `missing-moduledoc-false-codec-modules`, `missing-moduledoc-false-nft-implementation`, `missing-moduledoc-false-nfnl-codec`. Non-breaking.
4. **`specs: add @spec to public clauses missing them`** — closes `missing-spec-netfilter-pull-clause`, `missing-spec-mount-module-public-funcs`, `missing-spec-tty-format-error-clauses`, `missing-spec-capabilities-read-clause`, `missing-spec-seccomp-error-clauses`, `missing-spec-sysctl-list-clause`. Non-breaking.
5. **`test: fix cgroup integration tagging + audit Process/Tty tags`** — closes `cgroup-moduletag-in-mixed-file`; addresses `process-kernel-tests-untagged`, `tty-kernel-tests-untagged`. Non-breaking (test-only).
6. **`docs: forward-compat strategy + Netlink moduledoc tree`** — closes `forward-compat-strategy-undocumented`, `netlink-unknown-attributes-silent-drop`, `mount-unknown-flags-caller-error`, `cgroup-parse-keyed-forward-compat-drop`, `process-error-stages-unknown-not-mentioned`, `tty-error-stages-unknown-not-mentioned`, `netlink-attr-codec-dispatch-error-shape`, `netlink-top-module-sparse`, `rtnl-entry-module-minimal`, `nfnl-entry-module-minimal`, `rtnl-resource-modules-no-examples`, `netlink-inconsistent-structure`, `in-option-netlink-socket-type-name-divergence`, `capabilities-enumerable-vs-mapset-semantic-ambiguity`. Non-breaking (docs-only).
7. **`error: add :operation to Linx.Netlink.Error` — ⚠ BREAKING (D2)** — closes `netlink-missing-operation`, `missing-operation-on-netlink-error`, `netlink-error-missing-operation`, `netlink-error-missing-operation-field`, and the wording portion of `message-wording-inconsistency-path-suffix`. Changes the struct's `@enforce_keys`/fields and `from_errno/2`; all error-building sites must populate `:operation`.
8. **`process: uniform validation tuples` — ⚠ BREAKING (D2)** — closes `process-validation-bare-atoms`, `process-inconsistent-namespaces-tuple`. Converts bare `:bad_*` atoms to `{:error, {:bad_*, reason}}`.
9. **`seccomp: normalize validation error shapes` — ⚠ BREAKING (D2)** — closes `seccomp-bad-action-vs-unknown-syscall`, `seccomp-bad-rules-arg`; addresses `user-bad-entry-vs-bad-map`. Renames `:unknown_syscall→:bad_syscall` and normalizes `:bad_rules_arg`.
10. **`error: add Linx.Process.Error + Linx.Tty.Error` (D2)** — closes `process-no-error-struct-d2-gap`, `process-no-error-struct`, `tty-no-error-struct-d2-gap`, `tty-no-error-struct`, and the struct half of `process-and-tty-no-error-structs-yet`. New files; non-breaking addition unless wired into existing returns.
11. **`process+tty: collapse post-terminal atoms to {:error, :no_process}` — ⚠ BREAKING (D1)** — closes `already-terminated-process-proceed`, `already-terminated-process-abort`, `already-terminated-cap-commands`, `ended-process-signal`, `session-ended-process-wait`, `session-ended-process-pty`, `session-terminated-tty-attach`, `session-ended-tty-attach`, `seccomp-already-terminated`, `process-tty-atom-consolidation-d1`, and the atom half of `process-and-tty-no-error-structs-yet`. Update implementations, specs, docstrings, and `Tty.format_error/1`.
12. **`test: update assertions for :no_process unification`** — closes `process-test-already-terminated`, `process-test-ended`, `process-test-session-ended`, `capabilities-test-already-terminated`, `seccomp-test-already-terminated`, `tty-test-session-terminated`, `tty-test-session-ended`. Pairs with commit 11.
13. **`docs: replace :already_terminated etc. with :no_process` (D1)** — closes `doc-readme-already-terminated`, `doc-v0.1.0-plan-post-terminal`; then `mix docs` regenerates `_build/docs/` to close `generated-docs-already-terminated`.
14. **`api: harmonize verbs (supported?/0, create_*, window_size)` — ⚠ partially BREAKING** — closes `supported-parity-gap` (additive, non-breaking), `create-vs-add-collision` + `netfilter-ruleset-put-vs-add` (breaking renames), `tty-window-query-verb-asymmetry` (breaking rename or doc-only); documentation note for `rtnl-delete-naming-inconsistency`.
