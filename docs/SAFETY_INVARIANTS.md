# Safety invariants

The rules this project has learned the hard way, one per entry, each with the test that enforces it and the place it is enforced. Nine betas of investigation logging
(5.68.0-beta.1 to -29) were reviewed to death one sequence at a time; what stayed true after each one is written down here so that the next change - and the next review - starts from
the list instead of rediscovering it.

**How to read an entry.** *Rule* is the sentence. *Established* is the Q that put it in force. *Enforced at* is the choke point: the one place every write or read of the thing passes
through (an invariant enforced on a list of callers is not enforced - see IDENT-001). *Tests* are the tests that fail when the rule breaks, written `path::Class`, `path::function` or
`path::Class::method`, relative to the repository root.

**How the registry stays true.** `tests/test_safety_invariants.py` parses this file with the standard library: every entry has an id, a rule, a Q and at least one test reference; every
reference resolves, by `ast`, to a class or function that exists in the tree; ids are unique and an id is never reused (a retired id moves to the last section). An entry with no automated
test is allowed only with a `(no automated test: <reason>)` line, and the test prints those so they stay visible. A new rule gets an entry in the same commit that adds its test; an
audit of a release (`docs/RELEASE_AUDIT.md`) starts by asking which ids the release touches.

## Investigation logging and the Kea host

### INV-001 - A temporary change to another machine is guaranteed by that machine's own dead-man timer
**Rule.** A change Jen makes to a Kea host that must not outlive a deadline (investigation logging's DEBUG level) is put back by the HOST - a root-owned timer holding its own record of the
original - never by the caller's bookkeeping. A daemon the host was armed for is never at DEBUG 55 more than 120 s past its deadline, whatever has happened to Jen.
**Established.** Q165.
**Enforced at.** `jen-kea-helper` (`investigation-arm`, `--self-restore`), armed by `investigation_logging.turn_on`.
**Tests.**
- `tests/test_investigation_model.py::TestTheKeaHostKeepsTheDeadline` (the walk's I10, with Jen stopped, and the mutation check that goes red without the timer)
- `tests/test_investigation_host.py::TestTurnOnNeedsTheHost`
- `tests/test_kea_helper_investigation.py::TestSelfRestore`
- `tests/system/test_boundaries.py::test_19_the_kea_host_puts_investigation_logging_back_with_jen_stopped_or_its_database_down_or_pointed_elsewhere`

### INV-002 - A daemon's state is observed, never inferred from a reply
**Rule.** Investigation logging's running state is read from the daemon (`config-get`), after every reload and restart. A reload whose reply was lost may have been applied; "the call
returned an error" is not "the daemon did not change".
**Established.** Q158.
**Enforced at.** `investigation_logging.observe` / `daemon_logger`.
**Tests.**
- `tests/test_investigation_logging.py::TestALostReloadReplyIsNotAFailure`
- `tests/kea_compat/test_log_levels.py::test_config_reload_applies_the_investigation_log_level_without_a_restart`

### INV-003 - An index entry is dropped only when the daemon was seen restored
**Rule.** The entry that remembers outstanding investigation state is dropped when the config file is restored AND the running daemon was SEEN restored; anything else keeps it, pending.
**Established.** Q158.
**Enforced at.** `investigation_logging._finish` (the one drop path).
**Tests.**
- `tests/test_investigation_logging.py::TestAnEntryIsDroppedOnlyWhenTheDaemonWasSeenRestored`
- `tests/test_investigation_model.py::TestTheWalk` (invariant I7)

### INV-004 - An unreadable or unavailable safety record is never evidence that nothing is outstanding
**Rule.** A record of investigation logging that cannot be read (malformed, or the settings table itself unavailable) does not say that no session exists: every reader refuses or
fails closed, nothing is written over it, and the old value is kept.
**Established.** Q159, Q160, Q161, Q164.
**Enforced at.** `investigation_logging._record` (`damaged`, `unavailable`).
**Tests.**
- `tests/test_investigation_logging.py::TestEveryReaderOfTheRecordHandlesDamaged`
- `tests/test_identity_guard.py::TestAnUnavailableSettingsReadIsNeverAnEmptyRecord`
- `tests/test_investigation_model.py::TestTheWalk` (invariants I2, I6, I9)

### INV-005 - A server with outstanding investigation state keeps its connection identity
**Rule.** While investigation state is outstanding for a Kea server, the settings that say which Kea Jen reaches for it (`api_url`, `ssh_host`, `ssh_user`, `kea_conf`) and the global
connection mode do not change, and nothing but investigation logging may erase, replace or DAMAGE its marker in the Kea config file: a candidate whose marker is absent, carries a different
restore object or deadline, or is malformed (`restore: {}`, a string, a list, not an object) is refused whenever the entry recorded a valid restore.
**Established.** Q162, Q164 (and the installer's `--configure` guard, Q165; the malformed-marker rows, Q167).
**Enforced at.** `AppConfig._write_parser` (the config) and `kea_host.apply_config` (the Kea file); `install.sh _guard_endpoint_changes` for the installer.
**Tests.**
- `tests/test_identity_guard.py::TestTheConfigWriterRefusesAnIdentityChange`
- `tests/test_identity_guard.py::TestTheKeaFileWriterRefusesToEraseTheMarker`
- `tests/test_investigation_host.py::TestTheElevenRowsOfTheCandidateMarker`
- `tests/test_install_endpoint_guard.py::TestTheInstallerRefusesAnEndpointChangeWithoutTheFlag`
- `tests/test_investigation_model.py::TestTheWalk` (invariants I4, I8)

### INV-006 - The daemon step is bounded
**Rule.** Putting a log level back asks the daemon for at most `RELOAD_TRIES` reloads and one restart per entry; "Jen keeps trying every minute" is for a person to read, never a restart a minute.
**Established.** Q158.
**Enforced at.** `investigation_logging._daemon_phase`.
**Tests.**
- `tests/test_investigation_logging.py::TestTheDaemonStepIsBounded`
- `tests/test_investigation_model.py::TestTheWalk` (invariant I3)

### INV-007 - A host restore is recorded as done only when Kea's own log shows the reload or start completed
**Rule.** The Kea host writes `restored_at` only after a VERIFIED reload or restart: Kea's own log, past the offset noted before the SIGHUP, shows the reload completed (or started and stayed
free of a failure id when the restored level hides the completion line); "the unit is active" is not evidence that Kea re-read its file. A refused or unconfirmed restore is retried, counted, and
after ten ticks says a person has to act.
**Established.** Q167.
**Enforced at.** `jen-kea-helper` `_reload_daemon` / `_restore_state` (the only writer of `restored_at`).
**Tests.**
- `tests/test_kea_helper_investigation.py::TestARestoreIsDoneWhenKeasOwnLogSaysSo`
- `tests/kea_compat/test_log_levels.py::test_sighup_reload_log_lines`

### INV-008 - An unresolved host record is never overwritten by an arm
**Rule.** The Kea host's record of an unresolved investigation session is authoritative: an arm that does not match it (a Jen restored from an older backup, a second Jen, a stale sweep) is
refused with the record; the same session again is a no-op and the same restore with a later deadline is an extension. Jen shows the conflict and refuses to turn logging on over it.
**Established.** Q167.
**Enforced at.** `jen-kea-helper` `op_investigation_arm`; `investigation_logging._host_phase` and `turn_on` for the display and the refusal.
**Tests.**
- `tests/test_kea_helper_investigation.py::TestAnUnresolvedHostRecordIsNeverOverwritten`

## Access control and shared definitions

### RBAC-001 - Stored data is judged by its own subnet; a hidden object never influences a visible answer
**Rule.** Subnet-scoped data is judged by the stored object's own subnet, a live act by the current subnet, and an object in a subnet the caller cannot see never influences an answer the
caller can.
**Established.** Q143, Q144, Q145, Q146, Q147.
**Enforced at.** `add_subnet_restriction` / `assert_subnet_access` (`jen/services/access.py`) and the authorization matrix.
**Tests.**
- `tests/test_authz_matrix.py::TestEveryDiagnosticRouteIsAccountedFor`
- `tests/test_authz_matrix_plugins.py::TestAStoredObjectIsJudgedByItsOwnSubnet`

### RBAC-002 - A denial and a not-found are one message
**Rule.** A request for an object the caller may not see answers exactly as one for an object that does not exist; there is no oracle for what a hidden subnet holds.
**Established.** Q145, Q156.
**Enforced at.** The routes' shared refusal wording and `access.py`.
**Tests.**
- `tests/test_explain_route.py::TestAReservationInAHiddenSubnetIsNotAnOracle`

### DEF-001 - One definition of a current lease, used everywhere
**Rule.** What counts as a current lease is spelled one way (`jen/services/leases_sql.py`) and every query that means it uses that spelling.
**Established.** Q145, Q153.
**Enforced at.** `jen/services/leases_sql.py`, held by a whole-tree source test.
**Tests.**
- `tests/test_active_lease.py::TestTheWholeTreeHasOneSpelling`

### DEF-002 - Pool use is the leases inside the pools, everywhere it is derived
**Rule.** A pool's use is the number of leases inside the pools, on every surface that shows or alerts on it; an unmeasured pool use is never replaced by another number.
**Established.** Q154, Q155.
**Enforced at.** The pool-use derivation and its whole-tree source test.
**Tests.**
- `tests/test_pool_used.py::TestNoPathReadsActiveLeasesAsPoolUse`
- `tests/test_pool_used.py::TestAnUnmeasuredPoolUseIsNeverReplacedByAnotherNumber`

## Delivery, configuration, files, migrations, transactions, liveness

### ALERT-001 - Attempted, delivered and recorded are different states
**Rule.** An alert's date or state is persisted only on delivery: a channel that failed leaves the alert due again, and a recovery follows a delivered warning.
**Established.** Q154, Q155, Q156, Q157.
**Enforced at.** `jen/services/alerts.py` (`notify_condition`, the daily summary).
**Tests.**
- `tests/test_alert_delivery.py::TestEveryChannelFails`
- `tests/test_alert_delivery.py::TestTheDailySummaryIsDueAtOrAfterItsTime`
- `tests/test_alert_delivery.py::TestTheRecoveryFollowsADeliveredWarning`

### CFG-001 - Every config write holds one lock across read-modify-replace, and the installer honours the same flock
**Rule.** Jen's config file is written under one lock for the whole read-modify-replace (a thread lock and an advisory `flock` on the lock file), and `install.sh --configure` takes the same one.
**Established.** Q152, Q153, Q155.
**Enforced at.** `AppConfig._write_lock` / `_file_lock`; `tools/private_write.py --lock` for the installer.
**Tests.**
- `tests/test_config_file_lock.py::TestAnExternalProcessAndTheServiceDoNotLoseEachOthersWrites`
- `tests/test_installer_trust.py::TestTheInstallerLocksTheSameInodeThroughTheOneOpen`

### FILE-001 - A secret is private from its first byte; a privileged write never resolves a service-owned parent by pathname
**Rule.** No secret is written by a plain `open`, redirect or `cp`; a `.prev` is made only by the certificate set's commit; root never copies anything into the app tree from the config or content directories.
**Established.** Q150, Q151, Q155.
**Enforced at.** `jen/services/private_files.py`, `tools/private_write.py`.
**Tests.**
- `tests/test_invariant_sweeps.py::TestS1SecretsArePrivateFromTheirFirstByte`
- `tests/test_invariant_sweeps.py::TestS2NoLiveFileIsMovedAwayBeforeItsReplacementExists`
- `tests/test_invariant_sweeps.py::TestS9TheRootInstallerTrustsOnlyTheTarballAndItsOwnSnapshots`
- `tests/test_private_write_tool.py::TestItRefusesToFollowOrReplaceALink`

### MIG-001 - Every DDL statement has its own guard, and an interrupted migration re-runs to the final schema
**Rule.** A schema change is a new numbered migration; every DDL statement in it has its own guard so a migration interrupted between statements finishes when it runs again.
**Established.** Q150, Q151.
**Enforced at.** `jen/models/migrations.py`.
**Tests.**
- `tests/test_invariant_sweeps.py::TestS3EveryMigrationStatementHasItsOwnGuard`
- `tests/test_migrations.py::TestMigration33ClientProblemsScopeKey::test_an_interrupted_migration_finishes_the_key_it_never_reached`
- `tests/test_migration_6_interrupted.py`

### TXN-001 - A multi-server change validates every target before the first write and compensates or stays visibly unresolved
**Rule.** One config edit pushed to several Kea servers is planned and preflighted on every target before the first write, committed sequentially, and reverted on the committed targets if a
later one fails; a revert that cannot finish is a persistent, named rollback failure.
**Established.** Q24, Q150, Q151.
**Enforced at.** `jen/services/kea_changeset.py::apply_change`.
**Tests.**
- `tests/test_kea_changeset.py::TestApplyChangeRevert`
- `tests/test_kea_changeset.py::TestFailedRestartRollsBack`
- `tests/test_author_config_changeset.py::TestAnAuthoredChangeIsAllOrNothing`

### BG-001 - Health reports what is proven, never what was once attempted
**Rule.** A background worker's health is its liveness, the age of its last dispatch and its job outcomes - never the fact that it was once started or once attempted.
**Established.** Q154, Q155, Q156, Q157.
**Enforced at.** `jen/services/health.py` and the scheduler's job bookkeeping.
**Tests.**
- `tests/test_health_liveness.py::TestBackgroundWorkersProveLiveness`
- `tests/test_health_liveness.py::TestTheSchedulerReportsItself`

## Failing closed and how rules are enforced

### FAIL-001 - A failed read on a security or safety path is distinguished from an empty result
**Rule.** In the modules that make security or safety decisions, an `except` that returns an empty value (`None`, `{}`, `[]`, `""`, `False`) or passes is on a reviewed list with the reason it
fails CLOSED there (a refusal, not a permission). A failed settings read answers "unknown", never "nothing outstanding".
**Established.** Q159, Q164, Q166.
**Enforced at.** The sweep S10 over the listed modules; `settings_ever_loaded` in `jen/models/user.py`.
**Tests.**
- `tests/test_invariant_sweeps.py::TestS10FailedReadsOnSecurityPathsAreNotEmptyResults`

### STATE-001 - A new state on a stored object is a definition
**Rule.** Adding a state, flag or field to a stored object changes what the object means: every reader handles it, pinned by a source test over every reader of the object.
**Established.** Q161.
**Enforced at.** The reader-census source test of the record.
**Tests.**
- `tests/test_investigation_logging.py::TestEveryReaderOfTheRecordHandlesDamaged`

### IDENT-001 - An invariant is enforced at the choke point its writes pass through, never on a list of callers
**Rule.** A rule about what may be written is checked in the one function every such write ends in; a check repeated in each route is a list, and the route that is added next will not have it.
**Established.** Q164.
**Enforced at.** `AppConfig._write_parser` and `kea_host.apply_config`.
**Tests.**
- `tests/test_identity_guard.py::TestTheIdentityInvariantHasOneChokePointInTheSource`
- `tests/test_identity_guard.py::TestTheKeaFileHasOneChokePointInTheSource`

## Retired ids

An id that is retired stays here, with the reason, so it is never given to a different rule. (None yet.)
