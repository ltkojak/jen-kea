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

### INV-007 - A host restore is recorded as done only on the daemon's own answer
**Rule.** The Kea host writes `restored_at` only on one of three recorded evidences: the running daemon's own `config-get` (asked on its control socket) shows the logger the restored FILE has;
Kea's own completion id (`DHCP4_DYNAMIC_RECONFIGURATION_SUCCESS`), read across rotation, when no socket answered; or a NEW active process running the validated file after the one restart. A
reload-START line is never completion, "the unit is active" is not evidence that Kea re-read its file, and the absence of a complaint is not evidence. A daemon that has answered once during a verification is judged only by its answer for the rest of that verification: no log line and no fresh process rescues it. A refused or unconfirmed restore is retried,
counted, and after ten ticks says a person has to act.
**Established.** Q167 (the log), rewritten by Q168 after the beta.30 review found a started line accepted as completion.
**Enforced at.** `jen-kea-helper` `_reload_daemon` / `_restore_state` (the only writer of `restored_at`, beside `evidence`).
**Tests.**
- `tests/test_kea_helper_investigation.py::TestARestoreIsDoneWhenTheDaemonSaysSo`
- `tests/kea_compat/test_log_levels.py::test_the_daemons_own_control_socket_answers_config_get`
- `tests/kea_compat/test_log_levels.py::test_sighup_reload_log_lines`
- `tests/test_investigation_model.py::TestWhatTheWalkFound` (invariant I11)

### INV-008 - An unresolved host record is never overwritten by an arm
**Rule.** The Kea host's record of an unresolved investigation session is authoritative: an arm that does not match it (a Jen restored from an older backup, a second Jen, a stale sweep) is
refused with the record; the same session again is a no-op and the same restore with a later deadline is an extension. Jen shows the conflict and refuses to turn logging on over it.
**Established.** Q167.
**Enforced at.** `jen-kea-helper` `op_investigation_arm`; `investigation_logging._host_phase` and `turn_on` for the display and the refusal.
**Tests.**
- `tests/test_kea_helper_investigation.py::TestAnUnresolvedHostRecordIsNeverOverwritten`

### INV-009 - A host record that cannot be read is never reported as no session
**Rule.** A state file that exists and cannot be read is `bad-state`, not "nothing armed": arm, disarm, status and the timer's tick give one answer about it, none of them overwrites it, and Jen shows
it as an unreadable conflict (Health fails, turning logging on is refused) while the sweep still restores at the deadline.
**Established.** Q168.
**Enforced at.** `jen-kea-helper` `_read_state` (the one loader, three answers); `kea_host._investigation_op` and `investigation_logging._host_phase` / `helper_gate` for the display and the refusal.
**Tests.**
- `tests/test_kea_helper_investigation.py::TestOneAnswerAboutTheStateFile`

### INV-010 - Log evidence follows the file's identity and is never assumed
**Rule.** Kea's log is read incrementally and followed by the file's identity (device and inode) across rotation and truncation; an exhausted, rotated-away or unreadable log is unconfirmed, never success.
**Established.** Q168.
**Enforced at.** `jen-kea-helper` `_LogCursor`, `_await_reload`.
**Tests.**
- `tests/test_kea_helper_investigation.py::TestTheLogIsFollowedNotAssumed`

### INV-011 - Every host record is verified by the one contract
**Rule.** Whatever build armed a record, its restore is verified by the same contract (INV-007); a record is never presented as verified by a weaker rule, and one nothing can verify is refused at the arm
(`no-evidence`), not accepted.
**Established.** Q168.
**Enforced at.** `jen-kea-helper` `_restore_state` and `op_investigation_arm`.
**Tests.**
- `tests/test_kea_helper_investigation.py::TestABuild15RecordIsVerifiedLikeAnyOther`

### INV-012 - A restart is issued only after its budget is recorded on disk
**Rule.** The one restart a restore session may spend is written to the host's state file, and the directory synced, BEFORE `systemctl restart` is issued; a budget that cannot be recorded means
the restart is not issued and the session stays unresolved. A helper killed between the restart and the end of its work never restarts Kea a second time.
**Established.** Q168 (the save), Q170 (a failed save refuses the restart; the directory is synced).
**Enforced at.** `jen-kea-helper` `_reload_daemon` and `_save_state`.
**Tests.**
- `tests/test_kea_helper_investigation.py::TestARestartIsIssuedOnlyAfterItsBudgetIsOnDisk`

### INV-013 - Failure to enumerate the host's records is never proof that none exist
**Rule.** A state directory that cannot be read is a failed tick (exit 1, reported), not "nothing armed"; `checked` counts only matched state files.
**Established.** Q170.
**Enforced at.** `jen-kea-helper` `_self_restore`.
**Tests.**
- `tests/test_kea_helper_investigation.py::TestAnUnreadableStateDirectoryIsAFailedTick`

### INV-014 - Malformed completion metadata is never a completed restore
**Rule.** A record that says it is done must be a completion the helper could have written (a deadline that parses, counters that are non-negative integers, a timestamp, a `how` of reload or
restart, an evidence of the three it writes); otherwise it is `bad-state` from all four ops. A completed record from before evidence existed is usable and is reported `legacy-unverified`,
never given an evidence it did not have.
**Established.** Q170.
**Enforced at.** `jen-kea-helper` `_state_usable` (through `_read_state`, the one loader).
**Tests.**
- `tests/test_kea_helper_investigation.py::TestTheCompletionValidator`

### INV-015 - The helper reads a credential or opens a socket only inside its walls, and only from a config it validated
**Rule.** A credential file named by a config is read only from under `/etc/kea` (bare name, regular file, bounded, owned by root or the daemon's account, not group- or world-writable, no symlink);
a unix control socket is used only under `/run/kea`, `/var/run/kea` or `/tmp`; and neither is derived from a config until `-t` has passed on it in this process.
**Established.** Q170 (after the release audit of Q168 proved the helper could be made to send a root-readable file to a local port).
**Enforced at.** `jen-kea-helper` `_read_credential`, `_socket_path_ok`, `_restore_locked` and `_arm_locked`.
**Tests.**
- `tests/test_kea_helper_investigation.py::TestTheCredentialAndSocketWalls`
- `tests/kea_compat/test_log_levels.py::test_the_daemons_own_control_socket_answers_config_get`

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
**Established.** Q145, Q156, Q171 (the v4 per-object admin routes: lease release, reservation edit and delete, device edit and delete, subnet delete, edit, preview and move; the fixup: the API's reservation delete and device patch, Timeline, the subnet note and the reservation-add refusals).
**Enforced at.** The routes' shared refusal wording and `access.py`.
**Tests.**
- `tests/test_explain_route.py::TestAReservationInAHiddenSubnetIsNotAnOracle`
- `tests/test_q171_access.py::TestHiddenAndNonexistentAreOneAnswer`
- `tests/test_api_writes.py::TestAHiddenObjectIsAnsweredAsOneThatIsNotThere`

### RBAC-003 - The settings that decide who the superadmins are, and the restart that applies them, are superadmin and step-up
**Rule.** Where Jen's own database and Kea's database point, and the restart of Jen, are changed only by a superadmin whose password was confirmed in the last ten minutes: an admin who could
repoint `[jen_db]` at a database of their own and restart Jen would be whatever role that database says. Subnet creation, and the DDNS log and hostname lookup, are for a caller who may see
every subnet (the DDNS Verify tab too: it resolves any name and address through the Jen host). An admin makes the MFA policy stricter and never less strict.
**Established.** Q171.
**Enforced at.** `@_superadmin_required` + `@_recent_auth_required` on `save_infra_jen_db`, `save_infra_kea_db`, `save_infra_kea6` and `restart_jen`; `current_user.all_subnets` in `add_subnet`, `add_subnet_post`,
the DDNS status context and `ddns()` (the Verify tab); the rank table in `save_mfa_mode`.
**Tests.**
- `tests/test_q171_access.py::TestDatabaseCardsAndRestartAreSuperadminWithStepUp`
- `tests/test_q171_access.py::TestAddSubnetNeedsEverySubnet`
- `tests/test_q171_access.py::TestDdnsStatusIsScoped`
- `tests/test_settings.py::TestMfaPolicyIsNeverWeakenedByAnAdmin`

### AUTH-001 - A password change ends every other session of the account
**Rule.** A session carries a fingerprint of the password hash it was opened under; `load_user` ends the session on its next request when the row's fingerprint is no longer the same, and the session
that made the change is rebuilt and stays. `token_version` moves in the same statement (it refreshes a cached role or subnet list; it never ends a session by itself).
**Established.** Q171.
**Enforced at.** `jen/__init__.py` `load_user`, `jen/models/user.py` `password_fingerprint`, `jen/services/oidc.py` `establish_session`.
**Tests.**
- `tests/test_q171_access.py::TestAPasswordChangeEndsTheOtherSessions`

### DEF-001 - One definition of a current lease, used everywhere
**Rule.** What counts as a current lease is spelled one way (`jen/services/leases_sql.py`) and every query that means it uses that spelling.
**Established.** Q145, Q153.
**Enforced at.** `jen/services/leases_sql.py`, held by a whole-tree source test.
**Tests.**
- `tests/test_active_lease.py::TestTheWholeTreeHasOneSpelling`

### DEF-002 - Pool use is the leases inside the pools, everywhere it is derived
**Rule.** A pool's use is the number of leases inside the pools, on every surface that shows or alerts on it; an unmeasured pool use is never replaced by another number.
**Established.** Q154, Q155, Q172 (Health's "near exhaustion" is the alert's own `pool_exhaustion_free` free addresses, no longer a flat 95 %).
**Enforced at.** The pool-use derivation and its whole-tree source test.
**Tests.**
- `tests/test_pool_used.py::TestNoPathReadsActiveLeasesAsPoolUse`
- `tests/test_pool_used.py::TestAnUnmeasuredPoolUseIsNeverReplacedByAnotherNumber`
- `tests/test_health_center.py::TestPoolUtilization`

## Delivery, configuration, files, migrations, transactions, liveness

### ALERT-001 - Attempted, delivered and recorded are different states
**Rule.** An alert's date or state is persisted only on delivery: a channel that failed leaves the alert due again, and a recovery follows a delivered warning.
**Established.** Q154, Q155, Q156, Q157, Q172 (every kind: `stale_reservation`, `config_drift_*` and `kea_down` / `kea_up` now go through `notify_condition` and its persisted state; the Problems sweep marks an alert attempted in the same transaction as its events and watermark, before the send).
**Enforced at.** `jen/services/alerts.py` (`notify_condition`, the daily summary, `check_kea_status_alert`, `check_stale_reservation_alerts`, `check_drift_alerts`), `jen/services/client_problems.py::sweep`.
**Tests.**
- `tests/test_alert_delivery.py::TestEveryChannelFails`
- `tests/test_alert_delivery.py::TestEventStyleAlertsRemember`
- `tests/test_client_problems_db.py::TestASweepIsOneTransaction`
- `tests/test_alert_delivery.py::TestTheDailySummaryIsDueAtOrAfterItsTime`
- `tests/test_alert_delivery.py::TestTheRecoveryFollowsADeliveredWarning`

### TIME-001 - Jen's clock is UTC, in SQL and in Python
**Rule.** Every connection Jen opens - the pooled ones, the direct fallbacks, the export and migration helpers - runs `SET time_zone = '+00:00'`, so `NOW()`, `CURRENT_TIMESTAMP` and Kea's own `lease4.expire`
are read on the clock Python uses; "today" is the UTC date; the Problems sweep's `now` is whole seconds (its columns are DATETIME(0)). A database host's zone changes nothing Jen shows or decides.
**Established.** Q172.
**Enforced at.** `jen/models/db.py` (`SESSION_TIME_ZONE_INIT` on all six connection sites) and `jen/services/dbexport.py`; `client_problems._now()` / `sweep`; `capacity.forecast`.
**Tests.**
- `tests/test_db_session.py::TestEveryConnectionIsUtc`
- `tests/test_db_session.py::TestNoConnectionIsOpenedWithoutIt`
- `tests/test_client_problems_db.py::TestTheSweepsClockIsWholeSeconds`

### PLUG-001 - A plugin is registered whole or not at all
**Rule.** A plugin's blueprints are registered only after its `register(app)` returned: a `register` that raises leaves no route, no job and a per-process failure marker (`plugin_load_failed`, the exception CLASS only)
that the Plugins page shows. A required OS package counts as present when any binary it provides is on PATH (`OS_PACKAGE_BINARIES`), and every package a bundled manifest declares is in that map and in the root
updater's allowlist.
**Established.** Q172.
**Enforced at.** `jen/services/plugins.py` (`_run_register_blueprints_last`, `_load_plugin`, `missing_os_packages`).
**Tests.**
- `tests/test_plugin_registry.py::TestBlueprintsAreRegisteredLast`
- `tests/test_plugin_registry.py::TestOsPackageBinaryMap`

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
- `tests/test_invariant_sweeps.py::TestS9TheRootInstallerTrustsOnlyTheTarballAndItsOwnSnapshots` (Q171: the updater opens no path for writing that is not reviewed; the layout-check cache is written by `mkstemp` + `os.replace`)
- `tests/test_jen_update_root.py::TestLayoutCheckCacheIsWrittenByReplacement`
- `tests/test_q171_access.py::TestDdnsLogPathStaysInsideVarLog` (the legacy `sudo tail` is handed only a `*.log` under /var/log)
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
- `tests/test_kea_changeset.py::TestTwoServersWithOneNameAreTwoTargets`
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

### LEAK-001 - A route never shows what a broad `except` caught
**Rule.** In `jen/routes/`, the name bound by `except Exception as e` is used only to log or to name its class: the text of a driver, `requests` or SSH error carries URLs with their query strings, account and
host names and paths. The reviewed list is empty.
**Established.** Q171 (sweep S11; the older line scanner in `test_no_raw_exception_leaks.py` stays), Q172 (an alert channel's token, webhook URL or password is redacted from `alert_log.error`, the event detail, the log and the test button; a transport error is stored by class).
**Enforced at.** The route that catches: `logger.exception(...)` and a fixed sentence.
**Tests.**
- `tests/test_invariant_sweeps.py::TestS11ARouteNeverShowsWhatABroadExceptCaught`
- `tests/test_q171_access.py::TestDdnsLookupErrorNeverCarriesTheProviderUrl`
- `tests/test_alert_delivery.py::TestAChannelsSecretNeverLandsInText`
- `tests/test_no_raw_exception_leaks.py::TestNoUnexplainedRawExceptionLeaksInRoutes`

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
