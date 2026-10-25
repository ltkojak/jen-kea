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

### RBAC-004 - Where Jen reaches a Kea server, and so where its credentials go, is a superadmin's setting with a recent password
**Rule.** A config write that changes where Jen reaches a Kea server or sends a credential - the API URL, the SSH host, user or config path, the connection mode, a server added or removed, AND
every other endpoint a credential goes to (`[kea6]`, `[d2]`, both database hosts and ports, an additional server's IPv6 and D2 addresses) - is a superadmin's, with a password confirmed in the last ten
minutes, whichever route (or plugin or hand-made request) asked. The rule is asked where every write passes, not on a list of routes: a destination guard, beside (and asked before) the investigation
guard. Outside a request (`install.sh --configure`, tools) and for a request that is not a signed-in session (an API key) there is no caller to judge. An admin sees the cards as facts and the probe is
limited to the host Jen already reaches. A password-only change is not a destination change here; CRED-002 and CRED-004 judge it.
**Established.** Q179 (the beta.9 review: an admin could point the Kea API, SSH, D2 or an additional server at a host of their own and receive the stored credential); Q180 (the beta.10 review: the guard saw
only the four identity keys, so a write of `[kea6] api_url`, `[d2] api_url`, a database host or an extra server's IPv6 or D2 address was not its question - it is asked of `destination_view` now).
**Enforced at.** `access.identity_change_needs_superadmin`, registered with `config.register_destination_guard` at import and imported by `create_app`; asked by `AppConfig._check_identity` (and so by
`preflight_identity_change`) from `AppConfig._write_parser` on `config.destination_view` - `identity_view`'s four keys and the mode PLUS the url of every endpoint `credentials.resolve` names. The investigation
guard keeps `identity_view` (its concern is WHICH Kea). A route that must ask for the confirmation inside its body (the setup wizard's POST steps, the IPv6 step) calls `access.step_up_redirect`, and a
confirmation made at the start of a request is remembered for its last write (`g.reauth_ok_minutes`), so the direct-socket routes are not asked a second time after they have changed the Kea host.
**Tests.**
- `tests/test_identity_guard.py::TestIdentityIsASuperadminsSetting`
- `tests/test_identity_guard.py::TestAConfirmationMadeAtTheStartOfARequestIsNotAskedAgain`
- `tests/test_setup_wizard_stepup.py::TestTheWizardAsksForTheConfirmationItNeeds`
- `tests/test_kea_connection_forms.py::TestEveryIdentityRouteIsASuperadminsForm`
- `tests/test_credential_destinations.py::TestTheDestinationGuardSeesEveryEndpoint`

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
**Rule.** (Q190, second half:) an ADDRESS is shown by one helper, `auth.shown_url` - scheme, host and port, never user-info, a path or a query - in every flash, audit row, log line and incident, and text Jen did not write (a `requests` message) goes through `auth.scrub_urls`; `tests/test_invariant_sweeps.py` S14 refuses a route that formats a `*url` name into text without it (the reviewed list is empty). 
In `jen/routes/`, the name bound by `except Exception as e` is used only to log or to name its class: the text of a driver, `requests` or SSH error carries URLs with their query strings, account and
host names and paths. The reviewed list is empty.
**Established.** Q171 (sweep S11; the older line scanner in `test_no_raw_exception_leaks.py` stays), Q172 (an alert channel's token, webhook URL or password is redacted from `alert_log.error`, the event detail, the log and the test button; a transport error is stored by class).
**Enforced at.** The route that catches: `logger.exception(...)` and a fixed sentence.
**Tests.**
- `tests/test_invariant_sweeps.py::TestS11ARouteNeverShowsWhatABroadExceptCaught`
- `tests/test_invariant_sweeps.py::TestS14AnAddressIsShownByOneHelper`
- `tests/test_invariant_sweeps.py::TestS14bAServiceShowsAnAddressByTheHelperToo`
- `tests/test_direct_socket_lock.py::TestTheTwinRefusalShowsTheAddressThroughTheHelper`
- `tests/test_url_never_carries_a_password.py::TestTheDnsProvidersAddressAndTheRestOfQ191`
- `tests/test_url_never_carries_a_password.py::TestShownUrl`
- `tests/test_url_never_carries_a_password.py::TestTheSecondPassOfQ190`
- `tests/test_url_never_carries_a_password.py::TestTheKeaClientNeverPrintsALegacyPassword`
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

### LOG-001 - Where kea-dhcp4 writes its log is one definition, and every reader of that log asks it
**Rule.** The file Jen reads for the daemon's log is `kea_log_trace.log_path_for(config)`: the `kea-dhcp4` logger's own first file output that the host's helper would read, else `[kea] dhcp4_log_path`
when it would, else nothing - asked per server (`log_tail.path_for`) by the Problems inbox sweep, Trace, Explain and the investigation arm. No reader reads the configured path itself, and a
Health row that cannot read the log says WHICH file was missing (the one it tried), not "check SSH".
**Established.** Q175 (the sweep read the configured path for 1447 sweeps of a host whose logger wrote to stdout, while the arm already asked the daemon's own logger).
**Enforced at.** `kea_log_trace.log_path_for`, through `log_tail.path_for`.
**Tests.**
- `tests/test_kea_log_trace.py::TestNothingElseReadsTheConfiguredLogPath`
- `tests/test_kea_log_trace.py::TestLogPathForIsTheLoggersOwnFile`
- `tests/test_log_tail.py::TestPathForIsWhereTheServersOwnLoggerWrites`
- `tests/test_client_problems_db.py::TestTheSweepReadsTheFileTheServersLoggerWrites`
- `tests/test_health_liveness.py::TestTheSweepRowSaysWhatTheErrorMeans`

### DNS-CRED-001 - A credential stored for one DNS provider is never reused for a different provider
**Rule.** `[ddns] api_token` is kept only for the provider it was typed for: a provider switch, the remove-token checkbox, or a provider with no credential (`ssh`, `generic`, `none`) removes it, and a switch with
nothing typed says so. A provider's block shows only its own saved endpoint and says "(unchanged)" only for the token it holds, and a lookup never sends an empty credential.
**Established.** Q177 (the beta.7 review: a Technitium token was stored as the Pi-hole password and POSTed to the Pi-hole URL).
**Enforced at.** `save_infra_ddns`'s `_apply` (the one place the token is written or kept) and `_provider_lookup`.
**Tests.**
- `tests/test_ddns.py::TestACredentialBelongsToItsProvider`

### LOG-IDENTITY-001 - A cached log result is reused only for the same effective Kea endpoint
**Rule.** The 3 s log-read cache and the path cache are keyed by the server's identity (host, user, config path) as well as its id; a server edited to point at a different host under the same id is never answered
with the old host's lines. A display name is not part of the identity.
**Established.** Q177.
**Enforced at.** `log_tail.identity`, used by `log_tail.tail` and `log_tail.path_for`.
**Tests.**
- `tests/test_log_tail.py::TestAReadBelongsToItsEndpoint`

### PROBLEMS-IDENTITY-001 - Persisted Problems progress is never reused after the identity of its source server changes
**Rule.** The sweep's watermark, last read, last error, misses, clock offset and log path are the progress of one endpoint. The sweep records the server's identity and, when it changes, deletes every progress key of that
id in one transaction before the next read and starts the server afresh; historical rows are kept; a first sight only records the identity.
**Established.** Q177.
**Enforced at.** `client_problems._reset_if_endpoint_changed`, called by the sweep before any of a server's progress is read; `_SERVER_KEY_PREFIXES` is the one list of what progress is.
**Tests.**
- `tests/test_client_problems_db.py::TestProgressBelongsToItsEndpoint`

### DDNS-STATUS-001 - DDNS status distinguishes an absent configuration, an unavailable observation and a loaded hook whose behaviour is unknown
**Rule.** The Status tab's mode is `none` only when the config was read and nothing is configured, `unknown` when it could not be read, and `hook` when a run_script hook is loaded and D2 is off; an explicit
`[ddns] mode` (including `none`) wins; D2, hook and provider stay separate facts.
**Established.** Q176 (unknown), Q177 (explicit none, hook).
**Enforced at.** `jen/routes/ddns.py::_ddns_mode`.
**Tests.**
- `tests/test_ddns.py::TestTheModeSaysWhatItKnows`

### CRED-002 - A kept secret is kept only for the endpoint it was typed for
**Rule.** A form that keeps a blank secret keeps it only while the endpoint it names is the same place (`auth.same_endpoint`: scheme, host and port - never the path or the query; a bare host has no default port).
Two behaviours, by consequence. A LOOKUP credential (the DDNS token) is REMOVED when the provider or its address changes, with a warning, and never sent to the new place. A CONNECTION credential (the Kea API,
Kea6, D2, an additional server's, Kea's database, Jen's database) is REQUIRED for a new endpoint: the form refuses a blank password with one sentence and writes nothing; "Inherit", where a form has one, is the way out.
A password a form INHERITS (Kea6 and D2 use the Kea API's when they have none of their own, and "Inherit" removes theirs) stays with the Kea API's HOST: another port of the same host is the same Kea,
a different host needs its password typed, "Inherit" included (`auth.same_host`, `infrastructure._inherited_secret_refusal`). A genuinely new additional-server row takes the primary's password only through its own "Share the primary's API password" box (CRED-003; Q178 let it inherit silently), and the setup wizard
and the probe are the superadmin's deliberate tests of a typed address (an admin's probe is limited to the host Jen already reaches, RBAC-004). A form that offers "Inherit" AND a password box gets one
answer: ticking both is refused (`infrastructure._one_answer_for_a_secret`), and the checks judge the EFFECTIVE secret.
(DNS-CRED-001 is the provider-level half of the same rule; CRED-004 is the definition every form's check now agrees with.)
**Established.** Q178 (the beta.8 review: Technitium at A to Technitium at B kept A's token, and six more forms kept a blank password across a new URL or host).
**Enforced at.** `auth.same_endpoint`, through `infrastructure._secret_for_new_endpoint` (every connection route, before its write) and `save_infra_ddns`'s `_apply`.
**Tests.**
- `tests/test_same_endpoint.py::TestSameEndpoint`
- `tests/test_kea_connection_forms.py::TestTheKeaApiForm`
- `tests/test_kea_connection_forms.py::TestTheKea6Form`
- `tests/test_kea_connection_forms.py::TestTheD2Form`
- `tests/test_kea_connection_forms.py::TestAnAdditionalServer`
- `tests/test_kea_connection_forms.py::TestTheDatabaseForms`
- `tests/test_kea_connection_forms.py::TestAPasswordTheFormInheritsStaysWithTheKeaHost`
- `tests/test_kea_connection_forms.py::TestOneAnswerForASecret`
- `tests/test_ddns.py::TestADifferentEndpointIsNotTheSameProvider`

### CRED-003 - An additional server takes the primary's password only on purpose, and an inherited secret is named
**Rule.** (Q179; the note-only wording is SUPERSEDED by CRED-004 - an inherited secret on a different host is no longer used, it is refused and named.) The form COPIES the primary's password into a NEW
additional-server row only through its own checkbox ("Share the primary's API password"), marked `api_pass_shared = 1`; ticking it AND typing a password is refused ("Choose one"). A row that keeps a
password keeps the one its connection resolves, so moving it to a new address needs the password typed (an IPv6 address on the host it was on, or on the API address's host, is not moved).
**Established.** Q179 (the beta.9 review), Q180 (the beta.10 review: the derivation kept the fallback, so an unticked box still sent the primary's password; CRED-004 removes it).
**Enforced at.** `infrastructure.save_extra_servers`' `_rewrite_extra_servers`; the Doctor's `endpoint-has-no-credential` and `credential-shared-same-host` (`config_doctor._check_credential_endpoints`).
**Tests.**
- `tests/test_config_doctor.py::TestEndpointCredentials`
- `tests/test_kea_connection_forms.py::TestAnAdditionalServerUsesTheCredentialItIsGiven`

### CRED-004 - A secret is used at its own endpoint or inherited by a daemon on the same host; `credentials.resolve` is the one definition
**Rule.** Which password Jen sends to which endpoint is decided in ONE pure function, `credentials.resolve(parser)`, and every consumer asks it: `AppConfig.apply` (the KEA6, D2 and KEA6_DB globals),
`derive_kea_servers` (each server's `api_pass`, `api6_pass`, `api_d2_pass` and their `*_withheld`), `kea._endpoint_for`, the Configuration Doctor and the Health row "Every endpoint has a credential". A
secret is used at its OWN endpoint, or inherited by another daemon ON THE SAME HOST (`auth.same_host`: another port of that host is the same box); an endpoint on a different host with no secret of its own
has NONE - never its neighbour's, and `_endpoint_for` answers with a sentence and sends nothing. A blank `api_pass =` is an explicit no-credential; an ABSENT key is "inherit, if the host is the same". The URL and the USER are decided by the same function under the same three readings (a value is its
own; a present-blank key is explicit - no endpoint, no user, no password; an absent key inherits: the url from the parent in CA mode and nothing in direct mode, the password on the same host only, the user on
the same host or alongside a password the endpoint owns - and NOT beside a PRESENT-BLANK password, which says "no authentication" and so sends no user and no Authorization header - a user TYPED beside it is the endpoint's own and is sent; a database keeps its user; the present-blank case only - an absent password on a primary that has none leaves the user, and an endpoint on its host sends `Basic user:` like the primary), and the transport reads only those resolved fields: what `resolve` returns is what `requests.post` receives, and nothing downstream may change it. The Kea6 database is an endpoint like the rest: a present-blank `[kea6_db] host =` is "no Kea6 database" and a withheld password is none - `models/db.py` opens no pool and no connection for either, and Health says so.
The writer asks one more question for every write (`AppConfig._write_parser` through `credentials.move_refusal`, never per form): a saved password does not FOLLOW an endpoint to a new host, and does not
appear on a SECOND host, unless it was typed in this request (`mutate(fn, typed=...)`). A legacy endpoint that inherited its parent's password across hosts (an extra server since 5.10; Kea6, D2, the Kea6 database and a server's IPv6 and D2 endpoints) is converted ONCE PER INSTALL, audibly,
at `create_app` (`credentials.materialise`, gated on `[jen] credential_model = explicit` IN jen.config, written in the same atomic write as the copies - the marker is in the file it describes, so a restored older database
changes nothing and a restored pre-beta.11 config converts again, correctly; a fresh install (installer, wizard, container) is born with it; the settings key beta.11 wrote is read once more, by `already_converted`: the copy, a `<key>_shared` marker, one `CONFIG_MIGRATION` audit row each); a later change of the parent's
password does not follow it, and a section left WITHOUT a key afterwards is never filled in at a restart. An explicit blank (`api_pass =`, the forms' "No password" boxes) is how a Kea with no
authentication is said, and nothing is withheld from it. `Set up direct socket` keeps a daemon's password as its own copy when the address it moves to is the same box spelled differently.
**Established.** Q180 (the beta.10 review - and the four before it: beta.7 provider switch, beta.8 same-provider URL change, beta.9 inherit plus typed and an extra server without a key, beta.10 the
unchecked share box and the extra server's IPv6 and D2 endpoints: one defect, a fallback written in a different place each time); Q181 (the transport reads only resolved fields); Q182 (every
exemption in the rule is itself a row first: the mode-switch skip, no authentication is no header, the marker is a value, the probed pair is kept, the installer's merge asks the same question);
Q183 (the flip carries only a password that already went to the parent's host, a password value changes only when typed, every `_shared` marker has a reader and a clearer, a row must REACH the skip it
names, and the second pass EXECUTES `tests/probe/credential_probe.py`).
**Enforced at.** `jen/services/credentials.py` (`resolve`, `move_refusal`, `materialise`); `jen/config.py` (`apply`, `derive_kea_servers`, `_write_parser`); `jen/services/kea.py` (`_endpoint_for` reads only resolved fields; `tests/test_credential_transport.py` compares the two). A saved password's FIRST address is a move too (`move_refusal`: a password that had no address and is given one needs to be typed). Exception (Q182, Q183): a switch of the connection mode exempts ONLY an endpoint whose address is DERIVED (its url key absent: `Endpoint.url_own` False) from a parent whose host did not change AND whose password already went to that host (it had an address there before: a password typed for another host whose address was removed is given a FIRST address by the flip, and is refused) - an address of the daemon's own, or a Control Agent on a new host, is judged as any move; a third shape (c) refuses an own password VALUE that changed, or is new, without being typed for that endpoint (a `mutate` that copies a value in); and every exemption in the rule is a matrix row that uses it for a different purpose (RELEASE_AUDIT step (n)). The conversion copies the parent's USER with the password and marks the file only when nothing is pending (a restored legacy file is converted, not merely marked); a legacy present-blank `api6_pass` / `api_d2_pass` is "inherit" in a file without the marker. The marker is a VALUE: `credentials.model_marker` is absent / explicit / invalid, and an invalid one converts nothing and shows in Doctor and Health as `credential-model-invalid`. The direct-socket routes write the pair that answered the probe as the endpoint's own when the resolver would withhold it at the new address, take their defaults from `resolve` (`_daemon_creds`), type only the endpoint they repoint, and handle a failed write of Jen's settings like a refusal. The installer's merge (`tools/config_merge.py`) runs the same `move_refusal`. The writer's `typed` set is a human's act in this request or the one-time conversion; a route never derives it from hosts, DNS or history (`tests/test_credentials.py::TestTypedIsAHumansAct`, through `tests/typed_claims.py`, refuses a `typed=` that is not a set display of string literals, `set()`, `None`, a conditional whose test is a boolean over `request.form.get/getlist` values and constants only, or a name bound exactly once to one of those and used for nothing else - no read of `extensions`, no other call, f-string, comprehension, walrus, lambda, `getattr`, `partial` or aliased writer; eight named functions are dynamic by nature and each may do ONE reviewed extra thing, listed in `tests/typed_claims.py` DYNAMIC and asserted by the test). The checker's reach layer is syntactic reach - the ancestors of the call inside the innermost function, a smell detector for a claim moved under a test the request does not decide; the guarantee is the shape rule, and an unconditional literal claim is accepted by design. A dhcp4 removal that would flip Jen to Control Agent mode needs a Control Agent address to flip to (none saved, or the saved one is the socket's own, and no other server keeps direct mode: the form asks for it and identifies it as a Control Agent before the socket goes; a SAVED address is identified the same way before it is restored, because a saved address that only differs as text from the socket is no proof of a Control Agent), the Control Agent's pair is saved as it WAS - a value, a blank or ABSENT - and a restore puts every half back as it was, and the dependant keep writes a user only beside a password of its own. The "Remove socket" forms therefore carry a password field, a No password box and - when the Control Agent's own pair was saved beside its address at setup (`direct_prev_api_user` / `direct_prev_api_pass`) - a "restore the saved pair" box; the route types the endpoint it repoints only when one of the three was used, the daemons a switch-back re-derives are never typed there (the writer refuses one whose saved password would reach a new place, and the page says to type it under Settings -> Kea first), and a daemon removal in Control Agent mode removes the daemon's own user, password and marker, which were the socket's; and a URL with a backslash, a control, zero-width or no-break space character names no place, and `a.` (the absolute name) is not `a` (`auth._endpoint_parts` / `valid_api_url` / `_plain_host`), because `urlsplit` and `requests` read them differently. `preflight_identity_change` asks it too (with the route's typed set), so a route that acts on the Kea host first is refused before the host is touched; the switch-back types the daemons it re-derives. A request for an endpoint
with no authentication carries no Authorization header and no netrc lookup (`kea._NO_AUTH`). An unreadable settings table is not an absent row: the conversion waits for the next start (`credentials.beta11_flag`). The two
greps `fallback=primary_pass` and `or server.get("api_pass"` over `jen/` find nothing, and `tests/test_credentials.py` says so.
**Tests.**
- `tests/test_credentials.py::TestResolve`
- `tests/test_credentials.py::TestTheConsumersAreOnTheResolver`
- `tests/test_credentials.py::TestEndpointForSendsNothingWithoutACredential`
- `tests/test_credentials.py::TestMaterialise`
- `tests/test_credentials.py::TestTheMarkerLivesInTheFileItDescribes`
- `tests/test_credentials.py::TestTheThreeReadingsForEveryField`
- `tests/test_credentials.py::TestAFirstAddressIsAMove`
- `tests/test_credentials.py::TestNothingDownstreamDecides`
- `tests/test_credentials.py::TestTheUserFollowsAnOwnPassword`
- `tests/test_credentials.py::TestAModeSwitchRepointsTheDaemonsWholesale`
- `tests/test_credentials.py::TestAnUnreadableSettingsTableIsNotAnAbsentRow`
- `tests/test_credentials.py::TestUrlOwn`
- `tests/test_credentials.py::TestNoAuthenticationIsNoUser`
- `tests/test_credentials.py::TestTheMarkerIsAValue`
- `tests/test_credentials.py::TestTheBridgeKeepsBeta11sBlankAsAnAnswer`
- `tests/test_direct_socket_credentials.py::TestTheRemoveFormInfersNothing`
- `tests/test_credentials.py::TestTypedIsAHumansAct`
- `tests/test_same_endpoint.py::TestAUrlTheTwoParsersReadDifferentlyNamesNoPlace`
- `tests/test_credentials.py::TestEverySharedMarkerHasAReaderAndAClearer`
- `tests/test_credential_destinations.py::TestARetypedPasswordIsNoLongerASharedCopy`
- `tests/test_credential_destinations.py::test_the_row_a_continue_names_reaches_that_continue`
- `tests/test_credential_destinations.py::test_every_hit_names_the_row_its_continue_cites`
- `tests/test_credential_transport.py::test_the_same_with_a_primary_that_has_no_password`
- `tests/test_setup_wizard.py::TestEnableV6AnswersWithTextForAFailedWrite`
- `tests/test_credential_probe.py::test_the_scenario_observes_what_the_rule_says`
- `tests/test_direct_socket_credentials.py::TestSwitchingBackByNameIsAskedBeforeTheKeaHostIsTouched`
- `tests/test_credential_destinations.py::test_the_preflight_asks_the_move_question_before_the_kea_host_is_touched`
- `tests/test_credentials.py::TestALegacyBlankIsInherit`
- `tests/test_credentials.py::TestTheKea6DatabaseIsAnEndpoint`
- `tests/test_credential_transport.py::TestNoAuthenticationOnTheSameHostSendsNoHeader`
- `tests/test_credential_destinations.py::test_every_continue_in_move_refusal_names_the_row_that_uses_it`
- `tests/test_credential_destinations.py::TestTheCopyButtonActsOnlyOnACopy`
- `tests/test_direct_socket_credentials.py::TestTheProbedPairIsTheEndpointsOwn`
- `tests/test_direct_socket_credentials.py::TestDaemonCredsIsTheResolversAnswer`
- `tests/test_direct_socket_credentials.py::TestARemovedSocketLeavesTheCredentialsAndTheNextAddressIsAMove`
- `tests/test_direct_socket_lock.py::TestAFailedWriteOfJensSettingsIsHandledLikeARefusal`
- `tests/test_config_merge.py::TestTheMergeAsksTheWritersQuestion`
- `tests/test_config_doctor.py::TestTheCredentialModelMarkerAndTheBlankKea6Database`
- `tests/test_credential_transport.py::test_the_transport_posts_exactly_what_resolve_says`
- `tests/test_credential_transport.py::TestTheRowsTheReviewNamed`
- `tests/test_setup_wizard_stepup.py::TestTheIpv6StepCanSayNoAuthentication`
- `tests/test_credentials.py::TestAnIpv6LiteralDatabaseHost`
- `tests/test_credential_destinations.py::TestADirectSocketKeepsWhatWorkedWhenTheHostChangesSpelling`
- `tests/test_credential_destinations.py::TestTheFormsCanSayNoPassword`
- `tests/test_credential_destinations.py::TestTheWizardsFirstStepDoesNotSendASavedPasswordToANewHost`
- `tests/test_credential_destinations.py::test_the_row`
- `tests/test_credential_destinations.py::TestTheSevenFormsAreHeldByTheWriterWhoeverPosts`
- `tests/test_setup_wizard.py::TestEnableV6`
- `tests/test_setup_wizard_stepup.py::TestTheWizardAsksForTheConfirmationItNeeds`
- `tests/test_direct_socket_credentials.py::TestARemovalNeverLeavesJenPointingAtTheSocketItRemoved`
- `tests/test_direct_socket_credentials.py::TestARestorePutsBackAbsenceAndTheKeepNeedsAnOwnPassword`

### CRED-005 - A URL never carries a password
**Rule.** (Q190.) The credential rule's fields (`api_user`, `api_pass` and their per-daemon twins, resolved by `credentials.resolve`) are the ONLY place a Kea password lives. `auth.valid_api_url` refuses an address
with user-info (`https://user:password@host:8004`, `https://user@host`), the forms say so (`auth.userinfo_sentence`), and the same function is the one definition at every form and in the wizard. An address
that already carries user-info in jen.config is legacy input: `AppConfig.apply` logs ONE warning per section and key (never the value), Health's "Every endpoint has a credential" row names it and says to move
it to the user and password fields, and Jen keeps dialling it as written (the credential rule is not touched). Every sentence that shows an address goes through `auth.shown_url` (LEAK-001).
**Established.** Q190 (beta.20's review: `valid_api_url` accepted user-info and Rotate's probe-failure flash, the connection form's audit row and the authoring flash printed the address as typed).
**Enforced at.** `auth.valid_api_url` / `userinfo_sentence` / `shown_url` / `scrub_urls` / `urls_with_userinfo`; `config._warn_userinfo_urls`; `health._endpoint_credentials`.
**Tests.**
- `tests/test_url_never_carries_a_password.py::TestValidApiUrl`
- `tests/test_url_never_carries_a_password.py::TestLegacyUrls`
- `tests/test_kea_tls_rotation.py::TestALegacyUrlWithAPasswordNeverReachesText`
- `tests/test_direct_socket_lock.py::TestALegacyUrlWithAPasswordNeverReachesTheRecoveryLines`
- `tests/test_invariant_sweeps.py::TestS14AnAddressIsShownByOneHelper`

### REMOTE-001 - A TLS or socket operation is one transaction: local state first, every step proved, the restored endpoint answers, every unproved state durable, every target from the configuration, every record the host's own
**Rule.** (Final form, Q188; the target set and the record added by Q189.) A direct-socket or CA operation changes a Kea host and then Jen's own state. It is ONE transaction:
1. **Jen's own recovery state is committed before the host is touched.** The https setup writes `.prev` (a copy of the live pair: what the host has) and `.staged` (what it is about to be given) before
   `install_tls`; the rotation stages the new CA and client pair beside the live files. A copy Jen cannot keep stops the operation with nothing changed. A stale `.prev` from an older operation is never
   the rollback source. **A refusal changes nothing, and the cleanup of a failed run is scoped to what the run committed (Q198).** A failed rotation retires the `.prev` and the stale marker of a target
   only when THIS run wrote that target's record (`commit_issued` succeeded, or its own rollback re-wrote it); a target the run never attempted - the one after the name that was refused, the one a refusal
   at the inventory, the storage proof or the external probe never reached - keeps both, because its `.prev` can be the only copy of what its host holds. `record_state` says so: a live copy the stale
   marker calls not the host's is `jen-stale` (still a rotation target, and `host_material` answers its `.prev`). **Stale is a fact about the daemon (Q198):** a record whose server is CONFIGURED but not an
   https endpoint now is PARKED - its daemon may still present the certificate, so Jen keeps it, watches its expiry in Health, names it, never forgets it while the socket exists, and it is the daemon's again
   when the server is switched back; `stale` is only a record for a server that is not configured at all. A socket that references Jen's files with no record of them is `remote-unknown`, never `tls-local-stale`.
2. **Every step after the first remote change either proves itself or the operation stops and compensates.** The promotion of the staged pair to live is one: when it fails the previous material is
   reinstalled, the existing socket is probed, `.prev` is kept and the socket change never starts. A completed setup is reported only when the certificate the socket PRESENTS is the one Jen holds. The
   rotation promotes the staged CA last, inside one exception boundary, after Jen's TLS settings are saved; a failure rolls EVERY attempted target back to a CA-A certificate, restarts and probes it, and
   discards the staging in a `finally`. A transport exception from the channel (`socket.timeout`, `EOFError`, `SSHException`) is a failed answer from `install_tls` / `service_action`, never an escape.
3. **The compensation is a SNAPSHOT, not an inverse.** The daemon's whole `control-sockets` list is taken from the very read the change is planned on and the only compensation is restoring it; the TLS
   material the change replaced goes back BEFORE the restart the compensation makes. Jen manages one API socket: a daemon with more than one is refused before anything is sent, and a removal removes only
   the entry it names. An unreadable daemon config refuses an https change before any file is replaced (an unavailable observation never reads as safe).
4. **"Undone" means: config restored, material restored (both halves), daemon restarted, and the endpoint Jen dials ANSWERS as the right daemon with its recorded credentials and TLS context.** A
   file that already matched, a plan that never read the config, a restore that fails, a certificate whose Jen-side copy could not follow, or an endpoint that does not answer is the partial state, said,
   with the by-hand step. Recovery text, audit rows and log lines name a socket by type, address and port (`describe_socket`) and never print its entry (LEAK-001's family).
5. **What cannot be proved is a durable incident, written under a lock.** Ten categories (`remote-unknown`, `restored-restart-unverified`, `restart-failed`, `tls-not-restored`, `tls-local-stale`,
   `restored-endpoint-unreachable`, `probe-pending`, `aborted`, and from Q199 `tls-superseded` and `record-forgotten`), shown on Servers and in Health until a verified recovery of THAT server and service (a probe that got its answer; a removal clears only the
   `probe-pending` note of the socket it removed) or a superadmin's acknowledgement. The incident note is one settings row read-modify-written as a `SELECT ... FOR UPDATE` transaction
   (`kea_changeset._with_attention`), so two workers lose neither; a write that did not happen is never reported as done; an unreadable note is Health "unknown", not "ok"; the soft cap never evicts a
   recovery incident (the hard ceiling keeps the newest 200). An incident never carries a socket entry, a key or a credential.
6. **A daemon an operation leaves behind is a durable incident, and a record is the GROUP of its files (Q199).** A server that is configured but not dialled over https (PARKED) whose daemon still runs
   its https socket is on the CA a successful rotation just replaced: the rotation records `tls-superseded` (Servers, Health, the page; ended by a later setup that replaces or proves the certificate, or by
   the socket's removal), and a record forgotten on the operator's word leaves `record-forgotten` - no daemon is silently left unwatched. A cleanup reports success only after the files are gone
   (`discard_local_record` returns `removed`/`absent`/`failed` after re-checking every path; `forgotten` only when `failed` is empty); a routine save that drops a removed server's records names them in the flash
   and the audit row; discovery enumerates every recognised record file and groups them by `<n>-<service>`, so an orphan (a key without its certificate) is shown and forgettable and an unrecognised name is
   never touched; and a record carries its DESTINATION (`record_state` compares the certificate's SANs with the configured SSH host and address under `same_host`: a record kept under a server number now pointed
   at a different daemon refuses the rotation and is kept). **A multi-host operation enumerates its targets from the CONFIGURATION (every endpoint Jen dials) and refuses when its record of any one of them is missing or unreadable (Q189).** The rotation's targets are
   `kea_tls.rotation_inventory`: every https endpoint of every configured server, each with a certificate and key that load, are a pair and were issued by Jen's live CA - a missing, malformed or mismatched
   record, or a copies directory that cannot be listed, is a REFUSAL before the staging; an unlistable inventory is a refusal, never an empty set. The endpoints are read from the CONFIGURED address
   (`kea.configured_url`), never from the transport's answer - an endpoint whose password the resolver withheld still exists and still runs Jen's material, so it blocks the rotation instead of dropping out of it.
   A success is proved against the same set (the endpoints that answered with the new identity are the endpoints planned).
10. **Whether an endpoint depends on Jen's CA is a fact about CERTIFICATES, decided per endpoint - never from a path string and never for all endpoints at once (Q190).** `record_state` is asked FIRST: a
   copy issued by Jen's live CA is a target whatever the trust path says (its daemon presents Jen's material; rotating Jen's identity without it cuts Jen off); a copy issued by another CA is the
   administrator's, named and left alone; one issued by an earlier Jen CA is a refusal. Only an endpoint with NO copy at all asks the trust path - as the tiebreak, by identity (`kea_tls.trust_bundle`:
   every certificate of the bundle at `[kea] api_ca` compared by DER with Jen's live CA): Jen's CA only -> a refusal (it verifies this endpoint against its own CA and holds no record); Jen's CA AND another
   -> a refusal (the bundle does not say which - ambiguity is a refusal); another CA only -> the administrator's; no bundle -> the administrator's when Jen verifies against the system's CAs and a REFUSAL when
   Jen verifies nothing (it looks at no certificate, so it cannot tell); unreadable -> a refusal. Rotate rewrites `api_ca` only when it IS Jen's own file (`trust_kind() == "jens-file"`); an alias follows the file
   and is left as the operator wrote it (the flash says so); a COPY of Jen's CA, or a bundle that holds it, cannot be rewritten and would leave Jen holding the old CA, so a rotation with a Jen-issued target and
   either of them is a REFUSAL before anything is staged, naming the path. `tests/test_invariant_sweeps.py` S13 refuses any other comparison of `KEA_API_CA` (or the config key `api_ca`) with a path. The https setup
   gate passes only Jen's own file, an alias or a copy (never a bundle, an administrator's CA or an unreadable file), and its writer fills in a MISSING `api_ca` / client certificate instead of comparing paths.
   **Jen's identity to a daemon is its CA bundle AND its client pair (Q191).** A daemon with `cert-required` checks both, so every configured input to that identity is judged by certificate, per shape, before
   the first remote change, and a shape the rotation cannot carry (a copy) is a refusal. `kea_tls.client_kind()` is the ONE definition of the configured pair (`none` / `jens-file` / `alias` / `copy` / `other` /
   `unreadable`, by realpath and DER - S13 refuses any other comparison of `KEA_API_CLIENT_CERT` / `_KEY` or their config keys): the rotation asks it after the bundle and before staging, and with a Jen-issued
   target a `copy`, an `other` (the dial never worked) and an `unreadable` pair are a REFUSAL naming the path; an `alias` follows the replaced file; the https setup gate refuses the same three; the connection
   form refuses a `copy` (an operator's own PKI stays allowed).
   **An identity is replaced only after it has been proved, with the replacement, against every endpoint it is presented to; a damaged identity file is a recovery condition surfaced in Health and refused by
   every ordinary action, never evidence that the identity never existed; a pair is a pair only when the key is the certificate's (Q192).** (1) The rotation stages the new CA and client pair and, BEFORE the
   install loop, probes every external https endpoint (`rotation_inventory(...).external_endpoints`) with the configured bundle twice - with the LIVE client pair (the baseline: unreachable regardless is a
   refusal) and with the STAGED one - and refuses one that answers the first and refuses the second: its trust anchor for client certificates is Jen's current CA, and promoting CA-B would lock Jen out of it.
   "Prepare only" keeps `.next` (the keys private, the fingerprint shown, `PREPARE_KEA_CA` audited) for the operator to add to that daemon beside the current CA, a later Rotate reuses a consistent `.next`
   (an incomplete or inconsistent one is discarded and said), and a rotation that fails keeps a PREPARED one but discards one it staged itself. (2) `kea_tls.ca_state()` is the ONE definition of Jen's CA
   (`none` / `ok` / `damaged` with why; `ca_present` is deleted - sweep S15): `none` is the uninitialised world ONLY (no CA files, no client pair, no `.prev`, no `.next`, no `kea-servers` directory at all, nothing
   unlistable - T7); the same absence beside any of that is `damaged`, as is a certificate that parses but whose public key is unusable (it must never raise). `ensure_ca` creates only in `none` and raises
   `CaDamaged` otherwise, `issue_server_cert` / `issue_client_cert` raise it instead of signing, `_material` (the install payload) is built only from an ok CA, the https setup refuses a damaged CA before anything
   is CHANGED on a host, Health fails, and Rotate replaces a damaged CA only with an explicit acknowledgement that a server which fails part-way cannot be put back (the rollback records `tls-not-restored`; a recovery
   judges the CA bundle by PATH - Jen's file or a link replaced, anything else a copy - because its own certificate cannot be compared, and the live client pair without its issuer).
   A rotation also refuses before staging when a live identity file is a directory or a link it cannot replace (`promotion_blockers`). (3) `kea_tls.client_state()` is the ONE definition of Jen's client pair
   (SPKI, the live issuer, `clientAuth`, validity; `none` / `ok` / `expiring` / `damaged`): `issue_client_cert` re-issues a damaged pair from an ok CA (the old pair kept as `.prev`) and the setup that calls it
   says so. **The recovery's sentences (Q193).** Every sentence on the recovery path says what HAPPENED and names an action the damaged gate does not itself refuse: a failed acknowledged recovery (the CA
   was damaged before staging, no promotion ran) counts and names the daemons not re-issued, says Jen's CA is still damaged and that the action is to Rotate again with the acknowledgement - never "a
   promotion failed", never ".prev", never "set it up again" (the https setup is refused while the CA is damaged); Health, the page, Rotate's refusal, the setup's refusal and Prepare carry the SAME two
   actions (`kea_tls.DAMAGED_CA_ADVICE`: restore from a backup, or the acknowledged Rotate); Prepare works while the CA is damaged (it mints a fresh CA and reads nothing live); in a recovery an endpoint
   Jen verifies against its OWN CA file is a target whatever record it holds, and an unlistable copies directory is not a refusal while it can be WRITTEN (the read of the old copies is waived, never the write of the new ones: a host that took a pair Jen cannot record is cut off); a recovery that fails at ANY step - the promotion included - is judged by the CA now (as damaged as it was) and says what each daemon is: cut off by the replacement CA's pair (an incident with its own fixed sentence), unknown, or not changed; a sentence about a damaged CA offers the action that works (`_reissue_action`), never the setup; a refused first install is `remote-unknown` (the host's material is
   unknown), `tls-not-restored` only for a host KNOWN to hold the staged pair. (4) `tests/test_kea_tls_worlds.py` generates a world per (file, state) over every file the module reads, with T6 (no ordinary action replaces a damaged identity file) and T7, and a test lists the
   module's path functions, suffixes, configured inputs and reading functions so a new one is a new row. **A CA is healthy only when it is a certificate-signing authority (Q194).** `kea_tls.ca_identity`
   is the ONE judgment of CA material - the live, the prepared and the staged pair: both files load, the key is the certificate's, the certificate is inside its validity window now, `BasicConstraints`
   says `ca=True`, a `KeyUsage` - when there is one (RFC 5280: none means unrestricted, which is what an operator's `openssl req -x509` CA often has) - has `keyCertSign`, issuer equals subject, the self-signature verifies with its own public key, and the key is EC or RSA; a certificate that cannot be READ (a duplicated extension: `DuplicateExtension` is not a `ValueError`) is damaged, never an exception, and a self-signature Jen cannot verify (SHA-1) says that instead of "does not verify". `ca_state`, `_load_ca`, `ensure_ca`,
   `ca_consistent` (the failure paths' "the CA is still damaged"), `prepared_rotation`, the staged-set check before the first install and Health all ask it; an existing CA that fails it is DAMAGED -
   never absent, never replaced by an ordinary action - and an invalid prepared CA is refused, discarded by the writer with the reason, and never installed on a host. Q192's states were syntactic
   (absent, malformed, mismatched ...) and `ok` meant "a pair": a `ca=False` certificate, an expired one and a tampered self-signature were all `ok`. **A preflight that guards a remote change proves by
   doing the thing it guards (Q194).** `kea_tls.copies_dir_writable` CREATES the certificate-record directory (0700) and writes and removes a UNIQUELY named probe inside it (leftover probes are cleaned) - Q193's version inferred that a
   missing directory is writable and was asked only when LISTING raised - and it runs on every path that will need it: every rotation's inventory (recovery or not), the https setup before Jen creates
   a CA or a client pair of its own, and the recovery once more immediately before its first install (`HostRecordLost` stays the backstop). The PREFLIGHTS pass `keep=False` and leave the directory as they
   found it - a refusal changes nothing, and an EMPTY record directory in the uninitialised world would read as evidence that a CA existed; only the check immediately before a write keeps what it made. Read-only callers (the page, Health, the end-of-rotation comparison) pass `prove_storage=False`: a read
   creates nothing. **In a recovery an external endpoint is proved against the REPLACEMENT identity (Q195).** The live client pair fails beside an external that trusts the damaged CA BECAUSE that CA can no
   longer vouch (expired, not a CA, not yet valid), so Q192's "an endpoint that does not answer the live pair is unreachable regardless" does not hold in a recovery: when the live pair is REJECTED BY
   CERTIFICATE (a certificate alert, a named client certificate, or the connection CLOSED in the handshake - how a TLS 1.3 server says it: 88-95 percent of real rejections against an OpenSSL server were
   `EOF occurred in violation of protocol` / `Remote end closed connection`, executed - and not a timeout, a refusal, a name that does not resolve, or Jen failing to verify the daemon) the staged pair is tried: accepted is not a refusal; rejected too is "Prepare the
   new CA, install its certificate on that endpoint, then rotate again"; a transport fault keeps its sentence. A healthy rotation is unchanged. The fake daemon rejects an anchor OpenSSL would reject
   (`Lab.accepts_client`, `_anchor_usable`, pinned to the OpenSSL table that was executed: a self-signature is not checked, an issuer that is not the subject is rejected). **The failure of a rotation says the CA's state NOW (Q195):** a CA that became unusable without a promotion says `ca_state`'s why and the acknowledged Rotate
   (T2 pins the state, not a phrase); a probe file is Jen's only by its exact name (`kea_tls.PROBE_NAME`) - the cleanup removes only a LEFTOVER of it (older than a minute, never a probe being written right now) and never an operator's file.
   **A CA is healthy when the REAL verifier accepts what Jen issues from it, for both purposes (Q196).** `ca_identity` keeps its structural checks (they give the `why` a person recognises) and ends with
   `ca_verifier_rejection`: a throwaway server leaf and a throwaway client leaf are issued from the CA IN MEMORY (never written) and verified with `cryptography.x509.verification` - the verifier's own
   message is the `why` - so an Extended Key Usage that leaves out a purpose, a name constraint that excludes every name, a path length, a weak algorithm, or the next property a review names is caught
   by the same line. The web-PKI profile is relaxed only where RFC 5280 allows and the daemon's OpenSSL accepts (an absent KeyUsage, `policyConstraints`, `inhibitAnyPolicy`, and the CRITICALITY - never the
   meaning - of BasicConstraints, the Extended Key Usage and certificatePolicies: an EKU is still enforced as a PURPOSE through its validator) and the throwaway leaf is valid at the instant it is
   verified whatever `_now` says. What the library offers no switch for stays STRICTER than OpenSSL and is pinned (a leading-dot or directoryName name constraint, a key that is not P-256/384/521 or
   RSA of 2048 bits or more). **The REAL leaf is verified too (Q196, second pass):** the oracle's probe leaf has a DNS name, Jen's server leaf has the bind IP, so `issue_server_cert` and
   `issue_client_cert` verify the leaf they ACTUALLY issue - real SANs, the client profile relaxed for a leaf with no SAN - before returning it (`verify_issued`), and a CA that cannot sign for THIS server
   is refused before anything is installed; a leaf's AKI names the CA's actual SKI. Where the `openssl` CLI exists Health also asks `openssl verify`: evidence on the damaged row when Jen rejects and OpenSSL accepts (`openssl_second_opinion`, informational; an openssl that is
   broken or cannot run is no opinion). **Where the daemon's own library is on the box, it judges at the gate (Q197).** Q196 put the CLI in Health only ("a warning, never a refusal") and the gates asked the
   library alone, so a CA both real stacks reject was `ok` at the gate - an anyExtendedKeyUsage-only EKU (OpenSSL ignores it on a CA) and a self-issued root whose AuthorityKeyIdentifier keyid is not its own
   SubjectKeyIdentifier were the two the first pre-reviewer pass found and the handshake confirmed. Both are coded divergences and `damaged`, and `ca_identity` ends with `ca_gate_rejection`: the library's
   verdict first, then `openssl verify -purpose sslserver|sslclient -auth_level 2` over the same throwaway leaves; a CLI rejection is `damaged` with its own line, and a CLI that is absent, broken (exit
   127, a usage message, an exit code with no verdict), slow (the child AND its process group are killed at the timeout) or unreadable is NO opinion - never a rejection and never an acceptance. A verdict exists
   only on `verification failed`, `error N at D depth lookup` or `: OK`. The comparison with the CLI is with `ca_state`'s own verdict. **A healthy CA that cannot issue for THIS name is told so
   (Q197):** `verify_issued`'s refusal of a leaf's name is `NameRefused`, never `CaDamaged` - the setup, Rotate and the page say the CA is healthy, name the SAN that failed and ask for no acknowledgement; the
   form refuses an https direct host the verifier's DNSName parser rejects. **A record of an endpoint that is no longer https is stale, not valid, and no second owner of its daemon (Q197):** Health does not count it, Rotate ignores it, a removed
   socket drops it (`discard_local_record`), and a superadmin can forget the rest (local, audited). **One daemon is one record where the world is MADE (Q197):** an https setup is refused when another server
   record with the same SSH host already holds a Jen-issued certificate for the same service. **The staged rotation leaves no key copy (Q197):** the `.next` set is written without `.prev`. **One daemon is one rotation target (Q196).** Two targets with the same SSH host (`same_host`: exact,
   no DNS) and the same service are a refusal BEFORE staging; the route probes EVERY target once more with the staged identity after the last install and before the promotion, so each endpoint answers the
   FINAL material on its host (a failure there is the rollback).
11. **A stored incident Jen cannot recognise is kept (Q190).** Each entry of the recovery record has a shape (`kea_changeset.recognised_incident`: an attention incident has a known category, a service, a server
   id, a summary and a time; an outcome incident a `rolled_back`/`rollback_failed` status, a service and a time); `_incidents_of(strict=True)` raises `MalformedNote` naming the entry's INDEX, every writer
   refuses the whole note, `_incident_cleared` is False for an entry it cannot read (fail closed, in the lenient reader too), and the Servers banner says an incident Jen cannot read is on record.
12. **An invariant has no knob (Q190).** `Lab.check_invariants` ranges over the simulated host's daemons - T1 is judged by the certificate the HOST holds, T3 is relative (a daemon that answered Jen's live
   identity before a request answers after it, or an incident names it; one that did not is untouched), T4 looks for every configured secret including the password inside a configured address - and a test may
   not narrow it.
7. **Jen's record of what a host holds is the exact payload that host accepted, or "unknown" - never a copy made by the mechanism that failed (Q189).** `commit_issued` writes the pair the host was given
   as `.prev` and marks the live copy stale when its own write fails; when even that cannot be written (`HostRecordLost`) the route records `remote-unknown`, and `host_material` answers None - for an open
   `remote-unknown` or `tls-not-restored` incident, a `tls-local-stale` incident whose marker is missing, a record that cannot be read, or a pair that does not load. The fact is ALSO a file beside the pair
   (`.unknown`): an incident is acknowledged away by a person and resolved by a verified recovery, and neither makes the live copy the host's pair again - only an operation that gives the host a pair Jen then
   records (`commit_issued`, `promote_staged`, `restore_previous`) clears it, and an acknowledgement that cannot leave the marker is refused. A stale marker over a `.prev` pair that loads is the file layer
   KNOWING, and a transient failure to read the incident record does not destroy it. No re-assert installs a pair Jen does not know the host holds.
8. **A stored record of unresolved incidents that cannot be read is never written over (Q189).** `_incidents_of(strict=True)` admits three shapes (nothing; `{"incidents": [dicts]}`; the 5.65.x single note);
   anything else makes every writer refuse - unchanged, False - and a superadmin sets it aside (the raw value copied to its own settings row, the note cleared, the audit row carrying the length and the key).
9. **The pre-read is a call site (Q189).** `kea_host.read_config_versioned` answers a transport exception as a failed read; both routes refuse before they send anything.
**The invariants run after EVERY scenario (Q189, AE0).** `tests/test_kea_tls_rotation.py`'s `Lab.check_invariants()` runs in the fixture's teardown for every test in the file: T1 (Jen's record of each host's
pair is byte-equal to the pair the host holds, or None with an incident naming the server), T2 (the CA is a pair, or every target says it is not), T3 (every running daemon answers Jen's live CA and client
certificate, or an incident names it), T4 (nothing printed carries key material or the password), T5 (a refusal changes nothing); `TestTheInvariantsBite` breaks the product on purpose, once per invariant.
**Established.** Q186 (the snapshot, `describe_socket`), Q187 (the probe-failure branch, the TLS material, the persistent incident), Q188 (the transaction: local state first, the promotion, the rotation, the
endpoint that must answer, the locked incident store, the transport boundary), Q189 (the inventory, the host's record, the unreadable note, the pre-read, the invariants after every scenario), Q190 (who is on
Jen's CA by certificate identity, per endpoint; an invariant with no knob; an incident Jen cannot recognise is kept).
**Enforced at.** `kea_config_edit.control_sockets` / `restore_control_sockets` / `describe_socket`; `kea_tls.stage_issued` / `promote_staged` / `commit_issued` / `commit_rotation`;
`infrastructure._undo_remote_change` (the one compensation both direct-socket routes call), `_put_tls_back`, `_endpoint_answers`, `rotate_kea_ca`; `kea_changeset._with_attention`;
`user.update_global_setting`; `kea_host.install_tls` / `service_action` / `read_config_versioned` (the transport boundary); `kea_tls.rotation_inventory` / `record_state` / `commit_issued` /
`host_material` / `HostRecordLost`; `kea_tls.trust_bundle` / `trust_kind` / `trust_includes_jens_ca`; `kea_changeset._incidents_of(strict)` / `recognised_incident` / `_incident_cleared` / `set_aside_unreadable_note`.
**Tests.**
- `tests/test_kea_config_edit.py::TestControlSocketSnapshotAndRestore`
- `tests/test_direct_socket_lock.py::TestALateRefusalOnSetupPutsTheHostBack`
- `tests/test_direct_socket_lock.py::TestALateRefusalOnRemovalPutsTheSocketBack`
- `tests/test_direct_socket_lock.py::TestAFailedWriteOfJensSettingsIsHandledLikeARefusal`
- `tests/test_direct_socket_lock.py::TestAProbeThatFailsAfterAReplacementPutsTheWorkingSocketBack`
- `tests/test_direct_socket_lock.py::TestTheTlsMaterialIsPartOfTheSnapshot`
- `tests/test_direct_socket_lock.py::TestTheHttpsSetupCommitsJensStateFirstAndStopsAtTheFirstUnprovedStep`
- `tests/test_direct_socket_lock.py::TestAPartialTlsRestoreIsPartial`
- `tests/test_direct_socket_lock.py::TestUndoneMeansTheEndpointAnswered`
- `tests/test_direct_socket_lock.py::TestAnUnreadableConfigIsNotNoSocketUsesJensFiles`
- `tests/test_direct_socket_lock.py::TestTheChangeSetsTwoRollbackFailedStates`
- `tests/test_direct_socket_lock.py::TestANochangeRerunDoesNotReplaceFilesTheDaemonWillNotReload`
- `tests/test_kea_tls_rotation.py::TestAPromotionThatFailsPutsEveryTargetBack`
- `tests/test_kea_tls_rotation.py::TestATargetThatFailsAfterTheFirstIsRolledBackAndTheNextIsNeverTouched`
- `tests/test_kea_tls_rotation.py::TestARollbackThatCannotCompleteIsNamed`
- `tests/test_kea_tls_rotation.py::TestATransportExceptionNeverEscapes`
- `tests/test_kea_tls_rotation.py::TestTheSecondPassOfQ188`
- `tests/test_kea_tls_rotation.py::TestAStaleCopyIsTheHostsPreviousPair`
- `tests/test_direct_socket_lock.py::test_an_http_success_proves_nothing_about_a_certificate`
- `tests/test_kea_tls_rotation.py::TestInventory`
- `tests/test_kea_tls_rotation.py::TestHostRecord`
- `tests/test_kea_tls_rotation.py::TestTheInvariantsBite`
- `tests/test_kea_tls_rotation.py::TestTheSecondPassOfQ189`
- `tests/test_direct_socket_lock.py::TestTheSetupGateAndTheWriterJudgeTheTrustByCertificate`
- `tests/test_kea_tls_rotation.py::TestClientIdentity`
- `tests/test_kea_tls_rotation.py::TestTheConnectionFormJudgesTheClientPair`
- `tests/test_kea_tls_rotation.py::TestTheInvariantsBiteTooQ191`
- `tests/test_kea_tls_rotation.py::TestTheSecondPassOfQ191`
- `tests/test_direct_socket_lock.py::TestTheSecondPassOfQ191`
- `tests/test_kea_tls_rotation.py::TestSplitTrust`
- `tests/test_kea_tls_rotation.py::TestCaState`
- `tests/test_kea_tls_rotation.py::TestClientState`
- `tests/test_kea_tls_rotation.py::TestTheInvariantsBiteTooQ192`
- `tests/test_kea_tls_worlds.py::TestTheSecondPassOfQ192`
- `tests/test_kea_tls_rotation.py::TestAFailedRecoverySaysWhatHappened`
- `tests/test_kea_tls_worlds.py::TestTheRecoveryNamesActionsThatWork`
- `tests/test_direct_socket_credentials.py::TestTheProbeRowsOfQ193`
- `tests/test_kea_tls_rotation.py::TestTheSecondPassOfQ193`
- `tests/test_kea_tls_worlds.py::TestTheSecondPassOfQ193`
- `tests/test_kea_tls_rotation.py::TestCaIdentity`
- `tests/test_kea_tls_rotation.py::TestCopiesDir`
- `tests/test_kea_tls_rotation.py::TestTheSecondPassOfQ194`
- `tests/test_kea_tls_rotation.py::TestRecoveryBesideAnExternal`
- `tests/test_kea_tls_rotation.py::TestTheSmallOnesOfQ195`
- `tests/test_kea_tls_rotation.py::TestTheSecondPassOfQ195`
- `tests/test_kea_tls_rotation.py::TestCaIdentityIsTheVerifier`
- `tests/test_kea_tls_rotation.py::TestOneDaemonOneTarget`
- `tests/test_kea_tls_rotation.py::TestTheSecondPassOfQ196`
- `tests/test_kea_tls_rotation.py::TestTheDaemonsVerifierJudges`
- `tests/test_kea_tls_rotation.py::TestTheValueFamiliesAgainstTheRealCli`
- `tests/test_kea_tls_rotation.py::TestTheCliGateIsBounded`
- `tests/test_kea_tls_rotation.py::TestTheStaleRecords`
- `tests/test_kea_tls_rotation.py::TestHygieneOfQ197`
- `tests/test_kea_tls_rotation.py::TestTheNameWorldsOfRotate`
- `tests/test_kea_tls_rotation.py::TestARefusalChangesNothing`
- `tests/test_kea_tls_rotation.py::TestStaleIsAFactAboutTheDaemon`
- `tests/test_kea_tls_rotation.py::TestTheAkiAndNameRowsOfQ198`
- `tests/test_kea_tls_rotation.py::TestPreparedCaThatCannotNameAHost`
- `tests/test_kea_tls_rotation.py::TestTheSmallOnesOfQ198`
- `tests/test_direct_socket_lock.py::TestQ198TheSetupAndTheFormsAfterTheRecordsChange`
- `tests/test_direct_socket_credentials.py::TestTheProbeRowsOfQ198`
- `tests/test_config_merge.py::TestTheCertificateNameRuleInTheInstallerMerge`
- `tests/system/test_boundaries.py::test_22_l_a_rotation_refused_by_a_name_on_the_second_daemon_leaves_the_first_daemons_records_as_they_were`
- `tests/test_kea_tls_rotation.py::TestTheSecondPassOfQ197`
- `tests/test_kea_tls_rotation.py::TestADaemonLeftBehindIsAFact`
- `tests/test_kea_tls_rotation.py::TestTheStringTypeFamily`
- `tests/test_kea_tls_rotation.py::TestACleanupReportsWhatHappened`
- `tests/test_kea_tls_rotation.py::TestARecordIsTheGroupOfItsFiles`
- `tests/test_kea_tls_rotation.py::TestARecordCarriesItsDestination`
- `tests/test_kea_tls_rotation.py::TestTheSecondPassOfQ199`
- `tests/test_direct_socket_lock.py::TestQ199TheForgottenRecordDoesNotTakeTheAnswerWithIt`
- `tests/test_direct_socket_lock.py::TestQ199TheSetupAfterARotationLeftADaemonBehind`
- `tests/test_direct_socket_lock.py::TestQ199TheExtraServersSaveNamesWhatItDrops`
- `tests/test_direct_socket_lock.py::TestQ199TheSmallOnes`
- `tests/test_direct_socket_credentials.py::TestTheProbeRowsOfQ199`
- `tests/system/test_boundaries.py::test_22_m_a_daemon_a_rotation_left_behind_is_a_fact_the_setup_names_the_action_and_removal_with_a_setup_recovers`
- `tests/test_direct_socket_lock.py::TestTheSecondPassOfQ197`
- `tests/test_kea_tls_worlds.py::TestEveryValueFamilyIsARow`
- `tests/test_kea_tls.py::TestTheUnsafeReplacementPathIsGone`
- `tests/test_direct_socket_lock.py::TestQ197TheNameWorldsOfTheHttpsSetup`
- `tests/test_direct_socket_lock.py::TestQ197TheHostNameTheFormSavesIsTheNameACertificateCanCarry`
- `tests/test_direct_socket_lock.py::TestQ197TheSetupAsksTheOneDaemonQuestion`
- `tests/test_direct_socket_lock.py::TestQ197ARemovedSocketDropsItsRecord`
- `tests/test_direct_socket_credentials.py::TestTheProbeRowsOfQ197`
- `tests/system/test_boundaries.py::test_22_k_a_ca_whose_only_usage_is_any_extended_key_usage_refuses_an_https_setup_naming_the_daemons_verifier`
- `tests/test_direct_socket_credentials.py::TestTheProbeRowsOfQ196`
- `tests/system/test_boundaries.py::test_22_j_a_ca_a_real_verifier_rejects_refuses_an_https_setup_and_health_names_the_restriction`
- `tests/test_direct_socket_credentials.py::TestTheProbeRowsOfQ195`
- `tests/test_direct_socket_credentials.py::TestTheProbeRowsOfQ194`
- `tests/system/test_boundaries.py::test_22_i_a_recovery_that_cannot_write_its_certificate_records_is_refused_before_any_host_changes`
- `tests/test_kea_tls_worlds.py::TestTheWorldsOfTheLab`
- `tests/test_kea_tls_worlds.py::TestEveryInputOfTheModuleIsARow`
- `tests/test_direct_socket_lock.py::TestTheWorldsOfTheSetupHarness`
- `tests/test_direct_socket_lock.py::TestSetupWithADamagedCaOrClientPair`
- `tests/test_invariant_sweeps.py::TestS15TheCaIsReadThroughCaState`
- `tests/test_direct_socket_credentials.py::TestTheProbeRowsOfQ192`
- `tests/system/test_boundaries.py::test_22_h_a_damaged_ca_refuses_an_https_setup_and_is_replaced_only_by_an_acknowledged_rotation`
- `tests/test_direct_socket_lock.py::TestTheSetupGateJudgesTheClientPairByCertificate`
- `tests/test_direct_socket_credentials.py::TestTheProbeRowsOfQ191`
- `tests/test_kea_tls_rotation.py::TestWhoIsOnJensCaIsDecidedByCertificatesNotPaths`
- `tests/test_kea_tls_rotation.py::TestALegacyUrlWithAPasswordNeverReachesText`
- `tests/test_kea_tls_rotation.py::TestTheInvariantsBiteTooQ190`
- `tests/test_kea_changeset.py::TestEveryEntryOfTheNoteHasAShape`
- `tests/test_servers.py::TestAnIncidentJenCannotReadIsKeptAndSaid`
- `tests/test_invariant_sweeps.py::TestS13ATrustPathIsNeverComparedAsAString`
- `tests/test_direct_socket_credentials.py::TestTheProbeRowsOfQ190`
- `tests/test_direct_socket_lock.py::TestANewEntryStillInTheConfigIsNotNoSocketReferencesTheFiles`
- `tests/test_kea_changeset.py::TestTheSetAsideClearsOnlyWhatItCopied`
- `tests/test_kea_host.py::TestOnlyTheChannelsFailuresAreFailedReads`
- `tests/test_servers.py::TestAcknowledgingAnIncidentAboutACertificateRecordsThatJenDoesNotKnow`
- `tests/test_kea_changeset.py::TestMalformedNote`
- `tests/test_incident_store_locking.py::test_a_note_that_is_not_a_note_is_refused_unchanged_by_every_writer`
- `tests/test_servers.py::TestAnUnreadableRecoveryRecordIsSetAsideNeverOverwritten`
- `tests/test_kea_host.py::TestReadConfigIsATransportBoundaryToo`
- `tests/test_direct_socket_lock.py::TestThePreReadIsACallSiteToo`
- `tests/test_direct_socket_lock.py::TestAFirstSocketThatPresentsAnotherCertificateIsOneAnswer`
- `tests/test_direct_socket_credentials.py::TestTheProbeRowsOfQ189`
- `tests/test_health_center.py::TestKeaTlsExpiry`
- `tests/test_kea_changeset.py::TestAnUnprovedRecoveryIsAPersistentIncident`
- `tests/test_kea_changeset.py::TestTheIncidentNoteQ188`
- `tests/test_incident_store_locking.py::test_two_workers_recording_two_servers_both_land`
- `tests/test_incident_store_locking.py::test_two_workers_on_a_row_that_already_exists_neither_deadlocks_nor_loses_its_update`
- `tests/test_servers.py::TestARecoveryThatWasNotProvedIsShownUntilItIsAcknowledged`
- `tests/test_invariant_sweeps.py::TestS11bASocketEntryNeverReachesText`
- `tests/system/test_boundaries.py::test_22_a_failed_write_of_jens_settings_after_a_socket_change_puts_the_daemons_sockets_back`
- `tests/system/test_boundaries.py::test_22_b_a_replacement_that_never_answers_puts_the_working_socket_back`
- `tests/system/test_boundaries.py::test_22_c_an_https_replacement_whose_write_fails_puts_the_sockets_and_the_certificate_back`
- `tests/system/test_boundaries.py::test_22_d_an_https_replacement_whose_local_commit_fails_stops_with_the_previous_material_back`
- `tests/system/test_boundaries.py::test_22_e_a_ca_rotation_whose_promotion_fails_leaves_every_endpoint_answering_on_the_old_ca`
- `tests/system/test_boundaries.py::test_22_f_a_rotation_with_a_missing_record_is_refused_and_nothing_on_either_host_changes`
- `tests/system/test_boundaries.py::test_22_g_a_rotation_with_the_ca_bundle_an_alias_of_jens_ca_still_re_issues_and_answers`

### LOG-CACHE-002 - What a cache remembers about its readers is bounded by what is in flight, an unrelated key never waits, and a read begun before a clear is not kept
**Rule.** A second reader of the SAME key waits for the first one's read through a table of in-flight reads whose entries live only as long as their read - never one lock per key kept for the life of the process,
and never a striped set that lets an unrelated key's hung read hold another server's inside one budget; a `clear()` while a read is on the wire keeps that read's answer out of the cache.
**Established.** Q178 (`_per_key` grew one Lock per distinct (host, user, config path, id, path); the entry's 64 striped locks were tried and failed the model walk's E1 in CI, so the table is of in-flight reads).
**Enforced at.** `log_tail._flying` / `_flying_paths` and the generation counter in `log_tail.tail` and `log_tail.path_for`.
**Tests.**
- `tests/test_log_tail.py::TestTheGatesAreBounded`

### PROBLEMS-IDENTITY-002 - Rows of an earlier endpoint generation never suppress, trigger or absorb a replacement endpoint's problems
**Rule.** A Problems row belongs to the generation of the server id it was recorded under; the generation (`client_problems_gen:<id>`, part of the unique key) is incremented in the same transaction that clears the
server's progress when its identity (host, user, config path - never the display name) changes, and that transaction closes every open row of the older generations (resolved, with the pending qualification and
failed-attempt marker cleared). Every statement that reads or writes a server's rows filters by the current generation; the inbox says "(earlier host)" beside an earlier generation's rows and the dashboard never
counts them. The three statements that do not filter apply to every row of a server by design: the time-based resolution of any idle row, the 30-day retention prune, and the closing of a REMOVED server's open rows
(its number may be given to a new server, which must inherit nothing). The Problems page lists an earlier generation's rows only while they are the replacement's recent past (still active within the last 24 h
before the replacement), and the kind chips count only what is open now.
**Established.** Q178 (the beta.8 review: a replaced host inherited the old host's `alerted_at`, its failed-delivery retries and its open row's counts).
**Enforced at.** `client_problems._reset_if_endpoint_changed` and `_generation`, and migration 36 (`uq_client_problem_gen`).
**Tests.**
- `tests/test_client_problems_db.py::TestAReplacedHostIsANewGeneration`
- `tests/test_migrations.py::TestMigration36ProblemsGeneration`
- `tests/test_client_problems_db.py::TestTheInboxShowsOnlyTheReplacementsRecentPast`
- `tests/test_problems_generation_source.py::TestEveryStatementCarriesTheGeneration`

## Retired ids

An id that is retired stays here, with the reason, so it is never given to a different rule. (None yet.)
