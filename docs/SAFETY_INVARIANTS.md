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
**Enforced at.** `jen-kea-helper` (`investigation-arm`, `--self-restore`), armed by `investigation_logging.turn_on`. Since helper build 19 (Q212) the host keeps verifying AFTER a restore: until Jen forgets the session or its deadline + 15 minutes every tick asks again whether the file or the running daemon carries the marker and puts the logger back again when it does (an API write that lands over a restore: Kea has no compare-and-set) - since build 20 only the marker of the session the record is of (its deadline is the record's `until`; System boundaries test_19 on v7.0.0-beta.1 found build 19 taking a NEW session's marker out between Jen's file write and the arm, pinned by `TestWhatTheWalkFound` and `TestTheTickKeepsVerifying`); and Jen keeps out of the window in which that can happen (`investigation_logging.restore_window`, asked by `kea_api_config.apply`).
**Tests.**
- `tests/test_investigation_model.py::TestTheKeaHostKeepsTheDeadline` (the walk's I10, with Jen stopped, and the mutation check that goes red without the timer)
- `tests/test_investigation_model.py::TestTheApiWriteCannotLandOverTheHostsRestore` (the walk's API write and its fault - the host's restore landing between `config-hash-get` and `config-set` - and the mutation check that goes red without the window and the re-verification)
- `tests/test_investigation_model.py::TestTheWalkFindsTheBuild19Race` (the walk's I12 - a session Jen armed is intact before its own deadline - composed by `op_turn_on_again_inside_the_window` and the fault `tick_between_write_and_arm`, and the mutation check that goes red when the re-verify is build 19's)
- `tests/test_kea_helper_config_write.py::TestTheTickKeepsVerifying`
- `tests/test_kea_api_config.py::TestTheHostsDeadlineIsRespected`
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
**Enforced at.** `AppConfig._write_parser` (the config) and `kea_host.guard_kea_write` - the one definition of the marker question, called first by BOTH writers of a Kea configuration, `kea_host.apply_config` (the file) and `kea_api_config.apply` (the daemon's own API, Q212); `install.sh _guard_endpoint_changes` for the installer.
**Tests.**
- `tests/test_identity_guard.py::TestTheConfigWriterRefusesAnIdentityChange`
- `tests/test_kea_api_config.py::TestTheMarkerIsRefusedOverTheApi`
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
**Established.** Q143, Q144, Q145, Q146, Q147. Q224 (AJ4: `/settings/logs` - audit and alert-delivery rows carry no subnet - is for unrestricted callers only, refused at the route as Doctor is; AJ5: a subnet id that is not a whole number refuses the Users form whole in `set_user_subnets` and `edit_user`, as in `add_user` since Q171). Q225 (AK1: a subnet-restricted admin's alert channel never stores NULL - every subnet). Q226 (AL1, AL2, AL24: a restricted admin reads, edits, tests and deletes only an alert channel whose scope lies inside their own, and the channel list is the same set; a channel for every subnet prints that it is). Q226 (the review's P1 #2, Fable: P2 - no form writes it: `channel_allows_subnet` delivers NO subnet-specific alert for a scope that is present but empty, not a list of ids or unreadable; NULL stays the one deliberate "every subnet"). Q227 (the pass on 7.0.0-beta.12. AM2: a channel limited to some subnets was sent the daily summary, whose text names every subnet - a whole-network alert type goes only to a channel for every subnet, on the form and at delivery. AM22: the settings landing page counted every enabled channel for an admin limited to some - it counts what the Alerts page lists. AM24, AM25: the stored scope had three readings that disagreed about a damaged one - `alerts.channel_scope` is the one reading, a damaged scope is the empty tuple for delivery, for the route and for the page, and the card says it cannot be read).
**Enforced at.** `add_subnet_restriction` / `assert_subnet_access` (`jen/services/access.py`) and the authorization matrix; `_may_act_on` in `jen/routes/settings/alerts.py` at the page and the three acting routes (Q226); `alerts.channel_allows_subnet` at every delivery; `alerts.channel_scope`, the ONE reading of a stored scope (Q227: `channel_allows_subnet`, `channel_handles_alert`, `_may_act_on` and the page's card ask it, and a whole-tree source test holds that nothing else reads the value); `alerts.channel_handles_alert` with `WHOLE_NETWORK_ALERT_TYPES` at the form and at every delivery; `_enabled_channels` in `jen/routes/settings/__init__.py` (the landing page's count); `alerts.channel_inside` and `alerts.enabled_channels_for` (Q228, AN3: the ONE answer the list, the three acting routes and both pages that print a count ask - `/settings` and `/getting-started`, which Q227 left on a bare `COUNT(*)`; no statement under `jen/` outside a migration counts `alert_channels` in SQL)
**Tests.**
- `tests/test_authz_matrix.py::TestEveryDiagnosticRouteIsAccountedFor`
- `tests/test_authz_matrix_plugins.py::TestAStoredObjectIsJudgedByItsOwnSubnet`
- `tests/test_a_scoped_admin_reads_no_log.py::TestAScopedAdminReadsNoLog`
- `tests/test_a_scoped_admin_reads_no_log.py::TestASubnetIdThatIsNotAWholeNumberRefusesTheForm`
- `tests/test_authz_matrix.py` (the rows `settings logs`)
- `tests/test_a_restricted_admins_channel_covers_its_subnets.py::TestARestrictedAdminsChannelCoversItsSubnets`
- `tests/test_a_bounded_number_is_read_as_it_is_written.py::TestARestrictedAdminSeesOnlyChannelsInsideTheirScope`
- `tests/test_the_alerts_page_keeps_its_secrets.py::TestARestrictedAdminSeesOnlyTheirChannels`
- `tests/test_a_bounded_number_is_read_as_it_is_written.py::TestADamagedScopeDeliversNoSubnetSpecificAlert`
- `tests/test_client_problems.py::TestAnAlertAboutAClientWithNoSubnetFailsClosedForAScopedChannel`
- `tests/test_a_page_carries_only_what_it_names.py::TestOneReadingOfAChannelsScope`
- `tests/test_a_page_carries_only_what_it_names.py::TestTheDailySummaryGoesOnlyToAChannelForEverySubnet`
- `tests/test_a_page_carries_only_what_it_names.py::TestTheLandingPageCountsWhatTheAlertsPageLists`
- `tests/test_the_alerts_page_keeps_its_secrets.py::TestAScopedChannelIsNotSentTheDailySummary`
- `tests/test_a_secret_stays_with_its_destination.py::TestEveryChannelCountAsksTheService`

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
repoint `[jen_db]` at a database of their own and restart Jen would be whatever role that database says; and who may sign in, and with what role, is the same question (Q203: the `[oidc]` settings - `role_map`, `default_role` which accepts `superadmin`, `auto_create` - are a superadmin's with a recent password, as are the routes that write the Kea host's config file or restart its daemon by a call written in the route, authoring a Kea config, installing the helper, and replacing Jen's only SSH key: one `ast` walk over `jen/routes/` follows every chain of functions in `jen/` to the five writes (Q204 AT8 a) and a named list asks the rest. Q204: `install_kea_binary` (`apt` on every SSH host; a fetch route, so a stale confirmation is a 401 JSON with `reauth` that `jenFetch` follows - `recent_auth_required(fetch=True)`) and `toggle_ipv6` carry the step-up too, and `KNOWN_OPEN` is empty. The open population is exactly two ADMIN routes, named with their reasons: `restart_kea_server` (the Servers page's operational restart of kea-dhcp4 on its own saved host: it writes no config and chooses no destination - the maintainer's standing decision) and `investigation_logging` (an admin's by Q138/Q167)). Subnet creation, and the DDNS log and hostname lookup, are for a caller who may see
every subnet (the DDNS Verify tab too: it resolves any name and address through the Jen host). An admin makes the MFA policy stricter and never less strict - and the idle session timeout
and login rate limiting the same (Q224, AJ14): off or 0 is the least strict, fewer minutes, fewer attempts and a longer lockout are stricter, and the rate-limit MODE is part of the
strictness (Q225, AK2: `both` counts two buckets and locks on the larger, so an admin may move to it and may not leave it or trade one bucket for the other). The three measures are judged
together, so an admin cannot trade attempts for lockout length in either direction (AK24: the conservative side; a superadmin makes the trade).
**Established.** Q171. Q224 (AJ14: the two knobs beside the MFA mode had no ratchet). Q225 (AK2: the mode). Q226 (AL12: a permanent lockout is `PERMANENT_LOCKOUT`, never 999 minutes; AL18: the detection window for a lockout of 0 is the longest lockout the page accepts, so 0 is the strictest in both halves). Q226 (the beta.11 review's P2 #3 and #4: a PERMANENT lockout is a row in `login_lockouts` - migration 39 - read before the count, written when a bucket crosses the line under a lockout of 0 and ended only by clear-lockouts, since the attempts it was counted from are pruned; the countdown of a timed lockout is the Nth most recent attempt's expiry, N the threshold, the later bucket under `both`; the prune keeps a week, the longest lockout the page accepts). Clear-lockouts stays an ADMIN's act by decision (AL22): it resets counters and ends lockouts, changes no policy, and is audited. Q227 (AM3: an admin could set the lockout to 0 and make every lockout permanent - moving to 0 is a superadmin's change and the page says so; clear-lockouts stays an admin's and says how many attempts it cleared and how many permanent lockouts it ended. AM4: the OIDC callback recorded its failures under the one name `oidc`, so a handful of failed callbacks locked single sign-on for every account under a username mode - the callback names no account, `auth.NO_ACCOUNT`, and is counted by address alone).
**Enforced at.** `@_superadmin_required` + `@_recent_auth_required` on `save_infra_jen_db`, `save_infra_kea_db`, `save_infra_kea6`, `save_oidc`, `generate_ssh_key`, `config_history_restore`, `import_windows_apply`, `author_kea_config_post`, `install_kea_helper` (Q203 AS2), `install_kea_binary` and `toggle_ipv6` (Q204 AT6) and EVERY route that restarts Jen (Q202 AR6: `restart_jen`, `save_ports`, `upload_cert`, `remove_cert` - the verifier is the `ast` test over every caller of `runtime.restart_service()`); `current_user.all_subnets` in `add_subnet`, `add_subnet_post`,
the DDNS status context and `ddns()` (the Verify tab); the rank table in `save_mfa_mode`; `_session_looser` and `_rate_limit_looser` in `jen/routes/settings/security.py`; `auth.is_locked_out` (the one reader and writer of `login_lockouts`), `clear_lockouts` (its one deleter); `save_rate_limit`'s refusal of a lockout of 0 from an account that is not a superadmin (Q227); `auth.NO_ACCOUNT` at the OIDC callback's six rate-limit calls (Q227). `auth.is_mfa_locked_out` (Q228, the beta.13 review's #4: the second factor's countdown is the Nth most recent attempt's too - Q226 corrected the password limiter and left this twin on the oldest attempt; no statement under `jen/` reads `MIN(attempted_at)`).
**Tests.**
- `tests/test_q171_access.py::TestDatabaseCardsAndRestartAreSuperadminWithStepUp`
- `tests/test_kea_tls_rotation.py::TestEveryRestartOfJenIsBehindTheOneGate`
- `tests/test_route_gates.py::TestEveryWriterOfIdentityOrKeaConfigCarriesItsGate`
- `tests/test_route_gates.py::TestTheWalkIsTransitive`
- `tests/test_kea_authoring.py::TestTheKeaPackageInstallAsksForARecentPassword`
- `tests/test_kea6_service_toggle.py::TestTheIpv6ToggleAsksForARecentPassword`
- `tests/test_config_revisions.py::TestTheRestoreRouteIsHeldToItsSiblingsGate`
- `tests/test_q174_routes.py::TestOnlyASuperadminReplacesJensSshKey`
- `tests/test_oidc.py::TestOidcSettingsRoute`
- `tests/test_q171_access.py::TestAddSubnetNeedsEverySubnet`
- `tests/test_q171_access.py::TestDdnsStatusIsScoped`
- `tests/test_settings.py::TestMfaPolicyIsNeverWeakenedByAnAdmin`
- `tests/test_a_rollback_is_refused_before_its_set.py::TestTheSecurityRatchetAndTheBounds`
- `tests/test_a_scoped_admin_reads_no_log.py::TestAnAdminMakesThePolicyStricterOnly`
- `tests/test_the_mode_is_part_of_the_strictness.py::TestTheModeIsPartOfTheStrictness`
- `tests/test_a_bounded_number_is_read_as_it_is_written.py::TestTheLockoutSentinelAndTheWindow`
- `tests/test_a_bounded_number_is_read_as_it_is_written.py::TestAPermanentLockoutIsARow`
- `tests/test_the_mode_is_part_of_the_strictness.py::TestTheRemainingTimeIsTheNthMostRecentAttempt`
- `tests/test_auth.py::TestAPermanentLockoutIsARowInTheDatabase`
- `tests/test_a_page_carries_only_what_it_names.py::TestOnlyASuperadminMakesALockoutPermanent`
- `tests/test_a_page_carries_only_what_it_names.py::TestTheCallbackNamesNoAccount`
- `tests/test_a_secret_stays_with_its_destination.py::TestTheMfaCountdownIsTheNthNewest`

### RBAC-004 - Where Jen reaches a Kea server, and so where its credentials go, is a superadmin's setting with a recent password
**Rule.** A config write that changes where Jen reaches a Kea server or sends a credential - the API URL, the SSH host, user or config path, the connection mode, a server added or removed, AND
every other endpoint a credential goes to (`[kea6]`, `[d2]`, both database hosts and ports, an additional server's IPv6 and D2 addresses) - is a superadmin's, with a password confirmed in the last ten
minutes, whichever route (or plugin or hand-made request) asked. The rule is asked where every write passes, not on a list of routes: a destination guard, beside (and asked before) the investigation
guard. Outside a request (`install.sh --configure`, tools) and for a request that is not a signed-in session (an API key) there is no caller to judge. An admin sees the cards as facts and the probe is
limited to the host Jen already reaches, over no weaker scheme (`auth.no_weaker_scheme`, Q203: a probe is a credential send, and an admin's `http://` candidate against an `https://` endpoint would carry the saved credential in clear text). A password-only change is not a destination change here; CRED-002 and CRED-004 judge it.
**Established.** Q179 (the beta.9 review: an admin could point the Kea API, SSH, D2 or an additional server at a host of their own and receive the stored credential); Q180 (the beta.10 review: the guard saw
only the four identity keys, so a write of `[kea6] api_url`, `[d2] api_url`, a database host or an extra server's IPv6 or D2 address was not its question - it is asked of `destination_view` now).
**Enforced at.** `access.identity_change_needs_superadmin`, registered with `config.register_destination_guard` at import and imported by `create_app`; asked by `AppConfig._check_identity` (and so by
`preflight_identity_change`) from `AppConfig._write_parser` on `config.destination_view` - `identity_view`'s four keys and the mode PLUS the url of every endpoint `credentials.resolve` names PLUS the four TLS settings that decide who may RECEIVE what Jen sends (`api_ca`, `api_tls_verify`, `api_client_cert`, `api_client_key` - Q203 AS6). The investigation
guard keeps `identity_view` (its concern is WHICH Kea). A route that must ask for the confirmation inside its body (the setup wizard's POST steps, the IPv6 step) calls `access.step_up_redirect`, and a
confirmation made at the start of a request is remembered for its last write (`g.reauth_ok_minutes`), so the direct-socket routes are not asked a second time after they have changed the Kea host.
**Tests.**
- `tests/test_identity_guard.py::TestIdentityIsASuperadminsSetting`
- `tests/test_identity_guard.py::TestAConfirmationMadeAtTheStartOfARequestIsNotAskedAgain`
- `tests/test_setup_wizard_stepup.py::TestTheWizardAsksForTheConfirmationItNeeds`
- `tests/test_kea_connection_forms.py::TestEveryIdentityRouteIsASuperadminsForm`
- `tests/test_kea_connection_forms.py::TestAnAdminsProbeNeverDowngradesTheScheme`
- `tests/test_same_endpoint.py::TestNoWeakerScheme`
- `tests/test_credential_destinations.py::TestTheDestinationGuardSeesEveryEndpoint`

### RBAC-005 - The subnets themselves are scoped
**Rule.** A subnet's id, name, CIDR and counts are shown to an account only for the subnets it may see. RBAC-001 judges the data in a subnet; this judges the subnet: a list of subnets, a row per subnet, a message that
names one (a drift issue, a doctor finding, an undeclared id) or a scrape that prints every one is a reader of the subnet map, and every reader asks the question (`current_user.filter_subnet_map` / `can_access_subnet`), or is a
surface that needs every subnet (`all_subnets`: the Doctor, config history, the drift check, the metrics card and its save) or a superadmin's, or is a background job with no principal. A hidden subnet's row is DROPPED, never
renamed, and never counted into a visible row (Compare Leases). `/metrics` itself is a scrape endpoint authorized by a token and is unchanged: who may HOLD the token or set the open flag is the scope.
**Established.** Q156 (the About page), Q204 (Compare Leases, three Health checks, the drift route, the metrics settings - Opus's M1-M4 - and the readers the whole-tree sweep found: the OIDC mapping preview on Settings -> Security, the
D2 tab's reverse-zone hints).
**Enforced at.** `User.filter_subnet_map` / `can_access_subnet` (`jen/models/user.py`) at each reader: `kea_ha.compare_assigned(servers, subnet_filter=...)`, the `skip` for `not ctx["unrestricted"]` in `health._kea_config_drift`,
`_kea_subnets_declared` and `_config_doctor`, `current_user.all_subnets` in `check_config_drift_route` and `save_metrics_settings`, the metrics card's `can_grant_all_subnets`, the readiness row `kea32_removed_keys`, and every caller of `run_checks` / `readiness_checks` passing the caller's `unrestricted` (a source test); the whole tree by sweep S16.
**Tests.**
- `tests/test_invariant_sweeps.py::TestS16TheSubnetsThemselvesAreScoped`
- `tests/test_authz_matrix.py::TestTheBranchesRun`
- `tests/test_ha_console.py::TestCompareLeasesIsScoped`
- `tests/test_health_center.py::TestTheThreeChecksThatNameSubnetsAreForUnrestrictedAccounts`

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

### DEF-003 - One whole-number test for every form value and path segment
**Rule.** A value that must be a whole number is judged by `jen.services.text.is_whole` (ASCII digits, one to eighteen); `str.isdigit()`,
`isnumeric()` and `isdecimal()` are never the test under `jen/` (they accept a full-width or an Arabic-Indic digit that `int()` then raises on, or that a filter-and-convert comprehension
drops on the floor). A refusal is of the form whole, never of one value out of a list. (Q228, AN9: the rule used to add "and converted with `int()` only after it". No test scans for a bare `int()` on a request value - twenty sites have one inside a `try` - so the registry claims what its tests prove: the three predicates are never the test.)
**Established.** Q224 (AJ16: forty sites in nineteen files; AJ17: the OIDC subnet map raised on every login over one such digit). Q226 (AL13, AL19: the unrestricted branch of the channel's and the API key's scope writers refuse the form whole too; AL14: a query-string page number goes through `whole`, never a bare `int()`).
**Enforced at.** `jen/services/text.py` (`is_whole`, `whole`), held by a whole-`jen/` source test.
**Tests.**
- `tests/test_a_rollback_is_refused_before_its_set.py::TestOneWholeNumberTest`
- `tests/test_a_bounded_number_is_read_as_it_is_written.py::TestTheTreesSmallerRows`

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
**Established.** Q172. Q224 (AJ10: Health reads the newest lease snapshot's age in the query that reads the stamp, and Explain places a revision in Jen's clock by the age the database measured).
**Enforced at.** `jen/models/db.py` (`SESSION_TIME_ZONE_INIT` on all six connection sites) and `jen/services/dbexport.py`; `client_problems._now()` / `sweep`; `capacity.forecast`.
**Tests.**
- `tests/test_db_session.py::TestEveryConnectionIsUtc`
- `tests/test_db_session.py::TestNoConnectionIsOpenedWithoutIt`
- `tests/test_client_problems_db.py::TestTheSweepsClockIsWholeSeconds`
- `tests/test_kea_log_transactions.py::TestAClassListFromBeforeTheConfigChanged`

### PLUG-001 - A plugin is registered whole or not at all
**Rule.** A plugin's blueprints are registered only after its `register(app)` returned: a `register` that raises leaves no route, no job and a per-process failure marker (`plugin_load_failed`, the exception CLASS only)
that the Plugins page shows. A required OS package counts as present when any binary it provides is on PATH (`OS_PACKAGE_BINARIES`), and every package a bundled manifest declares is in that map and in the root
updater's allowlist.
**Established.** Q172.
**Enforced at.** `jen/services/plugins.py` (`_run_register_blueprints_last`, `_load_plugin`, `missing_os_packages`).
**Tests.**
- `tests/test_plugin_registry.py::TestBlueprintsAreRegisteredLast`
- `tests/test_plugin_registry.py::TestOsPackageBinaryMap`

### CFG-001 - Every config write holds one lock across read-modify-replace, and the installer honors the same flock
**Rule.** Jen's config file is written under one lock for the whole read-modify-replace (a thread lock and an advisory `flock` on the lock file), and `install.sh --configure` takes the same one.
**Established.** Q152, Q153, Q155.
**Enforced at.** `AppConfig._write_lock` / `_file_lock`; `tools/private_write.py --lock` for the installer.
**Tests.**
- `tests/test_config_file_lock.py::TestAnExternalProcessAndTheServiceDoNotLoseEachOthersWrites`
- `tests/test_installer_trust.py::TestTheInstallerLocksTheSameInodeThroughTheOneOpen`

### CFG-002 - A configuration change over the daemon's API stands only when the daemon's own answer proves it
**Rule.** A change written to a Kea daemon over its own API stands only when the daemon's `config-get` afterward carries the digest `config-set` returned AND `config-write` answered 0 (proved through the file where SSH exists); otherwise it is undone, or `needs_hands` with both digests, and a pending change (a record written before `config-set`) is reconciled by content on the next read. Kea has no compare-and-set: Jen compares `config-hash-get` with the digest its change was built from before it sets, a set that cannot be proved is never reported as done, and a `config-write` timeout is never "ok". An API write is refused when it would change a control socket, a hook library or Jen's TLS material (those go through the file path), when no probe has been read and allowed on the server's card, and while a refused `config-write` is remembered.
**Established.** Q212. Q224 (AJ19: a `config-set` that answers no digest is proved by CONTENT at step (7), as a set with no answer is). Q225 (AK4: the `unverified` sentence names the check that fired; AK17: a file with no section is not the daemon's; the kea-compat row `test_14` asks the daemon itself whether the file it wrote mirrors `config-get`). Q226 (AL27: a refusal before the send that needs hands for an EARLIER change says `sent: False`). Q227 (AM14: a rollback over the API that RAISED was reported as a server that still has the new configuration - what was sent is not known, and the line says `ROLLBACK_NOT_KNOWN`). Q228 (AN21: a File over SSH target whose restore raised is not known either, and the line says `RESTORE_NOT_KNOWN` - `raised` was read for an api target only; AN20: a running configuration that is not an object has its own sentence at the top level, where `_section` answers `{}`).
**Enforced at.** `jen/services/kea_api_config.py` (`apply`: the nine steps; `probe_gate`; `remember_refusal`), the change set's per-target transport (`kea_changeset._transport`, the commit order and the dispatch of every revert), the one change lock (`kea_changeset.change_lock`).
**Tests.**
- `tests/test_kea_api_config.py` (`TestApplyInOrder`, `TestConflictSendsNothing`, `TestTheApiOnlyGuard`, `TestSetFailedLeavesTheDaemon`, `TestWriteFailedIsUndone`, `TestAWriteTimeoutIsNeverOk`, `TestASetTimeoutIsAsked`, `TestUnverifiedIsNotUndone`, `TestThePendingRecord`)
- `tests/test_kea_changeset_transports.py` (`TestMixedTargets`, `TestOneChangeAtATime`, `TestTheCallersDoNotChange`)
- `tests/test_kea_api_probe.py` (`TestTheGate`, `TestARefusedWriteIsRemembered`)
- `tests/test_transport_switch.py`
- `tests/test_a_rollback_is_refused_before_its_set.py::TestASetWithoutADigestIsProvedByContent`
- `tests/kea_compat/test_config_write.py::test_14_the_file_kea_wrote_mirrors_config_get`
- `tests/test_the_mode_is_part_of_the_strictness.py::TestTheUnverifiedSentenceNamesTheCheckThatFired`
- `tests/test_a_bounded_number_is_read_as_it_is_written.py::TestARefusalBeforeTheSendSaysSo`
- `tests/test_a_page_carries_only_what_it_names.py::TestARollbackThatRaisedIsNotKnown`
- `tests/test_a_secret_stays_with_its_destination.py::TestAFileRestoreThatRaisedIsNotKnown`

### CFG-003 - A consent is given on the switch, for the facts whose time the form carries, by a superadmin with a recent confirmation; the gate's table is the oracle
**Rule.** The act of accepting what a switch to Live API changes (Kea rewrites the file in its own format; an endpoint with no authentication; a file edit discarded; no SSH so no include) is the POST that switches, not a click that reads: it is a superadmin's, it needs a recent confirmation of the password, it is given for the readiness check whose time (`probe_at`) the form carries - a check that ran again since is refused - and `kea_api_config.consent_gap` is the one table that says which consents the facts call for, asked by the switch, by the gate every change meets and by the card that offers the boxes. A consent is never recorded by the readiness check, and only the consents the facts call for are recorded (`consents_called_for` is the one table: a box the form sent that the facts never asked for is dropped and named, so it can never cover a fact that appears later). A consent of any kind - whatever the target - is given for the readiness check whose time the form carries, and a stored result that names no endpoint (`bound` absent) is checked again, never taken for the current one.
**Established.** Q216 (AA1), Q217 (BG2) and Q218 (AC4, AC6, AC18). Q224 (AJ6: a discard that found nothing to discard is never left on record; AJ7: the note about Config history is for a server with a file).
**Enforced at.** `jen/routes/settings/kea_transport.py` (`switch_kea_transport`: `probe_at`, the step-up), `jen/services/kea_transport_switch.py` (`_to_api`), `jen/services/kea_api_config.py` (`consent_gap`, `consents_called_for`, `probe_gate`).
**Tests.**
- `tests/test_kea_transport_routes.py` (`TestAConsentIsAnActNotAClick`)
- `tests/test_kea_consent.py` (`TestTheTenStateTable`)
- `tests/test_write_mode_card.py` (`TestTheCardIsOneChoice`, `TestAnAdminAndAViewerSeeTheHeader`, `TestOneEnabledInputPerConsentNamePerForm`)
- `tests/test_transport_switch.py`
- `tests/test_transport_switch.py::TestToApi::test_a_consent_the_facts_never_called_for_is_not_recorded`
- `tests/test_kea_transport_routes.py::TestAConsentIsAnActNotAClick::test_probe_at_is_checked_for_every_act_that_carries_a_consent`
- `tests/test_kea_consent.py::TestAStoredResultThatNamesNoEndpointIsCheckedAgain`
- `tests/test_kea_changeset_transports.py::TestAnAdminIsNotToldAHostFactByAChangeSetLine`
- `tests/e2e/test_write_mode_journeys.py::test_a_box_in_the_hidden_panel_is_not_a_consent`
- `tests/test_transport_switch.py::TestToApi::test_the_stored_facts_after_the_switch_are_the_facts_after_its_write` (Q219: a consent is never recorded over facts the act itself changed, and a used-up one is never left on record)
- `tests/test_kea_transport_routes.py::TestATickWithoutAStoredResultNamesTheCheck`
- `tests/test_write_mode_card.py::TestNoConsentBoxWithoutAStoredResult`
- `tests/test_write_mode_card.py::TestTheConsentValueIsOneConstant`
- `tests/test_a_rollback_is_refused_before_its_set.py::TestADiscardThatFoundNothingIsNotRecorded`
- `tests/test_a_rollback_is_refused_before_its_set.py::TestTheNoteIsForAServerWithAFile`

### CFG-004 - A file is the daemon's configuration when the daemon loaded it after it was written, or it is Jen's own rendering or the file the Plan proved; a model of Kea's defaults never decides
**Rule.** Whether the file on a Kea host may be replaced by the daemon's `config-write` is answered by facts the host and the daemon give themselves, never by a model of Kea inside Jen (`file_proof`, the one definition): the file's sha256 is the newest `rendering` row's - the file Kea itself wrote after a change over the API (R); or it is byte for byte the file the Plan proved before any `config-set` (P); or the daemon last committed a configuration at or after the file was written - the host's one clock: `mtime <= now - reload`, from helper build 22's `config-loaded` - AND the file is in the daemon one way (a reload that did not take is not a load) AND no change of Jen's is pending (then the daemon's last commit is Jen's own `config-set` and the time proves nothing) (L). In that order; none of them is a refusal that prints both times. A file that cannot be read, or a host that cannot say, is never overwritten without the named consent. The comparison with Kea's written-out defaults survives for one job: naming a path in the sentence, best effort - it decides nothing, and the verdicts are identical with the vector absent and with every key a default. A section that is empty, or is not an object, is not the daemon's configuration and mirrors nothing (Q225, Q226).
**Established.** Q217 (AB6, AB8), Q218 (D1), Q219 (AD1, AD20, AD21: the third kind - built-in, inherited, derived - a recording cannot tell apart; the fourth patch to a model is the proof). Q225 (AK17: an EMPTY section is never carried vacuously - a combined file holding only `Dhcp6` under a dhcp4 `kea_conf` was proved `loaded` and a change set sent it `config-set` and `config-write`). Q226 (AL29: a section is an OBJECT - a string or a number on both sides is no agreement). Q227 (AM13, AM28: a configuration that is not an object - a list, a string, a number - has no section, on either side and in every caller; and a daemon that answered with one is named as the daemon, before the file is asked).
**Enforced at.** `jen/services/kea_api_config.py` (`file_proof`, `compare`, `_ask_the_file`), `jen/services/kea_host.py` (`read_config_proof`), `jen-kea-helper` (`op_config_loaded`, build 22), `jen/services/config_revisions.py` (`latest_rendering`).
**Tests.**
- `tests/test_kea_api_config.py::TestTheProofIsTheDaemonsOwnAnswer`
- `tests/test_kea_api_config.py::TestFileProofOrder`
- `tests/test_kea_api_config.py::TestTheModuleIsTheOneSender`
- `tests/test_kea_api_config.py::TestADeletionIsADifference`
- `tests/test_kea_api_config.py::TestAScalarIsJudgedByItsValueToo`
- `tests/test_kea_helper.py::TestConfigLoadedOp`
- `tests/test_kea_host.py::TestReadConfigProof`
- `tests/test_config_revisions.py::TestLatestRendering`
- `tests/kea_compat/test_config_write.py::test_13_the_daemons_own_load_time` (the clock's own facts, per Kea minor)
- `tests/system/test_boundaries.py::test_24_a_hand_edit_without_a_reload_is_refused_and_the_edit_survives`
- `tests/system/test_boundaries.py::test_25_a_hand_edit_the_daemon_reloaded_is_accepted_and_rendered`
- `tests/test_the_mode_is_part_of_the_strictness.py::TestAFileWithNoSectionIsNotTheDaemons`
- `tests/test_a_bounded_number_is_read_as_it_is_written.py::TestASectionIsAnObject`
- `tests/test_kea_api_config.py::TestKeaWritesItsDefaultsOut` (Q228, F1: a file that says `dhcp-socket-type: raw` is carried by a daemon that reports no socket type - `OMITTED_AT_DEFAULT`'s third key, found on the first real server to walk the card)
- `tests/kea_compat/test_config_write.py::test_15_what_config_get_omits_at_its_default` (what each Kea minor reports for the `interfaces-config` keys written at their default)
- `tests/test_a_page_carries_only_what_it_names.py::TestAConfigurationThatIsNotAnObjectHasNoSection`

### CFG-005 - A `config-write` is sent only after the file it replaces has been read into Config history and proved: the daemon loaded it, it is Jen's own rendering, or it is the file the Plan proved
**Rule.** The daemon's `config-write` renders ITS configuration over the file on its host, so whatever the file carries that the daemon never loaded is destroyed. It is therefore sent only by `kea_api_config` (`_send_write`, the one sender), and only after `_ask_the_file`, which is `file_proof` and nothing else: on a server with an SSH host the file is READ (capturing: an edit is an `external` row in Config history before it can be lost) and proved (CFG-004). A `none` is refused with the times and the path (`unloaded-edit`, nothing sent) unless `discard_file_edit` was given on THIS act and the facts called for it; a file that cannot be read is refused with or without it. The Plan proves BEFORE any `config-set` and carries the proved file's sha256 as `planned_sha`; `apply` records it in the pending row and step (6) checks the file is still that one (or Jen's own rendering); a settlement of a pending change (the Plan's, and *Settle it now*) writes only over the file the row's `file_sha256` names, and a row that carries none - an earlier release wrote it - is refused with the restart sentence. A caller with no Plan (a restore, an import) proves the file itself before anything is sent.
**Established.** Q218 (AC1, AC2, AC14), Q219 (AD1). Q223 (AH2: a rollback whose forward change had no rendering row sent its `config-set` and was refused at its file, so the daemon went back and the file kept the change; a rollback now proves step (6) against the file it found when that file says what the daemon runs - a hand edit is still refused - and the row it leaves names the box before the restart). Q224 (AJ2, AJ3, AJ9: the rollback's ask is asked both ways - `mirrors`, two renderings of one configuration, a key deleted from the file is a hand edit; a rollback whose file is not proved is refused BEFORE its `config-set`, so the daemon and its file both keep the change and no row is left that a settlement could accept by proof (P)). Q225 (AK6: a discard ticked over a file that could not be read is a REFUSAL, never 'nothing to discard'; AK5: every one-state rollback refusal reads still-new). Q226 (AL28: the audit line names a discard only when the write discarded one, in every direction). Q227 (AM11, AM12: the sentence and the audit row named a discard from the consent that was TICKED, not from the write that was sent - a refused write followed by a proof that holds, and a file that no longer carried an edit, both name no discard; the consent is recorded only when the write discarded one).
**Enforced at.** `jen/services/kea_api_config.py` (`write_file`, `_ask_the_file`, `_send_write`, `_reconcile_pending`, `apply` steps (3) and (6)), `jen/services/kea_changeset.py` (`_unloaded_edit`: the Plan's proof), `jen/services/kea_transport_switch.py` (`_to_api`, `_to_file`: the only callers that pass `discard`).
**Tests.**
- `tests/test_kea_api_config.py::TestWriteFileAsksTheFile`
- `tests/test_kea_api_config.py::TestTheLiveBranchWaitsOnTheFile`
- `tests/test_kea_api_config.py::TestApplyAsksTheFileAtStepSix`
- `tests/test_kea_api_config.py::TestTheModuleIsTheOneSender::test_every_write_file_caller_is_one_of_three_and_none_passes_a_before`
- `tests/test_kea_api_config.py::TestTheModuleIsTheOneSender::test_config_write_has_one_sender_and_it_is_asked_first`
- `tests/test_kea_changeset_transports.py::TestThePlanProvesAndTheWriteChecksTheProofHeld`
- `tests/test_kea_api_config.py::TestAnOwnWriteIsNotChangedOutsideJen`
- `tests/test_transport_switch.py::TestToApi::test_a_discarded_edit_is_in_config_history_before_the_write`
- `tests/test_transport_switch.py::TestToApi::test_api_to_api_records_and_does_not_render`
- `tests/test_a_rollback_puts_the_file_back_too.py::TestARollbackPutsTheFileBackToo`
- `tests/test_a_rollback_is_refused_before_its_set.py::TestARollbackIsRefusedBeforeItsSet`
- `tests/test_kea_api_config.py::TestTheModuleIsTheOneSender::test_file_in_daemon_is_asked_by_the_proof_and_by_apply_only` (`mirrors` has one caller)
- `tests/test_the_mode_is_part_of_the_strictness.py::TestADiscardOverAnUnreadableFileIsRefused`
- `tests/test_the_mode_is_part_of_the_strictness.py::TestEveryOneStateRollbackResultIsBucketedAsStillNew`
- `tests/test_a_bounded_number_is_read_as_it_is_written.py::TestTheAuditLineNamesADiscardOnlyWhenOneWasMade`
- `tests/test_a_page_carries_only_what_it_names.py::TestTheSentenceAsksTheWrite`
- `tests/test_transport_switch.py::TestToFile`

### CFG-006 - A pending or damaged revision is the record of a change the daemon may be running: its write precedes the send, its finish precedes `ok`, the prune never removes it, no reader takes it for the last known state; there is one per server, and it carries the file the Plan proved
**Rule.** A change over the API is recorded as a `pending` revision BEFORE `config-set` and turned into the daemon's own record once the daemon proves it. A record that cannot be WRITTEN - the store refused the row, raised, or already holds a pending row for that server and service - stops the change with nothing sent (`unreadable`); a record that cannot be FINISHED is not `ok` (`unverified`) and the row is not discarded - it is the one record of what the daemon runs, and the next change or *Settle it now* finishes it by content; a settlement whose finish fails is not settled. At most ONE pending row exists per (server, service) and the STORE keeps it so (`record` answers None for a second); a restore over a live one is refused ("settle the unresolved change first") and over a stale one supersedes it. The row carries `file_sha256`, the file the Plan proved, which the settlement checks. The retention prune never deletes a `pending` or `damaged` row and does not count one among the rows kept; `latest`, `latest_of_kind` and `by_digest` never return one, so no reader compares the daemon with a digest a damaged row kept. A service section that is no object is a damaged row, not an unresolved candidate.
**Established.** Q218 (AC3, AC5, AC24, AC28; hypothesis D of Q217's second pass), Q219 (AD5, AD9, AD18). Q224 (AJ1: a NEGATIVE measured age - the database's clock stepped back since it stamped the row - is old, never in progress).
**Enforced at.** `jen/services/kea_api_config.py` (`apply` steps (3) and (9), `_reconcile_pending`, `_pending_candidate`, `_stale_pending`, `_capture`, `api_daemon_differs`), `jen/services/config_revisions.py` (`record`, `prune`, `latest`, `latest_of_kind`, `by_digest`).
**Tests.**
- `tests/test_kea_api_config.py::TestTheRecordIsAPreconditionOfTheSendAndOfOk`
- `tests/test_kea_api_config.py::TestAPendingOrDamagedRowIsNeverTheLastKnownState`
- `tests/test_kea_api_config.py::TestAStoreThatRaisesAtStepThreeIsUnreadable`
- `tests/test_kea_api_config.py::TestARestoreOverALivePendingChangeIsRefused`
- `tests/test_kea_api_config.py::TestLiveNotYetInItsFileIsTheLine`
- `tests/test_kea_api_config.py::TestADamagedPendingRecord`
- `tests/test_config_revisions.py::TestPruneKeepsTheRecordOfAChange`
- `tests/test_config_revisions.py::TestPruneKeepsTheRecordOfAChange::test_latest_skips_pending_and_damaged`
- `tests/test_config_revisions.py::TestOnePendingRowPerServer`
- `tests/test_migrations.py::TestMigration38RevisionsFileSha256`
- `tests/test_a_rollback_is_refused_before_its_set.py::TestANegativeAgeIsOld`

### CFG-007 - The write gate is a read: no page asks Kea or a host to print it, the write path re-reads a stored fact before it asks, and the way out a refusal names is one a control offers
**Rule.** `kea_api_config.probe_gate` is a settings read and pure rules. It never asks Kea, never asks a host and never writes the stored result, because every page derives the Live API badge from it. The write path refreshes before it asks (`refresh_if_stale`: facts older than a day, and a stored `agree` of False), the stored result is one snapshot with one time, and the file is judged in one place, live, by `file_proof`. A refusal names a way out a control offers: with a change unsettled that is a restart of Kea or the box beside *Settle it now* (`settle_pending(discard=True)`), never the card's discard, which the switch refuses while a change is unsettled; a file that cannot be read is never overwritten. A stored time the gate cannot take for a check this box made - unreadable, or in the future - closes it and is re-read by the write path like an old one (Q222, AG5). One change re-reads once: the Plan's re-read is the change's and `apply(refreshed=True)` is its word (AG6). The box beside *Settle it now* is the operator's word on the file whatever it holds, so it reaches the sender for a row that carries no planned file too; such a file is judged by `_ask_the_file` like any settlement's (AG3). The switch-to-File refusal names the box only when the card shows it (AG7).
**Established.** Q221 (AE8, AE9, AE10: Q219 E1's live proof sat inside the gate, so a page a viewer can load made an SSH read and a `config-get` and wrote the stored result; AE11: every control refused in a circle). Q222 (AG3, AG5, AG6, AG7). Q223 (AH1: a pending row's age was Jen's clock against the database host's stamp, so a database a day ahead made every reader say "in progress" for a day - the store measures the age by its own clock; AH4, AH5: the refusals name the box by the label the card prints and say how a Read-only server's card reaches the readiness check; AH6: a switch whose rendering row was refused says so; AH9: the stored result is bound to all four identity keys, and a two-key result is checked again).
**Enforced at.** `jen/services/kea_api_config.py` (`probe_gate`, `refresh_if_stale`, `apply` step (1b), `settle_pending`, `_reconcile_pending`, `file_proof`'s sentence); `jen/services/kea_changeset.py` (`_run_change_unlocked`, the Plan); `jen/routes/settings/kea_transport.py` (`settle_pending_change`); `jen/services/health.py` (`_kea_write_gate`).
**Tests.**
- `tests/test_the_gate_is_a_read.py::TestTheGateReachesNothingRemote`
- `tests/test_the_gate_is_a_read.py::TestTheGateAnswersFromTheStoredResult`
- `tests/test_the_gate_is_a_read.py::TestTheWritePathRefreshesBeforeItAsks`
- `tests/test_the_gate_is_a_read.py::TestHealthSaysWhatItKnowsAndWhen`
- `tests/test_the_way_out_is_offered.py::TestSettleItNowOffersBothWaysOut`
- `tests/test_the_way_out_is_offered.py::TestTheCardCarriesTheBox`
- `tests/test_kea_transport_routes.py::TestTheSettleRouteWorksUnderTheLockAndIsAudited`
- `tests/test_the_gate_is_a_read.py::TestAStoredTimeInTheFutureIsNotFresh`
- `tests/test_the_gate_is_a_read.py::TestOneChangeOneReRead`
- `tests/test_the_way_out_is_offered.py::TestARowWithNoPlannedFileTakesTheBox`
- `tests/test_a_rollback_puts_the_file_back_too.py::TestARowIsAgedByTheClockThatStampedIt`
- `tests/test_a_rollback_puts_the_file_back_too.py::TestTheRefusalNamesTheBoxByItsLabel`
- `tests/test_a_rollback_puts_the_file_back_too.py::TestTheSwitchSaysWhenTheRenderingRowWasRefused`
- `tests/test_a_rollback_puts_the_file_back_too.py::TestTheStoredResultIsBoundToTheFileToo`
- `tests/test_transport_switch.py::TestTheRefusalNamesAControlTheCardOffers`

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
**Established.** Q150, Q151. Q226 (migration 39, `login_lockouts`: one `CREATE TABLE IF NOT EXISTS`). Q227 (AM8: sweep S3's statement pattern did not match `CREATE TABLE`, so migration 39's guard was held by its own test alone; the pattern matches it).
**Enforced at.** `jen/models/migrations.py`.
**Tests.**
- `tests/test_invariant_sweeps.py::TestS3EveryMigrationStatementHasItsOwnGuard`
- `tests/test_migrations.py::TestMigration33ClientProblemsScopeKey::test_an_interrupted_migration_finishes_the_key_it_never_reached`
- `tests/test_migration_6_interrupted.py`
- `tests/test_migrations.py::TestMigration39LoginLockouts`
- `tests/test_a_page_carries_only_what_it_names.py::TestCreateTableIsDdl`

### TXN-001 - A multi-server change validates every target before the first write and compensates or stays visibly unresolved
**Rule.** One config edit pushed to several Kea servers is planned and preflighted on every target before the first write, committed sequentially, and reverted on the committed targets if a
later one fails; a revert that cannot finish is a persistent, named rollback failure.
**Established.** Q24, Q150, Q151. Q223 to Q228 (the ROLLBACK FAILED line names each target by what its revert REPORTED: still on the new config, half done over the API, or not known because the revert raised before it reported anything - CFG-002 holds the api half's rules and its tests; Q228, AN21 and AN25, brought the file half and this entry up to them).
**Enforced at.** `jen/services/kea_changeset.py::apply_change`.
**Tests.**
- `tests/test_kea_changeset.py::TestApplyChangeRevert`
- `tests/test_kea_changeset.py::TestFailedRestartRollsBack`
- `tests/test_kea_changeset.py::TestTwoServersWithOneNameAreTwoTargets`
- `tests/test_author_config_changeset.py::TestAnAuthoredChangeIsAllOrNothing`
- `tests/test_a_secret_stays_with_its_destination.py::TestAFileRestoreThatRaisedIsNotKnown`

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
**Established.** Q159, Q164, Q166. Q224 (AJ11: sweep S10 sees a tuple return whose first element is empty; `is_locked_out` and `is_mfa_locked_out` fail CLOSED - a lockout that cannot be measured is a lockout for a minute). Q225 (AK21: a stored `users.subnet_access` that is not a JSON list is NO subnets, never every subnet). Q226 (AL20: a list with an element that is not an id is no subnets either).
**Enforced at.** The sweep S10 over the listed modules; `settings_ever_loaded` in `jen/models/user.py`; `User.__init__` in `jen/models/user.py` (the one reader of a stored scope); the Security page's permanent-lockout count and the landing page's channel count (Q228, AN4: a count that could not be read is printed as could not be read, never as 0 - the page said no lockout was in force while `is_locked_out` failed closed)
**Tests.**
- `tests/test_invariant_sweeps.py::TestS10FailedReadsOnSecurityPathsAreNotEmptyResults`
- `tests/test_a_rollback_is_refused_before_its_set.py::TestTheLockoutChecksFailClosed`
- `tests/test_the_mode_is_part_of_the_strictness.py::TestAnUnreadableScopeIsNoSubnets`
- `tests/test_a_bounded_number_is_read_as_it_is_written.py::TestAScopeListWithABadElementIsNoSubnets`
- `tests/test_a_secret_stays_with_its_destination.py::TestACountThatCannotBeReadSaysSo`

### BOUND-001 - A stored number is bounded where it is written AND where it is read, and a reader puts a row the form never wrote where the policy is strictest
**Rule.** A settings number that reaches a statement (`INTERVAL %s DAY`, `INTERVAL %s MINUTE`) or a policy decision is bounded on the form (a thousand attempts, a week of lockout
minutes, ten years of retention days) and is a `%s` parameter, never text in the statement; and the READER applies the same bound and the same whole-number test, because a value
stored by an earlier release, or by hand, is past the form. A row the form never wrote reads as the STRICTEST policy, never as none: a rate-limit mode outside its four words is `both`,
a count or a duration that is not whole is its default, one past the bound is the bound, and a retention past the bound prunes at the bound (it used to make the DELETE fail on every
pass and the table was never pruned).
**Established.** Q224 (AJ18: the three bounds and the parameterized window). Q225 (AK3, AK13, AK19: the readers). Q226 (AL5, AL8, AL9, AL11: ONE table, `jen/services/setting_bounds.py`, and ONE reader, `bounded_setting`; every form asks `in_bounds` of the same table; a page prints what the server applies; a retention of 0 on a history key is 1, never a table emptied). Q227 (AM10: the Alerts and Reports pages were on the raw-reader test's allowlist and printed a stored 0 or 5000 the server never applies; AM27: `_int_setting`'s second argument is not read, so each caller's number is held equal to the table's).
**Enforced at.** `jen/services/setting_bounds.py`: `SETTING_BOUNDS` (the table), `bounded_setting` (the one reader - `auth.get_rate_limit_settings`, `alerts.purge_history`'s `days()`, `alerts._int_setting`, `alerts.alert_log_retention_days`, `user.get_stale_device_days`, Health's three reads and the Subnets page's threshold all read through it) and `in_bounds` (the forms' test: the Security, System, Alerts, Reports and Devices forms); the Security and System pages PRINT what the reader applies, never the stored text. Held by `TestOneTableOfBounds::test_no_reader_under_jen_reads_a_bounded_key_raw`, a whole-`jen/` source test. The System page's `MAX_AUDIT_RETENTION_DAYS` is `alerts.MAX_RETENTION_DAYS`, which is the table's bound. (Q227) The Alerts and Reports pages print through `bounded_setting` too, so the raw-reader test's allowlist is `setting_bounds.py` alone, and each caller of `alerts._int_setting` carries the table's default.
**Tests.**
- `tests/test_the_mode_is_part_of_the_strictness.py::TestARateLimitThatCannotBeReadIsTheStrictest`
- `tests/test_the_mode_is_part_of_the_strictness.py::TestARetentionPastTheBoundIsTheBound`
- `tests/test_a_rollback_is_refused_before_its_set.py::TestTheSecurityRatchetAndTheBounds`
- `tests/test_a_scoped_admin_reads_no_log.py::TestTheSecurityPageBoundsItsNumbers`
- `tests/test_a_bounded_number_is_read_as_it_is_written.py::TestOneTableOfBounds`
- `tests/test_a_bounded_number_is_read_as_it_is_written.py::TestAZeroRetentionNeverEmptiesATable`
- `tests/test_the_alerts_page_keeps_its_secrets.py::TestTheSecurityPagePrintsWhatTheServerApplies`
- `tests/test_a_page_carries_only_what_it_names.py::TestTheCallersNumbersAreTheTables`

### STORE-001 - A policy of several rows is saved whole or not at all, and the page says which
**Rule.** A settings POLICY that is more than one row (login rate limiting: attempts, lockout minutes, mode; the session timeout: minutes, enabled; the global alert settings; the report settings) is written by `user.set_global_settings` in ONE transaction, and a route says "saved" and writes its SAVE audit row only when the writer answered True; a single-row policy tests `set_global_setting`'s answer the same way. A False is logged by the writer and shown by the route as an error, never as success, and the previous policy stays in force.
**Established.** Q226 (the beta.11 review's P2 #5: three commits per policy, and "Rate limiting settings saved." with every write failed). Q227 (AM21: the IPv6 switch flashed "enabled" or "disabled" whatever its write answered - it says saved only when `set_global_setting` answers True, and says which state Jen stays in when it does not).
**Enforced at.** `jen/models/user.py::set_global_settings` (one `executemany`, one commit); the six policy routes (`save_rate_limit`, `save_session_settings`, `save_alert_global`, `save_report_settings`, `save_device_settings`, `save_audit_retention`), held by an `ast` test that no bare `set_global_setting(...)` statement is in them. The other settings writers under `jen/routes/` (display preferences, infrastructure facts) are not policies and are not under this rule yet. (Q227) `toggle_ipv6` in `jen/routes/settings/infrastructure.py` is a single-row policy under this rule: it tests the writer's answer (`IPV6_NOT_SAVED`).
**Tests.**
- `tests/test_a_bounded_number_is_read_as_it_is_written.py::TestAPolicyIsSavedWholeOrNotAtAll`
- `tests/test_auth.py::TestAPolicySaveThatFailsSaysSo`
- `tests/test_a_page_carries_only_what_it_names.py::TestTheIpv6SwitchSaysSavedOnlyWhenItIs`

### LEAK-001 - A route never shows what a broad `except` caught
**Rule.** (Q190, second half:) an ADDRESS is shown by one helper, `auth.shown_url` - scheme, host and port, never user-info, a path or a query - in every flash, audit row, log line and incident, and text Jen did not write (a `requests` message) goes through `auth.scrub_urls`; `tests/test_invariant_sweeps.py` S14 refuses a route that formats a `*url` name into text without it (the reviewed list is empty). 
In `jen/routes/`, the name bound by `except Exception as e` is used only to log or to name its class: the text of a driver, `requests` or SSH error carries URLs with their query strings, account and
host names and paths. The reviewed list is empty.
**Established.** Q171 (sweep S11; the older line scanner in `test_no_raw_exception_leaks.py` stays), Q172 (an alert channel's token, webhook URL or password is redacted from `alert_log.error`, the event detail, the log and the test button; a transport error is stored by class). Q224 (AJ12: a container under a secret-named key is masked whole in the bundle's one pass; AJ13: a spaced key is a secret name). Q226 (AL2: the Alerts page carried every channel's DECRYPTED config into a `<script>` block for every admin; the page carries `_shown`'s copy, every write-only key blank, and the edit form says the secret is saved). Q227 (AM1, AM7: `_shown` blanked the declared type's write-only keys and printed every key it did not know, so a config stored under another type, an extra key or an unknown type reached the page - it is an allowlist now, `SHOWN_KEYS`, and no shown key is write-only under any type).
**Enforced at.** The route that catches: `logger.exception(...)` and a fixed sentence; the two Health runners (`run_checks` and `readiness_checks`, Q204 AT2) log a check's exception through `_log_err` and the row carries `CHECK_ERRORED_DETAIL`; and what a masker hides is decided by ONE definition of a secret key, `jen/services/secret_keys.py::is_secret_key` (Q204 AT4: the config-history diff and download, the authoring preview and the support bundle all ask it). `SHOWN_KEYS` / `_shown` in `jen/routes/settings/alerts.py` (Q227: the Alerts page carries only the keys it names).
**Tests.**
- `tests/test_health_center.py::TestARunnerNeverShowsWhatACheckRaised`
- `tests/test_secret_keys.py::TestEveryMaskerUsesIt`
- `tests/test_secret_keys.py::TestNoSecondKeyListExists`
- `tests/test_invariant_sweeps.py::TestS11ARouteNeverShowsWhatABroadExceptCaught`
- `tests/test_invariant_sweeps.py::TestS14AnAddressIsShownByOneHelper`
- `tests/test_invariant_sweeps.py::TestS14bAServiceShowsAnAddressByTheHelperToo`
- `tests/test_a_rollback_puts_the_file_back_too.py::TestTwoValuesThatPrintAlikeAreSaidSo`
- `tests/test_direct_socket_lock.py::TestTheTwinRefusalShowsTheAddressThroughTheHelper`
- `tests/test_url_never_carries_a_password.py::TestTheDnsProvidersAddressAndTheRestOfQ191`
- `tests/test_url_never_carries_a_password.py::TestShownUrl`
- `tests/test_url_never_carries_a_password.py::TestTheSecondPassOfQ190`
- `tests/test_url_never_carries_a_password.py::TestTheKeaClientNeverPrintsALegacyPassword`
- `tests/test_q171_access.py::TestDdnsLookupErrorNeverCarriesTheProviderUrl`
- `tests/test_alert_delivery.py::TestAChannelsSecretNeverLandsInText`
- `tests/test_no_raw_exception_leaks.py::TestNoUnexplainedRawExceptionLeaksInRoutes`
- `tests/test_a_rollback_is_refused_before_its_set.py::TestTheBundleMasksAContainerAndASpacedName`
- `tests/test_a_bounded_number_is_read_as_it_is_written.py::TestAChannelsSecretIsWriteOnly`
- `tests/test_the_alerts_page_keeps_its_secrets.py::TestThePageCarriesNoSecret`

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

### DDNS-STATUS-001 - DDNS status distinguishes an absent configuration, an unavailable observation and a loaded hook whose behavior is unknown
**Rule.** The Status tab's mode is `none` only when the config was read and nothing is configured, `unknown` when it could not be read, and `hook` when a run_script hook is loaded and D2 is off; an explicit
`[ddns] mode` (including `none`) wins; D2, hook and provider stay separate facts.
**Established.** Q176 (unknown), Q177 (explicit none, hook).
**Enforced at.** `jen/routes/ddns.py::_ddns_mode`.
**Tests.**
- `tests/test_ddns.py::TestTheModeSaysWhatItKnows`

### CRED-002 - A kept secret is kept only for the endpoint it was typed for
**Rule.** A form that keeps a blank secret keeps it only while the endpoint it names is the same place (`auth.same_endpoint`: scheme, host and port - never the path or the query; a bare host has no default port). A secret that is SPENT on a path is compared with the path and the query too (`auth.same_destination`, Q228): an OIDC client secret (the issuer's path selects the realm or the tenant whose token endpoint receives it, and a changed client ID is another registration), a webhook's header value and an ntfy token. A blank OPTIONAL secret with nothing stored to keep - another type of channel, or a stored config that cannot be read - is none, never a secret to carry, and a save that kept nothing says which fields are empty.
Two behaviors, by consequence. A LOOKUP credential (the DDNS token) is REMOVED when the provider or its address changes, with a warning, and never sent to the new place. A CONNECTION credential (the Kea API,
Kea6, D2, an additional server's, Kea's database, Jen's database) is REQUIRED for a new endpoint: the form refuses a blank password with one sentence and writes nothing; "Inherit", where a form has one, is the way out.
A password a form INHERITS (Kea6 and D2 use the Kea API's when they have none of their own, and "Inherit" removes theirs) stays with the Kea API's HOST: another port of the same host is the same Kea,
a different host needs its password typed, "Inherit" included (`auth.same_host`, `infrastructure._inherited_secret_refusal`). A genuinely new additional-server row takes the primary's password only through its own "Share the primary's API password" box (CRED-003; Q178 let it inherit silently), and the setup wizard
and the probe are the superadmin's deliberate tests of a typed address (an admin's probe is limited to the host Jen already reaches, over no weaker scheme - `auth.no_weaker_scheme`, RBAC-004). A form that offers "Inherit" AND a password box gets one
answer: ticking both is refused (`infrastructure._one_answer_for_a_secret`), and the checks judge the EFFECTIVE secret.
(DNS-CRED-001 is the provider-level half of the same rule; CRED-004 is the definition every form's check now agrees with.)
**Established.** Q178 (the beta.8 review: Technitium at A to Technitium at B kept A's token, and six more forms kept a blank password across a new URL or host). Q226 (AL3: the alert channel's write-only secrets - the SMTP password, a Telegram or ntfy token, a webhook header, a Slack or Discord webhook URL, the Pushover pair - are kept on a blank only while the channel names the same place; for e-mail the place is the server, its port AND whether STARTTLS is on, since a kept password sent in clear is a secret sent somewhere it was not typed for; a blank for a new place is REFUSED with the field named). Q227 (AM5: the OIDC client secret was kept on a blank whatever the issuer became - it is kept only for the same issuer, and a blank after the issuer changed is refused with the field named. AM6: a channel whose stored settings cannot be read kept nothing and saved an empty secret - a blank is refused. AM1, AM23: a generic webhook's URL carries its token in the path or the query, so it is write-only like the Slack and Discord ones. And a channel with no stored secret can change its place: there is nothing to carry).
**Enforced at.** `auth.same_endpoint`, through `infrastructure._secret_for_new_endpoint` (every connection route, before its write) and `save_infra_ddns`'s `_apply`; `_kept_secrets` / `_endpoint` in `jen/routes/settings/alerts.py` (Q226); `save_oidc` in `jen/routes/settings/security.py` (Q227: `auth.same_endpoint` over the stored and the typed issuer).
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
- `tests/test_a_bounded_number_is_read_as_it_is_written.py::TestAChannelsSecretIsWriteOnly`
- `tests/test_the_alerts_page_keeps_its_secrets.py::TestABlankSecretIsKeptOnlyForTheSamePlace`
- `tests/test_a_page_carries_only_what_it_names.py::TestTheOidcSecretStaysWithItsIssuer`
- `tests/test_a_secret_stays_with_its_destination.py::TestTheDestinationIsThePlaceAndThePath`
- `tests/test_a_secret_stays_with_its_destination.py::TestTheOidcSecretStaysWithItsIssuerAndItsClient`
- `tests/test_a_secret_stays_with_its_destination.py::TestAKeptSecretIsJudgedByTheWholeAddress`
- `tests/test_a_secret_stays_with_its_destination.py::TestABlankOptionalSecretIsNone`

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
has NONE - never its neighbor's, and `_endpoint_for` answers with a sentence and sends nothing. A blank `api_pass =` is an explicit no-credential; an ABSENT key is "inherit, if the host is the same". The URL and the USER are decided by the same function under the same three readings (a value is its
own; a present-blank key is explicit - no endpoint, no user, no password; an absent key inherits: the url from the parent in CA mode and nothing in direct mode, the password on the same host only, the user on
the same host or alongside a password the endpoint owns - and NOT beside a PRESENT-BLANK password, which says "no authentication" and so sends no user and no Authorization header - a user TYPED beside it is the endpoint's own and is sent; a database keeps its user; the present-blank case only - an absent password on a primary that has none leaves the user, and an endpoint on its host sends `Basic user:` like the primary), and the transport reads only those resolved fields: what `resolve` returns is what `requests.post` receives, and nothing downstream may change it. The Kea6 database is an endpoint like the rest: a present-blank `[kea6_db] host =` is "no Kea6 database" and a withheld password is none - `models/db.py` opens no pool and no connection for either, and Health says so.
The writer asks one more question for every write (`AppConfig._write_parser` through `credentials.move_refusal`, never per form): a saved password does not FOLLOW an endpoint to a new host, and does not
appear on a SECOND host, unless it was typed in this request (`mutate(fn, typed=...)`). A legacy endpoint that inherited its parent's password across hosts (an extra server since 5.10; Kea6, D2, the Kea6 database and a server's IPv6 and D2 endpoints) is converted ONCE PER INSTALL, audibly,
at `create_app` (`credentials.materialize`, gated on `[jen] credential_model = explicit` IN jen.config, written in the same atomic write as the copies - the marker is in the file it describes, so a restored older database
changes nothing and a restored pre-beta.11 config converts again, correctly; a fresh install (installer, wizard, container) is born with it; the settings key beta.11 wrote is read once more, by `already_converted`: the copy, a `<key>_shared` marker, one `CONFIG_MIGRATION` audit row each); a later change of the parent's
password does not follow it, and a section left WITHOUT a key afterward is never filled in at a restart. An explicit blank (`api_pass =`, the forms' "No password" boxes) is how a Kea with no
authentication is said, and nothing is withheld from it. `Set up direct socket` keeps a daemon's password as its own copy when the address it moves to is the same box spelled differently.
**Established.** Q180 (the beta.10 review - and the four before it: beta.7 provider switch, beta.8 same-provider URL change, beta.9 inherit plus typed and an extra server without a key, beta.10 the
unchecked share box and the extra server's IPv6 and D2 endpoints: one defect, a fallback written in a different place each time); Q181 (the transport reads only resolved fields); Q182 (every
exemption in the rule is itself a row first: the mode-switch skip, no authentication is no header, the marker is a value, the probed pair is kept, the installer's merge asks the same question);
Q183 (the flip carries only a password that already went to the parent's host, a password value changes only when typed, every `_shared` marker has a reader and a clearer, a row must REACH the skip it
names, and the second pass EXECUTES `tests/probe/credential_probe.py`).
**Enforced at.** `jen/services/credentials.py` (`resolve`, `move_refusal`, `materialize`); `jen/config.py` (`apply`, `derive_kea_servers`, `_write_parser`); `jen/services/kea.py` (`_endpoint_for` reads only resolved fields; `tests/test_credential_transport.py` compares the two). A saved password's FIRST address is a move too (`move_refusal`: a password that had no address and is given one needs to be typed). Exception (Q182, Q183): a switch of the connection mode exempts ONLY an endpoint whose address is DERIVED (its url key absent: `Endpoint.url_own` False) from a parent whose host did not change AND whose password already went to that host (it had an address there before: a password typed for another host whose address was removed is given a FIRST address by the flip, and is refused) - an address of the daemon's own, or a Control Agent on a new host, is judged as any move; a third shape (c) refuses an own password VALUE that changed, or is new, without being typed for that endpoint (a `mutate` that copies a value in); and every exemption in the rule is a matrix row that uses it for a different purpose (RELEASE_AUDIT step (n)). The conversion copies the parent's USER with the password and marks the file only when nothing is pending (a restored legacy file is converted, not merely marked); a legacy present-blank `api6_pass` / `api_d2_pass` is "inherit" in a file without the marker. The marker is a VALUE: `credentials.model_marker` is absent / explicit / invalid, and an invalid one converts nothing and shows in Doctor and Health as `credential-model-invalid`. The direct-socket routes write the pair that answered the probe as the endpoint's own when the resolver would withhold it at the new address, take their defaults from `resolve` (`_daemon_creds`), type only the endpoint they repoint, and handle a failed write of Jen's settings like a refusal. The installer's merge (`tools/config_merge.py`) runs the same `move_refusal`. The writer's `typed` set is a human's act in this request or the one-time conversion; a route never derives it from hosts, DNS or history (`tests/test_credentials.py::TestTypedIsAHumansAct`, through `tests/typed_claims.py`, refuses a `typed=` that is not a set display of string literals, `set()`, `None`, a conditional whose test is a boolean over `request.form.get/getlist` values and constants only, or a name bound exactly once to one of those and used for nothing else - no read of `extensions`, no other call, f-string, comprehension, walrus, lambda, `getattr`, `partial` or aliased writer; eight named functions are dynamic by nature and each may do ONE reviewed extra thing, listed in `tests/typed_claims.py` DYNAMIC and asserted by the test). The checker's reach layer is syntactic reach - the ancestors of the call inside the innermost function, a smell detector for a claim moved under a test the request does not decide; the guarantee is the shape rule, and an unconditional literal claim is accepted by design. A dhcp4 removal that would flip Jen to Control Agent mode needs a Control Agent address to flip to (none saved, or the saved one is the socket's own, and no other server keeps direct mode: the form asks for it and identifies it as a Control Agent before the socket goes; a SAVED address is identified the same way before it is restored, because a saved address that only differs as text from the socket is no proof of a Control Agent), the Control Agent's pair is saved as it WAS - a value, a blank or ABSENT - and a restore puts every half back as it was, and the dependant keep writes a user only beside a password of its own. The "Remove socket" forms therefore carry a password field, a No password box and - when the Control Agent's own pair was saved beside its address at setup (`direct_prev_api_user` / `direct_prev_api_pass`) - a "restore the saved pair" box; the route types the endpoint it repoints only when one of the three was used, the daemons a switch-back re-derives are never typed there (the writer refuses one whose saved password would reach a new place, and the page says to type it under Settings -> Kea first), and a daemon removal in Control Agent mode removes the daemon's own user, password and marker, which were the socket's; and a URL with a backslash, a control, zero-width or no-break space character names no place, and `a.` (the absolute name) is not `a` (`auth._endpoint_parts` / `valid_api_url` / `_plain_host`), because `urlsplit` and `requests` read them differently. `preflight_identity_change` asks it too (with the route's typed set), so a route that acts on the Kea host first is refused before the host is touched; the switch-back types the daemons it re-derives. A request for an endpoint
with no authentication carries no Authorization header and no netrc lookup (`kea._NO_AUTH`). An unreadable settings table is not an absent row: the conversion waits for the next start (`credentials.beta11_flag`). The two
greps `fallback=primary_pass` and `or server.get("api_pass"` over `jen/` find nothing, and `tests/test_credentials.py` says so.
**Tests.**
- `tests/test_credentials.py::TestResolve`
- `tests/test_credentials.py::TestTheConsumersAreOnTheResolver`
- `tests/test_credentials.py::TestEndpointForSendsNothingWithoutACredential`
- `tests/test_credentials.py::TestMaterialize`
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
it to the user and password fields, and Jen keeps dialing it as written (the credential rule is not touched). Every sentence that shows an address goes through `auth.shown_url` (LEAK-001). What LEAVES the box carries no user-info at all (Q221): every member of the support bundle is written by `build_bundle`'s `put`, which removes the user-info of every address in whatever it is given (Q222, AG2: `README.txt` and `logs/README.txt` were made by no pass), and the members that carry structure go through a stricter pass first (`_json`, `redact_ini_text`, `scrub_log_text`), which removes the user-info of every address - a value by `secret_keys.without_userinfo` (split at the authority's last `@`, so a password with a quote, a space or an `@` in it goes too), text by `secret_keys.scrub_urls` - and the compare's sentence prints a leaf the same way. A secret-named INI key is masked BY NAME and its value is never consulted (Q222, AG1: a password that began with `/` was taken for a path and exported in clear; the name rule already keeps every path-naming key).
**Established.** Q190 (beta.20's review: `valid_api_url` accepted user-info and Rotate's probe-failure flash, the connection form's audit row and the authoring flash printed the address as typed). Q221 (AE7: the bundle exported a legacy `api_url` in the clear beside a masked `api_pass`, and its own test asserted the address passed through; AE12). Q222 (AG1: a secret whose value began with a path separator was written to `config.ini.redacted` in clear, in 5.70.0 too; AG2: two members outside every pass; AG11: a dict key and an object the encoder printed). Q223 (AH7: a string under a secret-named key is masked in `_scrubbed`, the pass every member goes through, whoever made the member; AH13: the INI masker reads a key as written, so a camelCase name is a secret name; AH14: a member's name is a plain relative path). Q227 (AM23: a webhook or ntfy address typed with `user:password@` in it was stored and printed - the save refuses it with `auth.userinfo_sentence`, before any secret is kept).
**Enforced at.** `auth.valid_api_url` / `userinfo_sentence` / `shown_url` / `scrub_urls` / `urls_with_userinfo`; `config._warn_userinfo_urls`; `health._endpoint_credentials`. `secret_keys.scrub_urls` / `without_userinfo` (the one definition; `auth`'s names delegate); `support_bundle._json` / `_scrubbed` / `redact_ini_text` / `scrub_log_line`; `kea_api_config._leaf`. `support_bundle.build_bundle`'s `put` (the choke point); `readme_text` (notes through `scrub_log_line`, cut at `NOTE_MAX_CHARS`). `auth.userinfo_sentence` in `save_alert_channel` (Q227). `auth.plain_address` in the Alerts page's `_shown` (Q228, AN1: the rule at the DISPLAY - a stored address with user-info, a query or a fragment is withheld from the page, kept as stored and said to be) and `auth.http_address` in `_address_refusal` (Q228, AN6: a typed address is an http(s) URL with a host - `u:p@host/path` has no authority for `userinfo_sentence` to read).
**Tests.**
- `tests/test_url_never_carries_a_password.py::TestValidApiUrl`
- `tests/test_url_never_carries_a_password.py::TestLegacyUrls`
- `tests/test_kea_tls_rotation.py::TestALegacyUrlWithAPasswordNeverReachesText`
- `tests/test_direct_socket_lock.py::TestALegacyUrlWithAPasswordNeverReachesTheRecoveryLines`
- `tests/test_invariant_sweeps.py::TestS14AnAddressIsShownByOneHelper`
- `tests/test_a_rollback_puts_the_file_back_too.py::TestTheBundlesChokePointMasksByName`
- `tests/test_an_exported_address_carries_no_password.py::TestTheOneDefinition`
- `tests/test_an_exported_address_carries_no_password.py::TestNoMemberOfTheBundleCarriesAPassword`
- `tests/test_an_exported_address_carries_no_password.py::TestTheComparesSentence`
- `tests/test_a_secret_leaves_the_box_masked.py::TestASecretIsMaskedByNameAlone`
- `tests/test_a_secret_leaves_the_box_masked.py::TestEveryMemberIsWrittenThroughOnePass`
- `tests/test_a_secret_leaves_the_box_masked.py::TestWhatTheEncoderAddsIsScrubbed`
- `tests/test_a_page_carries_only_what_it_names.py::TestAChannelUrlNeverCarriesAPassword`
- `tests/test_a_secret_stays_with_its_destination.py::TestThePageWithholdsAnAddressThatIsNotPlain`
- `tests/test_a_secret_stays_with_its_destination.py::TestATypedAddressIsAnHttpUrl`

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
5. **What cannot be proved is a durable incident, written under a lock.** Twelve categories (`remote-unknown`, `restored-restart-unverified`, `restart-failed`, `tls-not-restored`, `tls-local-stale`,
   `restored-endpoint-unreachable`, `probe-pending`, `aborted`, from Q199 `tls-superseded` and `record-forgotten`, and from Q201 `rotation-pending` - a rotation's bookkeeping written BEFORE its first remote change and finished from Jen's files, and from Q203 `config-restart-failed` - a config Jen wrote, a restored revision or an import, whose daemon did not restart), shown on Servers and in Health until a verified recovery of THAT server and service (a probe that got its answer; a removal clears only the
   `probe-pending` note of the socket it removed) or a superadmin's acknowledgment. The incident note is one settings row read-modify-written as a `SELECT ... FOR UPDATE` transaction
   (`kea_changeset._with_attention`), so two workers lose neither; a write that did not happen is never reported as done; an unreadable note is Health "unknown", not "ok"; the soft cap never evicts a
   recovery incident (the hard ceiling keeps the newest 200). An incident never carries a socket entry, a key or a credential.
6b. **A certificate's names carry their ROLES in their order; a recovery judges the record GROUP; a rotation's bookkeeping is written before its first remote change (Q201).** `issue_server_cert` writes the SANs as `[bind address, SSH host]` (de-duplicated when equal) and DER keeps the order: `_certificate_roles` reads the FIRST name as the address the daemon serves and the LAST as the machine the helper installed it on (one name is both), and `ssh_host_refusal` / `_destination_refusal` / `_pair_is_for_another_machine` each compare their role with their own configured name - a name that matches the OTHER role proves nothing. A damaged-CA recovery judges the record GROUP by `host_material`'s rule (`_group_certificate`: the live certificate when it loads and no stale marker says otherwise, the `.prev` one when stale-marked or when the live one is absent or unreadable, never `.staged`) and REFUSES a group that has files and no certificate (`record_group_refusal`); only a record with no files at all keeps the override, by design. Before the first remote change a rotation writes ONE `rotation-pending` note per record it does not rotate (every parked record, orphan group and forgotten record), read back - a note that cannot be stored refuses the rotation before staging; after the commit each is finished from the files (`group_verdict`, one judgment for a parked live pair and an orphan alike; `reconcile_rotation_pending`), one that cannot be finished stays pending and is said, Health only names it and the next Rotate (or Forget stale records) finishes it, and a rotation that does not commit clears what it wrote. The setup counts a PARKED twin as a second owner of the daemon (`other_record_on_same_daemon`, Q202 AR4: the SAME function the rotation asks of every target) and asks the destination question of its own record before it stages anything. A scoped IPv6 literal is not an SSH host (a certificate cannot carry the scope) and a scope is folded away when addresses are compared.
6a. **The SSH host is the mutation target; a record is the daemon's only when the name the helper will reach matches the name the certificate was issued for, ON ITS OWN (Q200).** `kea_tls._destination_refusal` compares BY ROLE and both must hold: the configured `ssh_host` is the certificate's SSH-role name (`ssh_host_refusal`; the LAST SAN, Q201) AND the URL's host is its bind-role name (the FIRST SAN) - a URL match proves nothing about the machine the helper logs into and modifies. The wall holds in a damaged-CA RECOVERY too (`record_destination_refusal` runs before the override that turns a damaged-CA `none`/`refuse` state into a target). A record that fails either is `refuse` BEFORE staging (nothing installed anywhere, the record kept, Health names it), and the paths that put a saved pair back on a host (`_reinstall_live_material`, `_put_tls_back`) refuse a pair whose certificate does not name that host's SSH host (the second wall). A forget on the operator's word stores and reads back its `record-forgotten` fact BEFORE it deletes (a store that returns False deletes nothing; a failed deletion updates the fact to 'incomplete'; Health names a forget that did not finish); an orphan group is judged by the certificate it holds (`group_verdict`: the CA just replaced -> `tls-superseded`; none that can say -> `remote-unknown`, never silence).
6c. **A pending note belongs to its generation; a certificate that names nothing proves nothing; the URL is judged as the TLS stack judges it; one daemon is one target, parked records included (Q202).** `record_attention` REFUSES to refresh a `rotation-pending` note written under another CA fingerprint (the dedupe key is where the earlier generation's note was overwritten), and a rotation reconciles an earlier note BEFORE it starts and refuses - changing nothing - when it cannot; its failure path clears only the notes it wrote. A Jen-signed certificate with no DNS or IP name (no SAN extension, one with only an e-mail or URI name, one that does not parse) is REFUSED wherever a role is judged - `record_state` (both branches), the setup's own-record check and the put-back: the absence of evidence is never evidence. The URL half of the destination check passes when ANY name the certificate carries matches the address Jen dials (what a TLS client does); the SSH half stays all of its own, the LAST name. `rotation_inventory` asks `other_record_on_same_daemon` of every target over the records that are not targets - a parked twin refuses the rotation, with the sentence the setup would give. Jen's own bookkeeping (`rotation-pending`) is never cleared by an ACKNOWLEDGMENT (a verified setup of that server, the removal of its socket, and the reconcile still end it). The dependency set and the reconcile read the incident store STRICT: a store that cannot be read refuses the rotation, it never reads as 'nothing is pending'. `issue_server_cert` asks `_is_ip_literal` of the bind itself. Q203 (AS3, AS4): a second record of the same daemon counts in EVERY state but `none` (an `external` pair - one an administrator's CA issued - holds files at the fixed remote paths too), and a certificate's names are its non-empty DNS names and its IP ADDRESSES only: an empty DNS name is no name and an IP network is a range, so a certificate whose only SAN is one reads as naming nothing, with AR2's sentence.
6d. **A restored config revision whose daemon did not restart is a durable fact, and a restore asks for what its siblings ask for (Q203).** `config_history_restore` is a superadmin's with a recent password (the unmasked download of the same revision asks for it), passes the `tls_paths` its config references (`kea_authoring.referenced_tls_paths`) to the test and the apply so the material-before-reference preflight runs, and records a `config-restart-failed` incident for (server, service) when the restart fails - shown on Servers, carried by Health's 'direct-socket changes are proved' row as a stopped daemon, persisted in `changeset_attention` (which a restart of Jen reads and a settings export carries), and ended by the next restart of that daemon that works (a restore, or the Servers restart) or a superadmin's acknowledgment.
6. **A daemon an operation leaves behind is a durable incident, and a record is the GROUP of its files (Q199).** A server that is configured but not dialed over https (PARKED) whose daemon still runs
   its https socket is on the CA a successful rotation just replaced: the rotation records `tls-superseded` (Servers, Health, the page; ended by a later setup that replaces or proves the certificate, or by
   the socket's removal), and a record forgotten on the operator's word leaves `record-forgotten` - no daemon is silently left unwatched. A cleanup reports success only after the files are gone
   (`discard_local_record` returns `removed`/`absent`/`failed` after re-checking every path; `forgotten` only when `failed` is empty); a routine save that drops a removed server's records names them in the flash
   and the audit row; discovery enumerates every recognized record file and groups them by `<n>-<service>`, so an orphan (a key without its certificate) is shown and forgettable and an unrecognized name is
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
   (`none` / `ok` / `damaged` with why; `ca_present` is deleted - sweep S15): `none` is the uninitialized world ONLY (no CA files, no client pair, no `.prev`, no `.next`, no `kea-servers` directory at all, nothing
   unlistable - T7); the same absence beside any of that is `damaged`, as is a certificate that parses but whose public key is unusable (it must never raise). `ensure_ca` creates only in `none` and raises
   `CaDamaged` otherwise, `issue_server_cert` / `issue_client_cert` raise it instead of signing, `_material` (the install payload) is built only from an ok CA, the https setup refuses a damaged CA before anything
   is CHANGED on a host, Health fails, and Rotate replaces a damaged CA only with an explicit acknowledgment that a server which fails part-way cannot be put back (the rollback records `tls-not-restored`; a recovery
   judges the CA bundle by PATH - Jen's file or a link replaced, anything else a copy - because its own certificate cannot be compared, and the live client pair without its issuer).
   A rotation also refuses before staging when a live identity file is a directory or a link it cannot replace (`promotion_blockers`). (3) `kea_tls.client_state()` is the ONE definition of Jen's client pair
   (SPKI, the live issuer, `clientAuth`, validity; `none` / `ok` / `expiring` / `damaged`): `issue_client_cert` re-issues a damaged pair from an ok CA (the old pair kept as `.prev`) and the setup that calls it
   says so. **The recovery's sentences (Q193).** Every sentence on the recovery path says what HAPPENED and names an action the damaged gate does not itself refuse: a failed acknowledged recovery (the CA
   was damaged before staging, no promotion ran) counts and names the daemons not re-issued, says Jen's CA is still damaged and that the action is to Rotate again with the acknowledgment - never "a
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
   found it - a refusal changes nothing, and an EMPTY record directory in the uninitialized world would read as evidence that a CA existed; only the check immediately before a write keeps what it made. Read-only callers (the page, Health, the end-of-rotation comparison) pass `prove_storage=False`: a read
   creates nothing. **In a recovery an external endpoint is proved against the REPLACEMENT identity (Q195).** The live client pair fails beside an external that trusts the damaged CA BECAUSE that CA can no
   longer vouch (expired, not a CA, not yet valid), so Q192's "an endpoint that does not answer the live pair is unreachable regardless" does not hold in a recovery: when the live pair is REJECTED BY
   CERTIFICATE (a certificate alert, a named client certificate, or the connection CLOSED in the handshake - how a TLS 1.3 server says it: 88-95 percent of real rejections against an OpenSSL server were
   `EOF occurred in violation of protocol` / `Remote end closed connection`, executed - and not a timeout, a refusal, a name that does not resolve, or Jen failing to verify the daemon) the staged pair is tried: accepted is not a refusal; rejected too is "Prepare the
   new CA, install its certificate on that endpoint, then rotate again"; a transport fault keeps its sentence. A healthy rotation is unchanged. The fake daemon rejects an anchor OpenSSL would reject
   (`Lab.accepts_client`, `_anchor_usable`, pinned to the OpenSSL table that was executed: a self-signature is not checked, an issuer that is not the subject is rejected). **The failure of a rotation says the CA's state NOW (Q195):** a CA that became unusable without a promotion says `ca_state`'s why and the acknowledged Rotate
   (T2 pins the state, not a phrase); a probe file is Jen's only by its exact name (`kea_tls.PROBE_NAME`) - the cleanup removes only a LEFTOVER of it (older than a minute, never a probe being written right now) and never an operator's file.
   **A CA is healthy when the REAL verifier accepts what Jen issues from it, for both purposes (Q196).** `ca_identity` keeps its structural checks (they give the `why` a person recognizes) and ends with
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
   (Q197):** `verify_issued`'s refusal of a leaf's name is `NameRefused`, never `CaDamaged` - the setup, Rotate and the page say the CA is healthy, name the SAN that failed and ask for no acknowledgment; the
   form refuses an https direct host the verifier's DNSName parser rejects. **A record of an endpoint that is no longer https is stale, not valid, and no second owner of its daemon (Q197):** Health does not count it, Rotate ignores it, a removed
   socket drops it (`discard_local_record`), and a superadmin can forget the rest (local, audited). **One daemon is one record where the world is MADE (Q197):** an https setup is refused when another server
   record with the same SSH host already holds a Jen-issued certificate for the same service. **The staged rotation leaves no key copy (Q197):** the `.next` set is written without `.prev`. **One daemon is one rotation target (Q196).** Two targets with the same SSH host (`same_host`: exact,
   no DNS) and the same service are a refusal BEFORE staging; the route probes EVERY target once more with the staged identity after the last install and before the promotion, so each endpoint answers the
   FINAL material on its host (a failure there is the rollback).
   **(Q201) `rotation-pending`:** a rotation's note for every record it does not rotate is written and read back BEFORE the first remote change and carries the live CA's fingerprint; it is finished from the files after the commit, and a note whose CA never changed is simply dropped. Health only READS it; the next Rotate and Forget stale records finish it under the identity lock. **(Q202) A note is refreshed only under the fingerprint it was written with: a different generation is refused at `record_attention`, and a rotation that cannot finish an earlier generation's note does not start; `acknowledge_recovery` never clears one (a verified setup, the removal of the socket and the reconcile still do).**
11. **A stored incident Jen cannot recognize is kept (Q190).** Each entry of the recovery record has a shape (`kea_changeset.recognized_incident`: an attention incident has a known category, a service, a server
   id, a summary and a time; an outcome incident a `rolled_back`/`rollback_failed` status, a service and a time); `_incidents_of(strict=True)` raises `MalformedNote` naming the entry's INDEX, every writer
   refuses the whole note, `_incident_cleared` is False for an entry it cannot read (fail closed, in the lenient reader too), and the Servers banner says an incident Jen cannot read is on record.
12. **An invariant has no knob (Q190).** `Lab.check_invariants` ranges over the simulated host's daemons - T1 is judged by the certificate the HOST holds, T3 is relative (a daemon that answered Jen's live
   identity before a request answers after it, or an incident names it; one that did not is untouched), T4 looks for every configured secret including the password inside a configured address - and a test may
   not narrow it.
7. **Jen's record of what a host holds is the exact payload that host accepted, or "unknown" - never a copy made by the mechanism that failed (Q189).** `commit_issued` writes the pair the host was given
   as `.prev` and marks the live copy stale when its own write fails; when even that cannot be written (`HostRecordLost`) the route records `remote-unknown`, and `host_material` answers None - for an open
   `remote-unknown` or `tls-not-restored` incident, a `tls-local-stale` incident whose marker is missing, a record that cannot be read, or a pair that does not load. The fact is ALSO a file beside the pair
   (`.unknown`): an incident is acknowledged away by a person and resolved by a verified recovery, and neither makes the live copy the host's pair again - only an operation that gives the host a pair Jen then
   records (`commit_issued`, `promote_staged`, `restore_previous`) clears it, and an acknowledgment that cannot leave the marker is refused. A stale marker over a `.prev` pair that loads is the file layer
   KNOWING, and a transient failure to read the incident record does not destroy it. No re-assert installs a pair Jen does not know the host holds.
8. **A stored record of unresolved incidents that cannot be read is never written over (Q189).** `_incidents_of(strict=True)` admits three shapes (nothing; `{"incidents": [dicts]}`; the 5.65.x single note);
   anything else makes every writer refuse - unchanged, False - and a superadmin sets it aside (the raw value copied to its own settings row, the note cleared, the audit row carrying the length and the key).
9. **The pre-read is a call site (Q189).** `kea_host.read_config_versioned` answers a transport exception as a failed read; both routes refuse before they send anything.
**The invariants run after EVERY scenario (Q189, AE0).** `tests/test_kea_tls_rotation.py`'s `Lab.check_invariants()` runs in the fixture's teardown for every test in the file: T1 (Jen's record of each host's
pair is byte-equal to the pair the host holds, or None with an incident naming the server), T2 (the CA is a pair, or every target says it is not), T3 (every running daemon answers Jen's live CA and client
certificate, or an incident names it), T4 (nothing printed carries key material or the password), T5 (a refusal changes nothing); `TestTheInvariantsBite` breaks the product on purpose, once per invariant.
**Established.** Q186 (the snapshot, `describe_socket`), Q187 (the probe-failure branch, the TLS material, the persistent incident), Q188 (the transaction: local state first, the promotion, the rotation, the
endpoint that must answer, the locked incident store, the transport boundary), Q189 (the inventory, the host's record, the unreadable note, the pre-read, the invariants after every scenario), Q190 (who is on
Jen's CA by certificate identity, per endpoint; an invariant with no knob; an incident Jen cannot recognize is kept).
**Enforced at.** `kea_config_edit.control_sockets` / `restore_control_sockets` / `describe_socket`; `kea_tls.stage_issued` / `promote_staged` / `commit_issued` / `commit_rotation`;
`infrastructure._undo_remote_change` (the one compensation both direct-socket routes call), `_put_tls_back`, `_endpoint_answers`, `rotate_kea_ca`; `kea_changeset._with_attention`;
`user.update_global_setting`; `kea_host.install_tls` / `service_action` / `read_config_versioned` (the transport boundary); `kea_tls.rotation_inventory` / `record_state` / `commit_issued` /
`host_material` / `HostRecordLost`; `kea_tls.trust_bundle` / `trust_kind` / `trust_includes_jens_ca`; `kea_changeset._incidents_of(strict)` / `recognized_incident` / `_incident_cleared` / `set_aside_unreadable_note`.
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
- `tests/test_kea_tls_rotation.py::TestTheSshHostIsTheTarget`
- `tests/test_kea_tls_rotation.py::TestAForgetPersistsItsFactBeforeItDeletes`
- `tests/test_kea_tls_rotation.py::TestAnOrphanIsJudgedByItsPreviousPair`
- `tests/test_kea_tls_rotation.py::TestTheSecondPassOfQ200`
- `tests/test_kea_tls_rotation.py::TestTheLabRoutesByMachine`
- `tests/test_kea_tls_rotation.py::TestTheRolesOfACertificateAreBoundByOrder`
- `tests/test_kea_tls_rotation.py::TestARecoveryJudgesTheRecordGroup`
- `tests/test_kea_tls_rotation.py::TestRotationBookkeepingIsDurable`
- `tests/test_kea_tls_rotation.py::TestTheGroupVerdictIsOneJudgment`
- `tests/test_kea_tls_rotation.py::TestTheHealthAndTheFlashesTellTheStateTheyAreIn`
- `tests/test_kea_tls_rotation.py::TestAScopedAddressIsRefused`
- `tests/test_kea_tls_rotation.py::TestTheSecondPassOfQ201`
- `tests/test_kea_tls_rotation.py::TestAPendingNoteBelongsToItsGeneration`
- `tests/test_kea_tls_rotation.py::TestACertificateThatNamesNothingProvesNothing`
- `tests/test_kea_tls_rotation.py::TestAGrandfatheredHostStaysOnItsRecord`
- `tests/test_kea_tls_rotation.py::TestOneDaemonIsOneTargetParkedIncluded`
- `tests/test_kea_tls_rotation.py::TestTheUrlIsJudgedByEveryName`
- `tests/test_kea_tls_rotation.py::TestAPendingNoteIsNotAcknowledgeable`
- `tests/test_kea_tls_rotation.py::TestTheDependencySetReadsFailClosed`
- `tests/test_kea_tls_rotation.py::TestTheSmallOnesOfQ202`
- `tests/test_kea_tls_worlds.py::TestTheLeafShapesOfQ202`
- `tests/test_incident_store_locking.py::test_a_rotation_pending_note_is_not_refreshed_under_another_ca_fingerprint_on_the_real_table`
- `tests/test_direct_socket_credentials.py::TestTheProbeRowsOfQ202`
- `tests/system/test_boundaries.py::test_22_q_a_parked_twin_of_the_target_refuses_the_rotation_and_no_daemon_is_touched`
- `tests/system/test_boundaries.py::test_22_r_a_second_rotation_over_an_unresolved_note_with_the_store_down_refuses_and_the_note_survives_a_restart_of_jen`
- `tests/system/test_boundaries.py::test_22_s_a_hand_placed_certificate_that_names_nothing_refuses_the_rotation_before_the_daemon_is_touched`
- `tests/test_kea_tls_rotation.py::TestTheSmallOnesOfQ203`
- `tests/test_config_revisions.py::TestTheRestoreRouteIsHeldToItsSiblingsGate`
- `tests/test_direct_socket_lock.py::TestQ201TheSetupAsksAboutItsOwnRecord`
- `tests/test_direct_socket_credentials.py::TestTheProbeRowsOfQ201`
- `tests/system/test_boundaries.py::test_22_o_a_role_swapped_ssh_host_and_a_group_with_only_a_previous_pair_are_refused_before_anything_is_installed`
- `tests/system/test_boundaries.py::test_22_p_a_note_the_database_could_not_take_after_the_commit_stays_pending_and_health_finishes_it`
- `tests/test_direct_socket_credentials.py::TestTheProbeRowsOfQ200`
- `tests/system/test_boundaries.py::test_22_n_a_record_whose_ssh_host_moved_to_another_machine_is_refused_before_anything_is_installed_on_either_daemon`
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

## The browser surface (Q208)

### SESSION-001 - The idle deadline is one function, and the only request that moves it on purpose is a signed-in, CSRF-checked POST
**Rule.** `last_active` moves on every request a signed-in person's browser makes EXCEPT `/api/`, `/metrics`, `/static/`, `/session/touch` (its own writer) and a request marked `X-Jen-Poll: 1` (a page that refreshes itself: Health Center, HA
maintenance, a Trace watch, the update screen's second request, and a page that reloads itself, which marks the reload `?_poll=1` because a navigation cannot carry a header - and the query marker is a GET's: on a POST it is nothing - `session_timeout.extends()` is the one definition, it names `/static/` where the middleware returns before it, and it is asked in all three branches of the middleware); the one request that moves it ON PURPOSE is a CSRF-checked POST to `/session/touch`. The poll header can only STOP an extension, never
cause one, so a forged one is the forger's own loss and it is not a CSRF surface. `session_timeout.deadline(session, user)` is the one definition of when an idle session ends: the timeout middleware, the `X-Jen-Session-Expires` header
(an epoch second, or the word `off` when the person's timeout is off - never an absence - always beside `X-Jen-Session-Now`), the body attributes and `POST /session/touch` all read it. The touch
endpoint is `@login_required`, POST only and CSRF-checked like every POST, writes `session["last_active"]` and nothing else, is open to a person held at the forced password change, and is never reachable by an anonymous or cross-site request; a
missing, unreadable, naive or unrepresentable `last_active` is None, never "expired", and a timeout setting that is not a whole number of minutes from 0 to 1440 reads as 60, never as a 500 - and the same parser (`parse_minutes`, ASCII digits) is the one every writer of the setting uses. The browser takes a deadline only with the server's clock
beside it, ignores a reply older than one it has taken or computed from an older session state (`X-Jen-Session-Active`, the epoch second of `last_active`: the clock orders replies SENT, the state orders what they say; the state travels beside EVERY deadline, `off` included, and is `0` when the session has no readable `last_active`, and a reply without a numeric one is not ours), ignores a clock more than a day ahead of its own anchor, counts on a monotonic clock, holds ONE pending timer however often the tab is focused, leaves its dialog alone when a page reloads itself, and keeps its cross-tab value under a key that belongs to one sign-in (`session["login_id"]`, a label and not a secret, present on every signed-in page whatever the deadline says). An expired GET is sent to the sign-in page with `next=` only for an ordinary page - never for a POST, the sign-in and sign-out pages, `/api/`, `/metrics`, `/static/` or the session endpoints - and the sign-in page's
`_safe_next` is the only parser of it. There are two producers of that redirect, the timeout middleware (an expired session) and Flask-Login's unauthorized handler (an anonymous request), and both call `session_timeout.login_redirect_location`, so
they answer the same `Location` for the same request.
**Established.** Q208 (AX2); Q210 (AZ1-AZ4, AZ9: the poll header, `off`, the server's clock, the one coercion); Q215 (Z1-Z5, Z13, Z15-Z17, Z19: the dialog under a self-reload, the state beside every deadline, the poll that was not marked, one redirect builder, the GET-only query marker, `/static/`, the drift cap, the stacked timers, the login label). Q224 (AJ15: the Users page prints the minutes the server applies for an account; AJ14: an admin makes the idle timeout and login rate limiting stricter only, Q171's rule for the MFA mode).
**Enforced at.** `jen/services/session_timeout.py` (`deadline`, `extends`, `is_poll`, `announcement`, `login_redirect_location`), the `check_session_timeout` middleware and the `unauthorized_handler` in `jen/__init__.py`, `jen/routes/auth.py::session_touch`, and `templates/_session_watch.html`.
**Tests.**
- `tests/test_session_notice.py::TestDeadline`
- `tests/test_session_notice.py::TestTouch`
- `tests/test_session_notice.py::TestTheRedirectCarriesNext`
- `tests/test_session_notice.py::TestTheReturnAddress`
- `tests/test_session_notice.py::TestMiddlewareUnchanged`
- `tests/test_session_notice.py::TestAPollNeverExtends`
- `tests/test_session_notice.py::TestTheBootstrapSkipsTheSamePaths`
- `tests/test_session_notice.py::TestTheSettingIsReadOnce`
- `tests/test_session_notice.py::TestEveryDeadlineCarriesNow`
- `tests/test_session_notice.py::TestTheLoginIdIsPerLogin`
- `tests/test_session_notice.py::TestTheForcedChangeScreenHasTheNotice`
- `tests/test_session_notice.py::TestARepeatingReloadReadsTheDialog`
- `tests/test_session_notice.py::TestTheOneDefinition`
- `tests/test_session_notice.py::TestTheWatchScriptRuns`
- `tests/test_a_scoped_admin_reads_no_log.py::TestTheUsersPagePrintsTheMinutesTheServerApplies`
- `tests/test_a_scoped_admin_reads_no_log.py::TestAnAdminMakesThePolicyStricterOnly`
- `tests/test_a_rollback_is_refused_before_its_set.py::TestTheSecurityRatchetAndTheBounds`

### FIELD-001 - A field error's name is validated before it can reach an id lookup, and its message is only ever escaped text
**Rule.** `forms.flash_field(field, message)` stores a field error only when `field` fully matches `[a-z0-9_\-\[\]]{1,64}` (`fullmatch`, so a trailing newline is not a name); any other name, and any overflow past 20, is an ordinary
flash. The serialized list may not pass 2,000 bytes whatever its count (it travels in the 4,093-byte session cookie). Each item carries the path of the page its form was on, and the script moves an error under an input only on that
page (an item with no path, which beta.4 wrote, may land on any page). A full page that has no such input (the sign-in page, the forced password change, the second factor, the error page) prints a pending error as a plain flash, so one never outlives one
full page. The message is cut to 300 characters, reaches the page through `{{ message }}` (autoescaped) and reaches the DOM through `textContent`; the script finds the input with `getElementById('f-' + name)`, never a selector built from the name.
**Established.** Q208 (AX4; the name test written for it found that the entry's own `^...$` accepts a trailing newline, so the check is `fullmatch`); Q210 (AZ5: the byte budget and the form path).
**Enforced at.** `jen/services/forms.py` (`flash_field`, `take_field_errors`), the flash block of `templates/base.html` and the four standalone pages' own (`login.html`, `force_password_change.html`, `mfa_challenge.html`, `error.html`).
**Tests.**
- `tests/test_field_errors.py::TestFlashField`
- `tests/test_field_errors.py::TestTheMarkupEscapes`
- `tests/test_field_errors.py::TestAFieldNameThatIsNotAFieldNameIsAFlash`
- `tests/test_field_errors.py::TestAnErrorLandsOnItsOwnForm`
- `tests/test_field_errors.py::TestTheByteBudget`

### MARK-001 - A search mark is applied to escaped text, so the only markup in the output is the mark
**Rule.** `text.mark_match(text, q)` escapes every piece of `text` and `q` and wraps matches in `<mark>`; a client-supplied hostname that is itself markup is printed as text with or without a match, the marks are always balanced, and
`copy_cell`'s `data-copy` is the raw value (never a mark).
**Established.** Q208 (AX6).
**Enforced at.** `jen/services/text.py::mark_match` and `templates/_copy.html::copy_cell`.
**Tests.**
- `tests/test_search_mark.py::TestMarkMatch`
- `tests/test_search_mark.py::TestTheMacro`

## Retired ids

An id that is retired stays here, with the reason, so it is never given to a different rule. (None yet.)
