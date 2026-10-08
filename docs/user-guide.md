# Jen User Guide

This guide covers the day-to-day use of Jen for managing your Kea DHCP infrastructure.

---

## First-hour setup wizard (v5.67.0)

A fresh install with Kea not yet connected lands a superadmin on `/setup`
right after the forced password change — six steps, each skippable and
resumable from [Getting started](#getting-started-v5390) later. The
six-dot progress indicator at the top of every step shows what's done,
skipped, or still open.

1. **Connect** — the Kea API URL, credentials, and Kea's own database
   connection. An **Advanced TLS** expander (collapsed unless you
   already have values to show) covers a CA bundle path, "do not
   verify," and a client certificate/key pair — the same four settings
   and the same validation as Settings → Kea Server, so a site with a
   private CA or Kea's default mutual-TLS control socket connects here
   just as it would there (v5.67.0-beta.5). The URL is tried exactly as
   typed, a custom port included; Jen guesses `:8004` (`:8006` for
   DHCPv6) only when you gave no port. It then asks what answered —
   the Control Agent or a daemon's own control socket — and saves
   Control Agent or direct mode accordingly, so a Kea 3.2 site that
   types `http://kea:8004` is saved as direct mode. A blank password
   field means "use the saved one", for the test as well as the save, and
   the database is tested the way the app will connect: its port, and
   `[kea_db] ssl_ca` when set. A failed connection reports the error for
   the URL you typed first (v5.67.0-beta.8).
2. **What Jen found** — Kea's version, loaded hooks, HA status, and the
   subnets it reports. A subnet Jen already knows by the same ID and
   CIDR keeps the name you already gave it; only a genuinely new
   subnet gets proposed as "Subnet*N*". Submitting this step **merges**
   into Jen's existing subnet map — it never silently drops a subnet
   Jen knows about that Kea didn't report this time around (a
   temporarily unreachable server, or one that lives elsewhere); those
   are listed separately with their own opt-in "remove" checkbox
   (v5.67.0-beta.5). **DHCPv6** starts as "not checked" — Jen never
   probes it on your behalf. Press **Check for DHCPv6** (direct mode
   asks for the dhcp6 control socket URL; Control Agent mode reuses the
   v4 connection with the dhcp6 service) to see whether Kea actually
   answers for v6; if it does, **Manage IPv6 in Jen** saves the
   endpoint, proposes a `[subnets6]` map, and turns on Jen's own IPv6
   management — nothing v6-related ever runs unless you press that
   button yourself. The check needs a real kea-dhcp6 answer (a
   `Dhcp6` section in its config), and enabling it **merges** into the
   `[subnets6]` you already have: names and IPv4 pairings are kept when
   the ID and network match, and anything Kea did not report is listed
   with an unchecked "remove" box (v5.67.0-beta.8). With Kea's HA hook
   configured, the page shows two separate facts — the HA peers Kea
   reports, and the servers Jen manages — and an **Add this peer to
   Jen** action for any peer Jen does not manage yet; it opens the
   additional-servers form with the name, URL and role filled in, and
   leaves the credentials and SSH details to you. If Kea does not answer
   when you submit the step, nothing is saved and the step stays open.
3. **Kea host helper** — installs/updates `jen-kea-helper` over SSH,
   the root-owned script Jen uses for config pushes and service
   control on the Kea host (`docs/ARCHITECTURE.md` §3.3). A host Jen
   cannot reach over SSH — no host set, or the key not authorised yet,
   which is the normal first try — is reported as a message naming the
   user, the host and the reason, here and on Settings → Kea → SSH
   (v5.67.0-beta.8).
4. **Baseline** — reads Kea's live config once, recording it as the
   first revision Jen can diff against later. Once IPv6 is actually
   being managed in Jen (step 2), this captures a dhcp6 baseline too.
5. **Recovery point** — download an encrypted recovery bundle (Settings
   → Databases → Recovery has the same control). This step only marks
   itself done once a bundle from *this* setup run has actually
   finished downloading — not just because a button was clicked
   (v5.67.0-beta.5); the page notices the download finishing and offers
   **Continue** without a reload, and a passphrase mismatch keeps you in
   the wizard (v5.67.0-beta.8). You can also schedule standing backups
   here.
6. **Investigate a client** — pick a recent lease and open its full
   Investigation page (Overview, Explain, Trace, Timeline, DNS, Config
   — the same page `/client?q=...` always opens) to see why that
   client got what it got.

---

## Dashboard

The dashboard is the first page you see after logging in. It gives you a live overview of your entire DHCP infrastructure at a glance.

### Subnet Utilization Cards

Each configured subnet has a card showing:

- **Active leases** — total number of devices currently holding a lease
- **Dynamic** — devices using a dynamically assigned address (no reservation)
- **Reserved** — devices with a static reservation

The utilization bar at the bottom of each card fills as the subnet's pools fill (v5.68.0-beta.18). A subnet is judged **as a whole over all of
its pools**: the capacity is every pool added together (ranges and CIDR pools alike - two ranges of 50 and 60 addresses are 110, not 60), and what
fills it is the active leases whose address is **inside** a pool. An active lease outside every pool - a reservation's address - is still an active
lease and still counted in *Active leases*, but it uses none of the pool's capacity, so it does not move the bar. The same capacity and the same count
are used by the Reports page, the Health Center, the REST API, Prometheus and the alerts below.

### Recently Issued Leases

The lower section of the dashboard shows leases issued within a recent time window. Use the dropdown in the top right of this section to change the window:

| Option | Shows leases from |
|---|---|
| Last 30 min | Default — good for seeing what just connected |
| Last 1 hour | Useful after a network change |
| Last 4 / 8 / 12 hours | Broader activity view |
| Last 24 hours | Full day overview |

Click **View All** to go to the full Leases page.

### Auto-Refresh

Dashboard statistics refresh automatically every 30 seconds. You do not need to reload the page.

### Kea Health Indicator

The small dot in the top right navigation bar shows whether Jen can reach the Kea DHCP service:

- 🟢 **Green** — Kea is online and responding
- 🔴 **Red** — Kea is unreachable (check if `isc-kea-dhcp4-server` is running on your Kea server)

### IPv6 (v5.45.0)

With IPv6 enabled (Settings → Infrastructure), the subnet grid shows IPv6 alongside IPv4 rather than as a separate section: a small **v4**/**v6** tag on each card tells you which is which, and an IPv6 subnet that's paired with one of your IPv4 subnets (configured in `jen.config`'s `[subnets6]` section) nests inside that same card instead of getting a card of its own — an unpaired IPv6 subnet still gets its own card. IPv6 has no pool-size concept comparable to IPv4's, so its cards show active leases and reservations only, with no utilization bar. The Total Summary widget adds IPv6 active/reserved numbers to the same row, tagged the same way.

### Customize and Arrange (v5.54.0)

**Customize** (top right) is where you turn widgets on and off — the original eight plus seven more added in v5.54.0: Pool Exhaustion Forecast, Packet Health, Kea 3.2 Readiness, Recent Events, HA State, DDNS Errors, and Getting Started. Each of the new ones only loads its data once it is actually on the dashboard, the same way the existing sparklines, top-devices and alert-summary widgets already worked — turning one off costs nothing. A widget with nothing to say for your install (HA State on a single-server setup, DDNS Errors when DDNS updates are off) simply doesn't appear. **Save Layout** saves which widgets show; it doesn't touch their order, width or the subnet cards' arrangement.

**Compact subnet cards** collapses each subnet card to its name, active count and utilization bar, dropping the dynamic/reserved detail line and the gateway/DNS/IPv6 extras — useful when you have many subnets and want to see more of them at once.

**Arrange…** puts the page into arrange mode: every widget and every subnet card gets a grip handle, up/down arrows, and (for widgets, on a desktop screen) a width picker — full, half or third of the row. On a desktop you can drag a card by its grip to reorder it; on a phone, use the arrows instead (dragging doesn't work reliably there). Each subnet card also gets a pin button, which moves it to the front ahead of everything else, and a hide button, which removes it from the dashboard without affecting anything else — a hidden subnet is still fully visible and manageable everywhere else in Jen (Leases, Reservations, Subnets), just not shown as a dashboard card. **Save arrangement** writes the new order, widths, and subnet pin/hide state to your account; **Cancel** puts everything back the way it was.

If your account's subnet access changes later, any pinned, hidden, or ordered subnet id you can no longer see is dropped automatically — it never lingers in your saved layout.

---

## Leases

The Leases page shows all active dynamic leases — devices that received an IP address from the DHCP pool but do not have a static reservation.

### Filtering Leases

**Subnet** — filter to show only leases from a specific subnet.

**Time filter** — show only leases issued or renewed within the last N minutes. Useful for finding recently connected devices.

**Search** — search across IP address, hostname, and MAC address simultaneously.

**Show History** — toggle to show expired leases instead of active ones. Useful for seeing what was on your network recently.

### Converting a Lease to a Reservation

Click the **📌** button next to any lease to convert it to a static reservation. This pre-fills the IP, MAC, and hostname from the lease. You can optionally set a DNS override at this step.

This is the fastest way to reserve an IP for a device that is already connected.

### Releasing a Lease

Click the **✕** button next to any lease to release it immediately. The device will request a new lease the next time it needs one. This is useful for troubleshooting or forcing a device to pick up a new address.

### Deleting Stale Leases

The **🗑️ Delete Stale** button removes expired leases from the database. Kea normally handles this automatically, but the button is useful if you want to clean up immediately.

### IP Address Map

Click **🗺️ IP Map** to see a visual grid of the selected subnet showing which addresses are free, dynamically leased, or reserved. Hover over any cell to see the hostname and lease type.

---

## Reservations

The Reservations page shows all static host reservations — devices that always receive the same IP address.

### Adding a Reservation

Click **+ Add Reservation** and fill in:

| Field | Required | Notes |
|---|---|---|
| Subnet | Yes | Select which subnet this reservation belongs to |
| IP Address | Yes | Must be within the selected subnet's CIDR range |
| MAC Address | Yes | Format: `aa:bb:cc:dd:ee:ff` |
| Hostname | No | DNS-friendly name for the device |
| DNS Override | No | Comma-separated IPs — overrides the subnet's default DNS servers for this device |
| Notes | No | Free-text notes stored in Jen's database |

Jen checks for duplicate IPs and MACs before adding — you'll get a clear error if a conflict exists.

### Editing a Reservation

Click **✏️** to edit a reservation. You can change the hostname, DNS override, and notes. The IP address and MAC address cannot be changed through the edit form — delete and recreate the reservation to change these.

### Deleting a Reservation

Click **🗑️** and confirm to delete a reservation. The device will fall back to dynamic addressing on its next DHCP request.

### Exporting Reservations

Click **⬇ Export CSV** to download all reservations as a CSV file. The export includes IP, MAC, hostname, subnet, DNS override, and notes.

### Importing Reservations

Click **⬆ Import CSV** to bulk-import reservations from a CSV file. The file must have at minimum these columns: `ip`, `mac`, `subnet_id`. Optional columns: `hostname`, `dns_override`, `notes`.

Duplicate IPs are skipped automatically. Any rows with validation errors are reported after the import completes.

---

## Getting started (v5.39.0)

**Getting started** (admins; the nav pill, or `/getting-started`) is the first-hour checklist: each row is one thing worth having in place — SSH and the Kea host helper current, HTTPS, MFA on your account, an alert channel, a backup, a second server for HA — with a **Fix** link on any that isn't. The pill in the top bar shows `done/total` until everything is green. A superadmin can hide the pill for the whole install with **Dismiss the nav reminder**; the page itself stays available.

## Investigating a client (v5.63.0, front door in v5.68.0)

The Investigation page is where every question about one client ends up, so it is one click from everywhere a client is named:

- **The search box** (top bar, or the Search page): type one whole MAC, IPv4 address, IPv6 address or DUID and it goes straight to the client; a hostname, a fragment or a partial MAC still lists results (the Investigation page links back to that list).
- **Every row that names a client** has an *Investigate* action — the action menu of a lease, reservation or device row, a search result, the dashboard's recent leases, events and top devices, the Alerts log (for alerts whose message names a client), the dashboard's alert strip, and the header of the Timeline page.
- **Network → Investigate** opens the empty form.

Give it a MAC, an IPv4 or IPv6 address, a DUID (`duid:00030001…`, or bare hex), or a hostname. Jen resolves it once — the same identity every tab below reads — then lays out seven tabs onto it:

- **Overview** — the device, its active lease(s) and reservation(s), its IPv6 leases and reservation (with any delegated prefix and excluded prefix) when IPv6 is on, the most recent alert that mentioned it, and a freshness line showing exactly when the data on screen was read.
- **Explain** — the same step-by-step decision Kea would make for this client (see below).
- **Trace** — the same tail-of-the-Kea-log view (see below); admin-only and needs access to every subnet, same as the standalone page.
- **Timeline** — the same merged event/audit/alert history (see below).
- **DNS** — checks this client's own names against DNS, the same forward/reverse verification the DDNS Reconcile tab runs fleet-wide. Every record you may see for the client is a row: each IPv4 reservation and lease, and with IPv6 on each IPv6 reservation address and lease, one row per distinct name and address (checked as an A record for an IPv4 address and an AAAA record for an IPv6 one). A client with a good first record and a wrong second one shows the wrong one. The first 20 records are checked, and the tab says when there are more.
- **Config** — the effective subnet, pool, options and classes from the same Explain evaluation, plus the live configuration's SHA so you can tell at a glance whether it's changed since you last looked.
- **Changes** — which Kea config changes touched *this client*. For the newest 50 revisions of each server's history, Jen compares each revision with the one before it over only the parts of the config that decide what this client gets: its subnet (by id or by CIDR), the shared network the subnet sits in, the pools its addresses fall in, the classes that guard that path or that it matches, its own reservation with any option on it, and the **global DHCP settings** every client in the service inherits — the global options, the valid lifetime and renew/rebind timers, how reservations are looked up (the host-reservation identifiers and the global / in-subnet / out-of-pool modes) and what the server does with the client id. A change to a global DNS option or a lifetime is often the answer to *why did this client's setting change*, and shows here; a change to logging, the control socket, hooks, interfaces or the lease database does not, because none of them changes what a client is given. A revision that changed none of those is not listed; one that did shows the lines that moved in the matching part, who made the change, when, its summary, and whether it was Jen's (`jen`, `restore`) or someone editing the file on the host (`external`). Each revision links to the full diff on the config history page. This tab needs what that page needs — an admin who may see every subnet — and is not offered to anyone else. A reservation kept in Kea's host database is not part of the config file, so a change to one does not show here.

### IPv6 addresses and DUIDs

With IPv6 turned on (Settings → Kea), an IPv6 address resolves through the lease table (or a reservation of it) to the DUID that holds it, and a DUID goes straight to its leases and its reservation. The MAC then carries the page on to everything keyed by MAC: the device record, the IPv4 leases and reservations, the Timeline. Where the MAC came from is on the page: *captured by Kea* is the hardware address Kea recorded on a lease; *read from the DUID* is Jen's own reading of a DUID-LL or DUID-LLT (which embeds a link-layer address) and is only as good as the DUID. A client Jen can find no MAC for (a DUID-EN or DUID-UUID, with no captured address) is shown as the IPv6 client it is: Explain, Trace, Config and Timeline are DHCPv4 tools, and say so in one line instead of guessing. With IPv6 off, an IPv6 address or DUID says so rather than looking anything up.

### What a restricted user sees

A hostname that more than one client currently uses shows every match you may see instead of guessing which one you meant. Every tab is subnet-restricted exactly the way the page it draws from already is: a client outside the subnets you can access says "No client matched" — the same answer as for one that does not exist. An IPv6 lease or reservation is judged on the IPv4 subnet its IPv6 subnet is paired with (an unpaired IPv6 subnet is for users with access to every subnet). The *last alert* line is shown to you when it is about a client you may see, with its type and time but never its message, because alert messages can name a subnet. The identifier and the active tab both live in the URL, so a tab is always a page you can reload, bookmark, or send to someone else with access.

### Why did this client get this? (v5.35.0)

Explain — reachable at **Network → Explain**, or as the Investigate page's Explain tab. Give it a MAC (and, if you have them, the vendor class, user class, hostname, client id, relay ids or giaddr the client sends) and Jen walks the decision Kea makes, step by step:

1. **Subnet selection** — the subnet you chose, or the lease's / a reservation's; a giaddr is checked against the subnet's relay addresses and range.
2. **Reservation** — by MAC or client id, in this subnet or globally when the subnet allows global reservations. This decides KNOWN / UNKNOWN.
3. **Client classes** — every class in config order, with *matched*, *no*, *undecided* (an input you didn't supply, named) or *not evaluable*. Jen evaluates exactly the expressions its own rule builder writes; anything else is shown verbatim rather than guessed.
4. **Subnet guards** — which subnets in the shared network the client is allowed into.
5. **Pools and address** — the reserved address, else the current lease (renewed), else the first pool whose guard classes are satisfied.
6. **Options** — the reply's options with where each came from and what it overrode (reservation > pool > subnet > shared network > class > global), and the lease lifetime.

Kea has no dry-run, so this is a reconstruction from the configuration Jen holds; it cannot see which interface a request arrived on. Only subnets you can access are shown.

### What Explain can and cannot know (v5.68.0-beta.2)

Explain can only decide a client-class test over what it knows about the client. It starts from the MAC and fills in the rest from the best source there is, and the **Inputs used** card on the page lists every input with where it came from, so you can see what an answer rests on:

| Input | Where Jen gets it |
|---|---|
| MAC | the one you asked about |
| Client id, hostname | the client's current lease |
| Circuit id, remote id | the lease's extended info — only when Kea runs with `store-extended-info: true`, which keeps the relay agent's options on the lease at any log level |
| Client id | the `cid=[…]` label Kea puts on every log line about a client, at any log level |
| Classes Kea assigned, and the vendor class | Kea's log at **debuglevel 45 or higher** — the `DHCP4_CLASSES_ASSIGNED` line lists them, and Kea's built-in `VENDOR_CLASS_<option 60>` class in that list *is* the vendor class |
| Hostname, vendor class, user class, circuit id, remote id | Kea's log at **debuglevel 55 or higher** — the `DHCP4_QUERY_DATA` packet dump |
| Anything | what you type into the form on the Explain tab (what you type wins) |

Those log levels were measured against real Kea 3.0.3, 3.2.0 and 3.3.1 (the same on all three), not assumed. At Kea's default INFO level, and at DEBUG with a debuglevel of 15 or 30, the log carries the packets, the offers and the allocations — and the client id — but not the vendor class, user class, hostname or relay options of the packet. To let Explain read them from Kea itself, set the `kea-dhcp4` logger to severity `DEBUG` with `debuglevel` 55 (45 is enough for the assigned classes and the vendor class). That is a lot of log; turn it back down afterwards. A class Kea listed as assigned is shown as *assigned by Kea at <time>* and outranks Jen's own reading of its test; a class Kea did not list keeps whatever Jen could work out.

With more than one Kea server, Jen reads every server's log **at the same time** and waits at most 20 seconds for all of them together (v5.68.0-beta.23); the newest complete exchange among the servers that answered in time is what Explain uses, and a server that did not answer is named under the Inputs card (*N server(s) could not be checked in time*). When another server also logged a complete exchange, the card says so: *at about the same time* when the two clocks can be compared, or *the two clocks cannot be compared, so this one was chosen because it is first in order* when they cannot. Reading Kea's log needs the Kea host helper and an admin with access to every subnet (the same rule as Trace: a log line has no subnet boundary Jen can trust). Anyone else still gets the lease-derived inputs for a subnet they may see, and can type the rest. `?auto=0` on the Explain page turns every inferred input off, leaving the MAC and what you typed.

**One exchange, from the server that handled it (v5.68.0-beta.10).** Everything Explain reads from Kea's log comes from a single exchange: the client's newest transaction that has a class list or a packet dump (a transaction is the set of log lines sharing the client's transaction id, `tid=`). The client id, the classes and the options are never mixed from three different exchanges, and the Inputs card says which exchange it used (*the one at 15:10:39, transaction 0x20006, on kea-b*). With more than one Kea server, Jen reads the HA-active server's log first, then the rest in order, until one names the client; a standby, an unreachable server or one without the helper is skipped. If the exchange was logged before the live config's newest revision (Jen only says this when it knows the Kea host's clock), the class row says *observed before the config changed*: that is what Kea decided under the older config.

**Option 77 and the relay circuit id are compared as bytes.** A client sends its user class either as the bare string (`dhclient`'s `send user-class`, most Linux clients) or, as RFC 3004 says and Windows does, with a length byte in front (`08` then `jen-user`). Kea compares the bytes, so `option[77].hex == 'jen-user'` matches the first kind of client and not the second, and `option[77].hex == 0x086a656e2d75736572` the reverse (checked against real Kea 3.0.3, 3.2.0 and 3.3.1: identical on all three). Kea's packet dump supplies the bytes exactly, and Explain evaluates them; the *user class as sent* box on the Explain form takes them by hand. If you give only the text, Explain judges a test under both forms and calls it decided only when they agree; when they do not it says it is undecided and asks for the bytes. A circuit id that is not text (`DE AD BE EF`) is compared as the bytes `deadbeef`, not as the letters of its hex.

**What "current" means.** A lease Jen calls the client's current lease is one in state 0 whose expiry has not passed. Kea keeps an expired lease in the table until it is reclaimed, and an expired lease no longer decides who holds an address, which MAC a hostname belongs to, what the Investigation page calls the client's lease, what Explain reads the client id and hostname from, or how many active IPv6 leases a subnet has. The Leases page with *show expired* still lists it.

**Why not.** Beyond the address, Explain now says what stands in the way:

- **A full pool** is a verdict: *pool X: eligible but FULL (254 of 254 addresses leased)*, with the next eligible pool (and its free count) as the answer, or *every eligible pool is full* when there is none — Kea would NAK or stay silent.
- **A reserved address held by another client** names the holder and when its lease ends — Kea offers the reservation only once that lease expires or is released — and links to the holder's own Investigation page. The holder is only named when its lease is in a subnet you may see.
- **A reservation that is never matched**: if its identifier type (`hw-address`, `client-id`, …) is not in the config's `host-reservation-identifiers`, Explain says so instead of showing a reservation Kea will ignore.
- **A relay that does not match**: with a giaddr that is neither a relay address of the subnet nor inside it, the *Subnet selection* step reads *NOT selected*.

An admin who may see every subnet gets a *config changes to this* link beside each verdict, which opens the Changes tab filtered to the config element the verdict is about (a pool, the subnet, the reservation). The Overview carries the same engine's one sentence — *Would get 10.0.0.5 from the reservation*, *Would be NAKed: every eligible pool is full*, *Undecided: …* — computed from the lease-derived inputs and any Kea-log read already made, so opening the Overview never costs a trip to the Kea host.

### Trace a client (v5.48.0)

Trace — reachable at **Network → Explain → "What Kea logged"**, or as the Investigate page's Trace tab. Explain predicts what Kea *should* do; Trace shows what it *did*: Jen reads the tail of the Kea server's `kea-dhcp4` log (through the same helper `tail-log` op the DDNS log tab uses — no packet capture, nothing installed), keeps the lines that name the client's MAC, and shows them in plain English grouped into exchanges — DISCOVER → offer → REQUEST → ACK, a NAK, a release or a decline. Lines are grouped when they are less than two seconds apart. Above the timeline, Explain's answer for the same client ("Jen expects subnet 3, 10.0.1.55") sits next to it so the two can be compared.

**Watch this client for 10 minutes** re-reads the log every 3 seconds, then stops on its own (or when you leave the page).

What it can see depends on the server's log level. At Kea's default (INFO) the log shows packets received and sent, offers, allocations, reuse, releases, declines and errors — but not DISCOVER/REQUEST processing, subnet selection, or most of the reasons for a NAK, which Kea only logs at DEBUG. The page says which case it found; see the [Kea logging section](https://kea.readthedocs.io/en/latest/arm/logging.html) to raise the level. Kea logs no line when it queues a DDNS update — only when sending one fails — so a healthy DNS update leaves nothing to show here.

Only the last 1000 lines are scanned (the helper's own limit), so on a busy server an older exchange may already be out of the window. Trace needs the **Kea host helper** on the server (Settings → Kea → SSH → Install helper): it reads the log through the helper's bounded `tail-log`, never through the old `tail -200` sudo grant, which could not serve 1000 lines. Without the helper the page says so instead of showing a partial log. If your Kea writes its log somewhere other than `/var/log/kea/kea-dhcp4.log`, set `[kea] dhcp4_log_path`. The log can contain other clients' data — and Kea's log has no per-line subnet boundary Jen can trust, so a client's earlier activity in another subnet can sit in the last 1000 lines whatever its current lease says. Trace is therefore admin-only **and needs access to all subnets**: a subnet-restricted admin gets a refusal for every MAC, and the *Trace in Kea log* links are hidden from them. It is never part of the support bundle.

### Problems: which clients had trouble (v5.68.0-beta.5)

An investigation usually starts when someone already has a MAC. **Network → Problems** starts from the opposite end: the clients that had DHCP trouble lately, newest first, one row per client with what happened and how often, the server it happened on, when, and an **Investigate** button on every row. **Why?** on a row asks for the one-line answer the Investigation page gives (what Kea would do with this client) and shows it under the row; nothing is worked out until you ask. The filters narrow the list to one server or one kind, and the **NAK** and **Dropped** counters in a server's packet-health block on the Servers page link here, filtered to that server.

The times in the list are the times of the events themselves, in UTC: Kea writes its log in its host's local time and Jen converts it, which the **Last seen** header spells out for each server when you hover it. A client that was refused in one subnet and has since moved appears only for people who can see every subnet (the log names no subnet for it that Jen can prove), and Jen never alerts about a backlog it reads for the first time on a server.

What each kind means:

- **NAK** — Kea answered the client's request with a DHCPNAK: it asked for an address it may not have. Visible at Kea's default INFO level (as the DHCPNAK Kea sends); at DEBUG the reason is added.
- **Declined an address** — the client told Kea the address it was offered is already in use (a DHCPDECLINE). Kea keeps the address out of service for a while; INFO level.
- **DNS update failed** — Kea could not hand the client's update to kea-dhcp-ddns. INFO level.
- **Packet dropped** and **No subnet matched** — Kea dropped the client's packet, or could not pick a subnet for it. These are DEBUG messages: they appear only while a server logs at DEBUG, so turn on investigation logging (below) for a few minutes to see them.
- **Declined lease** and **Reservation held by a different client** — read from the lease database, not the log, so they appear at any log level and clear the moment the state is gone. A declined lease is about an address (Kea clears the declining client's hardware address); a held reservation is about the client the address is reserved for, whose address is leased to a different client right now.

Every five minutes Jen reads the last 1000 lines of each Kea server's log (the same bounded read Trace uses) and the lease database. A line read twice is counted once. A row whose kind has not come back for a day leaves the list; rows are kept 30 days. A server Jen cannot read adds nothing to the list — the Health Center's server rows say why — and on a very busy server the oldest lines between two reads can be missed, so the list is a lead to follow rather than a ledger.

A user restricted to some subnets sees only rows in their subnets; a row Jen could not place in a subnet is shown only to a user who may see every subnet. The dashboard's **Clients with problems** widget (Customize → pick it) shows how many clients had trouble in the last hour, by kind, and the five most recent. A channel that has opted into the **Client had DHCP trouble** alert gets one message when a client has the same kind of trouble three times within an hour (the number is `[alerts] client_problem_threshold`), and at most one per client and kind per day. Each row belongs to one subnet for good (v5.68.0-beta.14): the same client's trouble in two subnets is two rows with their own counts, times and alerts, never one row that moves between them. The inbox started again at that release (the old rows could have mixed subnets and were cleared); the next sweep refilled it from the Kea log.

### What else Jen knows (v5.68.0-beta.4)

Under the core facts on the Overview, **What else Jen knows** carries one card per plugin that has something to say about this client — a plugin that has nothing to say about it adds nothing, and the heading is absent when no plugin does. The seven bundled plugins each contribute:

- **Switch Port Locator** — the switch and port the client's MAC was last seen on, its VLAN, and whether it moved.
- **Presence** — its state (online or offline), when it was last seen, and the sink it is published to.
- **Network Discovery** — what the newest finished scan saw: open ports, vendor, the hostname it answered with.
- **IPAM Lite** — whether the client's address is designated, and to what; the next free address when the subnet is unmanaged.
- **Host Watchdog** — whether the host answers, since when, and how many checks in a row have failed.
- **DNS Sync** — the records that carry its name on each DNS target, and whether they match its lease or reservation.
- **Wake & Actions** — whether it is a favourite, whether a SecureOn password is set, and when it was last woken.

A card whose subject needs a look (a host that is down, a record that does not match) says **Needs a look**, and its one sentence is also added to the line at the top of the page under **Worth a look**. A plugin that cannot answer right now shows "unavailable" for its card and nothing else on the page changes. What a card shows follows the same rule as the rest of the page: a user restricted to some subnets sees a plugin's card only for a client in a subnet they may see, and a client outside them is the ordinary "No client matched" answer.

### Seeing what Kea did: investigation logging (v5.68.0-beta.3)

What Trace and Explain can read out of Kea's log depends on its level, which was measured on Kea 3.0.3, 3.2.0 and 3.3.1: at the default INFO it names the client on packets, offers, allocations, releases, declines and errors, and nothing of the decision; at **debuglevel 45** it adds the classes Kea assigned and which subnet it selected; at **debuglevel 55** it dumps every packet's options (hostname, vendor class, user class, client id, the relay agent's circuit and remote ids). A production DHCP server should not sit at 55, so Jen turns it on for you and turns it off itself.

On **Trace** (a card under the form) and on every **Servers** card, an admin with access to every subnet can press *5 min*, *15 min* or *60 min*. Jen puts the `kea-dhcp4` logger at DEBUG, debuglevel 55, on **that one server** (never two at once), through the same checked, reverted-on-failure config change every Kea edit uses, and tells the running daemon with `config-reload` — no restart, no dropped packets, nothing for HA to notice (a Kea that answers and does not offer `config-reload`, or refuses it, is restarted instead and the result says so; turning it ON never restarts Kea because its API failed: if Kea's API does not answer, or does not confirm the reload, the change is put back - and Jen then reads Kea's running log level, so a reload Kea applied although its answer was lost is found and undone within a minute (v5.68.0-beta.23) - and nothing is restarted — turning it off still restarts if it must). A banner on Trace, Servers, the dashboard and the Investigation page shows the time left, with *Turn it off now*. When the time is up the sweep (every minute) puts back exactly the severity and debuglevel the logger had — or removes the entry Jen created — without a restart, whether or not this Jen turned it on; if it cannot, the Health Center's **DEBUG logging left on** row goes red and the sweep keeps trying.

**The disk.** At debuglevel 55 Kea writes a packet dump for every client it hears from. On a busy server that is megabytes a minute, so 60 minutes asks you to confirm, and the shortest time that answers your question is the right one. Kea's own log rotation (`output-options` `maxsize`/`maxver`) still applies; Jen changes only `severity` and `debuglevel`.

With logging on, **Explain** fills its inputs from the packet dump, shows the classes Kea assigned beside Jen's own evaluation of each class, and says so when they disagree — *Jen evaluated class X as matched; Kea did not assign it — the test may read an input Jen does not have, or the config has changed since.* **Watch this client** on Trace re-reads the log every 3 seconds for ten minutes (it stops when you leave the page), so you can ask the device to renew and watch DISCOVER, the class assignments, subnet selection and the OFFER land. With logging off the watch shows the INFO events and a one-line note of what turning it on would add.

### Timeline (v5.42.0)

Timeline — reachable at **Network → Timeline**, or as the Investigate page's Timeline tab. Give it a MAC or an IP and it shows everything Jen has recorded about that one client, newest first:

- **Events** — a new lease, an IP or hostname change, an expired lease, a reservation added/deleted/changed, a config push, an HA state change, config drift detected or resolved, and every alert Jen sent, with which channel and whether it landed.
- **Audit log** entries and **alert** deliveries that mention the MAC or IP in their text.
- The device's first-seen/last-seen bookends, and its current lease and reservation, at the top.

An IP with no MAC given resolves to its current lease's MAC automatically. Filter chips narrow the list to one kind of event at a time. Only subnets you can access are shown — a client whose subnet you can't see, or one with no resolvable subnet at all, isn't shown to a subnet-restricted user.

Addresses get reused, so a timeline about a **MAC** shows only that client's own rows: events recorded for the same address under a different MAC are left out, and a row that names only the address (an audit or alert entry, or an event with no MAC) is kept but shown muted as *possibly related — same address, client unknown*. A timeline about an **IP** shows everyone who held it, and marks rows from an earlier holder *previous holder <mac>*.

Jen keeps events for 90 days by default — the same retention job that prunes lease history.

## Subnets & Scope Options

The Subnets page shows the live configuration of all subnets pulled directly from the Kea API. It is read-only by default unless SSH is configured for subnet editing.

### Reading Subnet Information

Each subnet card shows:

- **Lease Duration** — how long devices hold their lease before needing to renew
- **Renew Timer (T1)** — when devices first attempt to renew their lease
- **Rebind Timer (T2)** — when devices begin broadcasting for any DHCP server if renewal fails
- **Address Pools** — the range of IPs available for dynamic assignment
- **Scope Options** — DHCP options sent to devices on this subnet (router, DNS, etc.)

### Editing a Subnet

If SSH is configured in Settings, an **✏️ Edit** button appears on each subnet card. Click it to edit:

- **Address pool** range
- **Valid lifetime** (lease duration in seconds)
- **Renew timer** (T1 in seconds)
- **Rebind timer** (T2 in seconds)
- **Router** (gateway address)
- **DNS servers**

Changes are validated before being applied. If validation fails, your previous configuration is automatically restored from a backup. Kea restarts briefly when changes are applied — expect a few seconds of DHCP interruption.

---

## Reports and the exhaustion forecast (v5.36.0)

**Reports** charts each subnet's lease history from the snapshots Jen
takes every few minutes (the interval and retention are set at the
bottom of the page). Each subnet card shows the current active leases,
the peak over the selected range, the pool size and free addresses.

Below that is the forecast: the highest active-lease count in the last
30 days and the day it happened, the trend in leases per day, and — when
the trend is rising — roughly when it reaches 90 % of the pool, with the
date.

**The chart.** Each chart draws *Pool used* (the leases inside the pools -
the series the forecast is fitted on, recorded from the first snapshot taken
by 5.68.0-beta.19), *Reservations configured*, *Active clients (whole
subnet)* and the *Pool Size* — and, when there is enough history, a
dashed amber **Projected total (trend of daily peaks)** that continues the
Pool used line from its last point, 30 days ahead. The dashed line is a
straight-line fit of each day's peak over the last 30 days, carried forward
and kept between 0 and the pool size; a rising line stops the day it would
fill the pool. It is drawn for a **rising, a flat and a falling** trend
alike — a falling one slopes down toward zero, a flat one holds its level —
and the card's sentence says where it ends: "falling — about 12 in 30
days", "flat — holding near 80". Only a rising trend also gets an
exhaustion date; a pool that is flat or emptying has none.

With fewer than 7 days of snapshots, or no pool size recorded, there is
nothing to fit: the chart then has no dashed line and says so in one
sentence underneath ("No projection yet: 4 more day(s) of history needed",
or "No projection: this subnet has no pool") rather than listing a legend
entry that is not drawn.

How it is worked out: the highest active-lease count of each day over the
last 30 days, a straight line fitted through those daily peaks, extended
forward. It needs 7 days of snapshots before it says anything, only uses
snapshots taken since the pool was last resized, and reports a crossing
more than a year out as "beyond the horizon" rather than a date. It is a
trend, not a guarantee: a line fitted to the past does not know about the
new office or the Wi-Fi you are about to turn off. The forecast line turns
amber when 90 % is within 30 days and red within 7 — the same thresholds
the **Pool exhaustion forecast** check on the Health page and the optional
**Pool exhaustion forecast** alert use.

**Pool use, not active clients (v5.68.0-beta.19).** Each chart draws **Pool used** - the active leases whose address is inside the subnet's pools - against
the dashed **Pool Size**, a thin **Active clients (whole subnet)** line, and **Reservations configured** (how many reservations exist, not how many hold a
lease). The percentages, the *Free* figure, the peak, the Health row, the Prometheus ratio and the forecast all use pool use: eighty leases in a 100-address
pool plus thirty reservations outside it is **80 % used**, not 110 %. The old *Dynamic Leases* line is gone (a reservation made by client id counted as
dynamic). Snapshots taken before 5.68.0-beta.19 did not record pool use, so the lines start at the first snapshot after the upgrade and the forecast says
*No projection yet: N more day(s) of history needed* until about a week of new snapshots has accumulated.

**IPv6 subnets (v5.68.0-beta.17).** With IPv6 on, each IPv6 subnet you may see gets its own chart under the IPv4 ones, drawn from the same
snapshots: *Active addresses (IA_NA)* and *Active prefixes (IA_PD)* always, and *Temporary addresses* and the *Reserved* lines when there are any.
It shows counts only - a sentence above the charts says an IPv6 subnet has no finite pool to project against, so there is no utilization line
and no forecast. The history starts at the first snapshot after the upgrade: IPv6 counts were not recorded before then. The same retention applies
as for IPv4 (set at the bottom of the page).

---

## DDNS Status

### Reconcile (v5.47.0)

**Network → DDNS → Reconcile** checks every reservation and active lease that carries a hostname against DNS — does the name resolve to that IP, and does the IP resolve back to the name — and gives each row a verdict (`ok`, `missing-forward`, `wrong-forward`, `missing-ptr`, `wrong-ptr`, `stale-ptr`, `multiple-a`, `lookup-failed`). It is read-only and subnet-restricted; nothing is written to DNS or Kea. `lookup-failed` means the resolver could not answer — it says nothing about the record. Filter by verdict or export CSV; the admin guide has the full table.

## Configuration Doctor (v5.40.0)

**Network → Doctor** (admins with access to all subnets) reads the live Kea config and lists contradictions, unused objects and risky settings, worst first, each with what to change. It only reads. The admin guide's "Configuration Doctor" section lists every check.

## Recovery bundle (v5.44.0)

A superadmin can download one encrypted **recovery bundle** from Settings → Databases: config, keys, content and the Jen database in a single file protected by a passphrase you choose. It is for rebuilding a lost Jen host — see "Recovery Bundle" in the admin guide for the restore steps.

The DDNS Status page shows activity from the Technitium DNS update script that runs alongside Kea.

### Log Activity

The log panel shows the most recent 200 lines from the DDNS log file, newest first. Lines are color-coded:

- **Green** — successful DNS updates (new leases added)
- **Yellow** — deletions (leases expired or released)
- **Red** — errors

### Hostname Lookup

Enter a fully-qualified hostname in the lookup field and click **Lookup** to query your Technitium DNS server directly. The result shows all DNS records for that hostname including IP address, record type, and TTL.

---

## Capacity alerts that remember (v5.68.0-beta.18)

**Subnet utilization high** fires when a subnet's pools are at or above the threshold (Settings → Alerts, default 80 %) and **Subnet utilization
recovery** when they drop back; **Pool exhaustion warning** fires when the free addresses in the whole subnet are at or below the setting (default 5) and
the new **Pool exhaustion recovery** when they climb back to that number plus a margin of a fifth of it, at least 2 (7 free by default), so a subnet
hovering at the line does not flip between the two. Tick *Pool exhaustion recovery* on a channel to hear about the recovery; the existing channels keep
the types they had. Each is sent **once per episode**: before this release the exhaustion warning was repeated on every check for as long as the subnet
was low, and a Jen restart (every upgrade) re-sent every utilization and packet-health alert whose condition was still true and never sent the recovery
for one that cleared while Jen was down. Jen now remembers, in its settings, which side each condition is on, so a restart sends nothing new and a
recovery that happened while it was down is sent once when it comes back. The first check after upgrading sends the alerts for conditions that are true
at that moment once, because nothing had been recorded before.

**Delivery is part of the state (v5.68.0-beta.19).** A warning counts as sent only when at least one channel that handles it actually accepted it. If every
channel is down - or no channel handles that type yet - Jen keeps the warning pending and tries again after 1, 2, 4 ... up to 60 minutes for as long as the condition
holds, so enabling a channel later still delivers it. A recovery (*Subnet utilization recovery*, *Pool exhaustion recovery*, *Packet health recovery*) is sent only
after its warning was delivered, and a recovery that no channel accepted is itself retried (5.68.0-beta.20) with the same 1, 2, 4 ... 60 minute spacing until one does - the warning is never sent again meanwhile. One channel accepting is enough; the others are not retried. The *Pool exhaustion forecast* and *Certificate expiring* alerts use
the same rule (the forecast reminds weekly while the trend still reaches 90 %).

## Alert log retention (v5.68.0-beta.17)

**Settings → Logs → Alert Log** lists the deliveries of every alert. Each delivery is kept for 180 days after it was sent and then removed by the
same job that prunes the lease history; the page says how many days it keeps. The retention is the settings key `alert_log_retention_days`
(a whole number of days, 1 or more; anything else means 180). The total that Prometheus sees as `jen_alerts_sent_total` keeps counting what was
removed, so it never goes down.

## Audit Log

The Audit Log records every change made through Jen — who did it, when, and what changed.

### What Gets Logged

| Action | Logged when |
|---|---|
| LOGIN / LOGOUT | User signs in or out |
| ADD_RESERVATION | New reservation created |
| EDIT_RESERVATION | Reservation hostname or DNS changed |
| DELETE_RESERVATION | Reservation removed |
| RELEASE_LEASE | Lease manually released |
| DELETE_STALE | Stale leases purged |
| IMPORT_RESERVATIONS | CSV import completed |
| EXPORT_RESERVATIONS | CSV export downloaded |
| EDIT_SUBNET | Subnet configuration changed |
| ADD_USER / DELETE_USER | User account created or removed |
| CHANGE_PASSWORD | Password changed |
| UPLOAD_CERT | SSL certificate uploaded |
| SAVE_SETTINGS | Any settings page saved |
| GENERATE_SSH_KEY | SSH key pair generated |
| CLEAR_LOCKOUTS | Login attempt records cleared |

### Reading the Log

Each entry shows the timestamp, username, action type, the affected entity (usually an IP address or username), details, and the source IP address of the request.

The log is paginated — 50 entries per page.

---

## Theme (v5.56.1)

Click the palette icon in the top right navigation bar (or **Theme** in the phone's More sheet) to pick a look: Dark, Light, High contrast, Phosphor, Slate (cool blue), Ember (warm), Retro (the early-nineties desktop), or Custom once an install has defined one. Your pick is saved in your browser and persists between sessions — it never affects what anyone else sees. It's a preference of that browser, not of your Jen account: if two people share a browser, they share the pick.

At the top of the menu, **Install default (\<name\>)** switches back to whatever the install's superadmin has set as the default look (Settings → Appearance → Theme), for anyone who hasn't picked one for themselves. A checkmark shows which one is currently active — on a preset only if you've actually chosen it, on **Install default** otherwise.

---

## Device Inventory

The Device Inventory (Management → Devices) shows every MAC address ever seen on your network. Unlike the Leases page which only shows currently active leases, the Device Inventory is a persistent record that survives lease expiry.

### Device Fingerprint Badges

Jen automatically identifies devices by manufacturer and type using OUI (MAC address prefix) lookup. Identified devices show a colored badge with the manufacturer's brand logo next to their hostname — on the Device Inventory, Leases, Reservations, and Dashboard pages.

For devices using randomized MAC addresses (iOS 14+ private MACs), Jen falls back to hostname pattern matching to identify the device type.

### Filtering the Inventory

**Search** — search across MAC address, device name, owner, and IP.

**Subnet** — filter to show only devices last seen on a specific subnet.

**Device type filter bar** — click any type badge (Apple, IoT, Gaming, etc.) to filter the inventory to that device type.

**Show stale only** — show only devices that have been inactive for longer than the configured stale threshold (default 30 days). Adjust the threshold with the "Stale after N days" field in the top right.

### Editing a Device

Click the **✏** button on any device row to open the edit modal. You can set:

- **Device Name** — a friendly label (e.g. "Living Room TV", "Work Laptop")
- **Owner** — who the device belongs to
- **Device Type** — manually override the auto-detected type. Choose from Apple, Android, IoT, Gaming, etc. Manual overrides show a 🔒 indicator and dashed badge border. The background tracking loop will not overwrite manual overrides. Choose "Auto-detect" to clear the override.
- **Icon Override** — choose a specific brand logo from the visual picker, including any custom icons you've uploaded in Settings → Icons
- **Notes** — any notes about the device

### Deleting a Device

Click the **✕** button to remove a device from the inventory. It will reappear the next time it gets a lease.

### Converting to a Reservation

Click the **📌** button to pre-fill the Add Reservation form with this device's MAC, last IP, and hostname.

### IPv6 (v5.45.0)

With IPv6 enabled, a device row shows its current IPv6 address(es) in an **IPv6** column whenever Kea itself captured that device's hardware address on an IPv6 lease — Jen only ever links the two by the address Kea reports, never by guessing a MAC from a DUID. An IPv6 client that only ever sent a DUID — no hardware address at all — can't be safely matched to a device, so it appears as its own row at the bottom of the inventory, badged **DUID only**, rather than being merged into an existing one.

---

## API Keys

Jen provides a read-only REST API for integration with tools like Home Assistant, Zabbix, and custom scripts.

### Creating an API Key

Go to **Settings → API Keys** and click **Generate Key**. Give the key a descriptive name. The key is shown only once — copy it immediately. If you lose it, revoke it and generate a new one.

Keys use Bearer token authentication:
```
Authorization: Bearer jen_your_key_here
```

### API Documentation

Go to **Settings → API Docs** for full endpoint documentation with parameters, example requests, example responses, and ready-to-paste Home Assistant YAML and Zabbix HTTP agent config.

---

## MFA (Multi-Factor Authentication)

### Enrolling MFA

Go to **Profile → Security → Enable MFA**. Scan the QR code with an authenticator app (Google Authenticator, Authy, 1Password, etc.). Save your backup codes — they are shown only once and cannot be recovered.

### Passkeys (v5.31.0)

On the same page, **Add a Passkey** enrolls a passkey as your second factor — Windows Hello, Touch ID / iCloud Keychain, Android, a password manager such as 1Password, Bitwarden or Keeper, or a hardware key such as a YubiKey. Give it a name so you can tell them apart. At login you'll land on a **Passkey** tab and confirm with a fingerprint, face, PIN or touch instead of typing a code; the Authenticator and Backup Code tabs are still there. If the card says the browser can't create a passkey, the page isn't https — ask your administrator. Enrolling a passkey as your first factor also issues backup codes; keep them.

### Trusted Devices

After a successful MFA login, you can check "Trust this device for 30 days". Trusted devices skip MFA on subsequent logins from that browser. Manage trusted devices under **Profile → Security → Trusted Devices**.

### Backup Codes

If you lose access to your authenticator app, use one of your backup codes to log in. Each backup code can only be used once. After using one, go to Profile → Security to generate a fresh set.

---

## Settings → Icons

Go to **Settings → Icons** to manage the brand logos used in device fingerprint badges.

- **Bundled icons** — 24 brand logos included with Jen (Apple, Samsung, Cisco, Ubiquiti, Raspberry Pi, etc.)
- **Custom icons** — upload your own SVG to override any bundled icon or add a new manufacturer. Custom icons take priority over bundled ones and survive upgrades.

To upload a custom icon, enter an icon name (e.g. `amazon`, `mydevice`) and select an SVG file (max 100KB). The name must match the manufacturer key used in Jen's OUI database. See Settings → Icons for the list of available name keys.

---

## Mobile Access

Jen is fully usable on iPhone and iPad.

### iPhone
A tab bar along the bottom holds Dashboard, Leases, Reservations, Settings (a viewer, who has no Settings page, sees Devices there) and **More**. More opens a sheet that lists every page grouped as on desktop — Management, Network, Settings, plugins — with search, the theme picker, your account links and Logout. The top bar keeps the logo, the Kea status dot and your avatar. The section sub-tabs sit below it, scroll sideways, and start with the current page in view. Tables that have been converted show one two-line row per item; pages not yet converted still show per-row cards, so there is no horizontal scrolling either way.

### iPad
The full desktop navigation is shown. Some lower-priority columns (MAC addresses, timestamps) are hidden on narrower iPad screens to keep tables readable — they are still available on desktop.

### Double-tap
All interactive elements respond to a single tap. If you previously experienced a delay before navigation, upgrade to v2.5.7 or later.

---

## Alert Channels — ntfy and Discord

### ntfy
[ntfy](https://ntfy.sh) delivers push notifications to any device with the ntfy app installed.

To add an ntfy channel: go to **Settings → Alerts → Add Channel**, choose **ntfy**, enter your server URL (use `https://ntfy.sh` for the public server or your self-hosted URL), topic name, and optional access token and priority.

### Discord
To add a Discord channel: go to your Discord server → **Server Settings → Integrations → Webhooks → New Webhook**, copy the webhook URL, then go to **Settings → Alerts → Add Channel**, choose **Discord**, and paste the URL.

---

## Kea Servers and HA

The **Network → Servers** page shows the status of all configured Kea servers. In a High Availability setup it shows:

- Which node is currently **⚡ ACTIVE**
- The HA mode (hot-standby, load-balancing, passive-backup)
- The HA state of each node (hot-standby, syncing, partner-down, etc.)

If multiple servers are configured but HA mode is not set, the page shows a warning with a link to configure it.

Configure HA in **Settings → Infrastructure → High Availability**.

### Packet Health (v5.41.0)

Below each server's status card, the **Servers** page shows a **Packet health (last 60 min)** block — is Kea actually processing DHCP traffic cleanly, not just reachable?

- A status badge: **OK**, **Warn**, **Fail**, or **No traffic** (informational — a standby server in a hot-standby HA pair legitimately sees no traffic).
- A sparkline of packets received per snapshot.
- Rates for received / offered / acked / naked / dropped / parse-failed / allocation-failed traffic.
- A collapsed **All counters** table with every other `pkt4-*`/`v4-*` counter Kea reports — including any newer Kea version's counters Jen doesn't specifically name.

The block reads **Warn** when drops and parse failures exceed 1% of received traffic (over the trailing window) or any allocation failure occurred, and **Fail** when NAKs exceed 10% of ACKs or drops exceed 10% of received. It needs two snapshots before it can show a rate — the snapshot interval is the same one configured in **Reports → History Settings**.

A **Packet Health** alert fires once when a server's status flips to Warn or Fail, and again when it recovers — see **Alert Channels** above to configure where it's sent. The admin guide's Health Center also carries a `packet_health` row with the always-current verdict.

---

## Plugins

Bundled plugins install from **Settings → Plugins**: click **Install** next to one, Jen downloads and verifies it from its own plugin registry, and it's enabled once Jen restarts.

### Host Watchdog (v5.58.0)

Network Discovery (below) alerts when an *unknown* device shows up on a subnet; Host Watchdog is the other half — it alerts when a device you already know about stops answering, and again when it comes back.

Open **Network → Watchdog** and click **Add Target**. Pick a host already in Jen (a Kea reservation or, if IPAM Lite is installed, an IPAM entry) or type any IPv4 address directly. Choose a probe:

- **Ping (ICMP)** — works without any special privilege on the Jen host.
- **TCP connect** — one or more ports (e.g. `80,443`); any one answering counts as up. Use this for a host that doesn't respond to ping but does run a service you care about.

Set how often it's checked (1–60 minutes) and how many consecutive failed checks in a row count as "down" (1–10) — a single missed check never alerts by itself, only a genuine run of failures does. Each target's row shows its current state, when it was last seen up, a 7-day uptime percentage, and a history icon with its last 50 checks. Pause a target to stop probing it without losing its history, or delete it outright.

From **Reservations**, the row menu on any reservation offers **Watch this host** as a shortcut to add it without typing the address again.

Watchdog needs `ping` on the Jen host for ICMP targets (`iputils-ping` — Settings → Plugins offers an Install button on a systemd host) but nothing extra for TCP-only targets.

### Local DNS Sync (v5.59.0)

Kea's own DDNS integration assumes a BIND-style DNS server. If your network instead runs Pi-hole or AdGuard Home, Local DNS Sync pushes DHCP names into it so `nas.lan` resolves on the LAN without touching Kea's DDNS settings at all.

Open **Network → DNS Sync** and click **Add Target**: give it a name, pick Pi-hole or AdGuard Home, the server's URL and credentials (a Pi-hole password, or `user:pass` for AdGuard Home's admin login), a domain suffix (e.g. `lan`), which sources feed it — active leases, reservations, and IPAM Lite entries, in that order of priority when more than one names the same address — and which subnets it should watch. A target starts paused: click **Preview** to see exactly what it would add, change, or remove before anything is sent, and enable it once that looks right. A paused target can be previewed as many times as you like; it only ever goes live after you've looked.

Once enabled, a target syncs automatically a few seconds after a related lease or reservation change, and again on a 15-minute schedule regardless, so nothing is missed. Local DNS Sync only ever touches records it created itself — anything already on your DNS server that it didn't add is left alone, even if it looks unrelated to any current device. Credentials are stored encrypted and are never shown again once saved.

If your resolver is Unbound instead — which has no API to push to — each target's row offers an **Export Unbound local-data** download with the same records in Unbound's own config syntax, to include by hand.

### Switch Port Locator (v5.60.0)

Client Investigation can answer almost everything about a device except the one question that actually gets someone up from their desk: which switch port is it plugged into? Switch Port Locator polls your managed switches over SNMP and keeps track.

Open **Network → Switch Ports** and add a switch: its name, its IP or hostname, and its SNMP community string. Most non-Cisco switches (HP, Aruba ProCurve) need nothing else — pick **None** for VLAN indexing and one poll covers every VLAN. Cisco switches usually need **Cisco community@vlan** instead, with the VLAN IDs to poll listed alongside — Cisco's SNMP agent only ever shows one VLAN's table per community string, so the plugin asks for each one separately.

Every switch is polled every ten minutes. Type a MAC into the search box on the page (or use **Find switch port** from any Lease, Reservation, or Device row) to see its switch, port, alias, VLAN, and when it was last seen there. Each switch's own port table shows a live MAC count per port — a port carrying more than 8 MACs is treated as a trunk to another switch rather than somewhere a device lives, and is left out of search results accordingly; use the **Uplink** dropdown on any port to override that call by hand if the automatic count gets a particular port wrong.

When a known device's port changes — whether it moves to a different port on the same switch or to a different switch entirely — Switch Port Locator records the change, so a repeat lookup always reflects where it is now.

Switch Port Locator needs `snmpbulkwalk` on the Jen host (package `snmp` — Settings → Plugins offers an Install button on a systemd host).

### Wake & Actions (v5.61.0)

Every Lease, Reservation, and Device row gains a **Wake** action: click it, confirm the MAC it's about to wake, and Jen sends a standard Wake-on-LAN magic packet straight away — no separate tool needed to get a sleeping machine back online.

Open **Management → Wake** to see and manage a list of favourites: hosts you wake often enough to want one click from a dedicated page instead of hunting them down on Leases or Reservations. Add one by MAC address (reservations you can access appear in the picker as you type), with an optional label, an IP to help Jen work out which subnet it's on, and an optional SecureOn password for hardware that expects one. Each favourite remembers when it was last woken and by whom.

A wake packet goes out to both the target subnet's own broadcast address and the general broadcast address, which covers the common case of Jen and its targets sharing the same network; a target on a different network needs directed broadcast allowed on the router between them. Jen won't send more than one wake packet to the same MAC within five seconds, however it was triggered.

### Presence (v5.62.0)

Track a device and Jen tells the rest of your house when it comes and goes — a phone leaving for work, a laptop waking up on the desk — by publishing its online/offline state to Home Assistant, MQTT, or any HTTP endpoint that can receive one.

Nothing is published for a device you haven't explicitly tracked. Open **Management → Presence** and either use **Track a device** (pick from recent leases and devices you can access) or the **Track presence** action on any Lease or Device row. A tracked device's state comes from two places: an active Kea lease means it's online right away, and a background check every five minutes catches everything else — a device has to be missed three times in a row before Jen calls it offline, so one skipped check never flags it by mistake.

Add a sink under **Sinks** to actually receive the updates:

- **Home Assistant webhook** — the URL from a webhook-triggered automation in Home Assistant
- **MQTT** — publishes the state and a few details (IP, hostname, since when) to your own broker, with an optional Home Assistant auto-discovery message so a tracked device shows up as a device tracker with no extra setup on the Home Assistant side
- **Generic HTTP** — a plain JSON POST to any endpoint of your choosing

Each sink has a **Send test** button to confirm it's reachable before relying on it. Passwords and tokens are stored encrypted and never shown again once saved.

Every sink receives the state of every tracked device, whichever subnet it is in, so adding, pausing, testing and removing a sink is a **superadmin** action (since 5.65.5); an administrator scoped to some subnets can track devices in their own subnets but cannot configure where the updates go.

### Network Discovery (v5.30.0)

Scans a subnet with `nmap` and accounts for every live host: a Kea lease or reservation, the subnet's own infrastructure addresses, an IPAM Lite entry, a device Jen has seen, or one you marked *known*. Only a host that is none of those is *unknown*, and only an unknown host the previous scan had not seen sends a Rogue Device alert. Scans run from **Network → Discovery** or on a schedule; the results page shows the latest completed scan and says so when a newer one failed or is still running.

**Known** and **Forget** on a result row are for an administrator who can see every subnet (since 5.65.9). The known list has no subnet, so marking a host known silences its alert on every subnet; an administrator scoped to some subnets does not see the buttons and is refused if the request is made anyway. Starting a scan still needs only an administrator with access to that subnet.
