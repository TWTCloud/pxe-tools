# Native nginx dependency ownership (#61)

The signed package depends on nginx for its two dedicated instances. On Zorin,
APT also configured the distribution's generic nginx service and welcome site.
That service kept TCP80 and prevented boot HTTP from starting after setup.

## Approach

Reconcile the generic service in the core package's `postinst`, after dependencies
are configured and before resuming application services. Dependency configuration
may already have started nginx: a core `preinst` cannot reliably prevent that.
Do not install a global policy-rc.d, divert nginx, or change distribution files.

Automatic reconciliation requires positive package-manager provenance: nginx was
automatically installed in the same initial APT transaction as PXE Tools, plus
dpkg evidence that nginx was previously absent. Verify the full active stock
configuration, package conffile hashes, enabled default link, unmodified welcome
page, unit identity and process ownership again before stopping/disabling only
`nginx.service`. Missing/rotated/ambiguous evidence preserves the service and
prints an actionable conflict explanation. Existing stopped/disabled/masked
states remain untouched. No application/PXE/DHCP service is started by this helper.

An explicit root command may repair a verified stock service after confirmation
when historical provenance is unavailable. It must still refuse custom sites,
includes, web content, unit overrides, concurrent configuration/process changes
or unverifiable state. The existing onboarding conflict diagnostic remains real;
no warning is hidden. Preserve the generic package, configuration and content.

The same helper applies to fresh installs, affected upgrades and reinstallations.
Restoring a stopped service when disable fails is bounded by the original state;
report failure rather than pretending port80 is available. A successful result
is idempotent and does not reverse a later administrator choice.

## Validation and boundaries

An open APT history record must belong to the running APT/dpkg ancestor chain
of this postinst, not merely have a recent date. Current package status and
dpkg installation/configuration events supplement the planned APT entries.
Before changing a service, also verify its packaged unit, master command,
listening sockets and that the stock resources have not changed since startup.

The private ownership journal is
`/var/lib/pxe-tools-nginx-ownership/state.json` (root0600, parent0700).
This directory is separate from the native runtime: creating that runtime
before `configure-secure-tftp.py` would invalidate the first-install guard.
Format1 records the service, `before`/`after` active/enabled states, stock resource
hashes/timestamps, process identity and provenance. `phase=prepared` is durable
before mutation; `phase=complete` certifies both transitions. An incomplete
journal needs examination; a later administrator choice must not be reversed.
Removal tools must revalidate current resources/states against this record.

Regression first on the existing PR CI: real filesystem/package/log fixtures,
deterministic systemd/dpkg boundaries, fresh dependency activation, affected
upgrade, custom/preexisting nginx, intentional inactive states, idempotence and
failures/races. No local build/test or workflow changes. Existing CI uses a
Debian13 container rather than a real systemd boot; a clean native transaction
and reboot on supported distributions remain a separately authorized lab receipt.

Do not change the release manifest/version or publish a new package. The local
Zorin repair and Ansible playbook work are separate from this code delivery.
