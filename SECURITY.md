# Security

Send vulnerability reports to `prefl0p@proton.me`. Include the commit,
configuration, steps to reproduce the problem and its likely impact. Remove
passwords, session tokens, private keys and unrelated host details before
sending a report or opening an issue.

The project is under development. There is no maintained stable release series
or guaranteed response time yet.

## Access

The daemon runs as root. File permissions control access to its Unix socket,
and API changes require an administrator session. Only a local root connection
can set the initial password. Optional remote access uses TLS; restrict who can
reach the API before exposing it to an untrusted network.

The daemon records which network resources it owns. Existing addresses, routes,
firewall objects and processes must not be adopted or deleted without an
ownership record.

## Rollback and recovery

The daemon runs the confirmation timer. Disconnecting the client does not stop
an accepted operation. On normal shutdown, the daemon waits for those operations
before cleaning up pending changes.

Router transactions save a private snapshot before making changes. After a
restart, the daemon restores an uncommitted snapshot unless a matching commit
token was saved atomically. A corrupt journal or failed restore stops startup
and leaves the record available for diagnosis.

State schema version 3 can read version 2 records. Older binaries cannot read
newly saved version 3 records, so back up state before upgrading. If recovery
fails, keep `router-transaction.json` and the state directory. Deleting them to
get past the error also removes information needed for recovery.

Interface changes save snapshots too. Startup restores unconfirmed changes,
including changes to previously unmanaged interfaces, before applying committed
configuration.

Standalone DHCP, Wi-Fi and VPN operations do not use the confirmation timer.
Their persistent effects are protected by write-ahead ownership records: DHCP
leases record the route policy under which they were applied, Wi-Fi daemon
records are namespaced by process kind and written before launch, and WireGuard
activation records a launch marker before link configuration. Startup recovery
compares those proofs with committed intent and refuses to delete state whose
ownership cannot be verified. Legacy Wi-Fi AP/client ownership files are
validated by their recorded config path before migration into separate `wifi/ap`
and `wifi/client` namespaces.

Rollback cannot run while the daemon is stopped or killed; recovery resumes
when it starts again. Test recovery on the kernel, init system and hardware you
plan to use.
