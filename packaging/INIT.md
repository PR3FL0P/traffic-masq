# Boot service integration

Host installation uses `traffic-masqd install`. Service definitions are generated
by `src/app/init/render.rs` using the checked-in `packaging/init/` templates,
from the same installation plan as both binaries,
configuration, permissions and credentials. They are embedded in the binary;
a separate checkout or external template package is not required on the target.

```sh
sudo ./traffic-masqd install
sudo ./traffic-masqd install --non-interactive --user alex --defer-password \
  --install-deps --init-system auto --start
sudo ./traffic-masqd --config /etc/traffic-masq/config.toml install \
  --non-interactive --skip-user-access --defer-password --init-system systemd --dry-run
```

The interactive defaults include autostart. Unattended installation defaults to
`auto` too, while installing dependencies and starting immediately remain opt-in.
Detection uses running-system evidence (PID 1 and runtime markers), not just the
presence of a management executable. An unrecognized init system is left alone;
explicit selection checks its required commands before applying the plan.

| Backend | Service artifact | Boot registration | Runtime control |
| --- | --- | --- | --- |
| systemd | `/etc/systemd/system/traffic-masqd.service` | `systemctl enable traffic-masqd.service` | `systemctl start/stop traffic-masqd.service` |
| OpenRC | `/etc/init.d/traffic-masqd` | `rc-update add traffic-masqd default` | `rc-service traffic-masqd start/stop` |
| runit | `/etc/sv/traffic-masqd/run` and `check` | Link in the selected runsvdir scan directory | `sv -w 60 start/stop /etc/sv/traffic-masqd` |
| SysVinit | `/etc/init.d/traffic-masqd` | `update-rc.d` or `chkconfig` | `/etc/init.d/traffic-masqd start/stop` |

A shared `/etc/traffic-masq/service-run` launcher contains the installed binary
path and the explicitly resolved configuration path. Shell quoting preserves
spaces and metacharacters; control characters and non-UTF-8 paths are rejected.
Native service formats never interpolate arbitrary configuration paths.

Systemd and runit execute the foreground `run` command. Systemd restarts on
failure and gives the main daemon a graceful stop interval. Its deliberate
`KillMode=process` matches the application's `preserve_interfaces` policy, which
keeps Wi-Fi workers alive for adoption across daemon stops. `restore_interfaces`
asks the daemon to stop its workers itself. Killing the entire cgroup would
silently override this policy and interrupt Wi-Fi during an update. OpenRC and SysVinit call the daemon's private
direct start/stop paths, preserving its single locked PID file and API readiness
protocol without recursively calling their own init scripts. This also avoids
matching an exec-replaced shell launcher as if it were the daemon executable. OpenRC and SysVinit do not promise crash respawn.
No backend waits for network-online: traffic-masq may itself provide the network.

## Runtime and reboot

Normal `traffic-masqd --config PATH start/stop` routes through the recorded manager.
Stopping a runit-managed daemon requests supervisor shutdown of the service,
rather than merely signalling a PID which the supervisor would then restart.
With no matching registration, the original detached-process control remains.
`run` always stays a foreground command. `status` checks the daemon lock and API;
a manager accepting `start` alone is not reported as API readiness.

Runit's activation link starts the service as well as enabling it. Its install
therefore requires `--start`. The installer releases its daemon lock before
creating the link and waits for runsv to discover it. Scan directories are
searched as `/var/service`, `/service`, `/etc/service`; use
`--runit-service-dir PATH` for another existing, actively watched directory.
A user-provided `down` file is rejected because it would defeat boot autostart.

The daemon recreates its API runtime directory, group and `0750` permissions at
startup, including after `/run` is cleared. The socket remains `0660`. Group
access requires a dedicated directory, such as `/run/traffic-masq`, rather than
changing the permissions of a shared directory such as `/run` itself.

## Ownership, updates and removal

`/etc/traffic-masq/service-install.json` is a private `0600` installation receipt.
It records the backend, executable, configuration, exact generated files and
runit scan directory. Files with no ownership record, modified files and symlink
file targets are not overwritten or deleted. Vendor systemd units are not
silently shadowed. A separate installation lock serializes install/uninstall;
the daemon process lock still protects replacement of running binaries.

Updates require stopping the daemon first. They preserve the recorded backend
and regenerate definitions using the same configuration and prefix. The installer
quiesces the previous manager before taking the daemon lock, then enables the
prepared service after configuration and credentials are ready. `--init-system
none` removes this registration and leaves manual control. Changing backend,
prefix or configuration path requires uninstalling the old registration first;
this avoids leaving two services controlling the same daemon.

```sh
sudo traffic-masqd --config /etc/traffic-masq/config.toml stop
sudo ./traffic-masqd install
sudo traffic-masqd --config /etc/traffic-masq/config.toml uninstall --dry-run
sudo traffic-masqd --config /etc/traffic-masq/config.toml uninstall --yes
```

Uninstall verifies ownership, disables boot activation and stops the manager,
waits for the daemon lock to be released, removes owned service files and then
the binaries. Configuration, passwords, network state, group memberships and
packages are preserved. Runit's supervisor is shut down; its generated runtime
files are not recursively deleted. Custom prefixes/configuration paths must
match the receipt and be supplied when uninstalling.

Installation is not a system-wide transaction. A receipt is written before
service files; during upgrades it temporarily records both previous and new
contents. A failed write or manager command therefore leaves enough information
to retry or uninstall without adopting foreign files. Native command failures
and timeouts are surfaced. Package changes and completed installation steps are
not rolled back. Inspect the native manager and logs after a startup timeout;
boot registration may already be enabled.

## Validation scope and references

Tests use temporary filesystem roots and injected command runners to exercise
all four adapters, ownership, retries, enable failure, quoting, shell syntax,
configuration matching, and mutation locks without changing the host. An
additional opt-in test uses real `runsv` and `sv` with a temporary sleep workload:

```sh
cargo test --lib real_runit_stops_service_and_supervisor_before_removing_files -- --ignored
```

This test passed in the development environment, along with `cargo check
--all-targets`, the library suite (832 passed, 2 ignored), and
`sh packaging/smoke-test.sh`. Actual boot and shutdown still require testing on
each target distribution. s6, dinit,
Upstart and non-Linux systems are not claimed as supported adapters.

Native semantics follow the upstream [systemd service documentation](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml),
[OpenRC service guide](https://github.com/OpenRC/openrc/blob/master/service-script-guide.md),
[runit sv manual](https://smarden.org/runit/sv.8), and
[Debian update-rc.d manual](https://manpages.debian.org/bookworm/init-system-helpers/update-rc.d.8.en.html).
