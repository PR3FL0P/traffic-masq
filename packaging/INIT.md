# Boot service integration

`traffic-masqd install` installs the binaries and sets up the boot service.
Service templates live in `packaging/init/` and are embedded in the daemon;
`src/app/init/render.rs` fills them from the installation plan. The target
machine does not need a source checkout.

```sh
sudo ./traffic-masqd install
sudo ./traffic-masqd install --non-interactive --user alex --defer-password \
  --install-deps --init-system auto --start
sudo ./traffic-masqd --config /etc/traffic-masq/config.toml install \
  --non-interactive --skip-user-access --defer-password --init-system systemd --dry-run
```

Both interactive and unattended installation default to `--init-system auto`,
which enables boot autostart when it recognizes the running init system.
Unattended installation needs `--install-deps` to install packages and `--start`
to start the daemon immediately.

Detection checks PID 1 and runtime markers. If detection fails, startup stays
manual. You can select a backend explicitly; the installer checks its required
commands before making changes.

| Backend | Service artifact | Boot registration | Runtime control |
| --- | --- | --- | --- |
| systemd | `/etc/systemd/system/traffic-masqd.service` | `systemctl enable traffic-masqd.service` | `systemctl start/stop traffic-masqd.service` |
| OpenRC | `/etc/init.d/traffic-masqd` | `rc-update add traffic-masqd default` | `rc-service traffic-masqd start/stop` |
| runit | `/etc/sv/traffic-masqd/run` and `check` | Link in the selected runsvdir scan directory | `sv -w 60 start/stop /etc/sv/traffic-masqd` |
| SysVinit | `/etc/init.d/traffic-masqd` | `update-rc.d` or `chkconfig` | `/etc/init.d/traffic-masqd start/stop` |

`/etc/traffic-masq/service-run` holds the installed binary and configuration
paths. The launcher quotes spaces and shell metacharacters. Control characters
and non-UTF-8 paths are rejected.

Systemd and runit use the foreground `run` command. Systemd restarts the daemon
on failure and allows time for a graceful stop. Its `KillMode=process` lets
`preserve_interfaces` keep Wi-Fi workers alive across daemon restarts. With
`restore_interfaces`, the daemon stops those workers itself.

OpenRC and SysVinit use the daemon's internal start/stop commands. These share
its PID lock and API readiness check, without calling back into the init script
or mistaking the shell launcher for the daemon. Neither backend restarts the
daemon after a crash.

No backend waits for network-online: traffic-masq may be providing the network.

## Runtime and reboot

`traffic-masqd --config PATH start/stop` uses the registered service manager.
For runit, stopping also tells the supervisor to keep the service down. Without
a matching registration, these commands control the daemon directly.

`run` always runs in the foreground. `status` checks both the daemon lock and
the API; a successful manager command alone does not mean the daemon is ready.

Runit's activation link starts the service as well as enabling it. Its install
therefore requires `--start`. The installer releases its daemon lock before
creating the link and waits for runsv to discover it. Scan directories are
searched as `/var/service`, `/service`, `/etc/service`; use
`--runit-service-dir PATH` for another existing, actively watched directory.
The installer rejects a user-provided `down` file because it prevents autostart.

The daemon recreates its API runtime directory, group and `0750` permissions at
startup, including after `/run` is cleared. The socket remains `0660`. Group
access requires a dedicated directory, such as `/run/traffic-masq`, rather than
changing the permissions of a shared directory such as `/run` itself.

## Ownership, updates and removal

`/etc/traffic-masq/service-install.json` is a private `0600` installation receipt.
It records the backend, executable, configuration, generated file contents and
runit scan directory. The installer leaves unrecorded files, modified files
and symlink targets alone, and refuses to shadow vendor systemd units. An
installation lock prevents concurrent installs and uninstalls. The daemon's
process lock prevents replacement of running binaries.

Updates require stopping the daemon first. They preserve the recorded backend
and regenerate service files with the same configuration and prefix. Before
taking the daemon lock, the installer prevents the old service manager from
starting the daemon. It enables the service again once configuration and
credentials are ready. `--init-system none` removes the registration and leaves
manual control. Changing backend,
prefix or configuration path requires uninstalling the old registration first;
this avoids leaving two services controlling the same daemon.

```sh
sudo ./packaging/update.sh
# For binaries downloaded by gitcompile.sh:
sudo ./packaging/update.sh --binary-dir ./binaries
# From the root of an extracted release archive containing both binaries:
sudo ./packaging/update.sh --binary-dir .
sudo traffic-masqd --config /etc/traffic-masq/config.toml uninstall --dry-run
sudo traffic-masqd --config /etc/traffic-masq/config.toml uninstall --yes
```

`packaging/update.sh` uses prepared binaries from the project's `target/release`
directory by default, regardless of the working directory. Explicit
`--binary-dir` paths are relative to the working directory. The script does not
build, download or pull source code. It checks both executables and validates the
existing configuration before stopping the installed daemon, then delegates to
`traffic-masqd install --non-interactive --skip-user-access --defer-password --start`.
The installer preserves the recorded service backend, saved settings, existing
password and group memberships, and waits for daemon readiness after startup.
Stopping follows the configured shutdown policy and may interrupt connectivity.
Use `--prefix PATH` and `--config PATH` for a custom installation.
`--dry-run` validates inputs and describes the steps without stopping or installing;
the full native installation plan, including service ownership checks, is checked
after stopping. `--no-start` leaves the daemon stopped; runit does not support this
option because enabling its service starts it. If installation fails, inspect
the reported completed steps and retry; the wrapper does not attempt rollback
of a potentially partial installation.

Uninstall verifies ownership, disables boot activation and stops the manager,
waits for the daemon lock to be released, removes owned service files and then
the binaries. Configuration, passwords, persistent network intent, group memberships and
packages are preserved. Runtime cleanup follows the configured shutdown policy;
uninstall does not reset saved settings. Use [reset](../docs/usage.md#reset-all-settings)
for that separate operation. Runit's supervisor is shut down; its generated runtime
files are not recursively deleted. Custom prefixes/configuration paths must
match the receipt and be supplied when uninstalling.

A failed installation can leave completed steps in place. Package changes and
service operations are not rolled back. The installer writes its receipt before
service files; during an upgrade, it records both old and new contents so a
retry or uninstall can recognize either version.

Command failures and timeouts are reported. After a startup timeout, check the
service manager and daemon logs: boot autostart may already be enabled.

## Validation scope and references

Automated tests use temporary directories and substitute command runners. They
check all four backends, file ownership, retries, enable failures, quoting,
shell syntax, configuration matching and locks without changing host services.
An optional test runs real `runsv` and `sv` with a temporary sleep process:

```sh
cargo test --lib real_runit_stops_service_and_supervisor_before_removing_files -- --ignored
```

Boot and shutdown still need testing on each target distribution. There are
no adapters for s6, dinit, Upstart or non-Linux systems.

For service-manager behavior, see the [systemd service documentation](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml),
[OpenRC service guide](https://github.com/OpenRC/openrc/blob/master/service-script-guide.md),
[runit sv manual](https://smarden.org/runit/sv.8), and
[Debian update-rc.d manual](https://manpages.debian.org/bookworm/init-system-helpers/update-rc.d.8.en.html).

For archive contents, checksum verification and CI build behavior, see the
[release procedure](../docs/release.md).
