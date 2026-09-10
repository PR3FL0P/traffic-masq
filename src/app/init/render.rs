//! Native service descriptions. Paths with user input occur only in a quoted
//! shell launcher, never in a systemd directive or an OpenRC argument string.
use std::path::Path;

use super::{Artifact, Backend, Registration};

pub const LAUNCHER: &str = "/etc/traffic-masq/service-run";
pub const UNIT: &str = "/etc/systemd/system/traffic-masqd.service";
pub const INIT_SCRIPT: &str = "/etc/init.d/traffic-masqd";
pub const RUNIT_DIR: &str = "/etc/sv/traffic-masqd";

pub fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

pub fn artifacts(registration: &Registration) -> Vec<Artifact> {
    let mut files = vec![Artifact::new(LAUNCHER, format!(
        "#!/bin/sh\n# Managed by traffic-masqd install.\nset -eu\numask 027\nexec {} --config {} \"$@\"\n",
        shell_quote(&registration.daemon), shell_quote(&registration.config),
    ), 0o755)];
    let template = |source: &str| source.replace("@LAUNCHER@", LAUNCHER);
    match registration.backend {
        Backend::Systemd => files.push(Artifact::new(
            UNIT,
            template(include_str!("../../../packaging/init/systemd.service")),
            0o644,
        )),
        // Reuse the daemon's PID lock and readiness protocol. Matching an
        // exec-replaced shell launcher with start-stop-daemon is unreliable.
        Backend::Openrc => files.push(Artifact::new(
            INIT_SCRIPT,
            template(include_str!("../../../packaging/init/openrc")),
            0o755,
        )),
        Backend::Runit => {
            files.push(Artifact::new(
                format!("{RUNIT_DIR}/run"),
                template(include_str!("../../../packaging/init/runit-run")),
                0o755,
            ));
            files.push(Artifact::new(
                format!("{RUNIT_DIR}/check"),
                template(include_str!("../../../packaging/init/runit-check")),
                0o755,
            ));
        }
        Backend::Sysv => files.push(Artifact::new(
            INIT_SCRIPT,
            template(include_str!("../../../packaging/init/sysv")),
            0o755,
        )),
    }
    files
}
