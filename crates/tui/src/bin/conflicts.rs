//! Standalone read-only preflight; the same report is used by the installer.

pub async fn run(interfaces: &[String], json: bool) -> anyhow::Result<i32> {
    let report = traffic_masq_host_observation::scan_conflicts(interfaces).await;
    if json {
        let mut output = serde_json::to_value(&report)?;
        output["remediation"] = serde_json::to_value(report.remediation())?;
        output["exit_code"] = report.exit_code().into();
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("{}", report.render());
    }
    Ok(report.exit_code())
}
