//! Standalone process scan for the `traffic-masq --check-conflicts` command.

use traffic_masq_host_observation::find_competing_network_managers;

pub async fn run() {
    let managers = find_competing_network_managers().await;
    if managers.is_empty() {
        println!("No competing network managers detected.");
    } else {
        println!("Detected competing network manager(s) that may control wireless interfaces:");
        println!(
            "{}",
            traffic_masq_host_observation::format_competing_manager_advice(
                &managers,
                "<interface>"
            )
        );
    }
}
