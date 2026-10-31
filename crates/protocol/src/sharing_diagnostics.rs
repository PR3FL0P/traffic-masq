//! On-demand observations, not an end-to-end client connectivity guarantee.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharingDiagnostics {
    pub from: String,
    pub to: String,
    pub captured_at_unix: u64,
    pub sections: Vec<SharingDiagnosticSection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharingDiagnosticSection {
    pub title: String,
    pub detail: String,
}

#[cfg(test)]
mod tests {
    use crate::{ControlRequest, MutationKind};

    #[test]
    fn diagnostics_require_admin_but_do_not_acquire_network_mutation_gates() {
        let request = ControlRequest::SharingDiagnostics {
            from: "ap0".into(),
            to: "wan0".into(),
        };
        let policy = request.policy();
        assert!(policy.administrator);
        assert_eq!(policy.mutation, MutationKind::ReadOnly);
        assert!(!policy.needs_admission());
        assert!(!policy.needs_execution());
        assert!(policy.long_running);
        let encoded = serde_json::to_string(&request).unwrap();
        assert!(
            matches!(serde_json::from_str::<ControlRequest>(&encoded).unwrap(), ControlRequest::SharingDiagnostics { from, to } if from == "ap0" && to == "wan0")
        );
    }
}
