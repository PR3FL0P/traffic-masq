use std::net::Ipv4Addr;

use crossterm::event::KeyCode;
use ipnet::Ipv4Net;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Gauge, Paragraph, Row, Table};

use crate::tui::api::client::ApiClient;
use crate::tui::api::model::{Request, Response, RouterErrorDetail, RouterRecoveryNotice};
use traffic_masq_protocol::DhcpServiceView;
use traffic_masq_protocol::RecoveryAction;
use traffic_masq_protocol::{CoordinatorStatus, RouterHealthReport};
use traffic_masq_protocol::{
    InterfaceRole, OwnedIpv4RouteConfigView as OwnedIpv4RouteConfig,
    RouterConfigView as RouterConfig, RouterProposalRequestView as RouterProposalRequest,
};
use traffic_masq_protocol::{RouteOwnerView as RouteOwner, RouteStatusView as RouteStatus};
use traffic_masq_protocol::{
    RouterDataplaneTargetView, RouterDesiredView, RouterInterfaceDesiredView, RouterPlanView,
};

use super::layout::panel;
use super::logs::LogLevel;
use super::router_topology;
use super::theme;
use super::{current_unix_time, Screen, TuiApp};

mod controller;
mod editor;
mod pending;
mod plan;
mod view;

// Keep router's external surface stable while implementation is split by responsibility.
pub(crate) use controller::{
    focus_action, handle_router_key, load_router_data, refresh_router_data, refresh_router_status,
};
pub(crate) use editor::{focus_route_editor_action, handle_route_editor_key, render_route_editor};
pub(crate) use pending::{
    handle_router_pending_key, refresh_router_pending_screen, render_router_pending,
};
pub(crate) use plan::{handle_router_plan_key, open_router_plan, render_router_plan};
pub(crate) use view::render_router;

// Internal cross-module helpers are re-exported only within the router module tree.
use editor::{delete_selected_route, open_route_editor_for_add, open_route_editor_for_selected};
use view::{
    describe_router_error, format_forwarding_status, recovery_notice_text, summarize_uplink,
};

#[derive(Debug, Default, Clone)]
pub(crate) struct RouterData {
    pub(crate) desired_revision: Option<u64>,
    pub(crate) last_applied_revision: Option<u64>,
    pub(crate) editor_revision: Option<u64>,
    pub(crate) saved_router_config: Option<RouterConfig>,
    pub(crate) route_inventory: Option<Vec<traffic_masq_protocol::RouteInventoryEntry>>,
    pub(crate) saved_device_readiness: Option<traffic_masq_protocol::InterfaceReadiness>,
    pub(crate) observation_error: Option<String>,
    pub(crate) saved_interfaces: Vec<traffic_masq_protocol::InterfaceInventoryEntry>,
    pub(crate) offline_preview: Option<OfflineRouterPreview>,
    pub(crate) enabled: bool,
    pub(crate) ready: bool,
    pub(crate) coordinator_status: Option<CoordinatorStatus>,
    pub(crate) recovery: Option<RouterRecoveryNotice>,
    pub(crate) health: RouterHealthReport,
    pub(crate) routes: Vec<RouteStatus>,
    pub(crate) selected_route: usize,
    pub(crate) proposed_router_config: RouterConfig,
    pub(crate) staged: bool,
    pub(crate) plan: Option<RouterPlanView>,
    pub(crate) plan_scroll: usize,
    pub(crate) plan_max_scroll: usize,
    pub(crate) editor: Option<RouteEditor>,
    pub(crate) focus: RouterFocus,
    pub(crate) action: RouterAction,
    pub(crate) lease_counts: Vec<(String, usize)>,
    pub(crate) error: Option<RouterErrorDetail>,
    pub(crate) warning_message: Option<String>,
    pub(crate) topology: router_topology::TopologyView,
    pub(crate) pane: RouterPane,
    pub(crate) pane_tabs: Vec<(Rect, RouterPane)>,
    pub(crate) selected_connection: usize,
    pub(crate) sharing_action: usize,
    pub(crate) sharing_actions_focused: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct OfflineRouterPreview {
    pub(crate) baseline: RouterConfig,
    pub(crate) config: RouterConfig,
    pub(crate) revision: u64,
    pub(crate) blockers: Vec<traffic_masq_protocol::InterfaceReadinessBlocker>,
}

pub(super) fn row_config(
    row: &traffic_masq_protocol::RouteInventoryEntry,
) -> Option<OwnedIpv4RouteConfig> {
    row.configured.clone().or_else(|| {
        row.observed.as_ref().map(|route| OwnedIpv4RouteConfig {
            destination: route.destination,
            gateway: route.gateway,
            output_interface: route.output_interface.clone(),
            table: route.table,
            metric: route.metric,
        })
    })
}

impl RouterData {
    pub(crate) fn route_rows(&self) -> Vec<traffic_masq_protocol::RouteInventoryEntry> {
        use traffic_masq_protocol::RouteInventoryEntry;
        let Some(inventory) = &self.route_inventory else {
            return self
                .routes
                .iter()
                .map(|route| RouteInventoryEntry {
                    configured: route.owner.is_editable().then(|| OwnedIpv4RouteConfig {
                        destination: route.destination,
                        gateway: route.gateway,
                        output_interface: route.output_interface.clone(),
                        table: route.table,
                        metric: route.metric,
                    }),
                    observed: Some(route.clone()),
                    output_presence: None,
                })
                .collect();
        };
        let mut rows: Vec<_> = inventory
            .iter()
            .filter(|row| row_config(row).is_some())
            .filter(|row| {
                !self.staged
                    || row.configured.as_ref().is_none_or(|config| {
                        self.proposed_router_config.owned_routes.contains(config)
                    })
            })
            .cloned()
            .collect();
        if self.staged {
            for config in &self.proposed_router_config.owned_routes {
                if !rows
                    .iter()
                    .any(|row| row.configured.as_ref() == Some(config))
                {
                    let presence = config.output_interface.as_ref().map(|name| {
                        self.saved_interfaces
                            .iter()
                            .find(|entry| entry.name == *name)
                            .map_or(traffic_masq_protocol::InterfacePresence::Unknown, |entry| {
                                entry.presence
                            })
                    });
                    rows.push(RouteInventoryEntry {
                        configured: Some(config.clone()),
                        observed: None,
                        output_presence: presence,
                    });
                }
            }
        }
        rows
    }

    pub(crate) fn recovery_blocks_mutations(&self) -> bool {
        self.recovery.is_some()
            || matches!(
                self.coordinator_status,
                Some(
                    CoordinatorStatus::RollbackFailed
                        | CoordinatorStatus::RecoveryRequired
                        | CoordinatorStatus::CommitIndeterminate
                        | CoordinatorStatus::RecoveredButJournalCleanupPending
                )
            )
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouterPane {
    #[default]
    Routes,
    Sharing,
    Topology,
}

pub(crate) fn select_pane(app: &mut TuiApp, pane: RouterPane) {
    app.router.pane = pane;
    app.router.focus = RouterFocus::RouteTable;
    app.router.sharing_actions_focused = false;
    if pane == RouterPane::Topology {
        app.router.topology.show();
    } else {
        app.router.topology.open = false;
    }
    app.ui.buttons.clear();
    app.ui.list_area = None;
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouterFocus {
    #[default]
    RouteTable,
    Actions,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouterAction {
    #[default]
    AddRoute,
    EditRoute,
    DeleteRoute,
    PlanApply,
    ShareViaRoute,
    Refresh,
    Topology,
    Setup,
    Settings,
}

impl RouterAction {
    pub(crate) fn next(self) -> Self {
        match self {
            Self::AddRoute => Self::EditRoute,
            Self::EditRoute => Self::DeleteRoute,
            Self::DeleteRoute => Self::PlanApply,
            Self::PlanApply => Self::ShareViaRoute,
            Self::ShareViaRoute => Self::Refresh,
            Self::Refresh => Self::Topology,
            Self::Topology => Self::Setup,
            Self::Setup => Self::Settings,
            Self::Settings => Self::AddRoute,
        }
    }

    pub(crate) fn prev(self) -> Self {
        match self {
            Self::AddRoute => Self::Settings,
            Self::Settings => Self::Setup,
            Self::Setup => Self::Topology,
            Self::EditRoute => Self::AddRoute,
            Self::DeleteRoute => Self::EditRoute,
            Self::PlanApply => Self::DeleteRoute,
            Self::ShareViaRoute => Self::PlanApply,
            Self::Refresh => Self::ShareViaRoute,
            Self::Topology => Self::Refresh,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteEditorField {
    #[default]
    Destination,
    Gateway,
    OutputInterface,
    Metric,
    Table,
    AllowDefaultRouteChange,
    Save,
}

impl RouteEditorField {
    pub(crate) fn next(self) -> Self {
        match self {
            Self::Destination => Self::Gateway,
            Self::Gateway => Self::OutputInterface,
            Self::OutputInterface => Self::Metric,
            Self::Metric => Self::Table,
            Self::Table => Self::AllowDefaultRouteChange,
            Self::AllowDefaultRouteChange => Self::Save,
            Self::Save => Self::Destination,
        }
    }

    pub(crate) fn prev(self) -> Self {
        match self {
            Self::Destination => Self::Save,
            Self::Gateway => Self::Destination,
            Self::OutputInterface => Self::Gateway,
            Self::Metric => Self::OutputInterface,
            Self::Table => Self::Metric,
            Self::AllowDefaultRouteChange => Self::Table,
            Self::Save => Self::AllowDefaultRouteChange,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RouteEditor {
    pub(crate) original_route: Option<OwnedIpv4RouteConfig>,
    pub(crate) destination: String,
    pub(crate) gateway: String,
    pub(crate) output_interface: Option<String>,
    pub(crate) metric: String,
    pub(crate) table: String,
    pub(crate) allow_default_route_change: bool,
    pub(crate) field: RouteEditorField,
    pub(crate) cursor: usize,
    pub(crate) available_interfaces: Vec<String>,
}

impl RouteEditor {
    pub(crate) fn reset_cursor(&mut self) {
        self.cursor = match self.field {
            RouteEditorField::Destination => super::input::grapheme_count(&self.destination),
            RouteEditorField::Gateway => super::input::grapheme_count(&self.gateway),
            RouteEditorField::Metric => super::input::grapheme_count(&self.metric),
            RouteEditorField::Table => super::input::grapheme_count(&self.table),
            _ => 0,
        };
    }

    pub(crate) fn active_editor(&mut self) -> Option<super::input::TextEditor<'_>> {
        let cursor = &mut self.cursor;
        match self.field {
            RouteEditorField::Destination => {
                Some(super::input::TextEditor::new(&mut self.destination, cursor))
            }
            RouteEditorField::Gateway => {
                Some(super::input::TextEditor::new(&mut self.gateway, cursor))
            }
            RouteEditorField::Metric => {
                Some(super::input::TextEditor::new(&mut self.metric, cursor))
            }
            RouteEditorField::Table => Some(super::input::TextEditor::new(&mut self.table, cursor)),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RouterPendingView {
    pub(crate) token: String,
    pub(crate) applied_at_unix: u64,
    pub(crate) rollback_failure: Option<Vec<String>>,
    pub(crate) recovery: Option<RouterRecoveryNotice>,
    pub(crate) scroll: usize,
    pub(crate) max_scroll: usize,
}

impl RouterPendingView {
    pub(crate) fn commit_indeterminate(&self) -> bool {
        self.recovery
            .as_ref()
            .is_some_and(|notice| notice.invariant == "commit_indeterminate")
    }

    pub(crate) fn recovery_required(&self) -> bool {
        self.recovery.is_some() || self.rollback_failure.is_some()
    }
}

const ROUTER_APPLY_LABEL: &str = "[Apply temporarily] (Enter)";
const ROUTER_CANCEL_LABEL: &str = "[Cancel] return without applying (Esc)";

#[cfg(test)]
mod tests;
