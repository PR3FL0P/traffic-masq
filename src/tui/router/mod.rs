use std::net::Ipv4Addr;

use crossterm::event::KeyCode;
use ipnet::Ipv4Net;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Gauge, Paragraph, Row, Table};

use crate::api::client::ApiClient;
use crate::api::model::{Request, Response, RouteStatus, RouterErrorDetail, RouterProposalRequest};
use crate::config::{InterfaceRole, OwnedIpv4RouteConfig, RouterConfig};
use crate::core::router::{RouterDesired, RouterHealthReport, RouterInterfaceDesired, RouterPlan};
use crate::core::router_transaction::CoordinatorStatus;
use crate::dhcp::supervisor::DhcpServiceSpec;
use crate::firewall::RouterDataplaneTarget;
use crate::netlink::RouteOwner;

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
pub(crate) use controller::{focus_action, handle_router_key, load_router_data, refresh_router_data};
pub(crate) use pending::{
    handle_router_pending_key, refresh_router_pending_screen, render_router_pending,
};
pub(crate) use plan::{handle_router_plan_key, open_router_plan, render_router_plan};
pub(crate) use editor::{focus_route_editor_action, handle_route_editor_key, render_route_editor};
pub(crate) use view::render_router;

// Internal cross-module helpers are re-exported only within the router module tree.
use editor::{
    delete_selected_route, open_route_editor_for_add, open_route_editor_for_selected,
};
use view::{describe_router_error, format_forwarding_status, summarize_uplink};

#[derive(Debug, Default, Clone)]
pub(crate) struct RouterData {
    pub(crate) enabled: bool,
    pub(crate) ready: bool,
    pub(crate) coordinator_status: Option<CoordinatorStatus>,
    pub(crate) health: RouterHealthReport,
    pub(crate) routes: Vec<RouteStatus>,
    pub(crate) selected_route: usize,
    pub(crate) proposed_router_config: RouterConfig,
    pub(crate) staged: bool,
    pub(crate) plan: Option<RouterPlan>,
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
            Self::Topology => Self::AddRoute,
        }
    }

    pub(crate) fn prev(self) -> Self {
        match self {
            Self::AddRoute => Self::Topology,
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
    #[allow(dead_code)]
    pub(crate) plan: RouterPlan,
    pub(crate) applied_at_unix: u64,
    pub(crate) rollback_failure: Option<Vec<String>>,
    pub(crate) scroll: usize,
    pub(crate) max_scroll: usize,
}

const ROUTER_APPLY_LABEL: &str = "[Apply]  apply changes (Enter)";
const ROUTER_CANCEL_LABEL: &str = "[Cancel] return without applying (Esc)";

#[cfg(test)]
mod tests;
