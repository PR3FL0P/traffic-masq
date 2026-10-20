//! DNAT and narrowly scoped conntrack permissions, included in the owned atomic batch.
use crate::{owned_object, string_field, PortForwardConfig, RouterDataplaneDesired};
use ipnet::Ipv4Net;
use serde_json::{json, Value};
use std::collections::BTreeSet;

#[derive(Default)]
struct Rule {
    text: String,
    expr: Vec<Value>,
}
impl Rule {
    fn term(&mut self, text: impl AsRef<str>, expr: Value) {
        self.text.push_str(text.as_ref());
        self.text.push(' ');
        self.expr.push(expr);
    }
    fn matched(&mut self, text: impl AsRef<str>, left: Value, right: Value) {
        self.term(
            text,
            json!({"match": {"op": "==", "left": left, "right": right}}),
        );
    }
    fn interface(&mut self, key: &str, name: &str) {
        self.matched(
            format!("{key} \"{name}\""),
            json!({"meta": {"key": key}}),
            json!(name),
        );
    }
    fn other_interface(&mut self, key: &str, name: &str) {
        self.term(
            format!("{key} != \"{name}\""),
            json!({"match": {"op": "!=", "left": {"meta": {"key": key}}, "right": name}}),
        );
    }
    fn extend(&mut self, other: Rule) {
        self.text.push_str(&other.text);
        self.expr.extend(other.expr);
    }
    fn ct(&mut self, key: &str, direction: Option<&str>, value: Value, text: String) {
        let mut left = json!({"ct": {"key": key}});
        if let Some(direction) = direction {
            left["ct"]["dir"] = json!(direction);
        }
        self.matched(text, left, value);
    }
}
fn subnet(net: Ipv4Net) -> Value {
    if net.prefix_len() == 32 {
        json!(net.addr().to_string())
    } else {
        json!({"prefix": {"addr": net.network().to_string(), "len": net.prefix_len()}})
    }
}
fn nat(rule: &PortForwardConfig) -> Rule {
    let mut r = Rule::default();
    r.term(
        "meta nfproto ipv4",
        json!({"match": {"op": "==", "left": {"meta": {"key": "nfproto"}}, "right": "ipv4"}}),
    );
    r.interface("iifname", &rule.from);
    r.matched(
        "fib daddr type local",
        json!({"fib": {"result": "type", "flags": ["daddr"]}}),
        json!("local"),
    );
    if let Some(ip) = rule.destination_address {
        r.matched(
            format!("ip daddr {ip}"),
            json!({"payload": {"protocol": "ip", "field": "daddr"}}),
            json!(ip.to_string()),
        );
    }
    if let Some(net) = rule.source_subnet {
        r.matched(
            format!("ip saddr {net}"),
            json!({"payload": {"protocol": "ip", "field": "saddr"}}),
            subnet(net),
        );
    }
    let protocol = rule.protocol.as_str();
    r.matched(
        format!("{protocol} dport {}", rule.external_port),
        json!({"payload": {"protocol": protocol, "field": "dport"}}),
        json!(rule.external_port),
    );
    r.term(format!("dnat ip to {}:{}", rule.target_address, rule.target_port), json!({"dnat": {"family": "ip", "addr": rule.target_address.to_string(), "port": rule.target_port}}));
    r
}
fn connection(rule: &PortForwardConfig, reply: bool) -> Rule {
    let mut r = Rule::default();
    let direction = if reply { "reply" } else { "original" };
    r.ct(
        "direction",
        None,
        json!(direction),
        format!("ct direction {direction}"),
    );
    r.term(
        "ct status dnat",
        json!({"match": {"op": "in", "left": {"ct": {"key": "status"}}, "right": "dnat"}}),
    );
    r.ct(
        "protocol",
        None,
        json!(rule.protocol.as_str()),
        format!("ct original protocol {}", rule.protocol.as_str()),
    );
    r.ct(
        "proto-dst",
        Some("original"),
        json!(rule.external_port),
        format!("ct original proto-dst {}", rule.external_port),
    );
    r.ct(
        "ip saddr",
        Some("reply"),
        json!(rule.target_address.to_string()),
        format!("ct reply ip saddr {}", rule.target_address),
    );
    r.ct(
        "proto-src",
        Some("reply"),
        json!(rule.target_port),
        format!("ct reply proto-src {}", rule.target_port),
    );
    if let Some(ip) = rule.destination_address {
        r.ct(
            "ip daddr",
            Some("original"),
            json!(ip.to_string()),
            format!("ct original ip daddr {ip}"),
        );
    }
    if let Some(net) = rule.source_subnet {
        r.ct(
            "ip saddr",
            Some("original"),
            subnet(net),
            format!("ct original ip saddr {net}"),
        );
    }
    r
}
fn permission(rule: &PortForwardConfig, reply: bool) -> Rule {
    let mut r = Rule::default();
    let (from, to) = if reply {
        (&rule.to, &rule.from)
    } else {
        (&rule.from, &rule.to)
    };
    r.interface("iifname", from);
    r.interface("oifname", to);
    r.extend(connection(rule, reply));
    r.term(if reply { "ct state established,related" } else { "ct state established,related,new" }, json!({"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": if reply { json!(["established", "related"]) } else { json!(["established", "related", "new"]) }}}));
    r.term("accept", json!({"accept": null}));
    r
}
fn wrong_target_interface(rule: &PortForwardConfig, reply: bool) -> Rule {
    let mut r = Rule::default();
    // Scope by the external interface and original tuple so independent mappings
    // on other ingress interfaces do not block one another's replies.
    r.interface(if reply { "oifname" } else { "iifname" }, &rule.from);
    r.other_interface(if reply { "iifname" } else { "oifname" }, &rule.to);
    r.extend(connection(rule, reply));
    r.term("drop", json!({"drop": null}));
    r
}
fn forward_prefix(desired: &RouterDataplaneDesired) -> Vec<Rule> {
    // Reject misrouted DNAT before any accept, including broad sharing rules.
    desired
        .port_forwards
        .iter()
        .flat_map(|r| {
            [
                wrong_target_interface(r, false),
                wrong_target_interface(r, true),
            ]
        })
        .chain(
            desired
                .port_forwards
                .iter()
                .flat_map(|r| [permission(r, false), permission(r, true)]),
        )
        .collect()
}
fn drops(desired: &RouterDataplaneDesired) -> Vec<Rule> {
    // Explicit sharing may grant broader permissions before these pair guards.
    let pairs: BTreeSet<_> = desired
        .port_forwards
        .iter()
        .flat_map(|r| [(&r.from, &r.to), (&r.to, &r.from)])
        .collect();
    pairs.into_iter().map(|(from, to)| {
        let mut r = Rule::default();
        r.term("meta nfproto ipv4", json!({"match": {"op": "==", "left": {"meta": {"key": "nfproto"}}, "right": "ipv4"}}));
        r.interface("iifname", from); r.interface("oifname", to);
        r.term("drop", json!({"drop": null})); r
    }).collect()
}
fn lines(rules: &[Rule]) -> String {
    rules
        .iter()
        .map(|r| format!("    {}\n", r.text.trim_end()))
        .collect()
}

#[derive(Default)]
pub(super) struct RenderedRules {
    pub prerouting: String,
    pub forward_prefix: String,
    pub guards: String,
}

pub(super) fn render(desired: &RouterDataplaneDesired) -> RenderedRules {
    if desired.port_forwards.is_empty() {
        return RenderedRules::default();
    }
    let nat: Vec<_> = desired.port_forwards.iter().map(nat).collect();
    RenderedRules {
        prerouting: format!("  chain prerouting {{\n    type nat hook prerouting priority dstnat; policy accept;\n{}  }}\n", lines(&nat)),
        forward_prefix: lines(&forward_prefix(desired)),
        guards: lines(&drops(desired)),
    }
}

fn normalized(mut expr: Value) -> Value {
    if let Some(items) = expr.as_array_mut() {
        // nft removes redundant nfproto checks when an IPv4 payload constrains family.
        if items
            .iter()
            .any(|item| item.pointer("/match/left/payload/protocol") == Some(&json!("ip")))
        {
            items.retain(|item| item.pointer("/match/left/meta/key") != Some(&json!("nfproto")));
        }
        for item in items {
            if let Some(right) = item.pointer_mut("/match/right") {
                if let Some(set) = right.get("set").and_then(Value::as_array) {
                    *right = json!(set);
                }
            }
        }
    }
    expr
}
fn same(actual: &Value, expected: &Rule) -> bool {
    normalized(actual.get("expr").cloned().unwrap_or(Value::Null))
        == normalized(json!(expected.expr))
}

pub(super) fn verified_base_entries(
    entries: &[Value],
    desired: &RouterDataplaneDesired,
) -> Option<Vec<Value>> {
    let prerouting: Vec<_> = entries
        .iter()
        .filter_map(|e| e.get("chain"))
        .filter(|c| owned_object(c) && string_field(c, "name") == Some("prerouting"))
        .collect();
    if prerouting.len() != 1 {
        return None;
    }
    let c = prerouting[0];
    if string_field(c, "type") != Some("nat")
        || string_field(c, "hook") != Some("prerouting")
        || string_field(c, "policy") != Some("accept")
        || c.get("prio").and_then(Value::as_i64) != Some(-100)
    {
        return None;
    }
    // Hook order is part of the safety proof for the additional permissions.
    for (name, priority) in [("forward", 0), ("postrouting", 100)] {
        if !entries.iter().filter_map(|e| e.get("chain")).any(|c| {
            owned_object(c)
                && string_field(c, "name") == Some(name)
                && c.get("prio").and_then(Value::as_i64) == Some(priority)
        }) {
            return None;
        }
    }
    let rules = |chain| {
        entries
            .iter()
            .filter_map(|e| e.get("rule"))
            .filter(|r| owned_object(r) && string_field(r, "chain") == Some(chain))
            .collect::<Vec<_>>()
    };
    let nat_rules = rules("prerouting");
    if nat_rules.len() != desired.port_forwards.len()
        || !nat_rules
            .iter()
            .zip(&desired.port_forwards)
            .all(|(actual, r)| same(actual, &nat(r)))
    {
        return None;
    }
    let forward = rules("forward");
    let expected = forward_prefix(desired);
    let guards = drops(desired);
    if forward.len() < expected.len() + guards.len() {
        return None;
    }
    if !forward
        .iter()
        .zip(&expected)
        .all(|(actual, expected)| same(actual, expected))
    {
        return None;
    }
    if !forward[forward.len() - guards.len()..]
        .iter()
        .zip(&guards)
        .all(|(actual, expected)| same(actual, expected))
    {
        return None;
    }
    let mut index = 0;
    Some(
        entries
            .iter()
            .filter(|entry| {
                if let Some(chain) = entry.get("chain").filter(|c| owned_object(c)) {
                    if string_field(chain, "name") == Some("prerouting") {
                        return false;
                    }
                }
                if let Some(rule) = entry.get("rule").filter(|r| owned_object(r)) {
                    match string_field(rule, "chain") {
                        Some("prerouting") => return false,
                        Some("forward") => {
                            let keep =
                                index >= expected.len() && index < forward.len() - guards.len();
                            index += 1;
                            return keep;
                        }
                        _ => {}
                    }
                }
                true
            })
            .cloned()
            .collect(),
    )
}
