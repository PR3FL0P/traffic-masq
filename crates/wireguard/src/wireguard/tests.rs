use super::*;

const VALID_PRIVATE_KEY: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
const VALID_PUBLIC_KEY: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
const VALID_PRESHARED_KEY: &str = "FpCyhw6bDwNTKAP1sJ8fWTlwGJ8yVCLzYIT+DP4a6D4=";

fn valid_config() -> String {
    format!(
        "[Interface]\n\
         PrivateKey = {VALID_PRIVATE_KEY}\n\
         Address = 10.0.0.2/24, fd00::2/64\n\
         DNS = 1.1.1.1, 9.9.9.9\n\
         MTU = 1420\n\
         ListenPort = 51820\n\
         \n\
         [Peer]\n\
         PublicKey = {VALID_PUBLIC_KEY}\n\
         PresharedKey = {VALID_PRESHARED_KEY}\n\
         AllowedIPs = 0.0.0.0/0, ::/0\n\
         Endpoint = 203.0.113.1:51820\n\
         PersistentKeepalive = 25\n"
    )
}

#[test]
fn valid_profile_parses_through_driver() {
    let driver = WireGuardDriver;
    let profile = driver
        .parse_named_profile("home.conf", valid_config().as_bytes())
        .expect("valid profile should parse");

    assert_eq!(profile.name, "home.conf");
    assert_eq!(profile.interface.listen_port, Some(51820));
    assert_eq!(profile.interface.addresses.len(), 2);
    assert_eq!(profile.interface.dns.len(), 2);
    assert_eq!(profile.interface.mtu, Some(1420));
    assert_eq!(profile.peers.len(), 1);
    assert_eq!(profile.peers[0].allowed_ips.len(), 2);
    assert_eq!(
        profile.peers[0].endpoint,
        Some("203.0.113.1:51820".parse().unwrap())
    );
    assert_eq!(profile.peers[0].persistent_keepalive, Some(25));
    assert!(profile.peers[0].preshared_key.is_some());
}

#[test]
fn rejects_bad_base64_private_key() {
    let bad = valid_config().replace(VALID_PRIVATE_KEY, "not-valid-base64!!");
    let err = WireGuardDriver
        .parse_named_profile("home.conf", bad.as_bytes())
        .unwrap_err();
    assert_eq!(
        err,
        ProfileError::InvalidKey {
            field: "Interface.PrivateKey"
        }
    );
}

#[test]
fn rejects_wrong_length_key() {
    let short_key = base64::engine::general_purpose::STANDARD.encode(b"tooshort");
    let bad = valid_config().replace(VALID_PUBLIC_KEY, &short_key);
    let err = WireGuardDriver
        .parse_named_profile("home.conf", bad.as_bytes())
        .unwrap_err();
    assert_eq!(
        err,
        ProfileError::InvalidKey {
            field: "Peer.PublicKey"
        }
    );
}

#[test]
fn rejects_missing_required_field() {
    let missing_private_key =
        valid_config().replace(&format!("PrivateKey = {VALID_PRIVATE_KEY}\n"), "");
    let err = WireGuardDriver
        .parse_named_profile("home.conf", missing_private_key.as_bytes())
        .unwrap_err();
    assert_eq!(err, ProfileError::MissingInterfaceField("PrivateKey"));
}

#[test]
fn rejects_missing_address() {
    let missing_address = valid_config().replace("Address = 10.0.0.2/24, fd00::2/64\n", "");
    let err = WireGuardDriver
        .parse_named_profile("home.conf", missing_address.as_bytes())
        .unwrap_err();
    assert_eq!(err, ProfileError::MissingInterfaceField("Address"));
}

#[test]
fn rejects_malformed_cidr() {
    let bad_cidr = valid_config().replace(
        "Address = 10.0.0.2/24, fd00::2/64\n",
        "Address = not-an-ip/24\n",
    );
    let err = WireGuardDriver
        .parse_named_profile("home.conf", bad_cidr.as_bytes())
        .unwrap_err();
    assert_eq!(
        err,
        ProfileError::InvalidCidr {
            field: "Interface.Address",
            value: "not-an-ip/24".to_string()
        }
    );
}

#[test]
fn rejects_invalid_listen_port() {
    let bad_port = valid_config().replace("ListenPort = 51820\n", "ListenPort = 99999\n");
    let err = WireGuardDriver
        .parse_named_profile("home.conf", bad_port.as_bytes())
        .unwrap_err();
    assert_eq!(err, ProfileError::InvalidListenPort("99999".to_string()));
}

#[test]
fn rejects_endpoint_missing_port() {
    let bad = valid_config().replace("Endpoint = 203.0.113.1:51820\n", "Endpoint = 203.0.113.1\n");
    let err = WireGuardDriver
        .parse_named_profile("home.conf", bad.as_bytes())
        .unwrap_err();
    assert_eq!(
        err,
        ProfileError::InvalidEndpoint("203.0.113.1".to_string())
    );
}

#[test]
fn rejects_endpoint_ipv6_without_brackets() {
    let bad = valid_config().replace("Endpoint = 203.0.113.1:51820\n", "Endpoint = ::1:51820\n");
    let err = WireGuardDriver
        .parse_named_profile("home.conf", bad.as_bytes())
        .unwrap_err();
    assert_eq!(err, ProfileError::InvalidEndpoint("::1:51820".to_string()));
}

#[test]
fn rejects_endpoint_garbage_host() {
    let bad = valid_config().replace(
        "Endpoint = 203.0.113.1:51820\n",
        "Endpoint = not-an-endpoint\n",
    );
    let err = WireGuardDriver
        .parse_named_profile("home.conf", bad.as_bytes())
        .unwrap_err();
    assert_eq!(
        err,
        ProfileError::InvalidEndpoint("not-an-endpoint".to_string())
    );
}

#[test]
fn accepts_endpoint_hostname_without_resolving_it_during_import() {
    let config = valid_config().replace("203.0.113.1:51820", "wg010.njalla.no:51820");
    let profile = WireGuardDriver
        .parse_named_profile("wg0.conf", config.as_bytes())
        .unwrap();
    assert_eq!(
        profile.peers[0].endpoint,
        Some(WireGuardEndpoint::Hostname {
            host: "wg010.njalla.no".into(),
            port: 51820
        })
    );
}

#[tokio::test]
async fn endpoint_resolution_handles_numeric_and_localhost_addresses() {
    let numeric: WireGuardEndpoint = "192.0.2.1:51820".parse().unwrap();
    assert_eq!(
        numeric.resolve().await.unwrap(),
        "192.0.2.1:51820".parse().unwrap()
    );
    let local: WireGuardEndpoint = "localhost:51820".parse().unwrap();
    let address = local.resolve().await.unwrap();
    assert!(address.ip().is_loopback());
    assert_eq!(address.port(), 51820);
}

#[test]
fn endpoint_hostname_allows_only_one_trailing_root_dot() {
    for host in ["vpn.example.com", "vpn.example.com."] {
        assert!(format!("{host}:51820").parse::<WireGuardEndpoint>().is_ok());
    }
    for host in ["vpn.example.com..", "vpn..example.com", "."] {
        let endpoint = format!("{host}:51820");
        assert_eq!(
            endpoint.parse::<WireGuardEndpoint>().unwrap_err(),
            ProfileError::InvalidEndpoint(endpoint)
        );
    }
}

#[test]
fn rejects_endpoint_with_out_of_range_port() {
    let bad = valid_config().replace(
        "Endpoint = 203.0.113.1:51820\n",
        "Endpoint = 203.0.113.1:99999\n",
    );
    let err = WireGuardDriver
        .parse_named_profile("home.conf", bad.as_bytes())
        .unwrap_err();
    assert_eq!(
        err,
        ProfileError::InvalidEndpoint("203.0.113.1:99999".to_string())
    );
}

#[test]
fn rejects_empty_private_key() {
    let bad = valid_config().replace(
        &format!("PrivateKey = {VALID_PRIVATE_KEY}"),
        "PrivateKey = ",
    );
    let err = WireGuardDriver
        .parse_named_profile("home.conf", bad.as_bytes())
        .unwrap_err();
    assert_eq!(
        err,
        ProfileError::InvalidKey {
            field: "Interface.PrivateKey"
        }
    );
}

#[test]
fn rejects_overlong_base64_key() {
    let long_key = base64::engine::general_purpose::STANDARD.encode(vec![0u8; 64]);
    let bad = valid_config().replace(VALID_PRIVATE_KEY, &long_key);
    let err = WireGuardDriver
        .parse_named_profile("home.conf", bad.as_bytes())
        .unwrap_err();
    assert_eq!(
        err,
        ProfileError::InvalidKey {
            field: "Interface.PrivateKey"
        }
    );
}

#[test]
fn rejects_malformed_preshared_key_without_touching_public_key() {
    let bad = valid_config().replace(VALID_PRESHARED_KEY, "not-valid-base64!!");
    let err = WireGuardDriver
        .parse_named_profile("home.conf", bad.as_bytes())
        .unwrap_err();
    assert_eq!(
        err,
        ProfileError::InvalidKey {
            field: "Peer.PresharedKey"
        }
    );
}

#[test]
fn rejects_invalid_persistent_keepalive() {
    let bad = valid_config().replace(
        "PersistentKeepalive = 25\n",
        "PersistentKeepalive = not-a-number\n",
    );
    let err = WireGuardDriver
        .parse_named_profile("home.conf", bad.as_bytes())
        .unwrap_err();
    assert_eq!(
        err,
        ProfileError::InvalidKeepalive("not-a-number".to_string())
    );
}

#[test]
fn rejects_negative_persistent_keepalive() {
    let bad = valid_config().replace("PersistentKeepalive = 25\n", "PersistentKeepalive = -1\n");
    let err = WireGuardDriver
        .parse_named_profile("home.conf", bad.as_bytes())
        .unwrap_err();
    assert_eq!(err, ProfileError::InvalidKeepalive("-1".to_string()));
}

#[test]
fn rejects_invalid_mtu() {
    let bad = valid_config().replace("MTU = 1420\n", "MTU = jumbo\n");
    let err = WireGuardDriver
        .parse_named_profile("home.conf", bad.as_bytes())
        .unwrap_err();
    assert_eq!(err, ProfileError::InvalidMtu("jumbo".to_string()));
}

#[test]
fn rejects_invalid_dns_address() {
    let bad = valid_config().replace("DNS = 1.1.1.1, 9.9.9.9\n", "DNS = not-an-ip\n");
    let err = WireGuardDriver
        .parse_named_profile("home.conf", bad.as_bytes())
        .unwrap_err();
    assert_eq!(
        err,
        ProfileError::InvalidIpAddr {
            field: "Interface.DNS",
            value: "not-an-ip".to_string()
        }
    );
}

#[test]
fn rejects_malformed_allowed_ips() {
    let bad = valid_config().replace(
        "AllowedIPs = 0.0.0.0/0, ::/0\n",
        "AllowedIPs = garbage/64\n",
    );
    let err = WireGuardDriver
        .parse_named_profile("home.conf", bad.as_bytes())
        .unwrap_err();
    assert_eq!(
        err,
        ProfileError::InvalidCidr {
            field: "Peer.AllowedIPs",
            value: "garbage/64".to_string()
        }
    );
}

#[test]
fn rejects_missing_peer_public_key() {
    let bad = valid_config().replace(&format!("PublicKey = {VALID_PUBLIC_KEY}\n"), "");
    let err = WireGuardDriver
        .parse_named_profile("home.conf", bad.as_bytes())
        .unwrap_err();
    assert_eq!(err, ProfileError::MissingPeerPublicKey(0));
}

#[test]
fn rejects_malformed_line_without_equals_sign() {
    let bad = valid_config().replace(
        "PersistentKeepalive = 25\n",
        "PersistentKeepalive = 25\nThisLineHasNoEquals\n",
    );
    let err = WireGuardDriver
        .parse_named_profile("home.conf", bad.as_bytes())
        .unwrap_err();
    assert_eq!(
        err,
        ProfileError::MalformedLine("ThisLineHasNoEquals".to_string())
    );
}

#[test]
fn rejects_unknown_section_header() {
    let bad = format!("[Bogus]\nFoo = bar\n\n{}", valid_config());
    let err = WireGuardDriver
        .parse_named_profile("home.conf", bad.as_bytes())
        .unwrap_err();
    assert_eq!(err, ProfileError::UnknownSection("Bogus".to_string()));
}

#[test]
fn rejects_non_utf8_config_bytes() {
    let mut bad = valid_config().into_bytes();
    bad.push(0xFF);
    let err = WireGuardDriver
        .parse_named_profile("home.conf", &bad)
        .unwrap_err();
    assert_eq!(err, ProfileError::InvalidEncoding);
}

#[test]
fn rejects_empty_config() {
    let err = WireGuardDriver
        .parse_named_profile("home.conf", b"")
        .unwrap_err();
    assert_eq!(err, ProfileError::MissingInterfaceSection);
}

#[test]
fn rejects_no_peers() {
    let no_peer = format!("[Interface]\nPrivateKey = {VALID_PRIVATE_KEY}\nAddress = 10.0.0.2/24\n");
    let err = WireGuardDriver
        .parse_named_profile("home.conf", no_peer.as_bytes())
        .unwrap_err();
    assert_eq!(err, ProfileError::NoPeers);
}

#[test]
fn rejects_path_traversal_in_name() {
    for name in [
        "../etc/passwd.conf",
        "../../evil.conf",
        "sub/dir.conf",
        "..",
        ".",
    ] {
        let err = validate_wireguard_profile_name(name).unwrap_err();
        assert!(matches!(
            err,
            ProfileError::InvalidName(_) | ProfileError::EmptyName
        ));
    }
}

#[test]
fn rejects_non_conf_extension() {
    let err = validate_wireguard_profile_name("profile.txt").unwrap_err();
    assert_eq!(err, ProfileError::InvalidName("profile.txt".to_string()));
}

#[test]
fn accepts_safe_basename() {
    assert!(validate_wireguard_profile_name("my-home_profile.1.conf").is_ok());
}

#[test]
fn debug_output_never_contains_secret_material() {
    let profile = WireGuardDriver
        .parse_named_profile("home.conf", valid_config().as_bytes())
        .expect("valid profile should parse");

    let debug_output = format!("{profile:?}");
    assert!(!debug_output.contains(VALID_PRIVATE_KEY));
    assert!(!debug_output.contains(VALID_PUBLIC_KEY));
    assert!(!debug_output.contains(VALID_PRESHARED_KEY));
    assert!(debug_output.contains("[REDACTED]"));

    let iface_debug = format!("{:?}", profile.interface);
    assert!(!iface_debug.contains(VALID_PRIVATE_KEY));

    let peer_debug = format!("{:?}", profile.peers[0]);
    assert!(!peer_debug.contains(VALID_PUBLIC_KEY));
    assert!(!peer_debug.contains(VALID_PRESHARED_KEY));

    assert_eq!(format!("{}", profile.interface.private_key), "[REDACTED]");
    assert_eq!(
        format!("{}", profile.peers[0].preshared_key.as_ref().unwrap()),
        "[REDACTED]"
    );

    let display_output = format!("{profile}");
    assert!(!display_output.contains(VALID_PRIVATE_KEY));
}
