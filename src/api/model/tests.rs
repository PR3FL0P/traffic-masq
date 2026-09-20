use super::*;

#[test]
fn route_status_serde_roundtrip() {
    let status = RouteStatus {
        destination: "192.168.1.0/24".parse().expect("dest"),
        gateway: Some(Ipv4Addr::new(10, 0, 0, 1)),
        output_interface: Some("eth0".to_string()),
        output_interface_index: Some(2),
        table: 254,
        metric: Some(100),
        protocol: 201,
        scope: 0,
        owner: RouteOwner::TrafficMasqStatic,
    };

    let json = serde_json::to_string(&status).expect("serialize");
    let parsed: RouteStatus = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed, status);
}

#[test]
fn request_and_response_route_variants_roundtrip() {
    let req = Request::ListRoutes {
        include_local_table: true,
    };
    let json_req = serde_json::to_string(&req).expect("serialize request");
    let parsed_req: Request = serde_json::from_str(&json_req).expect("deserialize request");
    match parsed_req {
        Request::ListRoutes {
            include_local_table,
        } => assert!(include_local_table),
        _ => panic!("wrong variant"),
    }

    let resp = Response::Routes {
        routes: vec![RouteStatus {
            destination: "0.0.0.0/0".parse().expect("dest"),
            gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
            output_interface: Some("wan0".to_string()),
            output_interface_index: Some(3),
            table: 254,
            metric: None,
            protocol: 201,
            scope: 0,
            owner: RouteOwner::TrafficMasqStatic,
        }],
    };
    let json_resp = serde_json::to_string(&resp).expect("serialize response");
    let parsed_resp: Response = serde_json::from_str(&json_resp).expect("deserialize response");
    match parsed_resp {
        Response::Routes { routes } => {
            assert_eq!(routes.len(), 1);
            assert_eq!(routes[0].owner, RouteOwner::TrafficMasqStatic);
        }
        _ => panic!("wrong variant"),
    }
}
