use super::*;
use std::sync::Arc;
use std::time::Duration;

/// H2 and Cool nodes still refuse a group detour outright: their flows ride
/// a tunnel the node keeps, so no detour can carry them. The refusal happens
/// before the detour resolves, so the path's target never matters.
#[tokio::test]
async fn h2_and_cool_nodes_refuse_a_group_detour() {
    for multiplex in [
        honk_config::node::VlessMultiplex::H2 { padding: false },
        honk_config::node::VlessMultiplex::Xray {
            tcp: Some(std::num::NonZeroU16::new(8).unwrap()),
            udp: honk_config::node::VlessUdpMux::SharedTcp,
            udp443: honk_config::node::Udp443Policy::Reject,
        },
    ] {
        let mut node = configured_vless_node(
            "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3",
            honk_config::node::VlessUdpEncoding::Auto,
            multiplex,
        );
        node.name = "vless-mux".into();
        node.address = "127.0.0.1".into();
        node.host = "127.0.0.1".into();
        node.port = 1;
        node.id = node.derive_id();
        let node_id = node.id;
        let generation = Arc::new(crate::runtime::OutboundRuntimeRegistry::build(&[node]).unwrap());
        let runtime = generation
            .get(&node_id)
            .expect("the VLESS node is in the generation");
        let path = Arc::new(crate::proxy::detour::DetourPath::new(
            Arc::new(crate::proxy::ProxyRegistry::new()),
            Arc::clone(&generation),
            uuid::Uuid::new_v4(),
        ));
        let error = VLessHandler::new()
            .dial_runtime_detoured_ctx(
                runtime,
                "93.184.216.34:80".parse().unwrap(),
                None,
                Duration::from_secs(5),
                &path,
                &crate::proxy::detour::DetourDialCtx::root(Duration::from_secs(5)),
            )
            .await
            .expect_err("an H2/Cool node refuses a group detour");
        assert!(
            error.to_string().contains("cannot be carried by a detour"),
            "the refusal names the detour: {error:#}"
        );
    }
}
