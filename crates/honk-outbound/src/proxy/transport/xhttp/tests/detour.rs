use super::*;
use crate::proxy::PacketOutbound;
use crate::proxy::detour::{DetourDialCtx, DetourPath};
use crate::proxy::trojan::TrojanHandler;
use honk_config::node::{Group, GroupPolicy};
use honk_config::types::NodeProtocol;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering;

/// A SOCKS5 front that counts the connections it carries, so the test can
/// prove the XHTTP carrier dial went through the detour instead of direct.
/// Same handshake as the detour fake: no-auth greeting, then a CONNECT it
/// proxies through to the requested address. `delay` holds each accepted
/// connection that long before answering, for the shared-deadline test.
async fn spawn_recording_socks5(delay: Duration) -> (SocketAddr, Arc<AtomicUsize>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    let seen = Arc::new(AtomicUsize::new(0));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen_clone = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            seen_clone.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let mut greeting = [0u8; 2];
                if stream.read_exact(&mut greeting).await.is_err() {
                    return;
                }
                let mut methods = vec![0u8; greeting[1] as usize];
                if stream.read_exact(&mut methods).await.is_err() {
                    return;
                }
                if stream.write_all(&[5, 0]).await.is_err() {
                    return;
                }
                let mut head = [0u8; 4];
                if stream.read_exact(&mut head).await.is_err() {
                    return;
                }
                let target = match head[3] {
                    1 => {
                        let mut buf = [0u8; 6];
                        if stream.read_exact(&mut buf).await.is_err() {
                            return;
                        }
                        SocketAddr::new(
                            IpAddr::V4(Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3])),
                            u16::from_be_bytes([buf[4], buf[5]]),
                        )
                    }
                    _ => return,
                };
                match TcpStream::connect(target).await {
                    Ok(mut upstream) => {
                        if stream
                            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                            .await
                            .is_err()
                        {
                            return;
                        }
                        let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
                    }
                    Err(_) => {
                        let _ = stream.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                    }
                }
            });
        }
    });
    (addr, seen)
}

/// A SOCKS5 node dialing the fake server at `server`.
fn socks5_node(name: &str, server: SocketAddr) -> Node {
    let mut node = Node {
        name: name.to_string(),
        host: server.ip().to_string(),
        address: server.ip().to_string(),
        port: server.port(),
        outbound: OutboundConfig::Socks5(Default::default()),
        ..Default::default()
    };
    node.id = node.derive_id();
    node
}

/// One group-detour scene for a Trojan XHTTP node: a recording SOCKS5 front
/// in group "front", the XHTTP node behind the h2 fake peer, and the path
/// the carrier dials through.
struct XhttpDetourScene {
    peer: Peer,
    runtime: Arc<crate::runtime::NodeRuntime>,
    path: Arc<DetourPath>,
    seen: Arc<AtomicUsize>,
}

async fn xhttp_detour_scene(delay: Duration) -> XhttpDetourScene {
    let peer = Peer::new(32).await;
    let mut node = node(XhttpMode::StreamOne, 97);
    node.address = peer.address.ip().to_string();
    node.port = peer.address.port();
    node.normalize_stream_transport().unwrap();
    node.id = node.derive_id();
    let node_id = node.id;
    let (front_addr, seen) = spawn_recording_socks5(delay).await;
    let front = socks5_node("front-socks", front_addr);
    let group = Group {
        name: "front".into(),
        policy: GroupPolicy::Selector,
        nodes: vec![front.id],
        ..Default::default()
    };
    let manager = Arc::new(crate::group::GroupManager::new(
        std::slice::from_ref(&group),
        std::slice::from_ref(&front),
    ));
    let generation =
        Arc::new(crate::runtime::OutboundRuntimeRegistry::build(&[front, node]).unwrap());
    let path = Arc::new(DetourPath::to_group(
        Arc::new(crate::proxy::ProxyRegistry::default_resolver().unwrap()),
        Arc::clone(&generation),
        "front",
        manager,
        NodeProtocol::Trojan,
    ));
    let runtime = generation
        .get(&node_id)
        .expect("the XHTTP node is in the generation");
    // The path keeps the generation alive; the scene only holds the runtime.
    XhttpDetourScene {
        peer,
        runtime,
        path,
        seen,
    }
}

/// A Trojan XHTTP carrier dials through the group detour the caller names:
/// the front sees the carrier connection and the peer gets the request.
#[tokio::test]
async fn xhttp_carrier_dials_through_a_group_detour() {
    tokio::time::timeout(DEADLINE, async {
        let mut scene = xhttp_detour_scene(Duration::ZERO).await;
        let timeout = Duration::from_secs(5);
        let (mut stream, preparation) = crate::proxy::transport::prepare_transport_runtime(
            &scene.runtime,
            None,
            timeout,
            Some(&scene.path),
            &DetourDialCtx::root(timeout),
        )
        .await
        .expect("the XHTTP carrier dials through the detour");
        preparation.commit().expect("the preparation commits");
        assert!(
            scene.seen.load(Ordering::SeqCst) > 0,
            "the front carried the carrier dial"
        );
        // The detoured carrier lives in the private runtime, never in the
        // node's shared pool: a later direct flow must not reuse it.
        assert_eq!(
            upload_pool(&scene.runtime).live_session_count(),
            0,
            "the detoured carrier must not land in the node's shared pool"
        );

        let mut download = scene.peer.next().await;
        assert_headers(&download.request);
        assert_eq!(download.request.method(), http::Method::POST);
        assert_eq!(download.request.uri().path(), WIRE_PREFIX);
        assert_eq!(
            download.request.headers()["content-type"],
            "application/grpc"
        );
        let payload: Vec<u8> = (0..513).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();
        let server = async {
            let body = download.request.body_mut();
            assert_eq!(receive(body, expected.len()).await, expected);
            eof(body).await;
            let mut reply = response(&mut download.respond, 200, false);
            send(&mut reply, Bytes::from_static(b"\0raw-reply\xff"), true).await;
        };
        let client = async {
            stream.write_all(&payload).await.unwrap();
            stream.flush().await.unwrap();
            stream.shutdown().await.unwrap();
            assert_eq!(
                stream.write(b"after-close").await.unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"\0raw-reply\xff");
        };
        tokio::join!(server, client);
    })
    .await
    .unwrap_or_else(|_| panic!("XHTTP detour exchange stalled"));
}

/// Without a detour the same scene still works, and the front sees nothing:
/// the private runtime is only for detoured flows.
#[tokio::test]
async fn xhttp_carrier_without_a_detour_still_uses_the_shared_pool() {
    tokio::time::timeout(DEADLINE, async {
        let mut scene = xhttp_detour_scene(Duration::ZERO).await;
        let timeout = Duration::from_secs(5);
        let (mut stream, preparation) = crate::proxy::transport::prepare_transport_runtime(
            &scene.runtime,
            None,
            timeout,
            None,
            &DetourDialCtx::root(timeout),
        )
        .await
        .expect("the XHTTP carrier dials direct");
        preparation.commit().expect("the preparation commits");
        assert_eq!(
            scene.seen.load(Ordering::SeqCst),
            0,
            "no detour means nothing dials the front"
        );
        // The direct carrier lands in the node's shared pool, the complement
        // of the detoured case above.
        assert_eq!(
            upload_pool(&scene.runtime).live_session_count(),
            1,
            "the direct carrier lands in the node's shared pool"
        );

        let mut download = scene.peer.next().await;
        assert_headers(&download.request);
        assert_eq!(download.request.method(), http::Method::POST);
        let payload: Vec<u8> = (0..513).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();
        let server = async {
            let body = download.request.body_mut();
            assert_eq!(receive(body, expected.len()).await, expected);
            eof(body).await;
            let mut reply = response(&mut download.respond, 200, false);
            send(&mut reply, Bytes::from_static(b"\0raw-reply\xff"), true).await;
        };
        let client = async {
            stream.write_all(&payload).await.unwrap();
            stream.flush().await.unwrap();
            stream.shutdown().await.unwrap();
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"\0raw-reply\xff");
        };
        tokio::join!(server, client);
    })
    .await
    .unwrap_or_else(|_| panic!("XHTTP direct exchange stalled"));
}

/// A carrier riding the node's own bound detour still uses the shared pool:
/// it follows the same fixed front the pool already uses, so pooling stays
/// safe. Only a *different* detour needs a private runtime.
#[tokio::test]
async fn xhttp_carrier_through_the_nodes_own_detour_still_uses_the_shared_pool() {
    tokio::time::timeout(DEADLINE, async {
        let mut scene = xhttp_detour_scene(Duration::ZERO).await;
        // Bind the scene's path as the node's own detour, the way a
        // generation binds a node's dialer-proxy.
        scene.runtime.bind_detour(Arc::clone(&scene.path));
        let timeout = Duration::from_secs(5);
        let (mut stream, preparation) = crate::proxy::transport::prepare_transport_runtime(
            &scene.runtime,
            None,
            timeout,
            Some(&scene.path),
            &DetourDialCtx::root(timeout),
        )
        .await
        .expect("the XHTTP carrier dials through the node's own detour");
        preparation.commit().expect("the preparation commits");
        assert!(
            scene.seen.load(Ordering::SeqCst) > 0,
            "the front carried the carrier dial"
        );
        // The carrier lands in the node's shared pool: the detour is the
        // node's own, so a later flow on the same node reuses it.
        assert_eq!(
            upload_pool(&scene.runtime).live_session_count(),
            1,
            "the node's own detour keeps carrier pooling"
        );

        let mut download = scene.peer.next().await;
        assert_headers(&download.request);
        assert_eq!(download.request.method(), http::Method::POST);
        let payload: Vec<u8> = (0..513).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();
        let server = async {
            let body = download.request.body_mut();
            assert_eq!(receive(body, expected.len()).await, expected);
            eof(body).await;
            let mut reply = response(&mut download.respond, 200, false);
            send(&mut reply, Bytes::from_static(b"\0raw-reply\xff"), true).await;
        };
        let client = async {
            stream.write_all(&payload).await.unwrap();
            stream.flush().await.unwrap();
            stream.shutdown().await.unwrap();
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"\0raw-reply\xff");
        };
        tokio::join!(server, client);
    })
    .await
    .unwrap_or_else(|_| panic!("XHTTP own-detour exchange stalled"));
}

/// The Trojan UDP-associate control connection rides the same detoured
/// carrier: the front sees it, and the control header reaches the peer.
///
/// The fake peer's stream window is 32 bytes and the header is 68, so the
/// header write only completes while the test drains the body: the dial and
/// the peer read run concurrently.
#[tokio::test]
async fn xhttp_trojan_udp_control_connection_dials_through_a_group_detour() {
    tokio::time::timeout(DEADLINE, async {
        let mut scene = xhttp_detour_scene(Duration::ZERO).await;
        let timeout = Duration::from_secs(5);
        let handler = TrojanHandler::new();
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();
        let runtime = Arc::clone(&scene.runtime);
        let path = Arc::clone(&scene.path);
        let dial = tokio::spawn(async move {
            handler
                .dial_udp_transport_runtime_detoured_ctx(
                    runtime,
                    target,
                    None,
                    timeout,
                    &path,
                    &DetourDialCtx::root(timeout),
                )
                .await
        });
        let mut upload = scene.peer.next().await;
        assert_eq!(upload.request.method(), http::Method::POST);
        // 56 hex + CRLF + CMD_UDP + 7-byte IPv4 address header + CRLF.
        let body = upload.request.body_mut();
        let header = receive(body, 68).await;
        assert_eq!(header.len(), 68);
        let _transport = dial
            .await
            .expect("the dial task finished")
            .expect("the UDP control connection opens through the detour");
        assert!(
            scene.seen.load(Ordering::SeqCst) > 0,
            "the front carried the UDP control connection"
        );
    })
    .await
    .unwrap_or_else(|_| panic!("XHTTP UDP detour exchange stalled"));
}

/// The detoured XHTTP leg shares the caller's deadline instead of resetting
/// it: a ctx with 300ms left fails the dial at ~300ms even though the nominal
/// timeout is 5s and the front would answer at 3s, and the failure names
/// hop 0. Without the threading the same dial would succeed at ~3s.
#[tokio::test]
async fn xhttp_detoured_leg_shares_the_caller_deadline() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let scene = xhttp_detour_scene(Duration::from_secs(3)).await;
        let started = tokio::time::Instant::now();
        let ctx = DetourDialCtx::root_at(started + Duration::from_millis(300));
        let error = match crate::proxy::transport::prepare_transport_runtime(
            &scene.runtime,
            None,
            Duration::from_secs(5),
            Some(&scene.path),
            &ctx,
        )
        .await
        {
            Ok(_) => panic!("the shared deadline expires before the front answers"),
            Err(error) => error,
        };
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_millis(1500),
            "the dial failed fast on the shared deadline, not after the nominal timeout: {elapsed:?}"
        );
        let hop = crate::proxy::failed_hop(&error).map(|failure| failure.hop);
        assert_eq!(hop, Some(0), "the timed-out leg names hop 0: {error:#}");
    })
    .await
    .unwrap_or_else(|_| panic!("XHTTP shared-deadline exchange stalled"));
}
