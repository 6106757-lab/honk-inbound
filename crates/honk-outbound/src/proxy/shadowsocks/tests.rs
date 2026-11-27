use super::*;
use std::net::{Ipv4Addr, SocketAddrV4};
use tokio::io::AsyncReadExt;

#[test]
fn test_evp_bytes_to_key() {
    let key = ShadowsocksHandler::master_key("foobar", 32);
    assert_eq!(key.len(), 32);
    // MD5("foobar") == 3858f62230ac3c915f300c664312c63f, which is the first
    // block of EVP_BytesToKey output.
    assert_eq!(
        &key[..16],
        &[
            0x38, 0x58, 0xf6, 0x22, 0x30, 0xac, 0x3c, 0x91, 0x5f, 0x30, 0x0c, 0x66, 0x43, 0x12,
            0xc6, 0x3f
        ]
    );
}

#[test]
fn test_nonce_increment() {
    let mut n = [0u8; 12];
    increment_nonce(&mut n);
    assert_eq!(n, [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    n[0] = 0xFF;
    increment_nonce(&mut n);
    assert_eq!(n, [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn test_cipher_conf_lookup() {
    assert!(CipherConf::for_method("aes-128-gcm").is_ok());
    assert!(CipherConf::for_method("AES-256-GCM").is_ok());
    assert!(CipherConf::for_method("chacha20-ietf-poly1305").is_ok());
    assert!(CipherConf::for_method("chacha20-poly1305").is_ok());
    assert!(CipherConf::for_method("2022-blake3-aes-128-gcm").is_ok());
    assert!(CipherConf::for_method("2022-blake3-aes-256-gcm").is_ok());
    assert!(CipherConf::for_method("2022-blake3-chacha20-poly1305").is_ok());
    assert!(CipherConf::for_method("rc4-md5").is_err());
}

#[test]
fn test_is_2022_method() {
    assert!(is_2022_method("2022-blake3-aes-128-gcm"));
    assert!(is_2022_method("2022-BLAKE3-AES-256-GCM"));
    assert!(is_2022_method("2022-blake3-chacha20-poly1305"));
    assert!(!is_2022_method("aes-256-gcm"));
    assert!(!is_2022_method("chacha20-ietf-poly1305"));
}

fn legacy_transport(socket: tokio::net::UdpSocket, target: SocketAddr) -> SsUdpTransport {
    SsUdpTransport {
        server_addr: socket.peer_addr().unwrap(),
        socket,
        crypto: tokio::sync::Mutex::new(SsUdpCrypto::Legacy(
            LegacyUdpCrypto::new("aes-128-gcm", "test-password").unwrap(),
        )),
        recv_buf: tokio::sync::Mutex::new(None),
        socks: addr::encode_address(target, None).unwrap(),
        target,
        target_domain: None,
    }
}

#[test]
fn test_legacy_udp_roundtrip() {
    let crypto = LegacyUdpCrypto::new("aes-128-gcm", "test-password").unwrap();
    let socks = addr::encode_address(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53)),
        None,
    )
    .unwrap();
    let payload = b"\xde\xad\xbe\xef dns query";
    let packet = crypto.seal(&socks, payload).unwrap();
    // salt + tag minimum
    assert!(packet.len() > 16 + 16 + payload.len());
    let opened = crypto.open(&packet).unwrap();
    assert_eq!(opened.payload(), payload);
    assert_eq!(
        opened.peer,
        addr::SocksAddr::V4("8.8.8.8:53".parse().unwrap())
    );
}

#[tokio::test]
async fn udp_send_waits_for_cipher_instead_of_reporting_a_drop_as_success() {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(server.local_addr().unwrap()).await.unwrap();
    let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let transport = Arc::new(legacy_transport(client, target));
    let guard = transport.crypto.lock().await;
    let sender = {
        let transport = Arc::clone(&transport);
        tokio::spawn(async move { transport.send_packet(b"retained").await })
    };
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    assert!(
        !sender.is_finished(),
        "cipher contention must apply backpressure instead of returning false success"
    );

    drop(guard);
    sender.await.unwrap().unwrap();
    let mut packet = [0u8; 256];
    let received =
        tokio::time::timeout(std::time::Duration::from_secs(1), server.recv(&mut packet))
            .await
            .unwrap()
            .unwrap();
    assert!(received > b"retained".len());
}

#[test]
fn test_legacy_udp_roundtrip_chacha() {
    let crypto = LegacyUdpCrypto::new("chacha20-ietf-poly1305", "test-password").unwrap();
    let socks = addr::encode_address(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 443)),
        Some("one.one"),
    )
    .unwrap();
    let payload = b"quic initial";
    let packet = crypto.seal(&socks, payload).unwrap();
    let opened = crypto.open(&packet).unwrap();
    assert_eq!(opened.payload(), payload);
    assert_eq!(opened.peer, addr::SocksAddr::Domain("one.one".into(), 443));
}

#[test]
fn test_legacy_udp_open_rejects_garbage() {
    let crypto = LegacyUdpCrypto::new("aes-256-gcm", "test-password").unwrap();
    assert!(crypto.open(&[0u8; 10]).is_err());
    let mut garbage = vec![0u8; 64];
    rand::rng().fill_bytes(&mut garbage);
    assert!(crypto.open(&garbage).is_err());
}

/// Batched seal/decrypt equivalence: any payload round-trips through
/// `seal_chunks_into` + `decrypt_chunks_in_place` in one batch.
#[test]
fn test_batched_chunk_roundtrip() {
    let cipher = AeadCipher::new("aes-128-gcm", &ShadowsocksHandler::master_key("pw", 16)).unwrap();
    for payload_len in [0usize, 1, 100, CHUNK_MAX_LEN, CHUNK_MAX_LEN + 17, 100_000] {
        let payload: Vec<u8> = (0..payload_len).map(|i| (i % 251) as u8).collect();
        let mut send_nonce = vec![0u8; 12];
        let mut sealed = Vec::new();
        seal_chunks_into(&cipher, &mut send_nonce, &payload, &mut sealed).unwrap();
        assert_eq!(
            sealed.len(),
            payload_len + payload_len.div_ceil(CHUNK_MAX_LEN) * (2 + 16 + 16)
        );

        let mut recv_nonce = vec![0u8; 12];
        let mut buf = sealed;
        let total = buf.len();
        let (out_len, carry) =
            decrypt_chunks_in_place(&cipher, &mut recv_nonce, &mut None, &mut buf, total, 16)
                .unwrap();
        assert_eq!(carry, 0, "complete batch must leave no carry");
        assert_eq!(&buf[..out_len], payload.as_slice());
    }
}

/// Split feeds: chunks spanning batch boundaries must be carried and
/// completed by the next feed.
#[test]
fn test_batched_decrypt_split_feeds() {
    let cipher = AeadCipher::new("aes-128-gcm", &ShadowsocksHandler::master_key("pw", 16)).unwrap();
    let payload: Vec<u8> = (0..50_000u32).map(|i| (i % 253) as u8).collect();
    let mut send_nonce = vec![0u8; 12];
    let mut sealed = Vec::new();
    seal_chunks_into(&cipher, &mut send_nonce, &payload, &mut sealed).unwrap();

    let mut recv_nonce = vec![0u8; 12];
    let mut pending = None;
    let mut received = Vec::new();
    let mut carry_buf = vec![0u8; 0];
    // Feed in awkward slices that split len fields and chunk bodies.
    for slice_len in [1usize, 3, 7, 8192, 5, 4096, 65536] {
        let take = slice_len.min(sealed.len());
        let mut feed = carry_buf.clone();
        feed.extend_from_slice(&sealed[..take]);
        sealed.drain(..take);
        let total = feed.len();
        let (out_len, rest) =
            decrypt_chunks_in_place(&cipher, &mut recv_nonce, &mut pending, &mut feed, total, 16)
                .unwrap();
        received.extend_from_slice(&feed[..out_len]);
        carry_buf = feed[out_len..out_len + rest].to_vec();
    }
    assert!(sealed.is_empty());
    let total = carry_buf.len();
    let (out_len, rest) = decrypt_chunks_in_place(
        &cipher,
        &mut recv_nonce,
        &mut pending,
        &mut carry_buf,
        total,
        16,
    )
    .unwrap();
    received.extend_from_slice(&carry_buf[..out_len]);
    assert_eq!(rest, 0);
    assert_eq!(received, payload);
}

/// Fake legacy-AEAD TCP server: salt + chunk codec, uppercases the payload
/// after skipping the 7-byte target header, like the inline server this
/// replaces in `test_dial_tcp_legacy_end_to_end`.
async fn spawn_legacy_ss_echo_server() -> SocketAddr {
    use tokio::io::AsyncWriteExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut server, _) = listener.accept().await.unwrap();
        let method = "aes-128-gcm";
        let password = "test-password";
        let conf = CipherConf::for_method(method).unwrap();
        let master = ShadowsocksHandler::master_key(password, conf.key_len);

        // Read the client salt + derive the c2s cipher.
        let mut c2s_salt = vec![0u8; conf.salt_len];
        server.read_exact(&mut c2s_salt).await.unwrap();
        let mut c2s_subkey = vec![0u8; conf.key_len];
        hkdf_sha1_derive(&master, &c2s_salt, &mut c2s_subkey);
        let c2s_cipher = AeadCipher::new(method, &c2s_subkey).unwrap();
        let mut c2s_nonce = vec![0u8; conf.nonce_len];

        // Send our salt back.
        let mut s2c_salt = vec![0u8; conf.salt_len];
        rand::rng().fill_bytes(&mut s2c_salt);
        server.write_all(&s2c_salt).await.unwrap();
        let mut s2c_subkey = vec![0u8; conf.key_len];
        hkdf_sha1_derive(&master, &s2c_salt, &mut s2c_subkey);
        let s2c_cipher = AeadCipher::new(method, &s2c_subkey).unwrap();
        let mut s2c_nonce = vec![0u8; conf.nonce_len];

        // Echo loop: decrypt chunks, uppercase the payload, re-seal.
        // The first plaintext bytes are the target header (own chunk);
        // skip them, echo the rest.
        let header_len = 7usize; // atyp + v4 + port of 93.184.216.34:80
        let mut skip = header_len;
        let mut buf = vec![0u8; 262144];
        let mut carry = 0usize;
        let mut pending_len = None;
        loop {
            let n = server.read(&mut buf[carry..]).await.unwrap();
            if n == 0 {
                return;
            }
            let total = carry + n;
            let (out_len, rest) = decrypt_chunks_in_place(
                &c2s_cipher,
                &mut c2s_nonce,
                &mut pending_len,
                &mut buf,
                total,
                conf.tag_len,
            )
            .unwrap();
            if out_len > 0 {
                let start = skip.min(out_len);
                skip -= start;
                if start < out_len {
                    let upper: Vec<u8> = buf[start..out_len]
                        .iter()
                        .map(|b| b.to_ascii_uppercase())
                        .collect();
                    let mut sealed = Vec::new();
                    seal_chunks_into(&s2c_cipher, &mut s2c_nonce, &upper, &mut sealed).unwrap();
                    server.write_all(&sealed).await.unwrap();
                }
            }
            if rest > 0 {
                buf.copy_within(out_len..out_len + rest, 0);
            }
            carry = rest;
        }
    });
    server_addr
}

/// End-to-end TCP test: mock legacy-AEAD TCP server (salt + chunk
/// codec), real `dial` through the inline `SsStream`, bulk data both
/// ways (chunk boundaries crossed many times).
#[tokio::test]
async fn test_dial_tcp_legacy_end_to_end() {
    let server_addr = spawn_legacy_ss_echo_server().await;

    let node = Node {
        name: "test-ss-tcp".into(),
        address: server_addr.ip().to_string(),
        port: server_addr.port(),
        outbound: honk_config::node::OutboundConfig::Shadowsocks(
            honk_config::node::ShadowsocksConfig {
                encryption: Some("aes-128-gcm".into()),
                password: Some("test-password".into()),
                ..Default::default()
            },
        ),
        ..Default::default()
    };
    let handler = ShadowsocksHandler::new();
    let target: SocketAddr = "93.184.216.34:80".parse().unwrap();
    let mut stream = handler
        .dial(&node, target, None, std::time::Duration::from_secs(3))
        .await
        .unwrap();

    // Bulk transfer both ways: ~1MB in 8 uneven writes.
    let payload: Vec<u8> = (0..1_000_000u32).map(|i| (i % 251) as u8).collect();
    let mut off = 0;
    for chunk in [3usize, 65536, 17, 262144, 999, 400_000, 131071, 271_329] {
        let end = (off + chunk).min(payload.len());
        stream.stream.write_all(&payload[off..end]).await.unwrap();
        off = end;
    }
    assert_eq!(off, payload.len());

    let mut received = vec![0u8; payload.len()];
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        stream.stream.read_exact(&mut received),
    )
    .await
    .expect("echo timed out")
    .unwrap();
    let expected: Vec<u8> = payload.iter().map(|b| b.to_ascii_uppercase()).collect();
    assert_eq!(received, expected);
}

/// A datagram the session cannot open is dropped; the next valid one is
/// delivered and the transport stays usable.
#[tokio::test]
async fn udp_receive_drops_an_unopenable_datagram_and_keeps_the_session() {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(server.local_addr().unwrap()).await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let transport = legacy_transport(client, target);
    let server_crypto = LegacyUdpCrypto::new("aes-128-gcm", "test-password").unwrap();
    let wrong_key = LegacyUdpCrypto::new("aes-128-gcm", "other-password").unwrap();
    let socks = addr::encode_address(target, None).unwrap();
    // Too short, wrong key, then a valid packet.
    server.send_to(&[0u8; 8], client_addr).await.unwrap();
    server
        .send_to(&wrong_key.seal(&socks, b"forged").unwrap(), client_addr)
        .await
        .unwrap();
    server
        .send_to(
            &server_crypto.seal(&socks, b"genuine").unwrap(),
            client_addr,
        )
        .await
        .unwrap();

    let mut buf = [0u8; 1500];
    let (n, src) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        transport.recv_packet(&mut buf),
    )
    .await
    .expect("the valid datagram must be delivered after the dropped ones")
    .unwrap();
    assert_eq!(src, target);
    assert_eq!(&buf[..n], b"genuine");
}

/// End-to-end UDP test over the real framed `dial_udp_transport` path.
#[tokio::test]
async fn test_dial_udp_transport_legacy_end_to_end() {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let server_crypto = LegacyUdpCrypto::new("aes-128-gcm", "test-password").unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 65536];
        loop {
            let (n, src) = server.recv_from(&mut buf).await.unwrap();
            let payload = server_crypto.open(&buf[..n]).unwrap();
            let reply: Vec<u8> = payload
                .payload()
                .iter()
                .map(|b| b.to_ascii_uppercase())
                .collect();
            let socks = addr::encode_address("8.8.8.8:53".parse().unwrap(), None).unwrap();
            let packet = server_crypto.seal(&socks, &reply).unwrap();
            server.send_to(&packet, src).await.unwrap();
        }
    });

    let node = Node {
        name: "test-ss-udp".into(),
        address: server_addr.ip().to_string(),
        port: server_addr.port(),
        outbound: honk_config::node::OutboundConfig::Shadowsocks(
            honk_config::node::ShadowsocksConfig {
                encryption: Some("aes-128-gcm".into()),
                password: Some("test-password".into()),
                ..Default::default()
            },
        ),
        ..Default::default()
    };
    let handler = ShadowsocksHandler::new();
    let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let transport = handler
        .dial_udp_transport(&node, target, None, std::time::Duration::from_secs(3))
        .await
        .unwrap();
    assert_eq!(transport.relay_addr(), target);

    let payload = [b'a'; 1200];
    let mut buf = [0u8; 1200];
    let (received, sent) = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        tokio::join!(biased; transport.recv_packet(&mut buf), transport.send_packet(&payload))
    })
    .await
    .expect("pending receive must not block the send that elicits its reply");
    sent.unwrap();
    let (n, src) = received.unwrap();
    assert_eq!(src, target);
    assert_eq!(&buf[..n], &[b'A'; 1200]);
}

/// Independent legacy-AEAD wire peer for the shared-association tests:
/// `salt | AEAD(HKDF-SHA1(key, salt, "ss-subkey"))(addr | payload)` with a
/// zero nonce, framed without the production UDP codec.
struct LegacyPeer {
    method: &'static str,
    key: Vec<u8>,
}

impl LegacyPeer {
    fn new(method: &'static str, password: &str) -> Self {
        use md5::{Digest, Md5};
        let key_len = if method == "aes-128-gcm" { 16 } else { 32 };
        let (mut key, mut prev) = (Vec::new(), Vec::new());
        while key.len() < key_len {
            prev.extend_from_slice(password.as_bytes());
            prev = Md5::digest(&prev).to_vec();
            key.extend_from_slice(&prev);
        }
        key.truncate(key_len);
        Self { method, key }
    }

    fn salt_len(&self) -> usize {
        self.key.len()
    }

    fn cipher(&self, salt: &[u8]) -> AeadCipher {
        let mut subkey = vec![0u8; self.key.len()];
        Hkdf::<Sha1>::new(Some(salt), &self.key)
            .expand(b"ss-subkey", &mut subkey)
            .unwrap();
        AeadCipher::new(self.method, &subkey).unwrap()
    }

    fn seal(&self, plain: &[u8]) -> Vec<u8> {
        let mut salt = vec![0u8; self.salt_len()];
        rand::rng().fill_bytes(&mut salt);
        let mut packet = salt.clone();
        packet.extend_from_slice(&self.cipher(&salt).seal(&[0u8; 12], plain).unwrap());
        packet
    }

    fn open(&self, packet: &[u8]) -> Vec<u8> {
        let (salt, sealed) = packet.split_at(self.salt_len());
        self.cipher(salt).open(&[0u8; 12], sealed).unwrap()
    }
}

/// SOCKS5 address bytes for a socket address, written by hand.
fn wire_addr(peer: SocketAddr) -> Vec<u8> {
    let mut out = Vec::new();
    match peer {
        SocketAddr::V4(v4) => {
            out.push(1);
            out.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            out.push(4);
            out.extend_from_slice(&v6.ip().octets());
        }
    }
    out.extend_from_slice(&peer.port().to_be_bytes());
    out
}

fn wire_domain(domain: &str, port: u16) -> Vec<u8> {
    let mut out = vec![3, domain.len() as u8];
    out.extend_from_slice(domain.as_bytes());
    out.extend_from_slice(&port.to_be_bytes());
    out
}

const LEGACY_METHODS: [&str; 3] = ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"];
const PASSWORD: &str = "shared-source-password";
const STEP: std::time::Duration = std::time::Duration::from_secs(2);

fn legacy_node(server: SocketAddr, method: &str) -> Node {
    let mut node = Node {
        name: "test-ss-shared".into(),
        address: server.ip().to_string(),
        port: server.port(),
        outbound: honk_config::node::OutboundConfig::Shadowsocks(
            honk_config::node::ShadowsocksConfig {
                encryption: Some(method.into()),
                password: Some(PASSWORD.into()),
                ..Default::default()
            },
        ),
        ..Default::default()
    };
    node.id = node.derive_id();
    node
}

struct Shared {
    server: tokio::net::UdpSocket,
    peer: LegacyPeer,
    transport: Arc<dyn MultiTargetTransport>,
}

impl Shared {
    async fn new(method: &'static str, target: SocketAddr, domain: Option<&str>) -> Self {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let node = legacy_node(server.local_addr().unwrap(), method);
        let transport = Arc::new(
            ShadowsocksHandler::udp_transport(&node, target, domain, STEP)
                .await
                .unwrap(),
        );
        Self {
            server,
            peer: LegacyPeer::new(method, PASSWORD),
            transport,
        }
    }

    async fn send(&self, to: SocketAddr, domain: Option<&str>, payload: &[u8]) {
        self.transport
            .send_to(to, domain, payload, false, None)
            .await
            .unwrap();
    }

    /// The client's outer source and the decrypted `addr | payload`.
    async fn server_recv(&self) -> (SocketAddr, Vec<u8>) {
        let mut buf = vec![0u8; 65536];
        let (n, from) = tokio::time::timeout(STEP, self.server.recv_from(&mut buf))
            .await
            .expect("server datagram")
            .unwrap();
        (from, self.peer.open(&buf[..n]))
    }

    async fn reply(&self, client: SocketAddr, addr: &[u8], payload: &[u8]) {
        let plain = [addr, payload].concat();
        self.server
            .send_to(&self.peer.seal(&plain), client)
            .await
            .unwrap();
    }

    async fn client_recv(&self) -> (Vec<u8>, SocketAddr) {
        let mut buf = vec![0u8; 65536];
        let (n, from) = tokio::time::timeout(STEP, self.transport.recv_packet(&mut buf))
            .await
            .expect("client datagram")
            .unwrap();
        (buf[..n].to_vec(), from)
    }
}

/// Two destinations over one transport reach the server from one outer
/// source (one server-side mapping); a reply from a never-contacted peer
/// returns that peer, IPv4-mapped sources normalize, empty payloads survive.
#[tokio::test]
async fn legacy_udp_one_association_serves_every_destination() {
    for method in LEGACY_METHODS {
        let a: SocketAddr = "198.51.100.1:53".parse().unwrap();
        let b: SocketAddr = "[2001:db8::2]:5353".parse().unwrap();
        let c: SocketAddr = "203.0.113.9:4000".parse().unwrap();
        let c6: SocketAddr = "[2001:db8::9]:9".parse().unwrap();
        let shared = Shared::new(method, a, None).await;
        assert_eq!(
            shared.transport.carrier_addr(),
            Some(shared.server.local_addr().unwrap())
        );

        shared.send(a, None, b"to-a").await;
        shared.send(b, None, b"to-b").await;
        shared.send(a, None, b"").await;
        let (src_a, plain_a) = shared.server_recv().await;
        let (src_b, plain_b) = shared.server_recv().await;
        let (src_empty, plain_empty) = shared.server_recv().await;
        assert_eq!(src_a, src_b, "{method}: one outer source for both targets");
        assert_eq!(src_a, src_empty);
        assert_eq!(plain_a, [wire_addr(a), b"to-a".to_vec()].concat());
        assert_eq!(plain_b, [wire_addr(b), b"to-b".to_vec()].concat());
        assert_eq!(plain_empty, wire_addr(a));

        // Unsolicited peers, then the contacted ones.
        shared.reply(src_a, &wire_addr(c), b"from-c").await;
        assert_eq!(shared.client_recv().await, (b"from-c".to_vec(), c));
        shared.reply(src_a, &wire_addr(c6), b"from-c6").await;
        assert_eq!(shared.client_recv().await, (b"from-c6".to_vec(), c6));
        shared.reply(src_a, &wire_addr(b), b"from-b").await;
        assert_eq!(shared.client_recv().await, (b"from-b".to_vec(), b));
        shared.reply(src_a, &wire_addr(a), b"").await;
        assert_eq!(shared.client_recv().await, (Vec::new(), a));

        let mapped = vec![
            4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 7, 0x1f, 0x90,
        ];
        shared.reply(src_a, &mapped, b"mapped").await;
        let expected: SocketAddr = "192.0.2.7:8080".parse().unwrap();
        assert_eq!(shared.client_recv().await, (b"mapped".to_vec(), expected));
    }
}

/// A domain source is accepted only as the dialed domain and port, and is
/// projected to the dialed target; any other name is dropped without DNS.
#[tokio::test]
async fn legacy_udp_domain_source_projects_only_the_dialed_name() {
    let a: SocketAddr = "198.51.100.1:443".parse().unwrap();
    let c: SocketAddr = "203.0.113.9:4000".parse().unwrap();
    let shared = Shared::new("aes-256-gcm", a, Some("Example.COM")).await;

    // Default target keeps its dialed name on the wire; the same IP without
    // the name is a different destination.
    shared.transport.send_packet(b"d").await.unwrap();
    shared.send(a, None, b"ip").await;
    shared.send(a, Some("other.example"), b"other").await;
    let (src, first) = shared.server_recv().await;
    assert_eq!(
        first,
        [wire_domain("Example.COM", 443), b"d".to_vec()].concat()
    );
    assert_eq!(
        shared.server_recv().await.1,
        [wire_addr(a), b"ip".to_vec()].concat()
    );
    assert_eq!(
        shared.server_recv().await.1,
        [wire_addr(a), b"other".to_vec()].concat(),
        "a name other than the dialed one goes out numerically"
    );

    shared
        .reply(src, &wire_domain("other.example", 443), b"x")
        .await;
    shared
        .reply(src, &wire_domain("example.com", 444), b"x")
        .await;
    shared
        .reply(src, &wire_domain("example.com", 443), b"named")
        .await;
    assert_eq!(shared.client_recv().await, (b"named".to_vec(), a));
    shared
        .reply(src, &wire_domain("other.example", 443), b"x")
        .await;
    shared.reply(src, &wire_addr(c), b"after").await;
    assert_eq!(shared.client_recv().await, (b"after".to_vec(), c));

    let overlong = "d".repeat(256);
    shared.send(a, Some(&overlong), b"long").await;
    assert_eq!(
        shared.server_recv().await.1,
        [wire_addr(a), b"long".to_vec()].concat()
    );
}

/// Short, wrong-key, truncated, unknown-ATYP and bad-domain frames each
/// drop only their own datagram.
#[tokio::test]
async fn legacy_udp_bad_frames_drop_only_the_datagram() {
    let a: SocketAddr = "198.51.100.1:53".parse().unwrap();
    let shared = Shared::new("aes-128-gcm", a, None).await;
    shared.send(a, None, b"hello").await;
    let (client, _) = shared.server_recv().await;

    let wrong_key = LegacyPeer::new("aes-128-gcm", "other-password");
    let frames = [
        vec![0u8; 8],
        wrong_key.seal(&[wire_addr(a), b"x".to_vec()].concat()),
        shared.peer.seal(&[1, 1, 2]),
        shared.peer.seal(&[5, 1, 2, 3, 4, 5, 6, 7]),
        shared.peer.seal(&[3, 0, 0, 53]),
        shared.peer.seal(&[3, 2, 0xff, 0xfe, 0, 53, 1]),
        shared.peer.seal(&[]),
    ];
    for frame in &frames {
        shared.server.send_to(frame, client).await.unwrap();
    }
    shared.reply(client, &wire_addr(a), b"genuine").await;
    assert_eq!(shared.client_recv().await, (b"genuine".to_vec(), a));
}

/// The largest datagram that fits one UDP packet crosses both ways; one byte
/// more is refused without hurting the association.
#[tokio::test]
async fn legacy_udp_max_size_boundary() {
    for method in LEGACY_METHODS {
        let a: SocketAddr = "198.51.100.1:53".parse().unwrap();
        let shared = Shared::new(method, a, None).await;
        // 65507 UDP payload = salt + IPv4 address (7) + payload + tag (16).
        let max = 65507 - shared.peer.salt_len() - 7 - 16;
        let payload = vec![0x5a; max];

        shared.send(a, None, &payload).await;
        let (client, plain) = shared.server_recv().await;
        assert_eq!(plain[7..], payload[..]);
        shared.reply(client, &wire_addr(a), &payload).await;
        assert_eq!(shared.client_recv().await, (payload.clone(), a));

        let error = shared
            .transport
            .send_to(a, None, &vec![0; max + 1], false, None)
            .await
            .unwrap_err();
        assert_eq!(
            crate::proxy::io_packet_rejection(&error),
            Some(crate::proxy::PacketRejection::InvalidSize),
            "a socket size refusal is local, not a dead tunnel"
        );
        shared.send(a, None, b"alive").await;
        assert_eq!(shared.server_recv().await.1[7..], b"alive"[..]);
    }
}

/// Dropping a transport closes its socket.
#[tokio::test]
async fn legacy_udp_drop_releases_the_socket() {
    let a: SocketAddr = "198.51.100.1:53".parse().unwrap();
    let shared = Shared::new("aes-128-gcm", a, None).await;
    shared.send(a, None, b"x").await;
    let (client, _) = shared.server_recv().await;
    assert!(
        std::net::UdpSocket::bind(client).is_err(),
        "the live transport owns its source port"
    );
    let Shared { transport, .. } = shared;
    drop(transport);
    drop(std::net::UdpSocket::bind(client).expect("drop closes the transport socket"));
}

/// The core reaches Shadowsocks only through the shared-source dispatch.
#[tokio::test]
async fn shared_source_dispatch_builds_a_shadowsocks_association() {
    let registry = crate::proxy::ProxyRegistry::default_resolver().unwrap();
    assert!(registry.has_shared_source(honk_config::types::NodeProtocol::SS));
    let a: SocketAddr = "198.51.100.1:53".parse().unwrap();
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let node = legacy_node(server.local_addr().unwrap(), "aes-128-gcm");
    let runtime = crate::runtime::NodeRuntime::try_ephemeral(&node).unwrap();
    let transport = registry
        .prepare_shared_source(runtime, a, None, STEP, true)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    transport.send_to(a, None, b"hi", true, None).await.unwrap();
    let mut buf = [0u8; 256];
    let (n, _) = tokio::time::timeout(STEP, server.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert!(n > b"hi".len());
}

/// Minimal SOCKS5 server: no-auth greeting, then a CONNECT it proxies
/// through to the requested address. Twin of
/// `crate::proxy::detour::tests::spawn_fake_socks5`, copied here because
/// that helper is private to its module and the SS rider tests need a
/// front of their own.
async fn spawn_fake_socks5() -> SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
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
                            std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                                buf[0], buf[1], buf[2], buf[3],
                            )),
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
    addr
}

fn socks5_node(name: &str, server: SocketAddr) -> Node {
    let mut node = Node {
        name: name.into(),
        address: server.ip().to_string(),
        port: server.port(),
        outbound: honk_config::node::OutboundConfig::Socks5(Default::default()),
        ..Default::default()
    };
    node.id = node.derive_id();
    node
}

fn ss_node(name: &str, server: SocketAddr, method: &str, password: &str) -> Node {
    let mut node = Node {
        name: name.into(),
        address: server.ip().to_string(),
        port: server.port(),
        outbound: honk_config::node::OutboundConfig::Shadowsocks(
            honk_config::node::ShadowsocksConfig {
                encryption: Some(method.into()),
                password: Some(password.into()),
                ..Default::default()
            },
        ),
        ..Default::default()
    };
    node.id = node.derive_id();
    node
}

/// Fake 2022 TCP server: reads the request handshake (salt, sealed fixed
/// and variable headers), then one data chunk, uppercases it, and answers
/// with the 2022 response prologue (salt, sealed fixed header naming the
/// first payload length, sealed first payload). The target header lives
/// in the variable header, so the data chunk carries no header to skip.
async fn spawn_2022_ss_echo_server() -> SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut server, _) = listener.accept().await.unwrap();
        let method =
            aead2022::Ss2022Method::new("2022-blake3-aes-128-gcm", "AAECAwQFBgcICQoLDA0ODw==")
                .unwrap();
        let mut request_salt = vec![0u8; method.key_len];
        server.read_exact(&mut request_salt).await.unwrap();
        let subkey = method.session_subkey(&request_salt);
        let recv_cipher = method.aead(&subkey).unwrap();
        let mut recv_nonce = vec![0u8; aead2022::NONCE_LEN];
        let mut fixed_sealed = vec![0u8; 11 + aead2022::TAG_LEN];
        server.read_exact(&mut fixed_sealed).await.unwrap();
        let fixed = recv_cipher.open(&recv_nonce, &fixed_sealed).unwrap();
        increment_nonce(&mut recv_nonce);
        assert_eq!(fixed[0], 0, "the request fixed header is a client header");
        let variable_len = u16::from_be_bytes([fixed[9], fixed[10]]) as usize;
        let mut variable_sealed = vec![0u8; variable_len + aead2022::TAG_LEN];
        server.read_exact(&mut variable_sealed).await.unwrap();
        let _variable = recv_cipher.open(&recv_nonce, &variable_sealed).unwrap();
        increment_nonce(&mut recv_nonce);

        // One data chunk: decrypt, uppercase, answer with the prologue.
        let mut buf = vec![0u8; 262144];
        let n = server.read(&mut buf).await.unwrap();
        assert!(n > 0, "the client writes its payload after the handshake");
        let mut pending_len = None;
        let (out_len, _rest) = decrypt_chunks_in_place(
            &recv_cipher,
            &mut recv_nonce,
            &mut pending_len,
            &mut buf,
            n,
            aead2022::TAG_LEN,
        )
        .unwrap();
        let upper: Vec<u8> = buf[..out_len]
            .iter()
            .map(|b| b.to_ascii_uppercase())
            .collect();

        let mut response_salt = vec![0u8; method.key_len];
        rand::rng().fill_bytes(&mut response_salt);
        let send_subkey = method.session_subkey(&response_salt);
        let send_cipher = method.aead(&send_subkey).unwrap();
        let mut send_nonce = vec![0u8; aead2022::NONCE_LEN];
        server.write_all(&response_salt).await.unwrap();
        let mut fixed_response = Vec::with_capacity(11 + method.key_len);
        fixed_response.push(aead2022::HEADER_TYPE_SERVER);
        fixed_response.extend_from_slice(&aead2022::unix_timestamp().to_be_bytes());
        fixed_response.extend_from_slice(&request_salt);
        fixed_response.extend_from_slice(&(upper.len() as u16).to_be_bytes());
        let sealed_fixed = send_cipher.seal(&send_nonce, &fixed_response).unwrap();
        increment_nonce(&mut send_nonce);
        server.write_all(&sealed_fixed).await.unwrap();
        let sealed_first = send_cipher.seal(&send_nonce, &upper).unwrap();
        server.write_all(&sealed_first).await.unwrap();
    });
    server_addr
}

/// One group-detour scene for an SS rider: a Socks5 front in group
/// "front", the SS node, and the path the rider dials through.
struct SsDetourScene {
    generation: std::sync::Arc<crate::runtime::OutboundRuntimeRegistry>,
    path: std::sync::Arc<crate::proxy::detour::DetourPath>,
    ss_runtime: std::sync::Arc<crate::runtime::NodeRuntime>,
}

fn ss_detour_scene(front: Node, ss: Node) -> SsDetourScene {
    use honk_config::node::{Group, GroupPolicy};
    let group = Group {
        name: "front".into(),
        policy: GroupPolicy::Selector,
        nodes: vec![front.id],
        ..Default::default()
    };
    let manager = std::sync::Arc::new(crate::group::GroupManager::new(
        std::slice::from_ref(&group),
        std::slice::from_ref(&front),
    ));
    let generation = std::sync::Arc::new(
        crate::runtime::OutboundRuntimeRegistry::build(&[front, ss.clone()]).unwrap(),
    );
    let path = std::sync::Arc::new(crate::proxy::detour::DetourPath::to_group(
        std::sync::Arc::new(crate::proxy::ProxyRegistry::default_resolver().unwrap()),
        std::sync::Arc::clone(&generation),
        "front",
        std::sync::Arc::clone(&manager),
        honk_config::types::NodeProtocol::SS,
    ));
    let ss_runtime = generation
        .get(&ss.id)
        .expect("the SS node is in the generation");
    SsDetourScene {
        generation,
        path,
        ss_runtime,
    }
}

/// A legacy Shadowsocks rider dials through a group detour: its TCP
/// handshake runs over the already-connected Socks5 front stream.
#[tokio::test]
async fn ss_rider_dials_through_a_group_detour() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let front_addr = spawn_fake_socks5().await;
    let ss_addr = spawn_legacy_ss_echo_server().await;
    let front = socks5_node("front-socks", front_addr);
    let ss = ss_node("ss-legacy", ss_addr, "aes-128-gcm", "test-password");
    let scene = ss_detour_scene(front, ss);
    let handler = ShadowsocksHandler::new();
    let target: SocketAddr = "93.184.216.34:80".parse().unwrap();
    let mut stream = handler
        .dial_runtime_detoured(
            scene.ss_runtime,
            target,
            None,
            std::time::Duration::from_secs(5),
            &scene.path,
        )
        .await
        .expect("the SS handshake runs over the front stream");
    stream.stream.write_all(b"hello").await.unwrap();
    let mut buf = [0u8; 5];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.stream.read_exact(&mut buf),
    )
    .await
    .expect("the echo answers through the detour")
    .unwrap();
    assert_eq!(&buf, b"HELLO");
}

/// A 2022 Shadowsocks rider dials through a group detour: the 2022
/// handshake takes the `aead2022::dial_stream` path, a different
/// generalization point from the legacy one, so it needs its own test.
#[tokio::test]
async fn ss_rider_dials_through_a_group_detour_2022() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let front_addr = spawn_fake_socks5().await;
    let ss_addr = spawn_2022_ss_echo_server().await;
    let front = socks5_node("front-socks", front_addr);
    let ss = ss_node(
        "ss-2022",
        ss_addr,
        "2022-blake3-aes-128-gcm",
        "AAECAwQFBgcICQoLDA0ODw==",
    );
    let scene = ss_detour_scene(front, ss);
    let handler = ShadowsocksHandler::new();
    let target: SocketAddr = "93.184.216.34:80".parse().unwrap();
    let mut stream = handler
        .dial_runtime_detoured(
            scene.ss_runtime,
            target,
            None,
            std::time::Duration::from_secs(5),
            &scene.path,
        )
        .await
        .expect("the 2022 handshake runs over the front stream");
    stream.stream.write_all(b"hello").await.unwrap();
    let mut buf = [0u8; 5];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.stream.read_exact(&mut buf),
    )
    .await
    .expect("the echo answers through the detour")
    .unwrap();
    assert_eq!(&buf, b"HELLO");
}

/// A legacy Shadowsocks node with its own `dialer-proxy` dials through
/// it: the node-level path shares the group path's handshake tail.
#[tokio::test]
async fn ss_rider_dials_through_its_own_detour() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let front_addr = spawn_fake_socks5().await;
    let ss_addr = spawn_legacy_ss_echo_server().await;
    let front = socks5_node("front-socks", front_addr);
    let mut ss = ss_node("ss-legacy", ss_addr, "aes-128-gcm", "test-password");
    ss.detour = Some("front".into());
    ss.id = ss.derive_id();
    let ss_id = ss.id;
    let scene = ss_detour_scene(front, ss);
    assert!(
        scene
            .generation
            .bind_detour(ss_id, std::sync::Arc::clone(&scene.path)),
        "the node detour binds into the generation"
    );
    let handler = ShadowsocksHandler::new();
    let target: SocketAddr = "93.184.216.34:80".parse().unwrap();
    let mut stream = handler
        .dial_runtime(
            scene.ss_runtime,
            target,
            None,
            std::time::Duration::from_secs(5),
        )
        .await
        .expect("the SS handshake runs over its own detour");
    stream.stream.write_all(b"hello").await.unwrap();
    let mut buf = [0u8; 5];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.stream.read_exact(&mut buf),
    )
    .await
    .expect("the echo answers through the detour")
    .unwrap();
    assert_eq!(&buf, b"HELLO");
}

/// Fake legacy-AEAD server that forwards instead of echoing: after the
/// handshake it reads the target header out of the first decrypted chunk,
/// TCP-connects there, and relays both directions (decrypting inbound
/// chunks, sealing outbound bytes into chunks). The target is whatever
/// the rider asked the front to reach.
async fn spawn_forwarding_ss_server() -> SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut server, _) = listener.accept().await.unwrap();
        let method = "aes-128-gcm";
        let password = "test-password";
        let conf = CipherConf::for_method(method).unwrap();
        let master = ShadowsocksHandler::master_key(password, conf.key_len);

        let mut c2s_salt = vec![0u8; conf.salt_len];
        server.read_exact(&mut c2s_salt).await.unwrap();
        let mut c2s_subkey = vec![0u8; conf.key_len];
        hkdf_sha1_derive(&master, &c2s_salt, &mut c2s_subkey);
        let c2s_cipher = AeadCipher::new(method, &c2s_subkey).unwrap();
        let mut c2s_nonce = vec![0u8; conf.nonce_len];

        let mut s2c_salt = vec![0u8; conf.salt_len];
        rand::rng().fill_bytes(&mut s2c_salt);
        server.write_all(&s2c_salt).await.unwrap();
        let mut s2c_subkey = vec![0u8; conf.key_len];
        hkdf_sha1_derive(&master, &s2c_salt, &mut s2c_subkey);
        let s2c_cipher = AeadCipher::new(method, &s2c_subkey).unwrap();
        let mut s2c_nonce = vec![0u8; conf.nonce_len];

        // First decrypted chunk opens with the 7-byte IPv4 target header.
        let mut buf = vec![0u8; 262144];
        let mut pending_len = None;
        let mut plain: Vec<u8> = Vec::new();
        let mut carry = 0usize;
        let target = loop {
            let n = server.read(&mut buf[carry..]).await.unwrap();
            if n == 0 {
                return;
            }
            let total = carry + n;
            let (out_len, rest) = decrypt_chunks_in_place(
                &c2s_cipher,
                &mut c2s_nonce,
                &mut pending_len,
                &mut buf,
                total,
                conf.tag_len,
            )
            .unwrap();
            plain.extend_from_slice(&buf[..out_len]);
            if rest > 0 {
                buf.copy_within(out_len..out_len + rest, 0);
            }
            carry = rest;
            if plain.len() >= 7 {
                let ip = std::net::Ipv4Addr::new(plain[1], plain[2], plain[3], plain[4]);
                let port = u16::from_be_bytes([plain[5], plain[6]]);
                break SocketAddr::new(ip.into(), port);
            }
        };
        let mut upstream = match tokio::net::TcpStream::connect(target).await {
            Ok(upstream) => upstream,
            Err(_) => return,
        };
        // Bytes already decrypted past the header belong to the target.
        if plain.len() > 7 {
            upstream.write_all(&plain[7..]).await.unwrap();
        }
        let (mut ss_read, mut ss_write) = server.into_split();
        let (mut up_read, mut up_write) = upstream.into_split();
        let client_to_target = async {
            let mut buf = vec![0u8; 262144];
            let mut carry = 0usize;
            let mut pending_len = None;
            loop {
                let n = ss_read.read(&mut buf[carry..]).await.unwrap();
                if n == 0 {
                    break;
                }
                let total = carry + n;
                let (out_len, rest) = decrypt_chunks_in_place(
                    &c2s_cipher,
                    &mut c2s_nonce,
                    &mut pending_len,
                    &mut buf,
                    total,
                    conf.tag_len,
                )
                .unwrap();
                if out_len > 0 {
                    up_write.write_all(&buf[..out_len]).await.unwrap();
                }
                if rest > 0 {
                    buf.copy_within(out_len..out_len + rest, 0);
                }
                carry = rest;
            }
        };
        let target_to_client = async {
            let mut buf = vec![0u8; 262144];
            loop {
                let n = up_read.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                let mut sealed = Vec::new();
                seal_chunks_into(&s2c_cipher, &mut s2c_nonce, &buf[..n], &mut sealed).unwrap();
                ss_write.write_all(&sealed).await.unwrap();
            }
        };
        tokio::join!(client_to_target, target_to_client);
    });
    server_addr
}

/// A Socks5 rider dials through a Shadowsocks front: the front's
/// rewritten `dial_runtime` must carry the rider's stream to the
/// rider's target (a Socks5 server here), exactly as production dials
/// every SS node through the control plane.
#[tokio::test]
async fn socks5_rider_dials_through_a_shadowsocks_front() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // Final listener: the Socks5 target CONNECTs here.
    let final_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let final_addr = final_listener.local_addr().unwrap();
    let accepted = tokio::spawn(async move {
        let (mut stream, _) = final_listener.accept().await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        buf
    });
    // The rider's target: a Socks5 server that proxies CONNECTs through.
    let socks_target = spawn_fake_socks5().await;
    // The front: a Shadowsocks server that forwards to the header target.
    let ss_addr = spawn_forwarding_ss_server().await;
    let front = ss_node("ss-front", ss_addr, "aes-128-gcm", "test-password");
    let rider = socks5_node("socks-rider", socks_target);
    let scene = ss_detour_scene(front, rider.clone());
    assert!(
        scene
            .generation
            .bind_detour(rider.id, std::sync::Arc::clone(&scene.path)),
        "the rider detour binds into the generation"
    );
    let rider_runtime = scene
        .generation
        .get(&rider.id)
        .expect("the rider is in the generation");
    let handler = crate::proxy::socks5::Socks5Handler::new();
    // The dial target is the final destination. The front is dialled
    // with the rider node's own server address (the Socks5 server), so
    // the Socks5 CONNECT inside the handshake names this target and the
    // fake Socks5 server proxies it to the final listener.
    let mut stream = handler
        .dial_runtime(
            rider_runtime,
            final_addr,
            None,
            std::time::Duration::from_secs(5),
        )
        .await
        .expect("the Socks5 handshake runs over the SS front stream");
    stream.stream.write_all(b"ping").await.unwrap();
    // Flush explicitly: the codec stream may hold sealed bytes until a
    // later write or read, and this test reads nothing back.
    stream.stream.flush().await.unwrap();
    let received = tokio::time::timeout(std::time::Duration::from_secs(10), accepted)
        .await
        .expect("the final listener answers within 10s");
    assert_eq!(
        received.unwrap(),
        *b"ping",
        "the rider's bytes reach the final listener through the SS front"
    );
}

/// A Shadowsocks node that names a dialer-proxy must not dial UDP directly:
/// the UDP dial is refused before any packet is sent. (The sandbox DNS
/// resolves any name, so this pins the refusal itself, not the refusal's
/// order relative to resolution; the refusal is the first statement in
/// `udp_transport`, which is what orders it before resolution.)
#[tokio::test]
async fn ss_udp_transport_refuses_a_node_with_a_detour() {
    let mut node = ss_node(
        "ss-a",
        "127.0.0.1:1".parse().unwrap(),
        "aes-128-gcm",
        "test-password",
    );
    node.address = "ss.invalid:8388".into();
    node.detour = Some("front".into());
    node.id = node.derive_id();
    let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let error = ShadowsocksHandler::new()
        .dial_udp_transport(&node, target, None, std::time::Duration::from_secs(3))
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("node ss-a: shadowsocks UDP cannot carry detour \"front\""),
        "unexpected error: {error:#}"
    );
}

/// Same refusal for the 2022 cipher family: the refusal sits before the
/// crypto branch, so both families must hit it.
#[tokio::test]
async fn ss_udp_transport_2022_refuses_a_node_with_a_detour() {
    let mut node = ss_node(
        "ss-a",
        "127.0.0.1:1".parse().unwrap(),
        "2022-blake3-aes-128-gcm",
        "AAECAwQFBgcICQoLDA0ODw==",
    );
    node.address = "ss.invalid:8388".into();
    node.detour = Some("front".into());
    node.id = node.derive_id();
    let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let error = ShadowsocksHandler::new()
        .dial_udp_transport(&node, target, None, std::time::Duration::from_secs(3))
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("node ss-a: shadowsocks UDP cannot carry detour \"front\""),
        "unexpected error: {error:#}"
    );
}

/// `dialer-proxy: direct` names no detour: the dial proceeds past the
/// refusal and builds a transport. This is a control: it passes before the
/// fix too, and guards the exemption once the refusal lands.
#[tokio::test]
async fn ss_udp_transport_direct_detour_is_not_a_detour() {
    let mut node = ss_node(
        "ss-a",
        "127.0.0.1:1".parse().unwrap(),
        "aes-128-gcm",
        "test-password",
    );
    node.detour = Some("direct".into());
    node.id = node.derive_id();
    let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let transport = ShadowsocksHandler::new()
        .dial_udp_transport(&node, target, None, std::time::Duration::from_secs(3))
        .await
        .unwrap();
    assert_eq!(transport.relay_addr(), target);
}

/// Control: the same node without a detour dials UDP fine, so the refusal
/// above is caused by the detour, not by a broken node.
#[tokio::test]
async fn ss_udp_transport_without_a_detour_still_dials() {
    let server = spawn_legacy_udp_echo_server().await;
    let node = ss_node("ss-a", server, "aes-128-gcm", "test-password");
    let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let transport = ShadowsocksHandler::new()
        .dial_udp_transport(&node, target, None, std::time::Duration::from_secs(3))
        .await
        .unwrap();
    assert_eq!(transport.relay_addr(), target);
}

async fn spawn_legacy_udp_echo_server() -> SocketAddr {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let server_crypto = LegacyUdpCrypto::new("aes-128-gcm", "test-password").unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 65536];
        loop {
            let (n, src) = server.recv_from(&mut buf).await.unwrap();
            let payload = server_crypto.open(&buf[..n]).unwrap();
            let reply: Vec<u8> = payload
                .payload()
                .iter()
                .map(|b| b.to_ascii_uppercase())
                .collect();
            let socks = addr::encode_address("8.8.8.8:53".parse().unwrap(), None).unwrap();
            let packet = server_crypto.seal(&socks, &reply).unwrap();
            server.send_to(&packet, src).await.unwrap();
        }
    });
    server_addr
}
