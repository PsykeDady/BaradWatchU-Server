use std::{
    net::{SocketAddr, UdpSocket},
    time::{Duration, Instant},
};

const PORT: u16 = 7444;

/// Find an address for a public identity already imported from a local file.
/// Replies are hints only; the subsequent connection verifies the pinned Ed25519 key.
pub fn find(device_id: &str) -> Vec<String> {
    let Ok(socket) = UdpSocket::bind("0.0.0.0:0") else {
        return vec![];
    };
    let _ = socket.set_broadcast(true);
    let _ = socket.set_read_timeout(Some(Duration::from_millis(250)));
    let query = format!("BARADWATCHU_DISCOVER_V1 {device_id}");
    for destination in [
        format!("255.255.255.255:{PORT}"),
        format!("127.0.0.1:{PORT}"),
    ] {
        let _ = socket.send_to(query.as_bytes(), destination);
    }
    let deadline = Instant::now() + Duration::from_millis(1500);
    let mut found = Vec::new();
    let mut packet = [0u8; 256];
    while Instant::now() < deadline {
        let Ok((length, source)) = socket.recv_from(&mut packet) else {
            continue;
        };
        let Ok(reply) = std::str::from_utf8(&packet[..length]) else {
            continue;
        };
        let mut words = reply.split(' ');
        if words.next() != Some("BARADWATCHU_FOUND_V1") || words.next() != Some(device_id) {
            continue;
        }
        let Some(port) = words.next().and_then(|value| value.parse::<u16>().ok()) else {
            continue;
        };
        if port == 0 || words.next().is_some() {
            continue;
        }
        let endpoint = SocketAddr::new(source.ip(), port).to_string();
        if !found.contains(&endpoint) {
            found.push(endpoint);
        }
    }
    found
}
