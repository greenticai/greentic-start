use std::net::{SocketAddr, TcpListener};

/// Try to bind to the preferred port; if it is already in use, scan upwards
/// through `range` consecutive ports and return the first one that is available.
/// The listener is dropped immediately after the check so the caller can bind
/// the port itself.
pub fn find_available_port(listen_addr: &str, preferred: u16, range: u16) -> anyhow::Result<u16> {
    for offset in 0..=range {
        let port = preferred.checked_add(offset).unwrap_or(preferred);
        let addr: SocketAddr = format!("{listen_addr}:{port}")
            .parse()
            .map_err(|err| anyhow::anyhow!("invalid address {listen_addr}:{port}: {err}"))?;
        match TcpListener::bind(addr) {
            Ok(_listener) => return Ok(port),
            Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(err) => {
                return Err(anyhow::anyhow!(
                    "failed to check port {port} on {listen_addr}: {err}"
                ));
            }
        }
    }
    Err(anyhow::anyhow!(
        "no available port found in range {}..={}",
        preferred,
        preferred.saturating_add(range)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_preferred_port_when_available() {
        // Use a high ephemeral port that is very likely free.
        let port = find_available_port("127.0.0.1", 19876, 10).expect("should find port");
        assert_eq!(port, 19876);
    }

    #[test]
    fn cycles_to_next_port_when_preferred_is_taken() {
        // Bind the preferred port so it is busy.
        let preferred = 19877u16;
        let _hold = TcpListener::bind(format!("127.0.0.1:{preferred}")).expect("bind preferred");
        let port = find_available_port("127.0.0.1", preferred, 10).expect("should find next port");
        assert!(port > preferred && port <= preferred + 10);
    }

    #[test]
    fn returns_error_when_no_port_available() {
        // Bind a tiny range and exhaust it.
        let base = 19880u16;
        let _hold0 = TcpListener::bind(format!("127.0.0.1:{}", base)).expect("bind 0");
        let _hold1 = TcpListener::bind(format!("127.0.0.1:{}", base + 1)).expect("bind 1");
        let result = find_available_port("127.0.0.1", base, 1);
        assert!(result.is_err());
    }
}
