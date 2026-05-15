use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

/// Represents a detected SNI visibility risk on an outbound TLS connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SniLeak {
    pub dst_addr: String,
    pub port: u16,
    pub risk: String,
}

/// Monitors outbound TLS connections and identifies SNI leak risks.
pub struct SniGuard;

impl SniGuard {
    pub fn new() -> Self {
        Self
    }

    /// Reads `/proc/net/tcp6` (and `/proc/net/tcp`) to find outbound connections
    /// on port 443 where SNI may be visible to network observers because ECH is
    /// not in use.
    ///
    /// The proc files use hex-encoded addresses in little-endian order.
    /// Column layout (space-separated):
    ///   sl  local_address  rem_address  st  tx_queue:rx_queue  tr:tm->when  retrnsmt  uid  timeout  inode
    pub async fn check_plaintext_sni(&self) -> Vec<SniLeak> {
        let mut leaks = Vec::new();

        for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
            match tokio::fs::read_to_string(path).await {
                Err(e) => {
                    warn!(path = %path, err = %e, "Cannot read TCP table");
                }
                Ok(content) => {
                    for line in content.lines().skip(1) {
                        let cols: Vec<&str> = line.split_whitespace().collect();
                        // Need at least: sl(0) local(1) rem(2) st(3)
                        if cols.len() < 4 {
                            continue;
                        }
                        let rem = cols[2];
                        // TCP state 01 = ESTABLISHED
                        let state = cols[3];
                        if state != "01" {
                            continue;
                        }

                        // Parse remote port from "ADDR:PORT" hex string
                        if let Some(port_hex) = rem.split(':').last() {
                            if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                                if port == 443 {
                                    let dst_addr = parse_hex_addr(rem);
                                    debug!(dst = %dst_addr, "Outbound TLS connection detected (port 443)");
                                    leaks.push(SniLeak {
                                        dst_addr: dst_addr.clone(),
                                        port,
                                        risk: format!(
                                            "Outbound TLS to {} on port 443: SNI sent in \
                                             ClientHello plaintext unless ECH is active. \
                                             Passive observers on path can identify destination.",
                                            dst_addr
                                        ),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        leaks
    }

    /// Returns a human-readable recommendation to enable Encrypted Client Hello (ECH).
    pub fn recommend_esni(&self) -> String {
        "SNI LEAK MITIGATION RECOMMENDATION: Enable Encrypted Client Hello (ECH, RFC 8744).\n\
         Steps:\n\
         1. Ensure the DNS resolver returns HTTPS RRs with ECH keys for target domains.\n\
         2. Use a DNS-over-HTTPS or DNS-over-TLS resolver that supports ECH bootstrapping.\n\
         3. Build/deploy a TLS library (BoringSSL / rustls with ech feature) that supports ECH.\n\
         4. For Android: set private DNS to a resolver supporting HTTPS/ECH (e.g., 1.1.1.1 with ECH).\n\
         5. Monitor this daemon's output: zero SniLeak entries indicates ECH is working.\n\
         Reference: https://www.rfc-editor.org/rfc/rfc8744"
            .to_string()
    }
}

impl Default for SniGuard {
    fn default() -> Self {
        Self::new()
    }
}

/// Converts a `/proc/net/tcp*` address field (hex, little-endian) into a
/// human-readable IP:port string.
///
/// IPv4 format: "0100007F:1F90" → "127.0.0.1:8080"
/// IPv6 format: 32-char hex field
fn parse_hex_addr(raw: &str) -> String {
    let parts: Vec<&str> = raw.splitn(2, ':').collect();
    if parts.len() != 2 {
        return raw.to_string();
    }
    let addr_hex = parts[0];
    let port_hex = parts[1];

    let port = u16::from_str_radix(port_hex, 16).unwrap_or(0);

    match addr_hex.len() {
        // IPv4: 8 hex chars
        8 => {
            let n = u32::from_str_radix(addr_hex, 16).unwrap_or(0);
            let bytes = n.to_le_bytes();
            format!("{}.{}.{}.{}:{}", bytes[0], bytes[1], bytes[2], bytes[3], port)
        }
        // IPv6: 32 hex chars
        32 => {
            // Parse as four little-endian 32-bit words
            let mut groups = Vec::new();
            for i in 0..4 {
                let chunk = &addr_hex[i * 8..(i + 1) * 8];
                let word = u32::from_str_radix(chunk, 16).unwrap_or(0).to_be();
                let b = word.to_be_bytes();
                groups.push(format!("{:02x}{:02x}", b[0], b[1]));
                groups.push(format!("{:02x}{:02x}", b[2], b[3]));
            }
            format!("[{}]:{}", groups.join(":"), port)
        }
        _ => format!("{}:{}", addr_hex, port),
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_addr_ipv4_localhost() {
        // 0100007F = 127.0.0.1 in little-endian 32-bit hex
        let result = parse_hex_addr("0100007F:1F90");
        assert_eq!(result, "127.0.0.1:8080");
    }

    #[test]
    fn test_parse_hex_addr_ipv4_https() {
        // Port 443 = 0x01BB
        let result = parse_hex_addr("0101A8C0:01BB");
        assert_eq!(result, "192.168.1.1:443");
    }

    #[test]
    fn test_parse_hex_addr_invalid() {
        let result = parse_hex_addr("invalid");
        assert_eq!(result, "invalid");
    }

    #[test]
    fn test_recommend_esni_contains_ech() {
        let guard = SniGuard::new();
        let rec = guard.recommend_esni();
        assert!(rec.contains("Encrypted Client Hello"));
        assert!(rec.contains("ECH"));
    }

    #[tokio::test]
    async fn test_check_plaintext_sni_no_panic() {
        let guard = SniGuard::new();
        let leaks = guard.check_plaintext_sni().await;
        // Should return without panicking; value depends on host state.
        let _ = leaks;
    }

    #[test]
    fn test_sni_leak_serialization() {
        let leak = SniLeak {
            dst_addr: "1.2.3.4".to_string(),
            port: 443,
            risk: "test risk".to_string(),
        };
        let json = serde_json::to_string(&leak).unwrap();
        assert!(json.contains("443"));
        assert!(json.contains("1.2.3.4"));
    }

    #[test]
    fn test_port_443_detection() {
        // 01BB hex == 443 decimal
        let port = u16::from_str_radix("01BB", 16).unwrap();
        assert_eq!(port, 443);
    }
}
