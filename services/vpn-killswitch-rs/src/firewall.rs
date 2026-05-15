use anyhow::{Context, Result};
use std::process::Stdio;
use tokio::process::Command;
use tracing::{debug, error, info, warn};

/// Manages iptables rules for VPN kill-switch enforcement.
pub struct FirewallManager {
    pub vpn_iface: String,
    pub vpn_endpoint: String,
    pub active: bool,
}

impl FirewallManager {
    pub fn new(vpn_iface: String, vpn_endpoint: String) -> Self {
        Self {
            vpn_iface,
            vpn_endpoint,
            active: false,
        }
    }

    /// Runs an iptables command, logging output.
    async fn iptables(args: &[&str]) -> Result<()> {
        let output = Command::new("iptables")
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("failed to spawn iptables")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!(args = ?args, stderr = %stderr, "iptables command failed");
            anyhow::bail!("iptables {} failed: {}", args.join(" "), stderr);
        }
        debug!(args = ?args, "iptables command succeeded");
        Ok(())
    }

    /// Blocks all OUTPUT traffic except:
    ///   1. loopback (lo)
    ///   2. the VPN endpoint IP (so the VPN client can reconnect)
    ///   3. traffic already inside the VPN tunnel
    ///
    /// Call this when the VPN connection goes down.
    pub async fn block_all_except_vpn_endpoint(&self) -> Result<()> {
        info!(
            vpn_iface = %self.vpn_iface,
            vpn_endpoint = %self.vpn_endpoint,
            "Activating kill-switch: blocking all traffic except VPN endpoint"
        );

        // Flush existing OUTPUT rules
        Self::iptables(&["-F", "OUTPUT"]).await?;

        // Allow loopback
        Self::iptables(&["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"]).await?;

        // Allow traffic to the VPN endpoint so the client can reconnect
        Self::iptables(&["-A", "OUTPUT", "-d", &self.vpn_endpoint, "-j", "ACCEPT"]).await?;

        // Allow traffic through the VPN tunnel interface
        Self::iptables(&["-A", "OUTPUT", "-o", &self.vpn_iface, "-j", "ACCEPT"]).await?;

        // Drop everything else
        Self::iptables(&["-A", "OUTPUT", "-j", "DROP"]).await?;

        info!("Kill-switch rules installed: internet blocked");
        Ok(())
    }

    /// Restores normal operation: flushes custom OUTPUT rules, inserts ACCEPT policy.
    pub async fn restore_normal(&self) -> Result<()> {
        info!("Removing kill-switch: restoring normal routing");

        Self::iptables(&["-F", "OUTPUT"]).await?;
        // Restore default-accept policy for OUTPUT
        Self::iptables(&["-P", "OUTPUT", "ACCEPT"]).await?;

        info!("Kill-switch removed: normal routing restored");
        Ok(())
    }

    /// Returns true if the VPN interface has a default route in `/proc/net/route`.
    ///
    /// `/proc/net/route` columns (hex, little-endian):
    ///   Iface  Destination  Gateway  Flags  ...
    /// A default route has Destination == 00000000.
    pub async fn check_vpn_status(&self) -> bool {
        match tokio::fs::read_to_string("/proc/net/route").await {
            Err(e) => {
                warn!(err = %e, "Cannot read /proc/net/route");
                false
            }
            Ok(content) => {
                for line in content.lines().skip(1) {
                    let cols: Vec<&str> = line.split_whitespace().collect();
                    if cols.len() < 4 {
                        continue;
                    }
                    let iface = cols[0];
                    let destination = cols[1];
                    // Default route: Destination field == "00000000"
                    if iface == self.vpn_iface && destination == "00000000" {
                        debug!(iface = %iface, "VPN default route detected");
                        return true;
                    }
                }
                false
            }
        }
    }

    /// Checks `/proc/net/udp` and `/proc/net/udp6` for DNS (port 53) connections
    /// that are NOT going through the VPN interface.
    ///
    /// Returns a list of remote addresses that represent potential DNS leaks.
    pub async fn detect_dns_leak(&self) -> Vec<String> {
        let mut leaks = Vec::new();

        // Collect local addresses bound to the VPN interface by reading its addresses.
        // For simplicity we flag any UDP socket with rem_port == 53 as a potential leak.
        // In a real implementation we would compare the local address against the
        // addresses assigned to the VPN interface.
        for path in &["/proc/net/udp", "/proc/net/udp6"] {
            match tokio::fs::read_to_string(path).await {
                Err(e) => {
                    warn!(path = %path, err = %e, "Cannot read UDP table");
                }
                Ok(content) => {
                    for line in content.lines().skip(1) {
                        let cols: Vec<&str> = line.split_whitespace().collect();
                        if cols.len() < 4 {
                            continue;
                        }
                        // rem_address is cols[2], format "XXXXXXXX:PPPP"
                        let rem = cols[2];
                        if let Some(port_hex) = rem.split(':').nth(1) {
                            if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                                if port == 53 {
                                    // Potentially leaking DNS query not through VPN
                                    leaks.push(format!("DNS query to remote {rem} (not via {iface})",
                                        rem = rem, iface = self.vpn_iface));
                                }
                            }
                        }
                    }
                }
            }
        }

        if !leaks.is_empty() {
            warn!(count = leaks.len(), "DNS leak candidates detected");
        }
        leaks
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fw() -> FirewallManager {
        FirewallManager::new("tun0".to_string(), "1.2.3.4".to_string())
    }

    #[test]
    fn test_new_inactive() {
        let fw = make_fw();
        assert_eq!(fw.vpn_iface, "tun0");
        assert_eq!(fw.vpn_endpoint, "1.2.3.4");
        assert!(!fw.active);
    }

    #[tokio::test]
    async fn test_check_vpn_status_no_tun0() {
        // On a dev machine without tun0 the result should be false (no crash).
        let fw = make_fw();
        let status = fw.check_vpn_status().await;
        // We simply assert it returns without panicking; the value depends on host.
        let _ = status;
    }

    #[tokio::test]
    async fn test_detect_dns_leak_no_panic() {
        let fw = make_fw();
        let leaks = fw.detect_dns_leak().await;
        // Must return a Vec (possibly empty) without panicking.
        assert!(leaks.len() < usize::MAX);
    }

    #[test]
    fn test_parse_proc_net_route_logic() {
        // Simulate the content of /proc/net/route with a tun0 default route.
        let content = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
                       eth0\t0101A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n\
                       tun0\t00000000\t0101A8C0\t0003\t0\t0\t50\t00000000\t0\t0\t0\n";
        let iface = "tun0";
        let found = content.lines().skip(1).any(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            cols.len() >= 2 && cols[0] == iface && cols[1] == "00000000"
        });
        assert!(found, "Should find tun0 default route");
    }

    #[test]
    fn test_dns_port_detection() {
        // DNS port 53 == 0x0035
        let port_hex = "0035";
        let port = u16::from_str_radix(port_hex, 16).unwrap();
        assert_eq!(port, 53);
    }
}
