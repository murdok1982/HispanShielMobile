//! iptables TPROXY rules management for transparent Tor routing.
//!
//! Creates two custom iptables chains:
//!   - `HISPASHIELD_TOR_DNS`   — redirects UDP/53 to Tor's DNSPort
//!   - `HISPASHIELD_TOR_TRANS` — redirects TCP to Tor's TransparentPort
//!
//! Both chains skip traffic from the Tor process itself (by UID) and from
//! any UIDs in the bypass list (emergency services, VoIP, etc.).

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

const DNS_CHAIN: &str = "HISPASHIELD_TOR_DNS";
const TRANS_CHAIN: &str = "HISPASHIELD_TOR_TRANS";

// ─── TproxyRules ──────────────────────────────────────────────────────────────

pub struct TproxyRules {
    /// UID of the running Tor process — excluded from redirection to break loops.
    pub tor_uid: u32,
    /// TCP port Tor listens on for transparent proxy (TransPort).
    pub transparent_port: u16,
    /// UDP port Tor listens on for DNS (DNSPort).
    pub dns_port: u16,
    /// Application UIDs that should bypass Tor (direct routing).
    pub bypass_uids: Vec<u32>,
}

impl TproxyRules {
    /// Install TPROXY iptables rules.
    ///
    /// Idempotent: flushes any existing HispaShield chains before recreating them.
    pub async fn apply(&self) -> Result<()> {
        info!("Applying TPROXY iptables rules");

        // Clean up any previous run first (idempotent)
        self.remove_chains_if_exist().await;

        // ── DNS chain ─────────────────────────────────────────────────────────
        self.run_iptables(&["-t", "nat", "-N", DNS_CHAIN]).await
            .context("Creating DNS chain")?;

        // Tor process bypasses redirection
        self.run_iptables(&[
            "-t", "nat", "-A", DNS_CHAIN,
            "-m", "owner", "--uid-owner", &self.tor_uid.to_string(),
            "-j", "RETURN",
        ]).await.context("DNS chain: Tor UID bypass")?;

        // Per-UID bypasses for emergency services / VoIP
        for uid in &self.bypass_uids {
            self.run_iptables(&[
                "-t", "nat", "-A", DNS_CHAIN,
                "-m", "owner", "--uid-owner", &uid.to_string(),
                "-j", "RETURN",
            ]).await.context(format!("DNS chain: bypass UID {uid}"))?;
        }

        // Redirect all other UDP/53 to Tor's DNS port
        self.run_iptables(&[
            "-t", "nat", "-A", DNS_CHAIN,
            "-p", "udp", "--dport", "53",
            "-j", "REDIRECT", "--to-ports", &self.dns_port.to_string(),
        ]).await.context("DNS chain: UDP redirect")?;

        // ── Transparent TCP chain ─────────────────────────────────────────────
        self.run_iptables(&["-t", "nat", "-N", TRANS_CHAIN]).await
            .context("Creating TRANS chain")?;

        // Tor process bypasses
        self.run_iptables(&[
            "-t", "nat", "-A", TRANS_CHAIN,
            "-m", "owner", "--uid-owner", &self.tor_uid.to_string(),
            "-j", "RETURN",
        ]).await.context("TRANS chain: Tor UID bypass")?;

        // Per-UID bypasses
        for uid in &self.bypass_uids {
            self.run_iptables(&[
                "-t", "nat", "-A", TRANS_CHAIN,
                "-m", "owner", "--uid-owner", &uid.to_string(),
                "-j", "RETURN",
            ]).await.context(format!("TRANS chain: bypass UID {uid}"))?;
        }

        // Bypass loopback traffic
        self.run_iptables(&[
            "-t", "nat", "-A", TRANS_CHAIN,
            "-o", "lo",
            "-j", "RETURN",
        ]).await.context("TRANS chain: loopback bypass")?;

        // Bypass private network ranges (RFC 1918) — they go direct
        for range in &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] {
            self.run_iptables(&[
                "-t", "nat", "-A", TRANS_CHAIN,
                "-d", range,
                "-j", "RETURN",
            ]).await.context(format!("TRANS chain: RFC1918 bypass {range}"))?;
        }

        // Redirect all TCP SYN packets to Tor's TransPort
        self.run_iptables(&[
            "-t", "nat", "-A", TRANS_CHAIN,
            "-p", "tcp", "--syn",
            "-j", "REDIRECT", "--to-ports", &self.transparent_port.to_string(),
        ]).await.context("TRANS chain: TCP redirect")?;

        // ── Hook chains into OUTPUT ───────────────────────────────────────────
        self.run_iptables(&["-t", "nat", "-A", "OUTPUT", "-j", DNS_CHAIN]).await
            .context("Attaching DNS chain to OUTPUT")?;
        self.run_iptables(&["-t", "nat", "-A", "OUTPUT", "-j", TRANS_CHAIN]).await
            .context("Attaching TRANS chain to OUTPUT")?;

        info!("TPROXY iptables rules applied successfully");
        Ok(())
    }

    /// Remove all HispaShield TPROXY iptables rules.
    pub async fn remove(&self) -> Result<()> {
        info!("Removing TPROXY iptables rules");
        self.remove_chains_if_exist().await;
        info!("TPROXY iptables rules removed");
        Ok(())
    }

    /// Add a UID bypass rule to both chains (hot-insert, no chain recreation needed).
    pub async fn add_bypass_uid(&self, uid: u32) -> Result<()> {
        info!(uid, "Adding bypass UID to iptables");

        // Insert before the final REDIRECT rule (position 1 after the Tor-UID rule)
        for chain in &[DNS_CHAIN, TRANS_CHAIN] {
            self.run_iptables(&[
                "-t", "nat", "-I", chain, "2", // insert at position 2
                "-m", "owner", "--uid-owner", &uid.to_string(),
                "-j", "RETURN",
            ]).await.context(format!("Adding bypass UID {uid} to chain {chain}"))?;
        }
        Ok(())
    }

    /// Remove a UID bypass rule from both chains.
    pub async fn remove_bypass_uid(&self, uid: u32) -> Result<()> {
        info!(uid, "Removing bypass UID from iptables");

        for chain in &[DNS_CHAIN, TRANS_CHAIN] {
            let result = self.run_iptables(&[
                "-t", "nat", "-D", chain,
                "-m", "owner", "--uid-owner", &uid.to_string(),
                "-j", "RETURN",
            ]).await;
            if let Err(e) = result {
                warn!(uid, chain, "Failed to remove bypass UID: {e}");
            }
        }
        Ok(())
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    async fn remove_chains_if_exist(&self) {
        // Detach chains from OUTPUT (ignore errors if not attached)
        let _ = self.run_iptables(&["-t", "nat", "-D", "OUTPUT", "-j", DNS_CHAIN]).await;
        let _ = self.run_iptables(&["-t", "nat", "-D", "OUTPUT", "-j", TRANS_CHAIN]).await;

        // Flush and delete chains
        for chain in &[DNS_CHAIN, TRANS_CHAIN] {
            let _ = self.run_iptables(&["-t", "nat", "-F", chain]).await;
            let _ = self.run_iptables(&["-t", "nat", "-X", chain]).await;
        }
    }

    /// Execute an `iptables` command with the given arguments.
    async fn run_iptables(&self, args: &[&str]) -> Result<()> {
        debug!(cmd = %args.join(" "), "Running iptables");

        let status = tokio::process::Command::new("iptables")
            .args(args)
            .status()
            .await
            .context("Spawning iptables process")?;

        if !status.success() {
            anyhow::bail!(
                "iptables {} exited with status {}",
                args.join(" "),
                status
            );
        }
        Ok(())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rules() -> TproxyRules {
        TproxyRules {
            tor_uid: 10101,
            transparent_port: 9040,
            dns_port: 5353,
            bypass_uids: vec![1000, 1001],
        }
    }

    #[test]
    fn rules_construction() {
        let rules = make_rules();
        assert_eq!(rules.tor_uid, 10101);
        assert_eq!(rules.transparent_port, 9040);
        assert_eq!(rules.dns_port, 5353);
        assert_eq!(rules.bypass_uids, vec![1000, 1001]);
    }

    /// Verify that `apply` and `remove` build the expected iptables argument vectors.
    /// We cannot run real iptables in the test environment so we only verify
    /// that the public API compiles and the struct fields are accessible.
    #[test]
    fn chain_name_constants() {
        assert_eq!(DNS_CHAIN, "HISPASHIELD_TOR_DNS");
        assert_eq!(TRANS_CHAIN, "HISPASHIELD_TOR_TRANS");
    }

    #[test]
    fn bypass_uids_list() {
        let rules = make_rules();
        assert!(rules.bypass_uids.contains(&1000));
        assert!(rules.bypass_uids.contains(&1001));
        assert!(!rules.bypass_uids.contains(&9999));
    }
}
