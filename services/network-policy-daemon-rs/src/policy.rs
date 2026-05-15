use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, warn};

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("No rule found for UID {0}")]
    NoRule(u32),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRule {
    pub uid: u32,
    pub allow_domains: Vec<String>,
    pub deny_domains: Vec<String>,
    pub deny_all: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
    DefaultDeny,
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Decision::Allow => write!(f, "ALLOW"),
            Decision::Deny => write!(f, "DENY"),
            Decision::DefaultDeny => write!(f, "DEFAULT_DENY"),
        }
    }
}

pub struct PolicyEngine {
    rules: HashMap<u32, NetworkRule>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            rules: HashMap::new(),
        }
    }

    pub fn load_from_file(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            anyhow::anyhow!("Failed to read policy file '{}': {}", path, e)
        })?;
        let rule_list: Vec<NetworkRule> = serde_json::from_str(&content)?;
        let mut rules = HashMap::new();
        for rule in rule_list {
            rules.insert(rule.uid, rule);
        }
        tracing::info!("Loaded {} network policy rules from {}", rules.len(), path);
        Ok(Self { rules })
    }

    /// Evaluate whether UID `uid` may access destination `dest`.
    /// `dest` may be a domain name or IP address string.
    pub fn evaluate(&self, uid: u32, dest: &str) -> Decision {
        match self.rules.get(&uid) {
            None => {
                debug!(uid, dest, "No rule found — applying default deny");
                Decision::DefaultDeny
            }
            Some(rule) => {
                if rule.deny_all {
                    warn!(uid, dest, "deny_all flag set — denying");
                    return Decision::Deny;
                }
                // Check explicit deny list first
                if Self::matches_domain_list(&rule.deny_domains, dest) {
                    warn!(uid, dest, "Destination matched deny list");
                    return Decision::Deny;
                }
                // Check allow list
                if Self::matches_domain_list(&rule.allow_domains, dest) {
                    debug!(uid, dest, "Destination matched allow list");
                    return Decision::Allow;
                }
                // Neither explicitly allowed nor denied — default deny
                debug!(uid, dest, "Destination not in allow list — default deny");
                Decision::DefaultDeny
            }
        }
    }

    /// Returns true if `dest` matches any pattern in `list`.
    /// Supports exact match and leading-wildcard suffix match (e.g. "*.example.com").
    fn matches_domain_list(list: &[String], dest: &str) -> bool {
        for pattern in list {
            if pattern == dest {
                return true;
            }
            if let Some(suffix) = pattern.strip_prefix("*.") {
                if dest.ends_with(suffix) {
                    return true;
                }
                // Also match the bare domain itself
                if dest == suffix {
                    return true;
                }
            }
        }
        false
    }

    pub fn add_rule(&mut self, rule: NetworkRule) {
        self.rules.insert(rule.uid, rule);
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rule(uid: u32, allow: &[&str], deny: &[&str], deny_all: bool) -> NetworkRule {
        NetworkRule {
            uid,
            allow_domains: allow.iter().map(|s| s.to_string()).collect(),
            deny_domains: deny.iter().map(|s| s.to_string()).collect(),
            deny_all,
        }
    }

    #[test]
    fn test_allow_exact_domain() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(1000, &["example.com"], &[], false));
        assert_eq!(engine.evaluate(1000, "example.com"), Decision::Allow);
    }

    #[test]
    fn test_wildcard_allow() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(1001, &["*.google.com"], &[], false));
        assert_eq!(engine.evaluate(1001, "maps.google.com"), Decision::Allow);
        assert_eq!(engine.evaluate(1001, "evil.com"), Decision::DefaultDeny);
    }

    #[test]
    fn test_deny_all() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(1002, &["example.com"], &[], true));
        assert_eq!(engine.evaluate(1002, "example.com"), Decision::Deny);
    }

    #[test]
    fn test_deny_list_takes_priority() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(1003, &["*.good.com"], &["bad.good.com"], false));
        assert_eq!(engine.evaluate(1003, "ok.good.com"), Decision::Allow);
        assert_eq!(engine.evaluate(1003, "bad.good.com"), Decision::Deny);
    }

    #[test]
    fn test_unknown_uid_default_deny() {
        let engine = PolicyEngine::new();
        assert_eq!(engine.evaluate(9999, "anything.com"), Decision::DefaultDeny);
    }
}
