use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

#[derive(Debug, Error)]
pub enum FilterError {
    #[error("AT command '{0}' is blocked by policy")]
    Blocked(String),
    #[error("Malformed AT command: '{0}'")]
    Malformed(String),
}

/// Represents a parsed AT command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ATCommand {
    /// The raw command string (e.g. "AT+CSQ")
    pub raw: String,
    /// The base command token (e.g. "+CSQ", "D", "E")
    pub command: String,
    /// Optional parameters after "=" or "?"
    pub params: Option<String>,
    /// True if this is a query ("?")
    pub is_query: bool,
}

impl ATCommand {
    /// Parse an AT command string into an ATCommand.
    /// Accepts formats: "AT+CMD", "AT+CMD?", "AT+CMD=value", "ATD...", "ATE0", etc.
    pub fn parse(input: &str) -> Result<Self, FilterError> {
        let trimmed = input.trim();
        if !trimmed.to_uppercase().starts_with("AT") {
            return Err(FilterError::Malformed(trimmed.to_string()));
        }
        let rest = &trimmed[2..]; // strip "AT"
        if rest.is_empty() {
            // bare "AT" — attention command
            return Ok(Self {
                raw: trimmed.to_string(),
                command: String::new(),
                params: None,
                is_query: false,
            });
        }

        let is_query = rest.ends_with('?');
        let rest = if is_query { &rest[..rest.len() - 1] } else { rest };

        let (command, params) = if let Some(eq_pos) = rest.find('=') {
            let cmd = rest[..eq_pos].to_string();
            let param = rest[eq_pos + 1..].to_string();
            (cmd, Some(param))
        } else {
            (rest.to_string(), None)
        };

        Ok(Self {
            raw: trimmed.to_string(),
            command,
            params,
            is_query,
        })
    }
}

/// Filter verdict for an AT command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FilterVerdict {
    Allow,
    Block,
    Sanitize(String), // Allow with a sanitized replacement command
}

/// Rules for what AT commands are allowed or blocked.
pub struct CommandFilter {
    /// Commands that are always permitted (prefix match on ATCommand::command)
    allowlist: Vec<String>,
    /// Commands that are always blocked
    blocklist: Vec<String>,
}

impl CommandFilter {
    pub fn new(allowlist: Vec<String>, blocklist: Vec<String>) -> Self {
        Self { allowlist, blocklist }
    }

    /// Default secure filter for AOSP baseband proxy.
    pub fn default_secure() -> Self {
        Self {
            allowlist: vec![
                // Signal quality and network info
                "+CSQ".into(),   // Signal strength
                "+CREG".into(),  // Network registration status
                "+COPS".into(),  // Operator selection (query only)
                "+CIMI".into(),  // IMSI (allowed for system, not apps)
                "+CGMI".into(),  // Manufacturer info
                "+CGMM".into(),  // Model info
                "+CGMR".into(),  // Firmware revision
                "+CGSN".into(),  // IMEI (system use only)
                "+CBC".into(),   // Battery status
                "+CCLK".into(),  // Clock query
                "E".into(),      // Echo control
                "Z".into(),      // Reset to factory defaults (supervised)
                "I".into(),      // Product info
                "".into(),       // Bare AT
            ],
            blocklist: vec![
                // Dangerous / exploitable commands
                "+CLAC".into(),    // List all AT commands (fingerprinting)
                "+CUSD".into(),    // USSD (can be exploited for fraud)
                "+CSIM".into(),    // SIM access command
                "+CRSM".into(),    // Restricted SIM access
                "+CGLA".into(),    // Generic UICC logical channel access
                "+CCHO".into(),    // Open logical channel
                "+CCHC".into(),    // Close logical channel
                "+STGI".into(),    // SIM toolkit get info
                "+STGR".into(),    // SIM toolkit get response
                "^STKPD".into(),   // Huawei SIM toolkit
                "+CMGW".into(),    // Write SMS to memory
                "+CMSS".into(),    // Send SMS from storage
                "+CMGD".into(),    // Delete SMS
                "+CPBW".into(),    // Write phonebook entry
                "+CLCK".into(),    // Facility lock (PIN manipulation)
                "+CPWD".into(),    // Change password (PIN)
                "+CACM".into(),    // Accumulated call meter
                "+CAMM".into(),    // Accumulated call meter maximum
                "D".into(),        // Dial (apps must use telephony API)
                "H".into(),        // Hang up (same)
                "A".into(),        // Answer
                "+VTS".into(),     // DTMF tones (direct modem access)
                "+CTFR".into(),    // Call transfer
            ],
        }
    }

    pub fn evaluate(&self, cmd: &ATCommand) -> FilterVerdict {
        let cmd_upper = cmd.command.to_uppercase();

        // Blocklist checked first (strict)
        for blocked in &self.blocklist {
            if cmd_upper == blocked.to_uppercase() {
                warn!(
                    command = %cmd.raw,
                    "AT command BLOCKED by policy"
                );
                return FilterVerdict::Block;
            }
        }

        // Allowlist
        for allowed in &self.allowlist {
            if cmd_upper == allowed.to_uppercase() {
                debug!(command = %cmd.raw, "AT command ALLOWED");
                return FilterVerdict::Allow;
            }
        }

        // Default: block anything not explicitly allowed
        warn!(command = %cmd.raw, "AT command not in allowlist — blocked by default");
        FilterVerdict::Block
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple() {
        let cmd = ATCommand::parse("AT+CSQ").unwrap();
        assert_eq!(cmd.command, "+CSQ");
        assert!(!cmd.is_query);
    }

    #[test]
    fn test_parse_query() {
        let cmd = ATCommand::parse("AT+CREG?").unwrap();
        assert_eq!(cmd.command, "+CREG");
        assert!(cmd.is_query);
    }

    #[test]
    fn test_parse_with_params() {
        let cmd = ATCommand::parse("AT+COPS=0,1,\"OperatorName\"").unwrap();
        assert_eq!(cmd.command, "+COPS");
        assert!(cmd.params.is_some());
    }

    #[test]
    fn test_parse_bare_at() {
        let cmd = ATCommand::parse("AT").unwrap();
        assert_eq!(cmd.command, "");
    }

    #[test]
    fn test_block_clac() {
        let filter = CommandFilter::default_secure();
        let cmd = ATCommand::parse("AT+CLAC").unwrap();
        assert_eq!(filter.evaluate(&cmd), FilterVerdict::Block);
    }

    #[test]
    fn test_allow_csq() {
        let filter = CommandFilter::default_secure();
        let cmd = ATCommand::parse("AT+CSQ").unwrap();
        assert_eq!(filter.evaluate(&cmd), FilterVerdict::Allow);
    }

    #[test]
    fn test_block_dial() {
        let filter = CommandFilter::default_secure();
        let cmd = ATCommand::parse("ATD18005551234;").unwrap();
        // "D18005551234;" starts with D which is in blocklist
        assert_eq!(filter.evaluate(&cmd), FilterVerdict::Block);
    }

    #[test]
    fn test_unknown_default_block() {
        let filter = CommandFilter::default_secure();
        let cmd = ATCommand::parse("AT+UNKNOWNCMD").unwrap();
        assert_eq!(filter.evaluate(&cmd), FilterVerdict::Block);
    }
}
