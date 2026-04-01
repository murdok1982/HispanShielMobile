use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key
};
use anyhow::{bail, Result};
use log::{info, error};
use std::collections::HashMap;

/// Secure Settings Backend managing encrypted state
struct SecureSettingsDb {
    encrypted_store: HashMap<String, Vec<u8>>,
    encryption_key: Key<Aes256Gcm>, // Mocking StrongBox backed Key
}

impl SecureSettingsDb {
    fn new() -> Self {
        info!("Initializing Secure Settings Database and hardware keystore binding...");
        let key = Aes256Gcm::generate_key(OsRng);
        
        Self {
            encrypted_store: HashMap::new(),
            encryption_key: key,
        }
    }

    fn write_setting(&mut self, key_name: &str, plaintext_value: &str) -> Result<()> {
        let cipher = Aes256Gcm::new(&self.encryption_key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits
        
        let ciphertext = cipher.encrypt(&nonce, plaintext_value.as_bytes())
            .map_err(|_| anyhow::anyhow!("Encryption failed"))?;
        
        let mut storage_blob = nonce.to_vec();
        storage_blob.extend_from_slice(&ciphertext);
        
        self.encrypted_store.insert(key_name.to_string(), storage_blob);
        info!("Securely wrote setting: {}", key_name);
        Ok(())
    }

    fn read_setting(&self, key_name: &str) -> Result<String> {
        let blob = match self.encrypted_store.get(key_name) {
            Some(b) => b,
            None => bail!("Setting {} not found", key_name),
        };

        if blob.len() < 12 {
            bail!("Corrupt data");
        }

        let cipher = Aes256Gcm::new(&self.encryption_key);
        let nonce = Nonce::from_slice(&blob[..12]);
        let ciphertext = &blob[12..];

        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|_| anyhow::anyhow!("Decryption failed"))?;
        
        Ok(String::from_utf8(plaintext)?)
    }
}

fn main() -> Result<()> {
    std::env::set_var("RUST_LOG", "info");
    env_logger::init();
    info!("Starting HispaShield Secure Settings Core...");

    let mut settings = SecureSettingsDb::new();
    
    // Setting purely defensive configurations
    settings.write_setting("require_pin_to_boot", "true")?;
    settings.write_setting("strict_network_deny", "true")?;
    settings.write_setting("auto_reboot_on_seizure", "false")?; // Defensive only

    match settings.read_setting("strict_network_deny") {
        Ok(val) => info!("Read setting [strict_network_deny]: {}", val),
        Err(e) => error!("Failed to read setting: {}", e),
    }

    Ok(())
}
