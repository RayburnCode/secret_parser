use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;
#[allow(unused_imports)]
use zeroize::Zeroize;

const KEY_SIZE: usize = 32; // 256 bits
const NONCE_SIZE: usize = 12; // 96 bits for GCM
const SALT_SIZE: usize = 16; // 128 bits

#[derive(Debug, Clone)]
pub struct MasterKey {
    key: [u8; KEY_SIZE],
}

impl MasterKey {
    /// Derive a master key from a password using PBKDF2
    pub fn from_password(password: &str, salt: &[u8], iterations: u32) -> Self {
        let mut key = [0u8; KEY_SIZE];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut key);
        Self { key }
    }

    /// Generate a random salt for key derivation
    pub fn generate_salt() -> [u8; SALT_SIZE] {
        let mut salt = [0u8; SALT_SIZE];
        OsRng.fill_bytes(&mut salt);
        salt
    }

    /// Get the key bytes for encryption
    fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.key
    }
}

pub struct CryptoManager {
    master_key: MasterKey,
}

impl CryptoManager {
    pub fn new(master_key: MasterKey) -> Self {
        Self { master_key }
    }

    /// Encrypt plaintext data
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(self.master_key.as_bytes())
            .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        // Prepend nonce to ciphertext for storage
        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt ciphertext data
    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        if encrypted_data.len() < NONCE_SIZE {
            return Err(anyhow!("Invalid encrypted data: too short"));
        }

        let cipher = Aes256Gcm::new_from_slice(self.master_key.as_bytes())
            .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;

        let (nonce_bytes, ciphertext) = encrypted_data.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("Decryption failed: {}", e))?;

        Ok(plaintext)
    }

    /// Encrypt a string and return base64-encoded result
    pub fn encrypt_string(&self, plaintext: &str) -> Result<String> {
        let encrypted = self.encrypt(plaintext.as_bytes())?;
        use base64::{Engine as _, engine::general_purpose};
        Ok(general_purpose::STANDARD.encode(&encrypted))
    }

    /// Decrypt a base64-encoded string
    pub fn decrypt_string(&self, encrypted_base64: &str) -> Result<String> {
        use base64::{Engine as _, engine::general_purpose};
        let encrypted = general_purpose::STANDARD.decode(encrypted_base64)
            .map_err(|e| anyhow!("Invalid base64: {}", e))?;
        let decrypted = self.decrypt(&encrypted)?;
        String::from_utf8(decrypted)
            .map_err(|e| anyhow!("Invalid UTF-8: {}", e))
    }
}

/// Utility functions for password validation and strength checking
pub mod password {
    use anyhow::{anyhow, Result};

    pub fn validate_strength(password: &str) -> Result<()> {
        if password.len() < 12 {
            return Err(anyhow!("Password must be at least 12 characters long"));
        }

        let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
        let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_special = password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c));

        let complexity_score = [has_upper, has_lower, has_digit, has_special]
            .iter()
            .filter(|&&x| x)
            .count();

        if complexity_score < 3 {
            return Err(anyhow!(
                "Password must contain at least 3 of: uppercase, lowercase, digits, special characters"
            ));
        }

        Ok(())
    }

    pub fn calculate_strength(password: &str) -> PasswordStrength {
        let length_score = match password.len() {
            0..=8 => 0,
            9..=12 => 1,
            13..=16 => 2,
            _ => 3,
        };

        let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
        let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_special = password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c));

        let complexity_score = [has_upper, has_lower, has_digit, has_special]
            .iter()
            .filter(|&&x| x)
            .count();

        let total_score = length_score + complexity_score;

        match total_score {
            0..=2 => PasswordStrength::Weak,
            3..=4 => PasswordStrength::Fair,
            5..=6 => PasswordStrength::Strong,
            _ => PasswordStrength::VeryStrong,
        }
    }

    #[derive(Debug, PartialEq)]
    pub enum PasswordStrength {
        Weak,
        Fair,
        Strong,
        VeryStrong,
    }

    impl std::fmt::Display for PasswordStrength {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                PasswordStrength::Weak => write!(f, "Weak"),
                PasswordStrength::Fair => write!(f, "Fair"),
                PasswordStrength::Strong => write!(f, "Strong"),
                PasswordStrength::VeryStrong => write!(f, "Very Strong"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption() {
        let password = "test_password_123!";
        let salt = MasterKey::generate_salt();
        let master_key = MasterKey::from_password(password, &salt, 10000);
        let crypto = CryptoManager::new(master_key);

        let plaintext = "Hello, World!";
        let encrypted = crypto.encrypt_string(plaintext).unwrap();
        let decrypted = crypto.decrypt_string(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_password_strength() {
        use password::*;

        assert_eq!(calculate_strength("weak"), PasswordStrength::Weak);
        assert_eq!(calculate_strength("StrongPass123!"), PasswordStrength::VeryStrong);
        
        assert!(validate_strength("StrongPass123!").is_ok());
        assert!(validate_strength("weak").is_err());
    }
}