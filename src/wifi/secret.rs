use std::fmt;

use thiserror::Error;
use zeroize::Zeroize;

use crate::config::{MAX_WIFI_PASSPHRASE_LEN, MIN_WIFI_PASSPHRASE_LEN};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PassphraseError {
    #[error("Wi-Fi passphrase is shorter than {MIN_WIFI_PASSPHRASE_LEN} characters")]
    TooShort,

    #[error("Wi-Fi passphrase is longer than {MAX_WIFI_PASSPHRASE_LEN} characters")]
    TooLong,

    #[error("Wi-Fi passphrase must contain only printable ASCII characters")]
    NotPrintableAscii,
}

#[derive(Clone, PartialEq, Eq)]
pub struct WifiPassphrase(String);

impl WifiPassphrase {
    pub fn new(raw: impl Into<String>) -> Result<Self, PassphraseError> {
        let raw = raw.into();
        let passphrase = Self(raw);
        passphrase.validate()?;
        Ok(passphrase)
    }

    fn validate(&self) -> Result<(), PassphraseError> {
        if self.0.len() < MIN_WIFI_PASSPHRASE_LEN {
            return Err(PassphraseError::TooShort);
        }
        if self.0.len() > MAX_WIFI_PASSPHRASE_LEN {
            return Err(PassphraseError::TooLong);
        }
        if !self
            .0
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
        {
            return Err(PassphraseError::NotPrintableAscii);
        }
        Ok(())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Zeroize for WifiPassphrase {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for WifiPassphrase {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for WifiPassphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl fmt::Display for WifiPassphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

#[cfg(test)]
mod tests;
