use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::Result;

use super::AppConfig;

pub const CONFIG_ENV: &str = "TRAFFIC_MASQ_CONFIG";
pub const DEFAULT_CONFIG_PATH: &str = "/etc/traffic-masq/config.toml";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSource {
    CommandLine(PathBuf),
    Environment(PathBuf),
    SystemFile(PathBuf),
    BuiltIn,
}

impl ConfigSource {
    /// Return the selected configuration file, or `None` for built-in defaults.
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::CommandLine(path) | Self::Environment(path) | Self::SystemFile(path) => {
                Some(path)
            }
            Self::BuiltIn => None,
        }
    }

    /// Report whether configuration came from built-in defaults.
    pub fn is_built_in(&self) -> bool {
        matches!(self, Self::BuiltIn)
    }
}

impl fmt::Display for ConfigSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommandLine(path) => write!(formatter, "{} (--config)", path.display()),
            Self::Environment(path) => write!(formatter, "{} ({CONFIG_ENV})", path.display()),
            Self::SystemFile(path) => write!(formatter, "{} (system default)", path.display()),
            Self::BuiltIn => formatter.write_str("built-in safe defaults"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub config: AppConfig,
    pub source: ConfigSource,
}

impl ResolvedConfig {
    /// Resolve configuration in CLI, environment, system-file, then built-in order.
    /// Validate the result; an explicitly selected unreadable or invalid file is an error.
    pub fn load(explicit: Option<PathBuf>) -> Result<Self> {
        let environment = std::env::var_os(CONFIG_ENV).map(PathBuf::from);
        Self::load_from(explicit, environment, PathBuf::from(DEFAULT_CONFIG_PATH))
    }

    /// Select the highest-priority configuration source and validate its contents.
    fn load_from(
        explicit: Option<PathBuf>,
        environment: Option<PathBuf>,
        system_path: PathBuf,
    ) -> Result<Self> {
        let source = if let Some(path) = explicit {
            ConfigSource::CommandLine(path)
        } else if let Some(path) = environment {
            ConfigSource::Environment(path)
        } else if system_path.is_file() {
            ConfigSource::SystemFile(system_path)
        } else {
            ConfigSource::BuiltIn
        };
        let config = match source.path() {
            Some(path) => AppConfig::load(path)?,
            None => AppConfig::default(),
        };
        config.validate()?;
        Ok(Self { config, source })
    }
}

#[cfg(test)]
mod tests;
