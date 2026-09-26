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
    /// Resolve configuration in CLI, environment, system-file, then built-in order and fully
    /// validate it for normal runtime use.
    pub fn load(explicit: Option<PathBuf>) -> Result<Self> {
        let environment = std::env::var_os(CONFIG_ENV).map(PathBuf::from);
        Self::load_from(
            explicit,
            environment,
            PathBuf::from(DEFAULT_CONFIG_PATH),
            true,
        )
    }

    /// Resolve and deserialize configuration without semantic admission.
    ///
    /// Daemon recovery uses this path so an unrelated invalid API/auth setting cannot prevent
    /// rollback of durable network journals. Syntax errors are still fatal because recovery paths
    /// cannot be recovered reliably from an undecodable file.
    pub fn load_unvalidated(explicit: Option<PathBuf>) -> Result<Self> {
        let environment = std::env::var_os(CONFIG_ENV).map(PathBuf::from);
        Self::load_from(
            explicit,
            environment,
            PathBuf::from(DEFAULT_CONFIG_PATH),
            false,
        )
    }

    /// Select the highest-priority configuration source and optionally admit its contents.
    fn load_from(
        explicit: Option<PathBuf>,
        environment: Option<PathBuf>,
        system_path: PathBuf,
        validate: bool,
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
            Some(path) if validate => AppConfig::load(path)?,
            Some(path) => AppConfig::load_unvalidated(path)?,
            None => AppConfig::default(),
        };
        if validate {
            config.validate()?;
        }
        Ok(Self { config, source })
    }
}

#[cfg(test)]
mod tests;
