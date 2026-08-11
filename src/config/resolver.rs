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
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::CommandLine(path) | Self::Environment(path) | Self::SystemFile(path) => {
                Some(path)
            }
            Self::BuiltIn => None,
        }
    }

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
    pub fn load(explicit: Option<PathBuf>) -> Result<Self> {
        let environment = std::env::var_os(CONFIG_ENV).map(PathBuf::from);
        Self::load_from(explicit, environment, PathBuf::from(DEFAULT_CONFIG_PATH))
    }

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
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    fn write_config(path: &Path) {
        fs::write(
            path,
            toml::to_string_pretty(&AppConfig::default()).expect("serialize defaults"),
        )
        .expect("write config");
    }

    #[test]
    fn precedence_is_cli_then_environment_then_system_then_builtin() {
        let directory = tempdir().expect("tempdir");
        let cli = directory.path().join("cli.toml");
        let environment = directory.path().join("environment.toml");
        let system = directory.path().join("system.toml");
        write_config(&cli);
        write_config(&environment);
        write_config(&system);

        let resolved =
            ResolvedConfig::load_from(Some(cli.clone()), Some(environment.clone()), system.clone())
                .expect("CLI resolution");
        assert_eq!(resolved.source, ConfigSource::CommandLine(cli));

        let resolved = ResolvedConfig::load_from(None, Some(environment.clone()), system.clone())
            .expect("environment resolution");
        assert_eq!(resolved.source, ConfigSource::Environment(environment));

        let resolved =
            ResolvedConfig::load_from(None, None, system.clone()).expect("system resolution");
        assert_eq!(resolved.source, ConfigSource::SystemFile(system));

        let missing = directory.path().join("missing.toml");
        let resolved = ResolvedConfig::load_from(None, None, missing).expect("built-in resolution");
        assert_eq!(resolved.source, ConfigSource::BuiltIn);
        assert!(resolved.config.network.interfaces.is_empty());
    }

    #[test]
    fn an_explicit_missing_file_is_an_error_not_a_builtin_fallback() {
        let directory = tempdir().expect("tempdir");
        let missing = directory.path().join("missing.toml");
        assert!(ResolvedConfig::load_from(Some(missing), None, PathBuf::new()).is_err());
    }
}
