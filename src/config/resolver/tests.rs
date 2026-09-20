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
