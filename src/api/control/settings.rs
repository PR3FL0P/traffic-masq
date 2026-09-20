use super::*;

impl ControlService {
    pub(super) async fn api_https_config_response(&self) -> Result<Response> {
        let snapshot = self.overrides.snapshot().await;
        let desired = self.overrides.effective_api_config().await?;
        let active = api_https_settings_from_config(&self.config.api);
        let desired = api_https_settings_from_config(&desired);
        Ok(Response::ApiHttpsConfig {
            restart_required: active != desired,
            override_active: snapshot.api.is_some(),
            active,
            desired,
        })
    }

    pub(super) async fn configure_api_https_settings(
        &self,
        settings: ApiHttpsSettings,
    ) -> Result<Response> {
        let api = api_https_settings_to_config(settings)?;
        self.overrides.set_api_config(api).await?;
        self.api_https_config_response().await
    }

    pub(super) async fn reset_api_https_settings(&self) -> Result<Response> {
        self.overrides.clear_api_config().await?;
        self.api_https_config_response().await
    }

    pub(super) async fn security_config_response(&self) -> Result<Response> {
        let snapshot = self.overrides.snapshot().await;
        let desired = self.overrides.effective_security_config().await?;
        let active = SecuritySettings::from(&self.config.security);
        let desired = SecuritySettings::from(&desired);
        Ok(Response::SecurityConfig {
            restart_required: active != desired,
            override_active: snapshot.security.is_some(),
            active,
            desired,
        })
    }

    pub(super) async fn configure_security_settings(
        &self,
        settings: SecuritySettings,
    ) -> Result<Response> {
        let security = SecurityConfig {
            rollback_timeout_seconds: settings.rollback_timeout_seconds,
        };
        self.overrides.set_security_config(security).await?;
        self.security_config_response().await
    }

    pub(super) async fn reset_security_settings(&self) -> Result<Response> {
        self.overrides.clear_security_config().await?;
        self.security_config_response().await
    }
}

pub(super) fn api_https_settings_from_config(config: &ApiConfig) -> ApiHttpsSettings {
    config
        .tcp
        .as_ref()
        .map(ApiHttpsSettings::from)
        .unwrap_or_default()
}

pub(super) fn api_https_settings_to_config(settings: ApiHttpsSettings) -> Result<ApiConfig> {
    let tcp = TcpApiConfig {
        enabled: settings.enabled,
        listen: settings.listen.trim().parse()?,
        certificate_path: settings
            .certificate_path
            .and_then(normalize_optional_path_string)
            .map(Into::into),
        private_key_path: settings
            .private_key_path
            .and_then(normalize_optional_path_string)
            .map(Into::into),
    };
    let api = ApiConfig { tcp: Some(tcp) };
    let candidate = AppConfig {
        api: api.clone(),
        ..Default::default()
    };
    candidate.validate()?;
    Ok(api)
}

pub(super) fn normalize_optional_path_string(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}
