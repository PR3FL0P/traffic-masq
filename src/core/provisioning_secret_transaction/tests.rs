use super::*;

#[tokio::test]
async fn uncommitted_journal_restores_prior_secret() {
    let temp = tempfile::tempdir().expect("tempdir");
    let store = ProvisioningSecretTransactionStore::in_state_dir(temp.path());
    let passphrases = PassphraseStore::new(temp.path().join("wifi/psk-ap"));
    let old = WifiPassphrase::new("old-password").expect("old");
    let new = WifiPassphrase::new("new-password").expect("new");
    passphrases.set("wlan0", &old).expect("old write");
    store
        .stage(BTreeMap::from([(
            "wlan0".to_owned(),
            (WifiCredentialRole::Ap, Some(old)),
        )]))
        .await
        .expect("stage");
    passphrases.set("wlan0", &new).expect("new write");
    store.bind_token("token").await.expect("bind");

    assert!(store
        .recover(Some("different-token"))
        .await
        .expect("recover"));
    assert_eq!(
        passphrases
            .get("wlan0")
            .expect("read")
            .expect("secret")
            .expose(),
        "old-password"
    );
}

#[tokio::test]
async fn committed_journal_keeps_new_secret() {
    let temp = tempfile::tempdir().expect("tempdir");
    let store = ProvisioningSecretTransactionStore::in_state_dir(temp.path());
    let passphrases = PassphraseStore::new(temp.path().join("wifi/psk-ap"));
    let old = WifiPassphrase::new("old-password").expect("old");
    let new = WifiPassphrase::new("new-password").expect("new");
    store
        .stage(BTreeMap::from([(
            "wlan0".to_owned(),
            (WifiCredentialRole::Ap, Some(old)),
        )]))
        .await
        .expect("stage");
    passphrases.set("wlan0", &new).expect("new write");
    store.bind_token("token").await.expect("bind");

    assert!(!store.recover(Some("token")).await.expect("recover"));
    assert_eq!(
        passphrases
            .get("wlan0")
            .expect("read")
            .expect("secret")
            .expose(),
        "new-password"
    );
}

#[tokio::test]
async fn reconvergence_restore_keeps_journal_until_explicit_completion() {
    let temp = tempfile::tempdir().expect("tempdir");
    let store = ProvisioningSecretTransactionStore::in_state_dir(temp.path());
    let passphrases = PassphraseStore::new(temp.path().join("wifi/psk-ap"));
    let old = WifiPassphrase::new("old-password").expect("old");
    let new = WifiPassphrase::new("new-password").expect("new");
    store
        .stage(BTreeMap::from([(
            "wlan0".to_owned(),
            (WifiCredentialRole::Ap, Some(old)),
        )]))
        .await
        .expect("stage");
    passphrases.set("wlan0", &new).expect("new write");

    assert!(store.restore(None).await.expect("restore"));
    assert_eq!(
        passphrases
            .get("wlan0")
            .expect("read")
            .expect("secret")
            .expose(),
        "old-password"
    );
    assert!(store
        .unresolved_after_committed_cleanup(None)
        .await
        .expect("journal must remain"));

    store.finish(None).await.expect("complete recovery");
    assert!(!store
        .unresolved_after_committed_cleanup(None)
        .await
        .expect("journal cleared"));
}

#[tokio::test]
async fn restore_rejects_wrong_token_and_retains_journal_until_finish() {
    let temp = tempfile::tempdir().expect("tempdir");
    let store = ProvisioningSecretTransactionStore::in_state_dir(temp.path());
    let passphrases = PassphraseStore::new(temp.path().join("wifi/psk-ap"));
    let old = WifiPassphrase::new("old-password").expect("old");
    let new = WifiPassphrase::new("new-password").expect("new");
    store
        .stage(BTreeMap::from([(
            "wlan0".to_owned(),
            (WifiCredentialRole::Ap, Some(old)),
        )]))
        .await
        .expect("stage");
    passphrases.set("wlan0", &new).expect("new write");
    store.bind_token("expected").await.expect("bind");

    assert!(store.restore(Some("other")).await.is_err());
    assert!(store.finish(Some("other")).await.is_err());
    assert!(store.restore(None).await.is_err());
    assert_eq!(
        passphrases
            .get("wlan0")
            .expect("read")
            .expect("secret")
            .expose(),
        "new-password"
    );

    assert!(store.restore(Some("expected")).await.expect("restore"));
    assert!(store
        .unresolved_after_committed_cleanup(None)
        .await
        .expect("journal remains"));
    assert!(store.finish(Some("expected")).await.expect("finish"));
    assert!(!store
        .unresolved_after_committed_cleanup(None)
        .await
        .expect("journal cleared"));
}

#[tokio::test]
async fn committed_unknown_schema_is_retired_before_full_decode() {
    let temp = tempfile::tempdir().expect("tempdir");
    let store = ProvisioningSecretTransactionStore::in_state_dir(temp.path());
    let passphrases = PassphraseStore::new(temp.path().join("wifi/psk-ap"));
    let current = WifiPassphrase::new("current-password").expect("current");
    passphrases.set("wlan0", &current).expect("current write");
    tokio::fs::create_dir_all(temp.path().join("wifi"))
        .await
        .expect("wifi dir");
    tokio::fs::write(
        temp.path().join("wifi/router-provisioning-secrets.json"),
        br#"{"version":999,"token":"committed","future_field":true}"#,
    )
    .await
    .expect("journal");

    assert!(!store.recover(Some("committed")).await.expect("recover"));
    assert!(!temp
        .path()
        .join("wifi/router-provisioning-secrets.json")
        .exists());
    assert_eq!(
        passphrases
            .get("wlan0")
            .expect("read")
            .expect("secret")
            .expose(),
        "current-password"
    );
}

#[tokio::test]
async fn uncommitted_unknown_schema_remains_operator_blocking() {
    let temp = tempfile::tempdir().expect("tempdir");
    let store = ProvisioningSecretTransactionStore::in_state_dir(temp.path());
    tokio::fs::create_dir_all(temp.path().join("wifi"))
        .await
        .expect("wifi dir");
    let journal = temp.path().join("wifi/router-provisioning-secrets.json");
    tokio::fs::write(
        &journal,
        br#"{"version":999,"token":"uncommitted","previous":{}}"#,
    )
    .await
    .expect("journal");

    let error = store
        .recover(Some("different"))
        .await
        .expect_err("unsupported uncommitted schema must remain blocked");
    let diagnostic = format!("{error:#}");
    assert!(diagnostic.contains("recovery_code=TM-REC-303"));
    assert!(diagnostic.contains("supported_provisioning_secret_schema"));
    assert!(diagnostic.contains("journal_schema=999"));
    assert!(diagnostic.contains("supported_schemas=2"));
    assert!(diagnostic.contains("operator_action=use_compatible_daemon"));
    assert!(journal.exists());
}

#[tokio::test]
async fn missing_committed_token_never_proves_null_journal_token_committed() {
    let temp = tempfile::tempdir().expect("tempdir");
    let store = ProvisioningSecretTransactionStore::in_state_dir(temp.path());
    tokio::fs::create_dir_all(temp.path().join("wifi"))
        .await
        .expect("wifi dir");
    let journal = temp.path().join("wifi/router-provisioning-secrets.json");
    tokio::fs::write(&journal, br#"{"version":999,"token":null,"previous":{}}"#)
        .await
        .expect("journal");

    let error = store
        .recover(None)
        .await
        .expect_err("None == None is not independent commit proof");
    assert!(error
        .to_string()
        .contains("supported_provisioning_secret_schema"));
    assert!(journal.exists());
}

#[tokio::test]
async fn malformed_json_never_infers_commit_from_token_text() {
    let temp = tempfile::tempdir().expect("tempdir");
    let store = ProvisioningSecretTransactionStore::in_state_dir(temp.path());
    tokio::fs::create_dir_all(temp.path().join("wifi"))
        .await
        .expect("wifi dir");
    let journal = temp.path().join("wifi/router-provisioning-secrets.json");
    tokio::fs::write(&journal, br#"{"token":"committed""#)
        .await
        .expect("journal");

    let error = store
        .recover(Some("committed"))
        .await
        .expect_err("malformed JSON has no trustworthy token proof");
    let diagnostic = error.to_string();
    assert!(diagnostic.contains("recovery_code=TM-REC-302"));
    assert!(diagnostic.contains("invariant=valid_provisioning_secret_snapshot"));
    assert!(diagnostic.contains(&format!("journal={}", journal.display())));
    assert!(diagnostic.contains("backup_scope=complete_state_directory"));
    assert!(diagnostic.contains("do_not_edit_journal=true"));
    assert!(diagnostic.contains("operator_action=restore_coherent_backup"));
    assert!(journal.exists());
}

#[tokio::test]
async fn router_secret_recovery_restores_each_role_without_touching_the_other() {
    let temp = tempfile::tempdir().unwrap();
    let journal = ProvisioningSecretTransactionStore::in_state_dir(temp.path());
    let ap = PassphraseStore::for_role(temp.path(), WifiCredentialRole::Ap);
    let client = PassphraseStore::for_role(temp.path(), WifiCredentialRole::Client);
    ap.set("wlan0", &WifiPassphrase::new("ap-new-password").unwrap())
        .unwrap();
    client
        .set("wlan0", &WifiPassphrase::new("client-preserved").unwrap())
        .unwrap();
    client
        .set(
            "wlan1",
            &WifiPassphrase::new("client-new-password").unwrap(),
        )
        .unwrap();
    ap.set("wlan1", &WifiPassphrase::new("ap-preserved").unwrap())
        .unwrap();
    journal
        .stage(BTreeMap::from([
            (
                "wlan0".into(),
                (
                    WifiCredentialRole::Ap,
                    Some(WifiPassphrase::new("ap-old-password").unwrap()),
                ),
            ),
            ("wlan1".into(), (WifiCredentialRole::Client, None)),
        ]))
        .await
        .unwrap();
    journal.recover(None).await.unwrap();
    assert_eq!(
        ap.get("wlan0").unwrap().unwrap().expose(),
        "ap-old-password"
    );
    assert!(client.get("wlan1").unwrap().is_none());
    assert_eq!(
        client.get("wlan0").unwrap().unwrap().expose(),
        "client-preserved"
    );
    assert_eq!(ap.get("wlan1").unwrap().unwrap().expose(), "ap-preserved");
}

#[tokio::test]
async fn new_router_secret_journal_without_roles_is_rejected_and_retained() {
    let temp = tempfile::tempdir().unwrap();
    let journal = ProvisioningSecretTransactionStore::in_state_dir(temp.path());
    std::fs::create_dir_all(temp.path().join("wifi")).unwrap();
    std::fs::write(
        &journal.journal,
        br#"{"version":2,"previous":{"wlan0":"old-password"}}"#,
    )
    .unwrap();
    assert!(journal.recover(None).await.is_err());
    assert!(journal.journal.exists());
    assert!(!temp.path().join("wifi/psk/wlan0").exists());
}

#[tokio::test]
async fn previous_secret_journal_schema_is_rejected_without_restoring_secrets() {
    let temp = tempfile::tempdir().unwrap();
    let store = ProvisioningSecretTransactionStore::in_state_dir(temp.path());
    std::fs::create_dir_all(temp.path().join("wifi")).unwrap();
    let bytes = br#"{"version":1,"previous":{"wlan0":"old-password"},"roles":{}}"#;
    std::fs::write(&store.journal, bytes).unwrap();
    assert!(store.recover(None).await.is_err());
    assert_eq!(std::fs::read(&store.journal).unwrap(), bytes);
    assert!(!temp.path().join("wifi/psk").exists());
}
