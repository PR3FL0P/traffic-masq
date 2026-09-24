use super::*;

#[tokio::test]
async fn uncommitted_journal_restores_prior_secret() {
    let temp = tempfile::tempdir().expect("tempdir");
    let store = ProvisioningSecretTransactionStore::in_state_dir(temp.path());
    let passphrases = PassphraseStore::new(temp.path().join("wifi/psk"));
    let old = WifiPassphrase::new("old-password").expect("old");
    let new = WifiPassphrase::new("new-password").expect("new");
    passphrases.set("wlan0", &old).expect("old write");
    store
        .stage(BTreeMap::from([("wlan0".to_owned(), Some(old))]))
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
    let passphrases = PassphraseStore::new(temp.path().join("wifi/psk"));
    let old = WifiPassphrase::new("old-password").expect("old");
    let new = WifiPassphrase::new("new-password").expect("new");
    store
        .stage(BTreeMap::from([("wlan0".to_owned(), Some(old))]))
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
    let passphrases = PassphraseStore::new(temp.path().join("wifi/psk"));
    let old = WifiPassphrase::new("old-password").expect("old");
    let new = WifiPassphrase::new("new-password").expect("new");
    store
        .stage(BTreeMap::from([("wlan0".to_owned(), Some(old))]))
        .await
        .expect("stage");
    passphrases.set("wlan0", &new).expect("new write");

    assert!(store
        .restore_staged_for_reconvergence()
        .await
        .expect("restore"));
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

    store
        .complete_reconvergence()
        .await
        .expect("complete recovery");
    assert!(!store
        .unresolved_after_committed_cleanup(None)
        .await
        .expect("journal cleared"));
}

#[tokio::test]
async fn committed_unknown_schema_is_retired_before_full_decode() {
    let temp = tempfile::tempdir().expect("tempdir");
    let store = ProvisioningSecretTransactionStore::in_state_dir(temp.path());
    let passphrases = PassphraseStore::new(temp.path().join("wifi/psk"));
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
    assert!(diagnostic.contains("supported_schemas=1"));
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
