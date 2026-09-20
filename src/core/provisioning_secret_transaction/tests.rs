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
