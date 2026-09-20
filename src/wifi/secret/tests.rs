use super::*;

#[test]
fn accepts_the_wpa_length_range() {
    WifiPassphrase::new("a".repeat(MIN_WIFI_PASSPHRASE_LEN)).expect("minimum length");
    WifiPassphrase::new("a".repeat(MAX_WIFI_PASSPHRASE_LEN)).expect("maximum length");

    assert_eq!(
        WifiPassphrase::new("a".repeat(MIN_WIFI_PASSPHRASE_LEN - 1)),
        Err(PassphraseError::TooShort)
    );
    assert_eq!(
        WifiPassphrase::new("a".repeat(MAX_WIFI_PASSPHRASE_LEN + 1)),
        Err(PassphraseError::TooLong)
    );
}

#[test]
fn rejects_characters_that_could_break_out_of_a_config_line() {
    assert_eq!(
        WifiPassphrase::new("secret\npassword"),
        Err(PassphraseError::NotPrintableAscii)
    );
    assert_eq!(
        WifiPassphrase::new("secret\rpassword"),
        Err(PassphraseError::NotPrintableAscii)
    );
    assert_eq!(
        WifiPassphrase::new("паролище"),
        Err(PassphraseError::NotPrintableAscii)
    );
}

#[test]
fn keeps_surrounding_spaces_and_allows_inner_ones() {
    let passphrase = WifiPassphrase::new(" correct horse ").expect("spaces are legal");
    assert_eq!(passphrase.expose(), " correct horse ");
}

#[test]
fn never_renders_its_value() {
    let passphrase = WifiPassphrase::new("correct horse battery").expect("valid");
    assert_eq!(format!("{passphrase:?}"), "[REDACTED]");
    assert_eq!(format!("{passphrase}"), "[REDACTED]");
}
