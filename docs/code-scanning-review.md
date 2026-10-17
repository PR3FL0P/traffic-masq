# Code scanning alert review

Reviewed the 77 open alerts exported in `code-scanning-alerts.json`.
The analyzed commit is `628f95a845476d41a5561c80f8cc41ccd1596722`;
local HEAD at review time is `68d53b5c1d34481c0560b4de1ee57d8145824b48`.
Alert locations below refer to the analyzed commit. The relevant authentication,
installer, credential-store and physical-test implementations are unchanged
between these commits.

## Findings

| Rule | Count | Assessment | Suggested disposition |
| --- | ---: | --- | --- |
| `rust/hard-coded-cryptographic-value` | 65 | Fixed passwords in test fixtures; no production default password identified in these alerts | Used in tests |
| `rust/cleartext-logging` | 11 | The reported output expressions do not print the password/PSK values identified by the rule | False positive |
| `rust/weak-sensitive-data-hashing` | 1 | SHA-256 hashes session bearer tokens generated from 32 random bytes; device passwords use salted Argon2id | False positive |

No exploitable vulnerability was confirmed in this set of alerts. This is a
source review of these findings, not a complete security audit or a fresh
CodeQL run. The export includes the alert message and sink location, but not
the complete SARIF data-flow trace. No GitHub alerts have been dismissed and no
scanner rules have been disabled by this review.

## Hard-coded values: 65 test fixtures

`src/auth/tests.rs` is included under `#[cfg(test)]` and creates an isolated
SQLite database under `TempDir`. `crates/api-client/src/tls_tests.rs` is also
included under `#[cfg(test)]`; alert #75 concerns a synthetic password used to
exercise a rejected initialization request. Other findings are integration
tests under `tests/`, using test daemons/databases or network namespaces.
The physical Wi-Fi test literals are device API test credentials, not the
operator's upstream/AP Wi-Fi passphrases. This review did not run physical or
namespace tests.

Keep useful deterministic test inputs. Replacing them with random strings
solely to hide findings would not address a production vulnerability. Prefer
reviewed test-specific dispositions over disabling the entire rule.

## Cleartext output: 11 findings

| Alerts | Reported output | Source evidence |
| --- | --- | --- |
| #11 | Saved connection name and HTTPS server origin | `SavedConnection` has only `server` and `ca_cert`; credentials reside in a separate session store. `save_in` normalizes the endpoint; `HttpsEndpoint::new` rejects URL credentials, queries and fragments. The output contains no session token or password. |
| #5 | Installer dependency diagnostics | `dependency_plan` constructs static capability messages and kernel probe results. This field is separate from `InstallPlan.password`. |
| #6 | Local account added to the access group | `plan.user` comes from the installer user argument and a local account lookup, not from the password field. This is an intentional account-status message. |
| #7, #8 | Adapter name in operator USB unplug/replug instructions | `original_uplink` comes from the interface-name input. Separate `upstream_psk_secret` and `ap_psk_secret` fields are not interpolated. |
| #9, #10 | DHCP timestamps, wait durations and process IDs | The output arguments are lease expiry values, durations and tracked PIDs, not Wi-Fi credentials. |
| #1–#4 | Assertion failure diagnostics in reconciliation tests | `failures` contains reconciliation error strings. Credential migration returns `Result<()>`; it does not return the secret. Store/passphrase error formatting contains fixed validation messages, interface names, paths and OS errors. `WifiPassphrase` implements redacted `Debug`. |

These are not reasons to treat every log statement as safe: paths, account
names and network metadata can still be operationally sensitive. The specific
reported password/PSK disclosure was not present in the reviewed expressions.

## Token hashing: alert #77

`AuthService::create_session` calls `generate_token`, which fills 32 bytes with
`OsRng` and encodes them as URL-safe base64. `hash_token_bytes` computes the
SHA-256 digest used as the database lookup key. Incoming tokens must decode to
32 bytes. This is a session-token digest, not the device-password verifier.

Device password storage goes through `hash_password`, using Argon2id with a
fresh `SaltString` from `OsRng`; verification uses the encoded Argon2 hash.
Replacing token hashing with a password KDF is not warranted by this finding.
The exact reason CodeQL labels the token input as a password cannot be proven
from the alert export alone; a SARIF trace would expose its modeled flow.

Rule references:
[hard-coded cryptographic value](https://codeql.github.com/codeql-query-help/rust/rust-hard-coded-cryptographic-value/),
[weak sensitive-data hashing](https://codeql.github.com/codeql-query-help/rust/rust-weak-sensitive-data-hashing/).

## Alert inventory

All 77 exported alerts are listed for traceability. No alert is excluded from
the counts above.

| Alert | Rule | Location | Suggested disposition |
| --- | --- | --- | --- |
| [#1](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/1) | `rust/cleartext-logging` | `src/app/tests.rs:959` | False positive |
| [#2](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/2) | `rust/cleartext-logging` | `src/app/tests.rs:1325` | False positive |
| [#3](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/3) | `rust/cleartext-logging` | `src/app/tests.rs:2504` | False positive |
| [#4](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/4) | `rust/cleartext-logging` | `src/app/tests.rs:2207` | False positive |
| [#5](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/5) | `rust/cleartext-logging` | `src/app/installer.rs:876` | False positive |
| [#6](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/6) | `rust/cleartext-logging` | `src/app/installer.rs:966` | False positive |
| [#7](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/7) | `rust/cleartext-logging` | `tests/wifi_router_physical.rs:464` | False positive |
| [#8](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/8) | `rust/cleartext-logging` | `tests/wifi_router_physical.rs:511` | False positive |
| [#9](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/9) | `rust/cleartext-logging` | `tests/wifi_router_physical.rs:705` | False positive |
| [#10](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/10) | `rust/cleartext-logging` | `tests/wifi_router_physical.rs:783` | False positive |
| [#11](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/11) | `rust/cleartext-logging` | `crates/tui/src/bin/traffic-masq.rs:86` | False positive |
| [#12](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/12) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:76` | Used in tests |
| [#13](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/13) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:85` | Used in tests |
| [#14](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/14) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:108` | Used in tests |
| [#15](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/15) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:112` | Used in tests |
| [#16](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/16) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:117` | Used in tests |
| [#17](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/17) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:117` | Used in tests |
| [#18](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/18) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:125` | Used in tests |
| [#19](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/19) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:129` | Used in tests |
| [#20](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/20) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:138` | Used in tests |
| [#21](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/21) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:145` | Used in tests |
| [#22](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/22) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:165` | Used in tests |
| [#23](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/23) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:169` | Used in tests |
| [#24](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/24) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:173` | Used in tests |
| [#25](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/25) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:177` | Used in tests |
| [#26](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/26) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:182` | Used in tests |
| [#27](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/27) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:190` | Used in tests |
| [#28](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/28) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:199` | Used in tests |
| [#29](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/29) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:203` | Used in tests |
| [#30](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/30) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:215` | Used in tests |
| [#31](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/31) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:232` | Used in tests |
| [#32](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/32) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:236` | Used in tests |
| [#33](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/33) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:240` | Used in tests |
| [#34](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/34) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:249` | Used in tests |
| [#35](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/35) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:253` | Used in tests |
| [#36](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/36) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:275` | Used in tests |
| [#37](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/37) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:279` | Used in tests |
| [#38](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/38) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:303` | Used in tests |
| [#39](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/39) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:307` | Used in tests |
| [#40](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/40) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:335` | Used in tests |
| [#41](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/41) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:339` | Used in tests |
| [#42](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/42) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:367` | Used in tests |
| [#43](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/43) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:371` | Used in tests |
| [#44](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/44) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:408` | Used in tests |
| [#45](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/45) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:413` | Used in tests |
| [#46](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/46) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:450` | Used in tests |
| [#47](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/47) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:454` | Used in tests |
| [#48](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/48) | `rust/hard-coded-cryptographic-value` | `tests/http_api.rs:121` | Used in tests |
| [#49](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/49) | `rust/hard-coded-cryptographic-value` | `tests/http_api.rs:128` | Used in tests |
| [#50](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/50) | `rust/hard-coded-cryptographic-value` | `tests/http_api.rs:204` | Used in tests |
| [#51](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/51) | `rust/hard-coded-cryptographic-value` | `tests/http_api.rs:213` | Used in tests |
| [#52](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/52) | `rust/hard-coded-cryptographic-value` | `tests/http_api.rs:214` | Used in tests |
| [#53](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/53) | `rust/hard-coded-cryptographic-value` | `tests/http_api.rs:508` | Used in tests |
| [#54](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/54) | `rust/hard-coded-cryptographic-value` | `tests/http_api.rs:509` | Used in tests |
| [#55](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/55) | `rust/hard-coded-cryptographic-value` | `tests/vpn_wireguard_namespace.rs:379` | Used in tests |
| [#56](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/56) | `rust/hard-coded-cryptographic-value` | `tests/http_api.rs:974` | Used in tests |
| [#57](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/57) | `rust/hard-coded-cryptographic-value` | `tests/vpn_policy_namespace.rs:544` | Used in tests |
| [#58](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/58) | `rust/hard-coded-cryptographic-value` | `tests/http_api.rs:982` | Used in tests |
| [#59](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/59) | `rust/hard-coded-cryptographic-value` | `tests/wifi_ap_physical.rs:208` | Used in tests |
| [#60](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/60) | `rust/hard-coded-cryptographic-value` | `tests/wifi_client_physical.rs:213` | Used in tests |
| [#61](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/61) | `rust/hard-coded-cryptographic-value` | `tests/http_api.rs:1384` | Used in tests |
| [#62](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/62) | `rust/hard-coded-cryptographic-value` | `tests/http_api.rs:1392` | Used in tests |
| [#63](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/63) | `rust/hard-coded-cryptographic-value` | `tests/http_api.rs:1569` | Used in tests |
| [#64](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/64) | `rust/hard-coded-cryptographic-value` | `tests/http_api.rs:1577` | Used in tests |
| [#65](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/65) | `rust/hard-coded-cryptographic-value` | `tests/http_api.rs:1611` | Used in tests |
| [#66](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/66) | `rust/hard-coded-cryptographic-value` | `tests/http_api.rs:1619` | Used in tests |
| [#67](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/67) | `rust/hard-coded-cryptographic-value` | `tests/http_api.rs:1885` | Used in tests |
| [#68](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/68) | `rust/hard-coded-cryptographic-value` | `tests/http_api.rs:1893` | Used in tests |
| [#69](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/69) | `rust/hard-coded-cryptographic-value` | `tests/http_api.rs:2107` | Used in tests |
| [#70](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/70) | `rust/hard-coded-cryptographic-value` | `tests/http_api.rs:2114` | Used in tests |
| [#71](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/71) | `rust/hard-coded-cryptographic-value` | `tests/http_api.rs:2547` | Used in tests |
| [#72](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/72) | `rust/hard-coded-cryptographic-value` | `tests/http_api.rs:2554` | Used in tests |
| [#73](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/73) | `rust/hard-coded-cryptographic-value` | `tests/http_api.rs:2667` | Used in tests |
| [#74](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/74) | `rust/hard-coded-cryptographic-value` | `tests/http_api.rs:2680` | Used in tests |
| [#75](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/75) | `rust/hard-coded-cryptographic-value` | `crates/api-client/src/tls_tests.rs:147` | Used in tests |
| [#76](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/76) | `rust/hard-coded-cryptographic-value` | `src/auth/tests.rs:143` | Used in tests |
| [#77](https://github.com/PR3FL0P/traffic-masq/security/code-scanning/77) | `rust/weak-sensitive-data-hashing` | `src/auth/mod.rs:714` | False positive |
