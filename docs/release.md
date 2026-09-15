# Releases

The release workflow builds and tests on Ubuntu 24.04. It produces a Linux
x86-64 archive and a SHA-256 checksum for review. Run it manually or push a
version tag. Publishing a GitHub release is a separate step.

1. Update the version in `Cargo.toml`, regenerate `Cargo.lock`, and prepare
   release notes.
2. Run the [standard checks](../README.md#checks) and
   `sh packaging/test-namespaces.sh` on a disposable VM. The latter includes
   both VPN test suites.
3. Tag the reviewed commit as `v<version>`; the archive script rejects a mismatch.
4. Download the workflow artifact and verify its checksum:

   ```sh
   sha256sum -c traffic-masq-*.tar.gz.sha256
   ```

5. Test installation, upgrade and uninstall in a clean VM before publishing the
   archive and checksum. Record the commit and test results in the release notes.

For a local archive:

```sh
cargo build --release --locked --bins
sh packaging/release.sh
```

Use `BINARY_DIR`, `OUTPUT_DIR` and `TARGET` to package binaries built elsewhere.
When cross-compiling, set both `BINARY_DIR` and the actual `TARGET` explicitly.
The archive contains both binaries in one directory so `traffic-masqd install`
can locate the terminal client. The default build targets the build host's libc;
it is not a universal static Linux binary.
