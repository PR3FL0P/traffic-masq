# Releases

The manual `Compile Binaries` workflow runs on Ubuntu 24.04. It builds a Linux
x86-64 archive containing the two binaries. Tests are optional and off by
default; enable `run_tests` to run them. The workflow does not run on tags or
produce a checksum. Publishing a GitHub release is a separate step.

1. Update the version in `Cargo.toml`, regenerate `Cargo.lock`, and prepare
   release notes.
2. Run the [standard checks](../README.md#checks) and
   `sh packaging/test-namespaces.sh` on a disposable VM. The latter includes
   both VPN test suites.
3. Build a release archive locally:

   ```sh
   cargo build --release --locked --bins
   sh packaging/release.sh
   ```

   If running the archive script in a tag-triggered environment, the tag must
   match `v<version>`.
4. Verify the locally generated checksum from the repository root:

   ```sh
   cd release
   sha256sum -c traffic-masq-*.tar.gz.sha256
   ```

5. Test installation, upgrade and uninstall in a clean VM before publishing the
   archive and checksum. Record the commit and test results in the release notes.

To obtain binaries from CI instead, run `Compile Binaries` manually with the
release profile. Download its `traffic-masq-binaries` artifact, which contains
the two binaries and `traffic-masq-linux-x86_64.tar.gz`. Generate a checksum
separately if publishing that archive. The workflow's optional tests run with
`cargo test --lib` by default; `test_filter=all` runs `cargo test`.

Use `BINARY_DIR`, `OUTPUT_DIR` and `TARGET` to package binaries built elsewhere.
When cross-compiling, set both `BINARY_DIR` and the actual `TARGET` explicitly.
The archive contains both binaries in one directory so `traffic-masqd install`
can locate the terminal client. The default build targets the build host's libc;
it is not a universal static Linux binary.
