# Building and packaging releases

## Local validation and archive

Use the toolchain pinned in [`rust-toolchain.toml`](../rust-toolchain.toml).
Build requirements and privileged test isolation are described in the
[operating guide](usage.md#requirements).

From the repository root:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo doc --locked --workspace --no-deps
cargo test --locked --workspace --doc
sh packaging/smoke-test.sh
sh packaging/test-namespaces.sh
cargo build --release --locked --bins
sh packaging/release.sh
```

The namespace runner executes eight network/VPN suites; use `--sudo` when
unprivileged user namespaces are unavailable, after authenticating sudo.
Physical Wi-Fi tests require an explicitly selected adapter and separate setup;
they are not part of this release validation command sequence.

`packaging/release.sh` reads the root package version from `Cargo.toml` and
creates `release/traffic-masq-<version>-<target>.tar.gz` plus a `.tar.gz.sha256`
checksum. It needs Python 3.11 or later (`tomllib`), `tar`, `sha256sum`, and
`rustc` to detect the host target unless `TARGET` is supplied. The archive
contains both executables, available top-level documentation, `Cargo.toml`,
and the `docs`, `examples`, and `packaging` directories. It does not contain a
complete source checkout or client session data.

Verify the checksum from the output directory:

```sh
(cd release && sha256sum -c ./*.sha256)
```

Override `BINARY_DIR`, `OUTPUT_DIR`, and `TARGET` when packaging another build:

```sh
BINARY_DIR=target/aarch64-unknown-linux-gnu/release \
  OUTPUT_DIR=release TARGET=aarch64-unknown-linux-gnu sh packaging/release.sh
```

The script packages existing binaries; it does not compile, cross-compile or
verify their architecture. `TARGET` labels the archive and must match the build.

## GitHub Actions

[`ci.yml`](../.github/workflows/ci.yml) is the shared validation gate for
pushes to `main`, pull requests, manual runs and binary builds. Lean transaction
proofs run first through [`lean.yml`](../.github/workflows/lean.yml), which also
supports manual dispatch. Rust checks then run workflow linting (actionlint
1.7.12), formatting, Clippy, workspace tests (including doctests), rustdoc, all
eight isolated network/VPN suites with sudo, and packaging smoke tests on
Ubuntu 24.04. Pull-request validation cancels superseded runs. Physical Wi-Fi
tests remain separate and are never selected by these workflows.

Both validation and binary builds use the pinned Rust toolchain and
[shared setup action](../.github/actions/setup-rust/action.yml) for the cache
and test runtime dependencies. The DHCP namespace fixture disables TX checksum
offload on its server veth so the pre-address raw client receives completed
UDP checksums; this does not change host interfaces or production validation.

CodeQL is managed by GitHub **Default setup** for Actions, Python and Rust.
The redundant Advanced workflow was removed because GitHub rejects its analysis
uploads while Default setup is enabled. Security scanning remains enabled;
this CI cleanup does not disable queries or dismiss alerts. If switching to
Advanced setup later, disable Default setup before adding that workflow.

[`compile.yml`](../.github/workflows/compile.yml) runs on `v*` tag pushes or
manual dispatch. It always waits for the complete reusable validation workflow,
including Lean, before building Linux x86_64 binaries. It uploads an Actions
artifact named `traffic-masq-binaries`, containing the archive, checksum and
loose binaries. It does not create or publish a GitHub Release.

For tag builds, the tag must equal `v<version>` from the root `Cargo.toml`;
packaging rejects a mismatch. Manual dispatch accepts `profile` (`release` or
`debug`), `run_tests`, `tests_only`, `test_filter`, and `cache`. Extra tests run
in debug mode: an empty filter runs library tests, `all` runs workspace tests,
and another value selects matching workspace tests. Setting a filter or
`tests_only` also enables extra tests. `tests_only` skips binary builds and
artifact upload after validation. The cache option applies to both validation
and compilation. Manual and tag build runs are not cancelled when another
build is queued for the same ref.

## Remote compilation helper

[`gitcompile.sh`](../gitcompile.sh) requires Bash, Git, authenticated GitHub CLI
(`gh`), and push/workflow access to the repository. Run `./gitcompile.sh --help`
for all options. For example:

```sh
./gitcompile.sh -n
./gitcompile.sh -n -t --test-filter wifi
./gitcompile.sh --test-only
./gitcompile.sh --download-only --dir ./binaries
```

`-n` uploads a working-tree snapshot, including untracked files not ignored by
Git, to a temporary `ci-temp-<branch>` branch. It leaves the active branch and
index unchanged, then attempts to delete the remote branch on exit. Without
`-n`, the helper pushes the active branch; a supplied commit message also stages
and commits changes before the push. Review the files included before invoking
it. Downloads go to `./binaries` by default. Download-only selects the latest
successful compile workflow run, which must have the binary artifact.

## Installation and upgrades

Unpack the archive and run `sudo ./traffic-masqd install` from its directory.
The target host needs runtime dependencies but no Rust toolchain. See
[installation](usage.md#install) and [service upgrades](../packaging/INIT.md#ownership-updates-and-removal).
Update daemon and client together. Preserve configuration and the complete
state directory before upgrades; recovery and override schemas determine
whether a downgrade can read the saved state.
