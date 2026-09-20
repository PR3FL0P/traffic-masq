use super::*;

#[tokio::test]
async fn timeout_terminates_and_reaps_the_child() {
    let directory = tempfile::tempdir().unwrap();
    let pid_path = directory.path().join("pid");
    // A shell builtin loop keeps the test to exactly one child process.
    let error = run(
        Path::new("/bin/sh"),
        &[
            "-c",
            "echo $$ > \"$1\"; while :; do :; done",
            "test",
            pid_path.to_str().unwrap(),
        ],
        &[],
        Duration::from_secs(1),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("timed out"), "{error:#}");
    let pid: u32 = std::fs::read_to_string(pid_path)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(!Path::new(&format!("/proc/{pid}")).exists());
}

#[tokio::test]
async fn large_input_and_output_are_processed_concurrently() {
    let input = vec![b'x'; 256 * 1024];
    let output = run(Path::new("/bin/cat"), &[], &input, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(output, input);
}

#[tokio::test]
async fn excessive_output_is_rejected() {
    let size = (MAX_OUTPUT_BYTES + 1).to_string();
    let error = run(
        Path::new("/usr/bin/head"),
        &["-c", &size, "/dev/zero"],
        &[],
        Duration::from_secs(5),
    )
    .await
    .unwrap_err();
    assert!(
        error.to_string().contains("output exceeds limit"),
        "{error:#}"
    );
}

#[tokio::test]
async fn version_probe_allows_hostapd_style_exit_status() {
    let output = run_inner(
        Path::new("/bin/sh"),
        &["-c", "echo version; exit 1"],
        &[],
        Duration::from_secs(5),
        false,
    )
    .await
    .unwrap();
    assert_eq!(output, b"version\n");
}

#[tokio::test]
async fn nonzero_exit_is_not_a_successful_preflight() {
    let error = run(
        Path::new("/bin/sh"),
        &["-c", "echo broken >&2; exit 3"],
        &[],
        Duration::from_secs(5),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("broken"));
}
