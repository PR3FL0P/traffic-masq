//! Bounded read-only tail of daemon-owned rolling logs.
use anyhow::{bail, Context, Result};
use std::{
    collections::VecDeque,
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};
use traffic_masq_protocol::DaemonLogSnapshot;

const MAX_BYTES: usize = 256 * 1024;
const MAX_LINE_CHARS: usize = 2048;

pub fn read_recent(directory: &Path, limit: usize) -> Result<DaemonLogSnapshot> {
    if !(1..=1000).contains(&limit) {
        bail!("log limit must be between 1 and 1000");
    }
    let mut files = Vec::new();
    for entry in fs::read_dir(directory)
        .context("daemon log directory unavailable")?
        .take(4096)
    {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !log_name(&name) || !entry.file_type()?.is_file() {
            continue;
        }
        files.push((entry.metadata()?.modified()?, name));
    }
    files.sort();
    if files.is_empty() {
        bail!("no daemon log files available (the daemon may be logging to stderr only)");
    }
    let mut snapshot = DaemonLogSnapshot {
        lines: Vec::new(),
        sources: Vec::new(),
        truncated: files.len() > 3,
    };
    let mut lines = VecDeque::new();
    let mut remaining = MAX_BYTES;
    for (_, name) in files.into_iter().rev().take(3) {
        if remaining == 0 || lines.len() >= limit {
            snapshot.truncated = true;
            break;
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(directory.join(&name))
            .context("could not open daemon log")?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            bail!("daemon log is not a regular file");
        }
        let offset = metadata.len().saturating_sub(remaining as u64);
        file.seek(SeekFrom::Start(offset))?;
        let mut bytes = Vec::new();
        file.take(remaining as u64).read_to_end(&mut bytes)?;
        remaining = remaining.saturating_sub(bytes.len());
        let start = if offset > 0 {
            snapshot.truncated = true;
            bytes
                .iter()
                .position(|b| *b == b'\n')
                .map_or(bytes.len(), |i| i + 1)
        } else {
            0
        };
        let text = String::from_utf8_lossy(&bytes[start..]);
        for line in text.lines().rev() {
            if lines.len() == limit {
                snapshot.truncated = true;
                break;
            }
            let line = plain_text(line);
            let shortened = line.chars().count() > MAX_LINE_CHARS;
            let mut line = line.chars().take(MAX_LINE_CHARS).collect::<String>();
            if shortened {
                line.push_str(" [line truncated]");
                snapshot.truncated = true;
            }
            lines.push_front(line);
        }
        snapshot.sources.push(name);
    }
    snapshot.sources.reverse();
    snapshot.lines = lines.into();
    Ok(snapshot)
}

fn log_name(name: &str) -> bool {
    if name == "traffic-masqd.log" {
        return true;
    }
    let Some(date) = name.strip_prefix("traffic-masqd.log.") else {
        return false;
    };
    date.len() == 10
        && date.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 4 | 7) {
                b == b'-'
            } else {
                b.is_ascii_digit()
            }
        })
}

fn plain_text(text: &str) -> String {
    let mut output = String::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            match chars.next() {
                Some('[') => {
                    for c in chars.by_ref() {
                        if ('@'..='~').contains(&c) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    let mut escape = false;
                    for c in chars.by_ref() {
                        if c == '\x07' || (escape && c == '\\') {
                            break;
                        }
                        escape = c == '\x1b';
                    }
                }
                _ => {}
            }
        } else if c == '\t' {
            output.push(' ');
        } else if !c.is_control() {
            output.push(c);
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tail_is_ordered_bounded_and_ignores_unrelated_files_and_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("traffic-masqd.log.2026-10-01"),
            "INFO first\nWARN second\nERROR third\n",
        )
        .unwrap();
        fs::write(dir.path().join("secret.txt"), "secret").unwrap();
        std::os::unix::fs::symlink(
            dir.path().join("secret.txt"),
            dir.path().join("traffic-masqd.log.2026-10-02"),
        )
        .unwrap();
        let result = read_recent(dir.path(), 2).unwrap();
        assert_eq!(result.lines, ["WARN second", "ERROR third"]);
        assert!(result.truncated);
        assert_eq!(result.sources.len(), 1);
        assert!(read_recent(dir.path(), 0).is_err());
        assert!(read_recent(dir.path(), 1001).is_err());
    }
    #[test]
    fn huge_lines_and_terminal_sequences_are_bounded() {
        assert_eq!(
            plain_text("\x1b[31mERROR\x1b[0m \x1b]52;c;secret\x07failure\r"),
            "ERROR failure"
        );
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("traffic-masqd.log"),
            format!("{}\nWARN end\n", "x".repeat(MAX_BYTES * 2)),
        )
        .unwrap();
        let result = read_recent(dir.path(), 500).unwrap();
        assert_eq!(result.lines, ["WARN end"]);
        assert!(result.truncated);
    }
}
