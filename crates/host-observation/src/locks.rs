//! File-lock ownership is kernel evidence, unlike the contents of a PID file.
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

pub fn file_lock_diagnostics(file: &File, path: &Path) -> String {
    let evidence = file.metadata().ok().and_then(|metadata| {
        std::fs::read_to_string("/proc/locks")
            .ok()
            .map(|locks| lock_pids(&locks, metadata.dev(), metadata.ino()))
    });
    let mut message = format!("Lock {}: ", path.display());
    match evidence {
        Some(pids) if !pids.is_empty() => {
            for pid in pids {
                let name = std::fs::read_to_string(format!("/proc/{pid}/comm"))
                    .unwrap_or_else(|_| "unknown".into());
                message.push_str(&format!("kernel lock holder PID {pid} ({}); inspect `ps -p {pid} -o pid,ppid,comm,args`. ", name.trim()));
            }
        }
        _ => message.push_str("No holding PID could be confirmed (permissions, PID namespace, OFD lock, or a concurrent exit may hide it). "),
    }
    message.push_str("Inspect `sudo lslocks`; wait for the operation to finish or stop its verified owning service manually, then retry. Do not delete the lock file: unlinking it can allow two writers. A lock failure alone does not identify a network manager.");
    message
}

fn lock_pids(locks: &str, device: u64, inode: u64) -> Vec<u32> {
    // Linux dev_t encoding, as used by /proc/locks' hexadecimal major:minor.
    let major = ((device >> 8) & 0xfff) | ((device >> 32) & 0xfffff000);
    let minor = (device & 0xff) | ((device >> 12) & 0xffffff00);
    let mut pids = Vec::new();
    for line in locks.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        // Waiting requests contain "->" and do not hold the lock.
        if fields.len() < 8 || fields[1] == "->" {
            continue;
        }
        let parts: Vec<_> = fields[5].split(':').collect();
        if parts.len() == 3
            && u64::from_str_radix(parts[0], 16).ok() == Some(major)
            && u64::from_str_radix(parts[1], 16).ok() == Some(minor)
            && parts[2].parse::<u64>().ok() == Some(inode)
        {
            if let Ok(pid) = fields[4].parse::<u32>() {
                if pid > 0 {
                    pids.push(pid);
                }
            }
        }
    }
    pids.sort_unstable();
    pids.dedup();
    pids
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reports_only_exact_holders_and_not_waiters_or_pidless_locks() {
        let locks = "1: FLOCK ADVISORY WRITE 42 08:01:123 0 EOF\n2: -> FLOCK ADVISORY WRITE 43 08:01:123 0 EOF\n3: OFDLCK ADVISORY WRITE -1 08:01:123 0 EOF\n4: FLOCK ADVISORY WRITE 44 08:02:123 0 EOF\n5: FLOCK ADVISORY WRITE 45 08:01:124 0 EOF\n";
        assert_eq!(lock_pids(locks, 0x801, 123), vec![42]);
    }
    #[test]
    fn handles_extended_linux_device_numbers() {
        let major = 0x1234u64;
        let minor = 0x5678u64;
        let device = ((major & 0xfff) << 8)
            | ((major & !0xfff) << 32)
            | (minor & 0xff)
            | ((minor & !0xff) << 12);
        assert_eq!(
            lock_pids("1: POSIX ADVISORY WRITE 99 1234:5678:5 0 EOF", device, 5),
            vec![99]
        );
    }
}
