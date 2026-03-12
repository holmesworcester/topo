use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::path::PathBuf;

pub struct DiscoveryTestGuard {
    file: File,
}

pub fn discovery_test_lock() -> DiscoveryTestGuard {
    let path: PathBuf = std::env::temp_dir().join("topo-discovery-tests.lock");
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap_or_else(|err| panic!("open discovery test lock {}: {}", path.display(), err));

    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        panic!(
            "lock discovery test file {} exclusively: {}",
            path.display(),
            err
        );
    }

    let current_flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
    if current_flags < 0 {
        let err = std::io::Error::last_os_error();
        panic!("read discovery test lock fd flags: {}", err);
    }
    let rc = unsafe {
        libc::fcntl(
            file.as_raw_fd(),
            libc::F_SETFD,
            current_flags | libc::FD_CLOEXEC,
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        panic!("set discovery test lock close-on-exec: {}", err);
    }

    DiscoveryTestGuard { file }
}

impl Drop for DiscoveryTestGuard {
    fn drop(&mut self) {
        let rc = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            panic!("unlock discovery test file: {}", err);
        }
    }
}
