mod sealed {
    pub trait Sealed {}
    impl Sealed for std::fs::File {}
}

#[cfg(unix)]
mod unix {
    use std::os::unix::io::AsRawFd;

    impl crate::LockFile for std::fs::File {
        fn lock(&self) -> std::io::Result<()> {
            let res = unsafe { libc::flock(self.as_raw_fd(), libc::LOCK_EX) };
            if res == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        }

        fn try_lock(&self) -> std::io::Result<bool> {
            let res = unsafe { libc::flock(self.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if res == -1 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    return Ok(false);
                } else {
                    return Err(err);
                }
            }
            Ok(true)
        }

        fn unlock(&self) -> std::io::Result<()> {
            let res = unsafe { libc::flock(self.as_raw_fd(), libc::LOCK_UN) };
            if res == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        }
    }
}

pub trait LockFile: sealed::Sealed {
    fn lock(&self) -> std::io::Result<()>;
    fn try_lock(&self) -> std::io::Result<bool>;
    fn unlock(&self) -> std::io::Result<()>;
}
