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

#[cfg(windows)]
mod windows {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Foundation::ERROR_IO_PENDING;
    use windows_sys::Win32::Foundation::ERROR_LOCK_VIOLATION;
    use windows_sys::Win32::Foundation::ERROR_NOT_LOCKED;
    use windows_sys::Win32::Foundation::FALSE;
    use windows_sys::Win32::Foundation::TRUE;
    use windows_sys::Win32::Storage::FileSystem::LockFileEx;
    use windows_sys::Win32::Storage::FileSystem::UnlockFile;
    use windows_sys::Win32::Storage::FileSystem::LOCKFILE_EXCLUSIVE_LOCK;
    use windows_sys::Win32::Storage::FileSystem::LOCKFILE_FAIL_IMMEDIATELY;
    use windows_sys::Win32::System::Threading::CreateEventW;
    use windows_sys::Win32::System::IO::GetOverlappedResult;
    use windows_sys::Win32::System::IO::OVERLAPPED;

    impl crate::LockFile for std::fs::File {
        fn lock(&self) -> std::io::Result<()> {
            let mut overlapped =
                unsafe { std::mem::MaybeUninit::<OVERLAPPED>::zeroed().assume_init() };
            let event =
                unsafe { CreateEventW(std::ptr::null_mut(), FALSE, FALSE, std::ptr::null()) };
            if event.is_null() {
                return Err(std::io::Error::last_os_error());
            }
            overlapped.hEvent = event;
            let res = unsafe {
                LockFileEx(
                    self.as_raw_handle(),
                    LOCKFILE_EXCLUSIVE_LOCK,
                    0,
                    u32::MAX,
                    u32::MAX,
                    &mut overlapped,
                )
            };
            let res = if res == FALSE {
                let res = std::io::Error::last_os_error();
                if res.raw_os_error() == Some(ERROR_IO_PENDING as i32) {
                    let mut bytes_transfered = 0;
                    let res = unsafe {
                        GetOverlappedResult(
                            self.as_raw_handle(),
                            &overlapped,
                            &mut bytes_transfered,
                            TRUE,
                        )
                    };
                    if res == FALSE {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(())
                    }
                } else {
                    Err(res)
                }
            } else {
                Ok(())
            };
            unsafe {
                CloseHandle(overlapped.hEvent);
            }
            res
        }

        fn try_lock(&self) -> std::io::Result<bool> {
            let mut overlapped =
                unsafe { std::mem::MaybeUninit::<OVERLAPPED>::zeroed().assume_init() };
            let res = unsafe {
                LockFileEx(
                    self.as_raw_handle(),
                    LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                    0,
                    u32::MAX,
                    u32::MAX,
                    &mut overlapped,
                )
            };
            if res == FALSE {
                let err = std::io::Error::last_os_error();
                match err.raw_os_error().map(|num| num as u32) {
                    Some(ERROR_IO_PENDING | ERROR_LOCK_VIOLATION) => Ok(false),
                    _ => Err(err),
                }
            } else {
                Ok(true)
            }
        }

        fn unlock(&self) -> std::io::Result<()> {
            // Unlock twice, see:
            // https://github.com/rust-lang/rust/blob/2b285cd5f0877e30ad1d83e04f8cc46254e43391/library/std/src/sys/fs/windows.rs#L451-L454
            let res = unsafe { UnlockFile(self.as_raw_handle(), 0, 0, u32::MAX, u32::MAX) };
            if res == FALSE {
                return Err(std::io::Error::last_os_error());
            }
            let res = unsafe { UnlockFile(self.as_raw_handle(), 0, 0, u32::MAX, u32::MAX) };
            if res == FALSE {
                let err = std::io::Error::last_os_error();
                match err.raw_os_error().map(|num| num as u32) {
                    Some(ERROR_NOT_LOCKED) => {}
                    _ => return Err(err),
                }
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
