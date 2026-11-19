use std::io;
use std::sync::atomic::AtomicBool;

#[cfg(windows)]
mod impl_ipc {
    use std::fs::{File, OpenOptions};
    use std::io::{self, Read, Write};
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};

    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_MORE_DATA,
        ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Storage::FileSystem::{FlushFileBuffers, ReadFile, WriteFile};
    use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
    use windows_sys::Win32::System::Pipes::{ConnectNamedPipe, DisconnectNamedPipe, WaitNamedPipeW};
    use windows_sys::Win32::System::Threading::{CreateEventW, ResetEvent, WaitForSingleObject};

    struct OwnedWinHandle(HANDLE);

    impl Drop for OwnedWinHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    fn new_manual_event() -> io::Result<OwnedWinHandle> {
        let ev = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if ev.is_null() {
            return Err(io::Error::from_raw_os_error(unsafe { GetLastError() } as i32));
        }
        Ok(OwnedWinHandle(ev))
    }

    fn cancel_and_drain_overlapped(pipe: HANDLE, ov: &mut OVERLAPPED) {
        unsafe {
            let _ = CancelIoEx(pipe, ov);
            let mut transferred: u32 = 0;
            let _ = GetOverlappedResult(pipe, ov, &mut transferred, 1);
        }
    }

    fn wait_overlapped_or_stop(
        pipe: HANDLE,
        event: HANDLE,
        ov: &mut OVERLAPPED,
        stop: &AtomicBool,
    ) -> io::Result<u32> {
        loop {
            if stop.load(Ordering::Acquire) {
                cancel_and_drain_overlapped(pipe, ov);
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "server shutdown requested",
                ));
            }
            let w = unsafe { WaitForSingleObject(event, 100) };
            if w == WAIT_OBJECT_0 {
                let mut transferred: u32 = 0;
                let ok = unsafe { GetOverlappedResult(pipe, ov, &mut transferred, 1) };
                if ok != 0 {
                    return Ok(transferred);
                }
                let err = unsafe { GetLastError() };
                if err == ERROR_MORE_DATA {
                    return Ok(transferred);
                }
                return Err(io::Error::from_raw_os_error(err as i32));
            } else if w != WAIT_TIMEOUT {
                let err = unsafe { GetLastError() };
                cancel_and_drain_overlapped(pipe, ov);
                return Err(io::Error::from_raw_os_error(err as i32));
            }
        }
    }

    fn accept_client(pipe: HANDLE, event: HANDLE, stop: &AtomicBool) -> io::Result<()> {
        unsafe {
            let _ = ResetEvent(event);
        }
        let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
        ov.hEvent = event;

        let ok = unsafe { ConnectNamedPipe(pipe, &mut ov) };
        if ok != 0 {
            return Ok(());
        }
        let err = unsafe { GetLastError() };
        match err {
            ERROR_PIPE_CONNECTED => Ok(()),
            ERROR_IO_PENDING => {
                let _ = wait_overlapped_or_stop(pipe, event, &mut ov, stop)?;
                Ok(())
            }
            other => Err(io::Error::from_raw_os_error(other as i32)),
        }
    }

    fn read_exact_overlapped(
        pipe: HANDLE,
        event: HANDLE,
        buf: &mut [u8],
        stop: &AtomicBool,
    ) -> io::Result<()> {
        let mut offset = 0usize;
        while offset < buf.len() {
            unsafe {
                let _ = ResetEvent(event);
            }
            let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
            ov.hEvent = event;
            let rem = u32::try_from(buf.len() - offset).unwrap_or(u32::MAX);
            let mut read_now: u32 = 0;
            let ok = unsafe {
                ReadFile(
                    pipe,
                    buf[offset..].as_mut_ptr(),
                    rem,
                    &mut read_now,
                    &mut ov,
                )
            };
            if ok != 0 {
                if read_now == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "pipe EOF"));
                }
                offset += read_now as usize;
                continue;
            }
            let err = unsafe { GetLastError() };
            match err {
                ERROR_MORE_DATA => {
                    let mut got: u32 = 0;
                    let ok = unsafe { GetOverlappedResult(pipe, &ov, &mut got, 1) };
                    let advanced = if ok != 0 || unsafe { GetLastError() } == ERROR_MORE_DATA {
                        got as usize
                    } else {
                        read_now as usize
                    };
                    if advanced == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "pipe closed on partial message",
                        ));
                    }
                    offset += advanced;
                }
                ERROR_IO_PENDING => {
                    let got = wait_overlapped_or_stop(pipe, event, &mut ov, stop)?;
                    if got == 0 {
                        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "pipe closed"));
                    }
                    offset += got as usize;
                }
                ERROR_BROKEN_PIPE => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "client disconnected",
                    ));
                }
                other => return Err(io::Error::from_raw_os_error(other as i32)),
            }
        }
        Ok(())
    }

    fn write_all_overlapped(
        pipe: HANDLE,
        event: HANDLE,
        buf: &[u8],
        stop: &AtomicBool,
    ) -> io::Result<()> {
        let mut offset = 0usize;
        while offset < buf.len() {
            unsafe {
                let _ = ResetEvent(event);
            }
            let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
            ov.hEvent = event;
            let rem = u32::try_from(buf.len() - offset).unwrap_or(u32::MAX);
            let mut written: u32 = 0;
            let ok = unsafe {
                WriteFile(
                    pipe,
                    buf[offset..].as_ptr(),
                    rem,
                    &mut written,
                    &mut ov,
                )
            };
            if ok != 0 {
                offset += written as usize;
                continue;
            }
            let err = unsafe { GetLastError() };
            if err == ERROR_IO_PENDING {
                let sent = wait_overlapped_or_stop(pipe, event, &mut ov, stop)?;
                offset += sent as usize;
            } else {
                return Err(io::Error::from_raw_os_error(err as i32));
            }
        }
        Ok(())
    }

    pub fn serve_win32_handle<F, G>(
        raw_pipe: usize,
        max_frame_bytes: usize,
        stop: &AtomicBool,
        max_sessions: Option<usize>,
        ready_signal: Option<std::sync::mpsc::Sender<()>>,
        mut on_payload: F,
        mut on_invalid_len: G,
    ) -> io::Result<()>
    where
        F: FnMut(&[u8]) -> Result<Vec<u8>, String>,
        G: FnMut(usize) -> Result<Vec<u8>, String>,
    {
        let pipe = OwnedWinHandle(raw_pipe as HANDLE);
        let event = new_manual_event()?;

        if let Some(tx) = ready_signal {
            let _ = tx.send(());
        }

        let mut served = 0usize;
        while !stop.load(Ordering::Acquire) {
            if let Some(limit) = max_sessions {
                if served >= limit {
                    break;
                }
            }

            match accept_client(pipe.0, event.0, stop) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => break,
                Err(e) => return Err(e),
            }

            loop {
                let mut hdr = [0u8; 4];
                if read_exact_overlapped(pipe.0, event.0, &mut hdr, stop).is_err() {
                    break;
                }

                let len = u32::from_le_bytes(hdr) as usize;
                let invalid_len = len == 0 || len > max_frame_bytes;
                let wire = if invalid_len {
                    on_invalid_len(len).map_err(io::Error::other)?
                } else {
                    let mut payload = vec![0u8; len];
                    if read_exact_overlapped(pipe.0, event.0, &mut payload, stop).is_err() {
                        break;
                    }
                    on_payload(&payload).map_err(io::Error::other)?
                };

                if write_all_overlapped(pipe.0, event.0, &wire, stop).is_err() || invalid_len {
                    break;
                }
            }

            unsafe {
                let _ = FlushFileBuffers(pipe.0);
                let _ = DisconnectNamedPipe(pipe.0);
            }
            served += 1;
        }
        Ok(())
    }

    pub struct LocalIpcClient {
        stream: File,
    }

    impl LocalIpcClient {
        pub fn connect(pipe_name: &str) -> io::Result<Self> {
            let wide: Vec<u16> = Path::new(pipe_name)
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            for attempt in 0..140 {
                match OpenOptions::new().read(true).write(true).open(pipe_name) {
                    Ok(file) => return Ok(Self { stream: file }),
                    Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) && attempt < 139 => {
                        let waited = unsafe { WaitNamedPipeW(wide.as_ptr(), 250) };
                        if waited == 0 {
                            std::thread::sleep(std::time::Duration::from_millis(50));
                        }
                    }
                    Err(e) => return Err(e),
                }
            }
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "named pipe busy after retries",
            ))
        }

        pub fn exchange_framed(&mut self, wire: &[u8], max_frame_bytes: usize) -> io::Result<Vec<u8>> {
            self.stream.write_all(wire)?;
            self.stream.flush()?;
            let mut hdr = [0u8; 4];
            self.stream.read_exact(&mut hdr)?;
            let len = u32::from_le_bytes(hdr) as usize;
            if len == 0 || len > max_frame_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("response frame length {len} outside 1..={max_frame_bytes}"),
                ));
            }
            let mut body = vec![0u8; len];
            self.stream.read_exact(&mut body)?;
            Ok(body)
        }
    }
}

#[cfg(unix)]
mod impl_ipc {
    use std::io::{self, Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    fn verify_peer_uid(stream: &UnixStream) -> io::Result<()> {
        let my_uid = unsafe { libc::geteuid() };
        #[cfg(target_os = "linux")]
        {
            let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
            let rc = unsafe {
                libc::getsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    (&mut cred as *mut libc::ucred).cast(),
                    &mut len,
                )
            };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            if cred.uid != my_uid {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("peer uid {} rejected (expected {})", cred.uid, my_uid),
                ));
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let mut euid: libc::uid_t = u32::MAX;
            let mut egid: libc::gid_t = u32::MAX;
            let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut euid, &mut egid) };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            if euid != my_uid {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("peer uid {euid} rejected (expected {my_uid})"),
                ));
            }
            Ok(())
        }
    }

    pub fn serve_unix_uds<F, G>(
        sock_path_str: &str,
        max_frame_bytes: usize,
        stop: &AtomicBool,
        max_sessions: Option<usize>,
        ready_signal: Option<std::sync::mpsc::Sender<()>>,
        mut on_payload: F,
        mut on_invalid_len: G,
    ) -> io::Result<()>
    where
        F: FnMut(&[u8]) -> Result<Vec<u8>, String>,
        G: FnMut(usize) -> Result<Vec<u8>, String>,
    {
        let sock_path = Path::new(sock_path_str);
        if let Some(parent) = sock_path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent)?;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }

        if sock_path.exists() {
            if UnixStream::connect(sock_path).is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("socket '{sock_path_str}' is already owned by an active guard daemon"),
                ));
            }
            std::fs::remove_file(sock_path)?;
        }

        let listener = UnixListener::bind(sock_path)?;
        std::fs::set_permissions(sock_path, std::fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;

        if let Some(tx) = ready_signal {
            let _ = tx.send(());
        }

        let mut served = 0usize;
        while !stop.load(Ordering::Acquire) {
            if let Some(limit) = max_sessions {
                if served >= limit {
                    break;
                }
            }

            let mut stream = match listener.accept() {
                Ok((s, _)) => s,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(25));
                    continue;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    let _ = std::fs::remove_file(sock_path);
                    return Err(e);
                }
            };

            let _ = stream.set_nonblocking(false);
            if verify_peer_uid(&stream).is_err() {
                continue;
            }

            loop {
                let mut hdr = [0u8; 4];
                if stream.read_exact(&mut hdr).is_err() {
                    break;
                }

                let len = u32::from_le_bytes(hdr) as usize;
                let invalid_len = len == 0 || len > max_frame_bytes;
                let wire = if invalid_len {
                    on_invalid_len(len).map_err(io::Error::other)?
                } else {
                    let mut payload = vec![0u8; len];
                    if stream.read_exact(&mut payload).is_err() {
                        break;
                    }
                    on_payload(&payload).map_err(io::Error::other)?
                };

                if stream.write_all(&wire).is_err() || stream.flush().is_err() || invalid_len {
                    break;
                }
            }
            served += 1;
        }

        let _ = std::fs::remove_file(sock_path);
        Ok(())
    }

    pub struct LocalIpcClient {
        stream: UnixStream,
    }

    impl LocalIpcClient {
        pub fn connect(pipe_name: &str) -> io::Result<Self> {
            for attempt in 0..40 {
                match UnixStream::connect(pipe_name) {
                    Ok(stream) => return Ok(Self { stream }),
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) && attempt < 39 =>
                    {
                        std::thread::sleep(Duration::from_millis(25));
                    }
                    Err(e) => return Err(e),
                }
            }
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "unix socket busy after retries",
            ))
        }

        pub fn exchange_framed(&mut self, wire: &[u8], max_frame_bytes: usize) -> io::Result<Vec<u8>> {
            self.stream.write_all(wire)?;
            self.stream.flush()?;
            let mut hdr = [0u8; 4];
            self.stream.read_exact(&mut hdr)?;
            let len = u32::from_le_bytes(hdr) as usize;
            if len == 0 || len > max_frame_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("response frame length {len} outside 1..={max_frame_bytes}"),
                ));
            }
            let mut body = vec![0u8; len];
            self.stream.read_exact(&mut body)?;
            Ok(body)
        }
    }
}

pub use impl_ipc::LocalIpcClient;

#[cfg(windows)]
pub fn serve_win32_handle<F, G>(
    raw_pipe: usize,
    max_frame_bytes: usize,
    stop: &AtomicBool,
    max_sessions: Option<usize>,
    ready_signal: Option<std::sync::mpsc::Sender<()>>,
    on_payload: F,
    on_invalid_len: G,
) -> io::Result<()>
where
    F: FnMut(&[u8]) -> Result<Vec<u8>, String>,
    G: FnMut(usize) -> Result<Vec<u8>, String>,
{
    impl_ipc::serve_win32_handle(
        raw_pipe,
        max_frame_bytes,
        stop,
        max_sessions,
        ready_signal,
        on_payload,
        on_invalid_len,
    )
}

#[cfg(unix)]
pub fn serve_unix_uds<F, G>(
    sock_path: &str,
    max_frame_bytes: usize,
    stop: &AtomicBool,
    max_sessions: Option<usize>,
    ready_signal: Option<std::sync::mpsc::Sender<()>>,
    on_payload: F,
    on_invalid_len: G,
) -> io::Result<()>
where
    F: FnMut(&[u8]) -> Result<Vec<u8>, String>,
    G: FnMut(usize) -> Result<Vec<u8>, String>,
{
    impl_ipc::serve_unix_uds(
        sock_path,
        max_frame_bytes,
        stop,
        max_sessions,
        ready_signal,
        on_payload,
        on_invalid_len,
    )
}
