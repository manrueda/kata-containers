// Copyright (c) 2022-2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use crate::{
    DeviceConfig, DiskConfig, FsConfig, NetConfig, VmConfig, VmInfo, VmResize, VsockConfig,
};
use anyhow::{anyhow, Context, Result};
use nix::fcntl::{fcntl, FcntlArg};
use serde::{Deserialize, Serialize};
use std::io::{Error as IoError, ErrorKind, Read, Write};
use std::os::{
    fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
    unix::net::UnixStream,
};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::task;
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

/// All Cloud Hypervisor HTTP API calls share a single `UnixStream`. Because
/// the CH API uses HTTP/1.1 over a Unix domain socket without pipelining,
/// concurrent requests on the same stream corrupt the response framing.
const DEFAULT_API_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_HTTP_HEADER_SIZE: usize = 64 * 1024;
/// CH API responses contain small JSON status and configuration payloads.
/// Bound them at 1 MiB so malformed framing cannot trigger unbounded allocation.
const MAX_HTTP_BODY_SIZE: usize = 1024 * 1024;
const COMMAND_QUEUED: u8 = 0;
const COMMAND_DISPATCHED: u8 = 1;
const COMMAND_ABANDONED: u8 = 2;
const COMMAND_FINISHED: u8 = 3;

#[derive(Debug, thiserror::Error)]
#[error("Cloud Hypervisor API {method} {endpoint} was not dispatched: {source}")]
pub struct ApiCommandNotDispatched {
    method: &'static str,
    endpoint: &'static str,
    #[source]
    source: anyhow::Error,
}

fn api_command_not_dispatched(
    method: &'static str,
    endpoint: &'static str,
    source: anyhow::Error,
) -> anyhow::Error {
    anyhow::Error::new(ApiCommandNotDispatched {
        method,
        endpoint,
        source,
    })
}

#[derive(Debug)]
pub struct ApiSocket {
    inner: Arc<Mutex<ApiConnection>>,
    timeout: Duration,
}

#[derive(Debug)]
struct ApiConnection {
    stream: Option<UnixStream>,
    socket_path: Option<PathBuf>,
}

impl ApiSocket {
    pub fn new(socket: Option<UnixStream>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ApiConnection {
                stream: socket,
                socket_path: None,
            })),
            timeout: DEFAULT_API_TIMEOUT,
        }
    }

    pub async fn replace(&self, socket: UnixStream, socket_path: Option<PathBuf>) {
        *self.inner.lock().await = ApiConnection {
            stream: Some(socket),
            socket_path,
        };
    }

    pub async fn close(&self) {
        *self.inner.lock().await = ApiConnection {
            stream: None,
            socket_path: None,
        };
    }

    pub async fn is_open(&self) -> bool {
        let connection = self.inner.lock().await;
        connection.stream.is_some() || connection.socket_path.is_some()
    }

    #[cfg(test)]
    fn with_timeout(socket: UnixStream, timeout: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ApiConnection {
                stream: Some(socket),
                socket_path: None,
            })),
            timeout,
        }
    }

    #[cfg(test)]
    fn with_timeout_and_path(socket: UnixStream, socket_path: PathBuf, timeout: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ApiConnection {
                stream: Some(socket),
                socket_path: Some(socket_path),
            })),
            timeout,
        }
    }
}

struct CommandOwnership {
    state: Arc<AtomicU8>,
    completed: bool,
}

impl CommandOwnership {
    fn new(state: Arc<AtomicU8>) -> Self {
        Self {
            state,
            completed: false,
        }
    }

    fn abandon_before_dispatch(&mut self) -> bool {
        self.completed = true;
        self.state
            .compare_exchange(
                COMMAND_QUEUED,
                COMMAND_ABANDONED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn finish(&mut self) {
        self.completed = true;
        self.state.store(COMMAND_FINISHED, Ordering::Release);
    }
}

impl Drop for CommandOwnership {
    fn drop(&mut self) {
        if !self.completed {
            let _ = self.state.compare_exchange(
                COMMAND_QUEUED,
                COMMAND_ABANDONED,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
    }
}

fn invalid_http(message: impl Into<String>) -> api_client::Error {
    api_client::Error::Socket(IoError::new(ErrorKind::InvalidData, message.into()))
}

fn duplicate_request_fds(fds: Option<Vec<RawFd>>) -> Result<Option<Vec<OwnedFd>>> {
    fds.map(|fds| {
        fds.into_iter()
            .map(|fd| {
                // SAFETY: The public API requires each descriptor to remain valid
                // for this synchronous duplication step.
                let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
                let duplicated = fcntl(borrowed, FcntlArg::F_DUPFD_CLOEXEC(0))
                    .with_context(|| format!("duplicate Cloud Hypervisor request fd {fd}"))?;
                // SAFETY: F_DUPFD_CLOEXEC returns a new descriptor owned by this worker.
                Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
            })
            .collect()
    })
    .transpose()
}

fn status_code_from_raw(code: usize) -> api_client::StatusCode {
    match code {
        100 => api_client::StatusCode::Continue,
        200 => api_client::StatusCode::Ok,
        204 => api_client::StatusCode::NoContent,
        400 => api_client::StatusCode::BadRequest,
        404 => api_client::StatusCode::NotFound,
        429 => api_client::StatusCode::TooManyRequests,
        500 => api_client::StatusCode::InternalServerError,
        501 => api_client::StatusCode::NotImplemented,
        _ => api_client::StatusCode::Unknown,
    }
}

fn command(
    stream: &mut UnixStream,
    method: &str,
    endpoint: &str,
    body: Option<&str>,
    fds: &[RawFd],
    reusable: &mut bool,
) -> std::result::Result<Option<String>, api_client::Error> {
    let request_line =
        format!("{method} /api/v1/{endpoint} HTTP/1.1\r\nHost: localhost\r\nAccept: */*\r\n");
    if fds.is_empty() {
        stream
            .write_all(request_line.as_bytes())
            .map_err(api_client::Error::Socket)?;
    } else {
        let sent = stream
            .send_with_fds(&[request_line.as_bytes()], fds)
            .map_err(|error| api_client::Error::Socket(IoError::other(error.to_string())))?;
        stream
            .write_all(&request_line.as_bytes()[sent..])
            .map_err(api_client::Error::Socket)?;
    }
    if let Some(body) = body {
        write!(stream, "Content-Length: {}\r\n", body.len()).map_err(api_client::Error::Socket)?;
    }
    stream
        .write_all(b"\r\n")
        .map_err(api_client::Error::Socket)?;
    if let Some(body) = body {
        stream
            .write_all(body.as_bytes())
            .map_err(api_client::Error::Socket)?;
    }
    stream.flush().map_err(api_client::Error::Socket)?;

    for _ in 0..8 {
        let mut response = Vec::new();
        loop {
            if response.len() >= MAX_HTTP_HEADER_SIZE {
                return Err(invalid_http("HTTP response headers exceed 64 KiB"));
            }
            let mut byte = [0_u8; 1];
            let count = stream.read(&mut byte).map_err(api_client::Error::Socket)?;
            if count == 0 {
                return Err(invalid_http("HTTP response ended before complete headers"));
            }
            response.push(byte[0]);
            if response.ends_with(b"\r\n\r\n") {
                break;
            }
        }

        let headers = std::str::from_utf8(&response)
            .map_err(|_| invalid_http("HTTP response headers are not UTF-8"))?;
        let mut lines = headers.split("\r\n");
        let status_line = lines.next().ok_or(api_client::Error::MissingProtocol)?;
        let status_raw = status_line
            .strip_prefix("HTTP/1.1 ")
            .ok_or(api_client::Error::MissingProtocol)?
            .split_whitespace()
            .next()
            .ok_or(api_client::Error::MissingProtocol)?
            .parse::<usize>()
            .map_err(api_client::Error::StatusCodeParsing)?;
        let mut content_length = None;
        for header in lines.filter(|line| !line.is_empty()) {
            let (name, value) = header
                .split_once(':')
                .ok_or_else(|| invalid_http(format!("invalid HTTP header {header:?}")))?;
            if name.trim().eq_ignore_ascii_case("content-length") {
                if content_length.is_some() {
                    return Err(invalid_http("duplicate HTTP Content-Length header"));
                }
                content_length = Some(
                    value
                        .trim()
                        .parse::<usize>()
                        .map_err(api_client::Error::ContentLengthParsing)?,
                );
            }
        }

        let informational = (100..200).contains(&status_raw);
        let body_forbidden = informational || status_raw == 204 || status_raw == 304;
        if body_forbidden && content_length.is_some_and(|length| length != 0) {
            return Err(invalid_http(format!(
                "HTTP status {status_raw} forbids a response body"
            )));
        }
        if informational {
            continue;
        }

        let body = if body_forbidden {
            if content_length.is_none() {
                *reusable = false;
            }
            None
        } else {
            match content_length {
                Some(content_length) => {
                    if content_length > MAX_HTTP_BODY_SIZE {
                        return Err(invalid_http(format!(
                            "HTTP response body exceeds {MAX_HTTP_BODY_SIZE} bytes"
                        )));
                    }
                    let mut body = vec![0_u8; content_length];
                    stream.read_exact(&mut body).map_err(|error| {
                        invalid_http(format!("HTTP body does not match Content-Length: {error}"))
                    })?;
                    Some(
                        String::from_utf8(body)
                            .map_err(|_| invalid_http("HTTP response body is not UTF-8"))?,
                    )
                }
                None if endpoint == "vmm.shutdown" => {
                    *reusable = false;
                    None
                }
                None => {
                    *reusable = false;
                    return Err(invalid_http(
                        "HTTP response permits a body but has no Content-Length",
                    ));
                }
            }
        };

        let mut extra = [0_u8; 1];
        match nix::sys::socket::recv(
            stream.as_raw_fd(),
            &mut extra,
            nix::sys::socket::MsgFlags::MSG_PEEK | nix::sys::socket::MsgFlags::MSG_DONTWAIT,
        ) {
            Ok(0) => *reusable = false,
            Err(nix::errno::Errno::EAGAIN) => {}
            Ok(_) => {
                return Err(invalid_http(
                    "HTTP response has bytes beyond Content-Length",
                ));
            }
            Err(error) => {
                return Err(api_client::Error::Socket(IoError::from_raw_os_error(
                    error as i32,
                )));
            }
        }

        let status = status_code_from_raw(status_raw);
        return if matches!(
            status,
            api_client::StatusCode::Ok | api_client::StatusCode::NoContent
        ) {
            Ok(body)
        } else {
            Err(api_client::Error::ServerResponse(status, body))
        };
    }

    Err(invalid_http("too many informational HTTP responses"))
}

/// Execute a CH API command while holding the API socket lock.
///
/// The blocking worker owns the mutex guard. Canceling the async caller cannot
/// release serialization ownership while the request is still active.
async fn api_command(
    api_socket: &ApiSocket,
    method: &'static str,
    endpoint: &'static str,
    body: Option<String>,
    fds: Option<Vec<RawFd>>,
) -> Result<Option<String>> {
    let fds = duplicate_request_fds(fds)
        .map_err(|error| api_command_not_dispatched(method, endpoint, error))?;
    let socket = api_socket.inner.clone();
    let timeout = api_socket.timeout;
    let state = Arc::new(AtomicU8::new(COMMAND_QUEUED));
    let worker_state = state.clone();
    let mut ownership = CommandOwnership::new(state);

    let worker = task::spawn_blocking(move || -> Result<Option<String>> {
        let mut guard = socket.blocking_lock_owned();
        if guard.stream.is_none() {
            let path = guard.socket_path.clone().ok_or_else(|| {
                api_command_not_dispatched(
                    method,
                    endpoint,
                    anyhow!("Cloud Hypervisor API socket is unavailable and has no reconnect path"),
                )
            })?;
            let stream = UnixStream::connect(&path)
                .with_context(|| format!("reconnect Cloud Hypervisor API socket {path:?}"))
                .map_err(|error| api_command_not_dispatched(method, endpoint, error))?;
            guard.stream = Some(stream);
        }
        let stream = guard.stream.as_mut().ok_or_else(|| {
            api_command_not_dispatched(
                method,
                endpoint,
                anyhow!("Cloud Hypervisor API socket is unavailable"),
            )
        })?;
        let socket_timeout = timeout.checked_mul(2).unwrap_or(timeout);
        stream
            .set_read_timeout(Some(socket_timeout))
            .context("set Cloud Hypervisor API read timeout")
            .map_err(|error| api_command_not_dispatched(method, endpoint, error))?;
        stream
            .set_write_timeout(Some(socket_timeout))
            .context("set Cloud Hypervisor API write timeout")
            .map_err(|error| api_command_not_dispatched(method, endpoint, error))?;

        if worker_state
            .compare_exchange(
                COMMAND_QUEUED,
                COMMAND_DISPATCHED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return Err(api_command_not_dispatched(
                method,
                endpoint,
                anyhow!("command was abandoned before dispatch"),
            ));
        }

        let mut reusable = true;
        let raw_fds = fds
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(AsRawFd::as_raw_fd)
            .collect::<Vec<_>>();
        let response = catch_unwind(AssertUnwindSafe(|| {
            command(
                stream,
                method,
                endpoint,
                body.as_deref(),
                &raw_fds,
                &mut reusable,
            )
        }));

        match response {
            Ok(Ok(response)) => {
                if !reusable {
                    guard.stream = None;
                }
                Ok(response)
            }
            Ok(Err(error @ api_client::Error::ServerResponse(..))) => {
                if !reusable {
                    guard.stream = None;
                }
                Err(anyhow!(error))
            }
            Ok(Err(error)) => {
                guard.stream = None;
                Err(anyhow!(error).context(format!(
                    "Cloud Hypervisor API {method} {endpoint} left uncertain HTTP framing; closed the socket for reconnect"
                )))
            }
            Err(_) => {
                guard.stream = None;
                Err(anyhow!(
                    "Cloud Hypervisor API {method} {endpoint} panicked while parsing malformed HTTP; closed the socket for reconnect"
                ))
            }
        }
    });

    match tokio::time::timeout(timeout, worker).await {
        Ok(result) => {
            ownership.finish();
            result.context("join Cloud Hypervisor API worker")?
        }
        Err(_) => {
            let abandoned = ownership.abandon_before_dispatch();
            if abandoned {
                Err(api_command_not_dispatched(
                    method,
                    endpoint,
                    anyhow!("timed out after {timeout:?} before dispatch"),
                ))
            } else {
                Err(anyhow!(
                    "Cloud Hypervisor API {method} {endpoint} timed out after {timeout:?}; the dispatched worker still owns and drains the request"
                ))
            }
        }
    }
}

pub fn is_api_command_not_dispatched(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<ApiCommandNotDispatched>().is_some())
}

pub fn is_definite_server_response(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<api_client::Error>(),
        Some(api_client::Error::ServerResponse(..))
    )
}

fn is_not_found_response(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<api_client::Error>(),
        Some(api_client::Error::ServerResponse(
            api_client::StatusCode::NotFound,
            _
        ))
    )
}

pub async fn cloud_hypervisor_vmm_ping(api_socket: &ApiSocket) -> Result<Option<String>> {
    api_command(api_socket, "GET", "vmm.ping", None, None).await
}

pub async fn cloud_hypervisor_vmm_shutdown(api_socket: &ApiSocket) -> Result<Option<String>> {
    api_command(api_socket, "PUT", "vmm.shutdown", None, None).await
}

pub async fn cloud_hypervisor_vm_create(
    api_socket: &ApiSocket,
    cfg: VmConfig,
) -> Result<Option<String>> {
    let body = serde_json::to_string_pretty(&cfg)?;
    api_command(api_socket, "PUT", "vm.create", Some(body), None).await
}

pub async fn cloud_hypervisor_vm_start(api_socket: &ApiSocket) -> Result<Option<String>> {
    api_command(api_socket, "PUT", "vm.boot", None, None).await
}

pub async fn cloud_hypervisor_vm_pause(api_socket: &ApiSocket) -> Result<Option<String>> {
    api_command(api_socket, "PUT", "vm.pause", None, None).await
}

pub async fn cloud_hypervisor_vm_resume(api_socket: &ApiSocket) -> Result<Option<String>> {
    api_command(api_socket, "PUT", "vm.resume", None, None).await
}

#[derive(Clone, Deserialize, Serialize, Default, Debug)]
pub struct VmSnapshotConfig {
    pub destination_url: String,
}

#[derive(Clone, Deserialize, Serialize, Default, Debug)]
pub struct RestoreConfig {
    pub source_url: String,
}

pub async fn cloud_hypervisor_vm_snapshot(
    api_socket: &ApiSocket,
    cfg: VmSnapshotConfig,
) -> Result<Option<String>> {
    let body = serde_json::to_string(&cfg)?;
    api_command(api_socket, "PUT", "vm.snapshot", Some(body), None).await
}

pub async fn cloud_hypervisor_vm_restore(
    api_socket: &ApiSocket,
    cfg: RestoreConfig,
) -> Result<Option<String>> {
    let body = serde_json::to_string(&cfg)?;
    api_command(api_socket, "PUT", "vm.restore", Some(body), None).await
}

#[allow(dead_code)]
pub async fn cloud_hypervisor_vm_stop(api_socket: &ApiSocket) -> Result<Option<String>> {
    api_command(api_socket, "PUT", "vm.shutdown", None, None).await
}

#[derive(Deserialize, Debug)]
pub struct PciDeviceInfo {
    pub id: String,
    pub bdf: String,
}

#[derive(Clone, Deserialize, Serialize, Default, Debug)]
pub struct VmRemoveDeviceData {
    #[serde(default)]
    pub id: String,
}

pub async fn cloud_hypervisor_vm_blockdev_add(
    api_socket: &ApiSocket,
    blk_config: DiskConfig,
) -> Result<Option<String>> {
    let body = serde_json::to_string(&blk_config)?;
    api_command(api_socket, "PUT", "vm.add-disk", Some(body), None).await
}

pub async fn cloud_hypervisor_vm_netdev_add(
    api_socket: &ApiSocket,
    net_config: NetConfig,
) -> Result<Option<String>> {
    let body = serde_json::to_string(&net_config)?;
    api_command(api_socket, "PUT", "vm.add-net", Some(body), None).await
}

pub async fn cloud_hypervisor_vm_netdev_add_with_fds(
    api_socket: &ApiSocket,
    net_config: NetConfig,
    request_fds: Vec<RawFd>,
) -> Result<Option<String>> {
    let body = serde_json::to_string(&net_config)?;
    api_command(
        api_socket,
        "PUT",
        "vm.add-net",
        Some(body),
        Some(request_fds),
    )
    .await
}

pub async fn cloud_hypervisor_vm_device_add(
    api_socket: &ApiSocket,
    device_config: DeviceConfig,
) -> Result<Option<String>> {
    let body = serde_json::to_string(&device_config)?;
    api_command(api_socket, "PUT", "vm.add-device", Some(body), None).await
}

#[allow(dead_code)]
pub async fn cloud_hypervisor_vm_device_remove(
    api_socket: &ApiSocket,
    device_data: VmRemoveDeviceData,
) -> Result<Option<String>> {
    let body = serde_json::to_string(&device_data)?;
    match api_command(api_socket, "PUT", "vm.remove-device", Some(body), None).await {
        Err(error) if is_not_found_response(&error) => Ok(None),
        result => result,
    }
}

pub async fn cloud_hypervisor_vm_fs_add(
    api_socket: &ApiSocket,
    fs_config: FsConfig,
) -> Result<Option<String>> {
    let body = serde_json::to_string(&fs_config)?;
    api_command(api_socket, "PUT", "vm.add-fs", Some(body), None).await
}

pub async fn cloud_hypervisor_vm_vsock_add(
    api_socket: &ApiSocket,
    vsock_config: VsockConfig,
) -> Result<Option<String>> {
    let body = serde_json::to_string(&vsock_config)?;
    api_command(api_socket, "PUT", "vm.add-vsock", Some(body), None).await
}

pub async fn cloud_hypervisor_vm_info(api_socket: &ApiSocket) -> Result<VmInfo> {
    let response = api_command(api_socket, "GET", "vm.info", None, None).await?;
    let vm_info = response.ok_or(anyhow!("failed to get vminfo"))?;
    serde_json::from_str(&vm_info).with_context(|| format!("failed to serde {vm_info}"))
}

pub async fn cloud_hypervisor_vm_resize(
    api_socket: &ApiSocket,
    vmresize: VmResize,
) -> Result<Option<String>> {
    let body = serde_json::to_string(&vmresize)?;
    api_command(api_socket, "PUT", "vm.resize", Some(body), None).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::task::{Context as TaskContext, Poll, Waker};
    use std::thread;

    #[derive(Debug)]
    struct Request {
        request_line: String,
    }

    fn read_request(socket: &mut UnixStream) -> Request {
        let mut bytes = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            socket.read_exact(&mut byte).unwrap();
            bytes.push(byte[0]);
            if bytes.ends_with(b"\r\n\r\n") {
                break;
            }
        }

        let headers = String::from_utf8(bytes).unwrap();
        let content_length = headers
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .map(|length| length.parse::<usize>().unwrap())
            .unwrap_or_default();
        let mut body = vec![0_u8; content_length];
        socket.read_exact(&mut body).unwrap();

        Request {
            request_line: headers.lines().next().unwrap().to_string(),
        }
    }

    fn write_response(socket: &mut UnixStream, status: &str, body: Option<&str>) {
        let response = match body {
            Some(body) => format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
            None => format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n"),
        };
        socket.write_all(response.as_bytes()).unwrap();
        socket.flush().unwrap();
    }

    fn run_async_test(future: impl Future<Output = ()>) {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(future);
    }

    fn poll_once<F: Future>(future: std::pin::Pin<&mut F>) -> Poll<F::Output> {
        let mut context = TaskContext::from_waker(Waker::noop());
        future.poll(&mut context)
    }

    async fn assert_peer_closed(mut peer: UnixStream) {
        tokio::task::spawn_blocking(move || {
            peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut byte = [0_u8; 1];
            assert_eq!(peer.read(&mut byte).unwrap(), 0);
        })
        .await
        .unwrap();
    }

    fn assert_uncertain_response_reconnects(response: &'static [u8]) {
        run_async_test(async {
            let temp_dir = tempfile::tempdir().unwrap();
            let socket_path = temp_dir.path().join("ch-api.sock");
            let listener = UnixListener::bind(&socket_path).unwrap();
            let client = UnixStream::connect(&socket_path).unwrap();
            let server = thread::spawn(move || {
                let (mut malformed_socket, _) = listener.accept().unwrap();
                let first = read_request(&mut malformed_socket);
                malformed_socket.write_all(response).unwrap();
                malformed_socket.flush().unwrap();
                drop(malformed_socket);

                let (mut replacement_socket, _) = listener.accept().unwrap();
                let second = read_request(&mut replacement_socket);
                write_response(&mut replacement_socket, "200", Some("{}"));
                (first, second)
            });
            let api_socket =
                ApiSocket::with_timeout_and_path(client, socket_path, Duration::from_secs(1));

            assert!(cloud_hypervisor_vmm_ping(&api_socket).await.is_err());
            assert_eq!(
                cloud_hypervisor_vmm_ping(&api_socket)
                    .await
                    .unwrap()
                    .as_deref(),
                Some("{}")
            );
            let (first, second) = server.join().unwrap();
            assert_eq!(first.request_line, "GET /api/v1/vmm.ping HTTP/1.1");
            assert_eq!(second.request_line, "GET /api/v1/vmm.ping HTTP/1.1");
        });
    }

    #[test]
    fn canceled_command_keeps_serialization_until_worker_finishes() {
        run_async_test(async {
            let (client, mut server_socket) = UnixStream::pair().unwrap();
            let api_socket = Arc::new(ApiSocket::with_timeout(client, Duration::from_secs(2)));
            let (first_seen_tx, first_seen_rx) = std::sync::mpsc::channel();
            let (respond_tx, respond_rx) = std::sync::mpsc::channel();
            let server = thread::spawn(move || {
                let first = read_request(&mut server_socket);
                first_seen_tx.send(()).unwrap();
                respond_rx.recv().unwrap();

                server_socket
                    .set_read_timeout(Some(Duration::from_millis(100)))
                    .unwrap();
                let mut byte = [0_u8; 1];
                let error = server_socket.read(&mut byte).unwrap_err();
                assert!(matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ));
                write_response(&mut server_socket, "200", Some("{}"));
                server_socket.set_read_timeout(None).unwrap();
                let second = read_request(&mut server_socket);
                write_response(&mut server_socket, "200", Some("{}"));
                (first, second)
            });

            let first_socket = api_socket.clone();
            let first =
                tokio::spawn(async move { cloud_hypervisor_vmm_ping(first_socket.as_ref()).await });
            tokio::task::spawn_blocking(move || first_seen_rx.recv().unwrap())
                .await
                .unwrap();
            first.abort();
            assert!(first.await.unwrap_err().is_cancelled());

            let second_socket = api_socket.clone();
            let second =
                tokio::spawn(
                    async move { cloud_hypervisor_vmm_ping(second_socket.as_ref()).await },
                );
            respond_tx.send(()).unwrap();

            assert_eq!(second.await.unwrap().unwrap().as_deref(), Some("{}"));
            let (first, second) = server.join().unwrap();
            assert_eq!(first.request_line, "GET /api/v1/vmm.ping HTTP/1.1");
            assert_eq!(second.request_line, "GET /api/v1/vmm.ping HTTP/1.1");
        });
    }

    #[test]
    fn canceled_queued_command_never_dispatches() {
        run_async_test(async {
            let (client, mut server_socket) = UnixStream::pair().unwrap();
            let api_socket = Arc::new(ApiSocket::with_timeout(client, Duration::from_secs(2)));
            let (first_seen_tx, first_seen_rx) = std::sync::mpsc::channel();
            let (respond_tx, respond_rx) = std::sync::mpsc::channel();
            let server = thread::spawn(move || {
                let first = read_request(&mut server_socket);
                first_seen_tx.send(()).unwrap();
                respond_rx.recv().unwrap();
                write_response(&mut server_socket, "200", Some("{}"));
                let next = read_request(&mut server_socket);
                write_response(&mut server_socket, "200", Some("{}"));
                (first, next)
            });

            let first_socket = api_socket.clone();
            let first =
                tokio::spawn(async move { cloud_hypervisor_vmm_ping(first_socket.as_ref()).await });
            tokio::task::spawn_blocking(move || first_seen_rx.recv().unwrap())
                .await
                .unwrap();
            let mut stale = Box::pin(cloud_hypervisor_vm_device_remove(
                api_socket.as_ref(),
                VmRemoveDeviceData {
                    id: "stale-remove".to_string(),
                },
            ));
            assert!(poll_once(stale.as_mut()).is_pending());
            drop(stale);

            respond_tx.send(()).unwrap();
            first.await.unwrap().unwrap();
            cloud_hypervisor_vmm_ping(api_socket.as_ref())
                .await
                .unwrap();

            let (first, next) = server.join().unwrap();
            assert_eq!(first.request_line, "GET /api/v1/vmm.ping HTTP/1.1");
            assert_eq!(next.request_line, "GET /api/v1/vmm.ping HTTP/1.1");
        });
    }

    #[test]
    fn timed_out_queued_command_never_dispatches() {
        run_async_test(async {
            let (client, mut server_socket) = UnixStream::pair().unwrap();
            let api_socket = Arc::new(ApiSocket::with_timeout(client, Duration::from_millis(50)));
            let (first_seen_tx, first_seen_rx) = std::sync::mpsc::channel();
            let (respond_tx, respond_rx) = std::sync::mpsc::channel();
            let server = thread::spawn(move || {
                let first = read_request(&mut server_socket);
                first_seen_tx.send(()).unwrap();
                respond_rx.recv().unwrap();
                write_response(&mut server_socket, "200", Some("{}"));
                let next = read_request(&mut server_socket);
                write_response(&mut server_socket, "200", Some("{}"));
                (first, next)
            });

            let first_socket = api_socket.clone();
            let first =
                tokio::spawn(async move { cloud_hypervisor_vmm_ping(first_socket.as_ref()).await });
            tokio::task::spawn_blocking(move || first_seen_rx.recv().unwrap())
                .await
                .unwrap();
            let error = cloud_hypervisor_vm_device_remove(
                api_socket.as_ref(),
                VmRemoveDeviceData {
                    id: "stale-remove".to_string(),
                },
            )
            .await
            .unwrap_err();
            assert!(error.to_string().contains("before dispatch"));
            assert!(is_api_command_not_dispatched(&error));

            respond_tx.send(()).unwrap();
            assert!(first.await.unwrap().is_err());
            cloud_hypervisor_vmm_ping(api_socket.as_ref())
                .await
                .unwrap();

            let (first, next) = server.join().unwrap();
            assert_eq!(first.request_line, "GET /api/v1/vmm.ping HTTP/1.1");
            assert_eq!(next.request_line, "GET /api/v1/vmm.ping HTTP/1.1");
        });
    }

    #[test]
    fn unavailable_socket_is_typed_as_never_dispatched() {
        run_async_test(async {
            let api_socket = ApiSocket::new(None);

            let error = cloud_hypervisor_vmm_ping(&api_socket).await.unwrap_err();

            assert!(is_api_command_not_dispatched(&error));
            assert!(error.to_string().contains("was not dispatched"));
        });
    }

    #[test]
    fn duplicated_request_fds_outlive_original_owner() {
        let (original, mut peer) = UnixStream::pair().unwrap();
        let duplicated = duplicate_request_fds(Some(vec![original.as_raw_fd()]))
            .unwrap()
            .unwrap();
        drop(original);

        peer.write_all(b"x").unwrap();
        let mut byte = [0_u8; 1];
        assert_eq!(nix::unistd::read(&duplicated[0], &mut byte).unwrap(), 1);
        assert_eq!(byte, [b'x']);
    }

    #[test]
    fn canceled_queued_fd_request_closes_worker_duplicates() {
        run_async_test(async {
            let (client, mut server_socket) = UnixStream::pair().unwrap();
            let api_socket = Arc::new(ApiSocket::with_timeout(client, Duration::from_secs(2)));
            let (first_seen_tx, first_seen_rx) = std::sync::mpsc::channel();
            let (respond_tx, respond_rx) = std::sync::mpsc::channel();
            let server = thread::spawn(move || {
                read_request(&mut server_socket);
                first_seen_tx.send(()).unwrap();
                respond_rx.recv().unwrap();
                write_response(&mut server_socket, "200", Some("{}"));
                server_socket
                    .set_read_timeout(Some(Duration::from_millis(100)))
                    .unwrap();
                let mut byte = [0_u8; 1];
                let error = server_socket.read(&mut byte).unwrap_err();
                assert!(matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ));
            });

            let first_socket = api_socket.clone();
            let first =
                tokio::spawn(async move { cloud_hypervisor_vmm_ping(first_socket.as_ref()).await });
            tokio::task::spawn_blocking(move || first_seen_rx.recv().unwrap())
                .await
                .unwrap();

            let (original, peer) = UnixStream::pair().unwrap();
            let mut queued = Box::pin(cloud_hypervisor_vm_netdev_add_with_fds(
                api_socket.as_ref(),
                NetConfig::default(),
                vec![original.as_raw_fd()],
            ));
            assert!(poll_once(queued.as_mut()).is_pending());
            drop(queued);
            drop(original);

            respond_tx.send(()).unwrap();
            first.await.unwrap().unwrap();
            assert_peer_closed(peer).await;
            server.join().unwrap();
        });
    }

    #[test]
    fn canceled_dispatched_fd_request_closes_worker_duplicates() {
        run_async_test(async {
            let (client, mut server_socket) = UnixStream::pair().unwrap();
            let api_socket = ApiSocket::with_timeout(client, Duration::from_secs(2));
            let (request_seen_tx, request_seen_rx) = std::sync::mpsc::channel();
            let (respond_tx, respond_rx) = std::sync::mpsc::channel();
            let server = thread::spawn(move || {
                let request = read_request(&mut server_socket);
                request_seen_tx.send(request).unwrap();
                respond_rx.recv().unwrap();
                write_response(&mut server_socket, "200", Some("{}"));
            });

            let (original, peer) = UnixStream::pair().unwrap();
            let mut dispatched = Box::pin(cloud_hypervisor_vm_netdev_add_with_fds(
                &api_socket,
                NetConfig::default(),
                vec![original.as_raw_fd()],
            ));
            assert!(poll_once(dispatched.as_mut()).is_pending());
            let request = tokio::task::spawn_blocking(move || request_seen_rx.recv().unwrap())
                .await
                .unwrap();
            assert_eq!(request.request_line, "PUT /api/v1/vm.add-net HTTP/1.1");
            drop(dispatched);
            drop(original);

            respond_tx.send(()).unwrap();
            assert_peer_closed(peer).await;
            server.join().unwrap();
        });
    }

    #[test]
    fn lowercase_content_length_is_accepted() {
        run_async_test(async {
            let (client, mut server_socket) = UnixStream::pair().unwrap();
            let server = thread::spawn(move || {
                let first = read_request(&mut server_socket);
                server_socket
                    .write_all(b"HTTP/1.1 200\r\ncontent-length: 2\r\n\r\n{}")
                    .unwrap();
                server_socket.flush().unwrap();
                let second = read_request(&mut server_socket);
                write_response(&mut server_socket, "200", Some("{}"));
                (first, second)
            });
            let api_socket = ApiSocket::new(Some(client));
            assert_eq!(
                cloud_hypervisor_vmm_ping(&api_socket)
                    .await
                    .unwrap()
                    .as_deref(),
                Some("{}")
            );
            cloud_hypervisor_vmm_ping(&api_socket).await.unwrap();
            server.join().unwrap();
        });
    }

    #[test]
    fn duplicate_content_length_reconnects() {
        assert_uncertain_response_reconnects(
            b"HTTP/1.1 200\r\nContent-Length: 2\r\ncontent-length: 2\r\n\r\n{}",
        );
    }

    #[test]
    fn missing_content_length_with_body_reconnects() {
        assert_uncertain_response_reconnects(b"HTTP/1.1 200\r\n\r\n{}");
    }

    #[test]
    fn malformed_content_length_reconnects() {
        assert_uncertain_response_reconnects(b"HTTP/1.1 200\r\nContent-Length: invalid\r\n\r\n{}");
    }

    #[test]
    fn no_body_status_rejects_content_length() {
        assert_uncertain_response_reconnects(b"HTTP/1.1 204\r\nContent-Length: 2\r\n\r\n{}");
    }

    #[test]
    fn response_body_at_limit_is_accepted() {
        run_async_test(async {
            let (client, mut server_socket) = UnixStream::pair().unwrap();
            let server = thread::spawn(move || {
                read_request(&mut server_socket);
                write!(
                    server_socket,
                    "HTTP/1.1 200\r\nContent-Length: {MAX_HTTP_BODY_SIZE}\r\n\r\n"
                )
                .unwrap();
                server_socket
                    .write_all(&vec![b'x'; MAX_HTTP_BODY_SIZE])
                    .unwrap();
                server_socket.flush().unwrap();
            });
            let api_socket = ApiSocket::new(Some(client));

            let response = cloud_hypervisor_vmm_ping(&api_socket)
                .await
                .unwrap()
                .unwrap();

            assert_eq!(response.len(), MAX_HTTP_BODY_SIZE);
            server.join().unwrap();
        });
    }

    #[test]
    fn oversized_response_body_is_rejected_and_reconnects() {
        run_async_test(async {
            let temp_dir = tempfile::tempdir().unwrap();
            let socket_path = temp_dir.path().join("ch-api.sock");
            let listener = UnixListener::bind(&socket_path).unwrap();
            let client = UnixStream::connect(&socket_path).unwrap();
            let server = thread::spawn(move || {
                let (mut oversized_socket, _) = listener.accept().unwrap();
                let first = read_request(&mut oversized_socket);
                write!(
                    oversized_socket,
                    "HTTP/1.1 200\r\nContent-Length: {}\r\n\r\n",
                    MAX_HTTP_BODY_SIZE + 1
                )
                .unwrap();
                let oversized_body = vec![b'x'; MAX_HTTP_BODY_SIZE + 1];
                let _ = oversized_socket.write_all(&oversized_body);
                drop(oversized_socket);

                let (mut replacement_socket, _) = listener.accept().unwrap();
                let second = read_request(&mut replacement_socket);
                write_response(&mut replacement_socket, "200", Some("{}"));
                (first, second)
            });
            let api_socket =
                ApiSocket::with_timeout_and_path(client, socket_path, Duration::from_secs(2));

            let error = cloud_hypervisor_vmm_ping(&api_socket).await.unwrap_err();
            assert!(format!("{error:#}").contains("response body exceeds"));
            assert_eq!(
                cloud_hypervisor_vmm_ping(&api_socket)
                    .await
                    .unwrap()
                    .as_deref(),
                Some("{}")
            );
            let (first, second) = server.join().unwrap();
            assert_eq!(first.request_line, "GET /api/v1/vmm.ping HTTP/1.1");
            assert_eq!(second.request_line, "GET /api/v1/vmm.ping HTTP/1.1");
        });
    }

    #[test]
    fn informational_response_is_consumed_before_final_response() {
        run_async_test(async {
            let (client, mut server_socket) = UnixStream::pair().unwrap();
            let server = thread::spawn(move || {
                let first = read_request(&mut server_socket);
                server_socket
                    .write_all(
                        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200\r\nContent-Length: 2\r\n\r\n{}",
                    )
                    .unwrap();
                server_socket.flush().unwrap();
                let second = read_request(&mut server_socket);
                write_response(&mut server_socket, "200", Some("{}"));
                (first, second)
            });
            let api_socket = ApiSocket::new(Some(client));
            cloud_hypervisor_vmm_ping(&api_socket).await.unwrap();
            cloud_hypervisor_vmm_ping(&api_socket).await.unwrap();
            server.join().unwrap();
        });
    }

    #[test]
    fn stalled_peer_times_out_and_reconnects() {
        run_async_test(async {
            let temp_dir = tempfile::tempdir().unwrap();
            let socket_path = temp_dir.path().join("ch-api.sock");
            let listener = UnixListener::bind(&socket_path).unwrap();
            let client = UnixStream::connect(&socket_path).unwrap();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let server = thread::spawn(move || {
                let (mut first_socket, _) = listener.accept().unwrap();
                let first = read_request(&mut first_socket);
                release_rx.recv().unwrap();
                drop(first_socket);

                let (mut second_socket, _) = listener.accept().unwrap();
                let second = read_request(&mut second_socket);
                write_response(&mut second_socket, "204", None);
                (first, second)
            });
            let api_socket =
                ApiSocket::with_timeout_and_path(client, socket_path, Duration::from_millis(50));

            let error = cloud_hypervisor_vmm_ping(&api_socket).await.unwrap_err();

            assert!(error
                .to_string()
                .contains("GET vmm.ping timed out after 50ms"));
            release_tx.send(()).unwrap();
            assert!(cloud_hypervisor_vm_device_remove(
                &api_socket,
                VmRemoveDeviceData {
                    id: "pending-device".to_string()
                }
            )
            .await
            .unwrap()
            .is_none());
            let (first, second) = server.join().unwrap();
            assert_eq!(first.request_line, "GET /api/v1/vmm.ping HTTP/1.1");
            assert_eq!(second.request_line, "PUT /api/v1/vm.remove-device HTTP/1.1");
        });
    }

    #[test]
    fn malformed_http_closes_stream_and_reconnects() {
        run_async_test(async {
            let temp_dir = tempfile::tempdir().unwrap();
            let socket_path = temp_dir.path().join("ch-api.sock");
            let listener = UnixListener::bind(&socket_path).unwrap();
            let client = UnixStream::connect(&socket_path).unwrap();
            let server = thread::spawn(move || {
                let (mut malformed_socket, _) = listener.accept().unwrap();
                let first = read_request(&mut malformed_socket);
                malformed_socket
                    .write_all(b"HTTP/1.1 200\r\nContent-Length: 5\r\n\r\n{}")
                    .unwrap();
                malformed_socket.flush().unwrap();
                drop(malformed_socket);

                let (mut replacement_socket, _) = listener.accept().unwrap();
                let second = read_request(&mut replacement_socket);
                write_response(&mut replacement_socket, "200", Some("{}"));
                (first, second)
            });
            let api_socket =
                ApiSocket::with_timeout_and_path(client, socket_path, Duration::from_secs(1));

            let error = cloud_hypervisor_vmm_ping(&api_socket).await.unwrap_err();
            assert!(error.to_string().contains("uncertain HTTP framing"));
            assert_eq!(
                cloud_hypervisor_vmm_ping(&api_socket)
                    .await
                    .unwrap()
                    .as_deref(),
                Some("{}")
            );

            let (first, second) = server.join().unwrap();
            assert_eq!(first.request_line, "GET /api/v1/vmm.ping HTTP/1.1");
            assert_eq!(second.request_line, "GET /api/v1/vmm.ping HTTP/1.1");
        });
    }
}
