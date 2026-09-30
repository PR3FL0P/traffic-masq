use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use thiserror::Error;
use tokio::net::UnixDatagram;
use tokio::sync::{broadcast, oneshot};
use tokio::task::JoinHandle;

pub(crate) const MAX_CTRL_MESSAGE_BYTES: usize = 4096;

const EVENT_CHANNEL_CAPACITY: usize = 64;

const DETACH_TIMEOUT: Duration = Duration::from_millis(500);

pub use traffic_masq_protocol::{MacAddr, MacAddrParseError};

#[derive(Debug, Error)]
pub enum CtrlError {
    #[error("I/O error on control socket: {0}")]
    Io(#[from] std::io::Error),

    #[error("control request timed out after {0:?}")]
    Timeout(Duration),

    #[error("the control interface rejected the request")]
    Failed,

    #[error("the control interface does not recognise the command {0:?}")]
    UnknownCommand(String),

    #[error("malformed control reply: {0:?}")]
    MalformedReply(String),

    #[error(transparent)]
    InvalidMacAddr(#[from] MacAddrParseError),
}

async fn control_request(
    socket: &UnixDatagram,
    timeout: Duration,
    command: &str,
) -> Result<String, CtrlError> {
    socket.send(command.as_bytes()).await?;
    let mut buffer = vec![0u8; MAX_CTRL_MESSAGE_BYTES];
    let read = tokio::time::timeout(timeout, socket.recv(&mut buffer))
        .await
        .map_err(|_| CtrlError::Timeout(timeout))??;
    let reply = String::from_utf8_lossy(&buffer[..read]).into_owned();
    if reply.trim_end() == "FAIL" {
        return Err(CtrlError::Failed);
    }
    if reply.starts_with("UNKNOWN COMMAND") {
        return Err(CtrlError::UnknownCommand(command.to_string()));
    }
    Ok(reply)
}

pub(crate) fn expect_ok(command: &str, reply: &str) -> Result<(), CtrlError> {
    if reply.trim_end() == "OK" {
        Ok(())
    } else {
        Err(CtrlError::MalformedReply(format!("{command} -> {reply:?}")))
    }
}

#[cfg(target_os = "linux")]
fn bind_client_socket() -> std::io::Result<std::os::unix::net::UnixDatagram> {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram as StdUnixDatagram};

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let name = format!("traffic-masq-wifi-ctrl-{}-{sequence}", std::process::id());
    let address = SocketAddr::from_abstract_name(name.as_bytes())?;
    let socket = StdUnixDatagram::bind_addr(&address)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

#[cfg(not(target_os = "linux"))]
fn bind_client_socket() -> std::io::Result<std::os::unix::net::UnixDatagram> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "ctrl_iface control sockets use Linux's abstract socket namespace",
    ))
}

fn bind_and_connect(ctrl_path: &Path) -> Result<UnixDatagram, CtrlError> {
    let socket = UnixDatagram::from_std(bind_client_socket()?)?;
    socket.connect(ctrl_path)?;
    Ok(socket)
}

pub(crate) struct CtrlSocket {
    socket: UnixDatagram,
    timeout: Duration,
}

impl CtrlSocket {
    pub(crate) async fn connect(ctrl_path: &Path, timeout: Duration) -> Result<Self, CtrlError> {
        Ok(Self {
            socket: bind_and_connect(ctrl_path)?,
            timeout,
        })
    }

    pub(crate) async fn request(&self, command: &str) -> Result<String, CtrlError> {
        control_request(&self.socket, self.timeout, command).await
    }
}

pub(crate) fn parse_kv_lines(reply: &str) -> std::collections::BTreeMap<String, String> {
    reply
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

pub(crate) fn indexed_field<'a>(
    raw: &'a std::collections::BTreeMap<String, String>,
    key: &str,
) -> Option<&'a str> {
    raw.get(&format!("{key}[0]"))
        .or_else(|| raw.get(key))
        .map(String::as_str)
}

pub(crate) fn strip_priority_prefix(line: &str) -> &str {
    let Some(rest) = line.strip_prefix('<') else {
        return line;
    };
    let Some(end) = rest.find('>') else {
        return line;
    };
    if rest[..end].bytes().all(|byte| byte.is_ascii_digit()) && !rest[..end].is_empty() {
        &rest[end + 1..]
    } else {
        line
    }
}

pub(crate) struct EventConnection<E, F> {
    socket: UnixDatagram,
    timeout: Duration,
    parse: F,
    _event: std::marker::PhantomData<E>,
}

impl<E, F> EventConnection<E, F>
where
    F: Fn(&str) -> E + Send + 'static,
    E: Clone + Send + 'static,
{
    /// Finish event subscription on an already-connected control socket.
    /// Splitting connect from ATTACH lets supervisors prove ownership after
    /// connect and before sending any command to the endpoint.
    pub(crate) async fn attach(
        self,
    ) -> Result<(EventClient<E>, broadcast::Receiver<E>), CtrlError> {
        let reply = control_request(&self.socket, self.timeout, "ATTACH").await?;
        expect_ok("ATTACH", &reply)?;

        let (sender, receiver) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        let (cancel_tx, cancel_rx) = oneshot::channel();
        let task = tokio::spawn(event_loop(self.socket, sender, cancel_rx, self.parse));

        Ok((
            EventClient {
                cancel: Some(cancel_tx),
                task: Some(task),
                _event: std::marker::PhantomData,
            },
            receiver,
        ))
    }
}

pub(crate) struct EventClient<E> {
    cancel: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
    _event: std::marker::PhantomData<E>,
}

impl<E> EventClient<E> {
    pub(crate) async fn connect<F>(
        ctrl_path: &Path,
        timeout: Duration,
        parse: F,
    ) -> Result<EventConnection<E, F>, CtrlError>
    where
        F: Fn(&str) -> E + Send + 'static,
        E: Clone + Send + 'static,
    {
        Ok(EventConnection {
            socket: bind_and_connect(ctrl_path)?,
            timeout,
            parse,
            _event: std::marker::PhantomData,
        })
    }

    pub(crate) async fn attach<F>(
        ctrl_path: &Path,
        timeout: Duration,
        parse: F,
    ) -> Result<(Self, broadcast::Receiver<E>), CtrlError>
    where
        F: Fn(&str) -> E + Send + 'static,
        E: Clone + Send + 'static,
    {
        Self::connect(ctrl_path, timeout, parse)
            .await?
            .attach()
            .await
    }

    pub(crate) async fn close(mut self) {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl<E> Drop for EventClient<E> {
    fn drop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
    }
}

async fn event_loop<E, F>(
    socket: UnixDatagram,
    sender: broadcast::Sender<E>,
    mut cancel: oneshot::Receiver<()>,
    parse: F,
) where
    F: Fn(&str) -> E,
    E: Clone,
{
    let mut buffer = vec![0u8; MAX_CTRL_MESSAGE_BYTES];
    loop {
        tokio::select! {
            _ = &mut cancel => {
                let _ = tokio::time::timeout(DETACH_TIMEOUT, socket.send(b"DETACH")).await;
                return;
            }
            result = socket.recv(&mut buffer) => {
                let Ok(read) = result else { return };
                let raw = String::from_utf8_lossy(&buffer[..read]).into_owned();


                let _ = sender.send(parse(&raw));
            }
        }
    }
}

#[cfg(test)]
mod tests;
