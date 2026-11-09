use super::seqnum::SeqNum;
use crate::{
    PacketReceiver, PacketSender, TTL,
    error::IpStackError,
    packet::{
        IpHeader, NetworkPacket, NetworkTuple, TransportHeader,
        tcp_flags::{ACK, FIN, PSH, RST, SYN},
        tcp_header_flags, tcp_header_fmt,
    },
    stream::tcb::{
        MAX_COUNT_FOR_DUP_ACK, MAX_RETRANSMIT_COUNT, MAX_UNACK, PacketType, READ_BUFFER_SIZE, RTO, Tcb, TcpState, ZERO_WINDOW_PROBE_BYTES,
    },
};
use etherparse::{IpNumber, Ipv4Header, Ipv6FlowLabel, TcpHeader, TcpOptionElement};
use std::{
    future::Future,
    io::ErrorKind::{BrokenPipe, ConnectionRefused, InvalidInput, UnexpectedEof},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite};

/// 2 * MSL (Maximum Segment Lifetime) is the maximum time a TCP connection can be in the TIME_WAIT state.
const TWO_MSL: Duration = Duration::from_secs(2);

const CLOSE_WAIT_TIMEOUT: Duration = Duration::from_secs(5);
const LAST_ACK_MAX_RETRIES: usize = 3;
const LAST_ACK_TIMEOUT: Duration = Duration::from_millis(500);
const TIMEOUT: Duration = Duration::from_secs(60);
const LINGER: Duration = Duration::from_secs(30);

#[non_exhaustive]
#[derive(Debug, Clone)]
/// TCP configuration
pub struct TcpConfig {
    /// Maximum number of retries for sending the last ACK in the LAST_ACK state. Default is 3.
    pub last_ack_max_retries: usize,
    /// Timeout for the last ACK in the LAST_ACK state. Default is 500ms.
    pub last_ack_timeout: Duration,
    /// Timeout for the CLOSE_WAIT state. Default is 5 seconds.
    pub close_wait_timeout: Duration,
    /// How long a connection may go without a valid segment from the other side,
    /// keep-alive probes included, before it is reset. Default is 60 seconds.
    pub timeout: Duration,
    /// How long a stream let go of before its close completed may take to finish it
    /// by itself (its FIN sent and acknowledged, the other side's taken); past it the
    /// connection is reset. Default is 30 seconds.
    pub linger: Duration,
    /// Timeout for the TIME_WAIT state. Default is 2 seconds.
    pub two_msl: Duration,
    /// Maximum number of unacknowledged bytes allowed in the send buffer.
    pub max_unacked_bytes: u32,
    /// Size of the read buffer for incoming data.
    pub read_buffer_size: usize,
    /// Maximum number of duplicate ACKs before triggering fast retransmission.
    pub max_count_for_dup_ack: usize,
    /// Retransmission timeout duration.
    pub rto: std::time::Duration,
    /// Maximum number of retransmissions before giving up.
    pub max_retransmit_count: usize,
    /// TCP options
    pub options: Option<Vec<TcpOptions>>,
}

#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum TcpOptions {
    /// Maximum segment size (MSS) for TCP connections.
    MaximumSegmentSize(u16),
}

impl Default for TcpConfig {
    fn default() -> Self {
        TcpConfig {
            last_ack_max_retries: LAST_ACK_MAX_RETRIES,
            last_ack_timeout: LAST_ACK_TIMEOUT,
            close_wait_timeout: CLOSE_WAIT_TIMEOUT,
            timeout: TIMEOUT,
            linger: LINGER,
            two_msl: TWO_MSL,
            max_unacked_bytes: MAX_UNACK,
            read_buffer_size: READ_BUFFER_SIZE,
            max_count_for_dup_ack: MAX_COUNT_FOR_DUP_ACK,
            rto: RTO,
            max_retransmit_count: MAX_RETRANSMIT_COUNT,
            options: Default::default(),
        }
    }
}

#[derive(Debug)]
enum Shutdown {
    None,
    Pending(Waker),
    Ready,
}

impl Shutdown {
    fn pending(&mut self, w: Waker) {
        *self = Shutdown::Pending(w);
    }
    fn ready(&mut self) {
        if let Shutdown::Pending(w) = self {
            w.wake_by_ref();
        }
        *self = Shutdown::Ready;
    }
}

impl std::fmt::Display for Shutdown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Shutdown::None => write!(f, "None"),
            Shutdown::Pending(_) => write!(f, "Pending"),
            Shutdown::Ready => write!(f, "Ready"),
        }
    }
}

static SESSION_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

type TcbPtr = std::sync::Arc<std::sync::Mutex<Tcb>>;

/// A TCP stream in the IP stack.
///
/// This type represents a TCP connection and implements `AsyncRead` and `AsyncWrite`
/// for bidirectional data transfer. It handles TCP state management, flow control,
/// and retransmission automatically.
///
/// # Examples
///
/// ```no_run
/// use ipstack::{IpStack, IpStackConfig, IpStackStream};
/// use tokio::io::{AsyncReadExt, AsyncWriteExt};
///
/// # async fn example(mut ip_stack: IpStack) -> Result<(), Box<dyn std::error::Error>> {
/// if let IpStackStream::Tcp(mut tcp_stream) = ip_stack.accept().await? {
///     println!("New TCP connection from {}", tcp_stream.peer_addr());
///     
///     // Read data
///     let mut buffer = [0u8; 1024];
///     let n = tcp_stream.read(&mut buffer).await?;
///     
///     // Write data
///     tcp_stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await?;
///     
///     // Shutdown the stream
///     tcp_stream.shutdown().await?;
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct IpStackTcpStream {
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    stream_sender: PacketSender,
    stream_receiver: Option<PacketReceiver>,
    up_packet_sender: PacketSender,
    tcb: TcbPtr,
    shutdown: std::sync::Arc<std::sync::Mutex<Shutdown>>,
    write_notify: std::sync::Arc<std::sync::Mutex<Option<Waker>>>,
    /// Wakes the TCP task when a segment goes in flight with none before it, so it
    /// arms the retransmission timer.
    inflight_notify: Arc<tokio::sync::Notify>,
    /// Fired when the peer acknowledges more of our bytes and when the connection
    /// ends: what [`IpStackTcpHandle::closed`] and [`IpStackTcpHandle::drained`] wait on.
    state_notify: Arc<tokio::sync::Notify>,
    destroy_messenger: Option<::tokio::sync::oneshot::Sender<()>>,
    data_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    data_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    read_notify: std::sync::Arc<std::sync::Mutex<Option<Waker>>>,
    task_handle: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
    exit_notifier: Option<tokio::sync::mpsc::Sender<()>>,
    temp_read_buffer: Vec<u8>,
    config: Arc<TcpConfig>,
}

impl IpStackTcpStream {
    pub(crate) fn new(
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        tcp: TcpHeader,
        up_packet_sender: PacketSender,
        mtu: u16,
        destroy_messenger: Option<::tokio::sync::oneshot::Sender<()>>,
        config: Arc<TcpConfig>,
    ) -> Result<IpStackTcpStream, IpStackError> {
        let mut tcb = Tcb::new(
            SeqNum(tcp.sequence_number),
            mtu,
            config.max_unacked_bytes,
            config.read_buffer_size,
            config.max_count_for_dup_ack,
            config.rto,
            config.max_retransmit_count,
        );
        // Sieve (2026-11-08): the SYN's window is the peer's first; upstream assumed
        // u16::MAX until the next ACK. No window scale is negotiated, so it is in bytes.
        tcb.update_send_window(tcp.window_size);
        let tuple = NetworkTuple::new(src_addr, dst_addr, true);
        if !tcp.syn {
            if !tcp.rst
                && let Err(err) = write_packet_to_device(&up_packet_sender, tuple, &tcb, None, ACK | RST, None, None)
            {
                log::warn!("Error sending RST/ACK packet: {err}");
            }
            let info = format!("Invalid TCP packet: {tuple} {}", tcp_header_fmt(&tcp));
            return Err(IpStackError::IoError(std::io::Error::new(ConnectionRefused, info)));
        }

        let (stream_sender, stream_receiver) = tokio::sync::mpsc::unbounded_channel::<NetworkPacket>();
        let (data_tx, data_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

        let mut stream = IpStackTcpStream {
            src_addr,
            dst_addr,
            stream_sender,
            stream_receiver: Some(stream_receiver),
            up_packet_sender,
            tcb: std::sync::Arc::new(std::sync::Mutex::new(tcb.clone())),
            shutdown: std::sync::Arc::new(std::sync::Mutex::new(Shutdown::None)),
            write_notify: std::sync::Arc::new(std::sync::Mutex::new(None)),
            inflight_notify: Arc::default(),
            state_notify: Arc::default(),
            destroy_messenger,
            data_tx,
            data_rx,
            read_notify: std::sync::Arc::new(std::sync::Mutex::new(None)),
            task_handle: None,
            exit_notifier: None,
            temp_read_buffer: Vec::new(),
            config,
        };

        let sessions = SESSION_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst).saturating_add(1);
        let (seq, ack, state) = { (tcb.get_seq().0, tcb.get_ack().0, tcb.get_state()) };
        log::debug!("{tuple} {state:?}: local {{ seq: {seq}, ack: {ack} }} session begins, total TCP sessions: {sessions}");

        stream.spawn_tasks()?;
        Ok(stream)
    }

    pub(crate) fn network_tuple(&self) -> NetworkTuple {
        NetworkTuple::new(self.src_addr, self.dst_addr, true)
    }

    /// Returns the local socket address of the TCP connection.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use ipstack::IpStackTcpStream;
    /// # fn example(tcp_stream: &IpStackTcpStream) {
    /// let local_addr = tcp_stream.local_addr();
    /// println!("Local address: {}", local_addr);
    /// # }
    /// ```
    pub fn local_addr(&self) -> SocketAddr {
        self.src_addr
    }

    /// Returns the remote socket address of the TCP connection.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use ipstack::IpStackTcpStream;
    /// # fn example(tcp_stream: &IpStackTcpStream) {
    /// let peer_addr = tcp_stream.peer_addr();
    /// println!("Peer address: {}", peer_addr);
    /// # }
    /// ```
    pub fn peer_addr(&self) -> SocketAddr {
        self.dst_addr
    }

    pub fn stream_sender(&self) -> PacketSender {
        self.stream_sender.clone()
    }

    /// Ends the connection now with an ACK|RST, the packet the stack sends when the
    /// session times out. Bytes in flight are given up. Later reads fail with
    /// `ConnectionAborted` once what the app sent before is read, later writes fail,
    /// and `shutdown` returns at once, sending no FIN.
    pub fn abort(&self) {
        self.handle().abort();
    }

    /// [`IpStackTcpHandle::closed`].
    pub fn closed(&self) -> impl Future<Output = ()> + Send + use<> {
        self.handle().closed()
    }

    /// [`IpStackTcpHandle::drained`].
    pub fn drained(&self) -> impl Future<Output = ()> + Send + use<> {
        self.handle().drained()
    }

    /// A handle on this connection for whoever does not own the stream: how long it
    /// has been idle, and a way to end it.
    pub fn handle(&self) -> IpStackTcpHandle {
        IpStackTcpHandle {
            tuple: self.network_tuple(),
            tcb: self.tcb.clone(),
            up_packet_sender: self.up_packet_sender.clone(),
            shutdown: self.shutdown.clone(),
            read_notify: self.read_notify.clone(),
            write_notify: self.write_notify.clone(),
            inflight_notify: self.inflight_notify.clone(),
            state_notify: self.state_notify.clone(),
        }
    }
}

/// See [`IpStackTcpStream::handle`].
#[derive(Debug, Clone)]
pub struct IpStackTcpHandle {
    tuple: NetworkTuple,
    tcb: TcbPtr,
    up_packet_sender: PacketSender,
    shutdown: Arc<std::sync::Mutex<Shutdown>>,
    read_notify: Arc<std::sync::Mutex<Option<Waker>>>,
    write_notify: Arc<std::sync::Mutex<Option<Waker>>>,
    inflight_notify: Arc<tokio::sync::Notify>,
    state_notify: Arc<tokio::sync::Notify>,
}

impl IpStackTcpHandle {
    /// How long the connection has gone unused: since the other side last sent a
    /// valid segment, keep-alives included, or the engine last wrote to it, whichever
    /// is later. Sieve (2026-11-09, P3-3): the engine's writes count, so a flow whose
    /// server is still sending is not idle.
    pub fn idle(&self) -> Duration {
        self.tcb.lock().unwrap().last_use().elapsed()
    }

    /// [`IpStackTcpStream::abort`].
    ///
    /// Sieve (2026-11-09, P2-a): the end is recorded as `ConnectionAborted`, so the
    /// reader is told the flow was cut short; it read the end of the stream, and a
    /// relay passed that upstream as a FIN and waited on.
    pub fn abort(&self) {
        {
            let mut tcb = self.tcb.lock().unwrap();
            if tcb.get_state() == TcpState::Closed {
                return;
            }
            reset_and_close("[abort]", &self.up_packet_sender, self.tuple, &mut tcb);
            tcb.close_with(std::io::ErrorKind::ConnectionAborted);
        }
        self.shutdown.lock().unwrap().ready();
        self.read_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
        self.write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
        self.state_notify.notify_waiters();
        // The TCP task ends now too, not at the next packet.
        self.inflight_notify.notify_one();
    }

    /// Completes once the connection is closed, however it ended (both FINs, a reset,
    /// the idle limit, an abort): for whoever waits on something else, such as a
    /// relay whose app half-closed and that reads only the server any more (P2-b).
    pub fn closed(&self) -> impl Future<Output = ()> + Send + use<> {
        wait_until(self.tcb.clone(), self.state_notify.clone(), |tcb| tcb.get_state() == TcpState::Closed)
    }

    /// Completes once every byte written is acknowledged, or the connection closed.
    pub fn drained(&self) -> impl Future<Output = ()> + Send + use<> {
        wait_until(self.tcb.clone(), self.state_notify.clone(), |tcb| {
            tcb.get_state() == TcpState::Closed || tcb.get_inflight_packets_total_len() == 0
        })
    }
}

/// Completes once `done` holds of the connection; `notify` fires on every change it
/// can see.
async fn wait_until(tcb: TcbPtr, notify: Arc<tokio::sync::Notify>, done: fn(&Tcb) -> bool) {
    loop {
        let notified = notify.notified();
        tokio::pin!(notified);
        // Asked for before the look, so a change made in between still wakes it.
        notified.as_mut().enable();
        let now = done(&tcb.lock().unwrap());
        if now {
            return;
        }
        notified.await;
    }
}

impl IpStackTcpStream {
    /// The app's next queued bytes, or its end once nothing more can come; None while
    /// nothing is queued.
    fn take_queued(&mut self, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Option<Poll<std::io::Result<()>>> {
        match self.data_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let capacity = buf.remaining();
                if capacity >= data.len() {
                    buf.put_slice(&data);
                } else {
                    // if `buf` is not enough, put the remaining data into the temp buffer
                    buf.put_slice(&data[..capacity]);
                    self.temp_read_buffer.extend_from_slice(&data[capacity..]);
                }
                Some(Poll::Ready(Ok(())))
            }
            Poll::Ready(None) => Some(Poll::Ready(Ok(()))),
            Poll::Pending => None,
        }
    }
}

impl AsyncRead for IpStackTcpStream {    fn poll_read(mut self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        // if there is data in the temp buffer, read it first
        if !self.temp_read_buffer.is_empty() {
            let len = std::cmp::min(buf.remaining(), self.temp_read_buffer.len());
            buf.put_slice(&self.temp_read_buffer[..len]);
            self.temp_read_buffer.drain(..len); // remove the read data from the temp buffer
            return Poll::Ready(Ok(()));
        }

        let network_tuple = self.network_tuple();

        // Sieve (2026-11-09): what the app sent before it closed is read first, then the
        // end. Upstream answered a closed stream with the end while its last bytes were
        // still queued, and never read the app's FIN as the end at all: the reader slept
        // until its own timeout (60 s, or hyper's 30 s for a request head), so a client
        // that left right after the handshake looked to self-healing like one that idled
        // half a minute (slice 7 U1, run 7), and its server kept the connection as long.
        if let Some(read) = self.take_queued(cx, buf) {
            return read;
        }
        // Asked for before the state is read, so an end the TCP task records after the
        // read still wakes this reader.
        self.read_notify.lock().unwrap().replace(cx.waker().clone());

        let (state, closed_by) = {
            let tcb = self.tcb.lock().unwrap();
            (tcb.get_state(), tcb.closed_by())
        };
        // The app's FIN came in order, after every byte it sent; the TCP task queues those
        // bytes before it records the end, under the lock the state was read with, so a
        // second look finds any that came with the FIN.
        let ended = matches!(state, TcpState::Closed | TcpState::CloseWait | TcpState::LastAck | TcpState::Closing | TcpState::TimeWait);
        if ended && let Some(read) = self.take_queued(cx, buf) {
            return read;
        }
        if state == TcpState::Closed {
            self.shutdown.lock().unwrap().ready();
            self.write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
            // Sieve (2026-11-09): a reset, or the idle limit the TCP task enforces, is an
            // error, not the end of what the app sent: a relay that read it as the end
            // would close an upload upstream as if it were complete. Upstream read a
            // reset as the end of the stream.
            if let Some(kind) = closed_by {
                log::debug!("{network_tuple} {state:?}: [poll_read] the connection ended: {kind:?}");
                return Poll::Ready(Err(std::io::Error::from(kind)));
            }
        }
        if ended {
            return Poll::Ready(Ok(()));
        }
        Poll::Pending
    }
}

impl AsyncWrite for IpStackTcpStream {
    fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let nt = self.network_tuple();

        let mut tcb = self.tcb.lock().unwrap();
        let state = tcb.get_state();
        let send_window = tcb.get_send_window();
        let is_full = tcb.is_send_buffer_full();

        if state == TcpState::Closed {
            self.shutdown.lock().unwrap().ready();
            self.read_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
            return Poll::Ready(Err(std::io::Error::new(BrokenPipe, "TCP connection closed")));
        }
        // Sieve (2026-11-09, P3-6): nothing goes after our FIN, queued (shutdown asked)
        // or sent; upstream took bytes after it and sent them past the end.
        if !fin_unsent(state) || !matches!(*self.shutdown.lock().unwrap(), Shutdown::None) {
            return Poll::Ready(Err(std::io::Error::new(BrokenPipe, "TCP stream shut down")));
        }

        // Sieve (2026-11-08): data waits for the handshake's last ACK (RFC 9293 3.10.2:
        // queued until ESTABLISHED); upstream sent it in SYN-RECEIVED.
        let handshaking = matches!(state, TcpState::Listen | TcpState::SynReceived);
        let timer_idle = tcb.get_inflight_packets_total_len() == 0;
        // Sieve (2026-11-08): a closed window with nothing in flight takes one byte, held
        // unsent as the zero-window probe; upstream waited for a window update, and a
        // lost one held the flow until its session timeout.
        let probe = send_window == 0 && timer_idle;
        if handshaking || (is_full && !probe) {
            self.write_notify.lock().unwrap().replace(cx.waker().clone());
            log::trace!("{nt} {state:?}: [poll_write] current send window: {send_window}, send buffer full: {is_full}, waiting for the other side to send ACK...");
            return Poll::Pending;
        }

        let payload_len = if probe {
            ZERO_WINDOW_PROBE_BYTES.min(buf.len())
        } else {
            write_packet_to_device(&self.up_packet_sender, nt, &tcb, None, ACK | PSH, None, Some(buf.to_vec()))?
        };
        tcb.add_inflight_packet(buf[..payload_len].to_vec())?;
        tcb.wrote();
        if timer_idle {
            self.inflight_notify.notify_one();
        }

        let (state, seq, ack) = (tcb.get_state(), tcb.get_seq(), tcb.get_ack());
        log::trace!("{nt} {state:?}: [poll_write] local {{ seq: {seq}, ack: {ack} }} upstream data written to device, len = {payload_len}");

        Poll::Ready(Ok(payload_len))
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// Ready once our FIN is sent (or the connection is closed); the TCP task sends it
    /// once every byte of ours is acknowledged, and keeps the connection until both
    /// sides' FINs are, as a socket's close does.
    ///
    /// Sieve (2026-11-09, P1-1/P1-2 of the second review of run 7): the ask is recorded
    /// first, under its lock, and only then is the state read and the task woken, so
    /// whatever the task does in between it sees the ask. Upstream sent the FIN only
    /// from here, so a shutdown asked with bytes in flight waited for a poll that
    /// nothing made after their ACK (a server that closed right after its last bytes
    /// left the app waiting for the idle limit); and it woke the task before recording
    /// the ask, so a task that looked in between slept on with no FIN sent. It was also
    /// Ready only once the connection was closed, which an app that keeps reading after
    /// our FIN never lets happen.
    fn poll_shutdown(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        {
            let mut shutdown = self.shutdown.lock().unwrap();
            if matches!(*shutdown, Shutdown::Ready) {
                return Poll::Ready(Ok(()));
            }
            shutdown.pending(cx.waker().clone());
        }
        let state = self.tcb.lock().unwrap().get_state();
        log::trace!("{} {state:?}: [poll_shutdown]", self.network_tuple());
        if !fin_unsent(state) {
            self.shutdown.lock().unwrap().ready();
            return Poll::Ready(Ok(()));
        }
        self.inflight_notify.notify_one();
        Poll::Pending
    }
}

/// Our FIN is still to send in `state`.
fn fin_unsent(state: TcpState) -> bool {
    matches!(state, TcpState::Listen | TcpState::SynReceived | TcpState::Established | TcpState::CloseWait)
}

/// Ends the connection with an ACK|RST at our next sequence and, when the peer has
/// not acknowledged everything, another at its last ACK: a client that has not seen
/// our unacknowledged bytes expects that one, and under RFC 5961 only challenges any
/// other reset.
fn reset_and_close(hint: &str, sender: &PacketSender, nt: NetworkTuple, tcb: &mut Tcb) {
    if let Err(err) = write_packet_to_device(sender, nt, tcb, None, ACK | RST, None, None) {
        log::warn!("{nt} {hint} error sending RST/ACK packet: {err}");
    }
    let acked = tcb.get_last_received_ack();
    if acked != tcb.get_seq()
        && let Err(err) = write_packet_to_device(sender, nt, tcb, None, ACK | RST, Some(acked), None)
    {
        log::warn!("{nt} {hint} error sending RST/ACK packet: {err}");
    }
    tcb.change_state(TcpState::Closed);
}

/// Resends every segment whose retransmission timer ran out, or resets the
/// connection when one has no retransmission left. False once it is reset.
fn retransmit_timed_out(sender: &PacketSender, nt: NetworkTuple, tcb: &mut Tcb) -> std::io::Result<bool> {
    let Some(packets) = tcb.collect_timed_out_inflight_packets() else {
        reset_and_close("[retransmit]", sender, nt, tcb);
        tcb.close_with(std::io::ErrorKind::TimedOut);
        return Ok(false);
    };
    for packet in packets {
        let (seq, count) = (packet.seq, packet.retransmit_count);
        log::debug!("{nt} inflight packet retransmission timeout: {seq:?}, retransmit_count: {count}");
        write_packet_to_device(sender, nt, tcb, None, ACK | PSH, Some(seq), Some(packet.payload))?;
    }
    Ok(true)
}

/// Completes at `deadline`, never without one.
async fn retransmission_due(deadline: Option<std::time::Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
        None => std::future::pending().await,
    }
}

impl Drop for IpStackTcpStream {
    fn drop(&mut self) {
        let (nt, state) = (self.network_tuple(), self.tcb.lock().unwrap().get_state());
        log::trace!("{nt} {state:?}: [drop] session dropping, ========================= ");
        // Sieve (2026-11-09): a connection let go of before it closed finishes closing
        // by itself, as a socket's close does: the TCP task sees the stream gone, sends
        // our FIN once every byte of ours is acknowledged, resends it until it is, takes
        // the app's, and resets the connection if that takes longer than `linger`.
        // Upstream tore the task down with the stream, so a FIN sent here was never
        // resent, the app's ACK of it met no session, and one sent by the task as well
        // made two.
        let closing = !matches!(state, TcpState::Listen | TcpState::SynReceived | TcpState::Closed);
        if closing && let Some(task_handle) = self.task_handle.take() {
            drop(task_handle);
            self.inflight_notify.notify_one();
        }
        if let Some(task_handle) = self.task_handle.take() {
            if !task_handle.is_finished() {
                if let Some(notifier) = self.exit_notifier.take() {
                    _ = tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(notifier.send(())));
                }
                // synchronously wait for the task to finish
                _ = tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(task_handle));
            } else {
                log::trace!("{nt} {state:?}: [drop] task already finished, no need to wait exiting");
            }
        }
        let sessions = SESSION_COUNTER.fetch_sub(1, std::sync::atomic::Ordering::SeqCst).saturating_sub(1);
        log::debug!("{nt} {state:?}: [drop] session dropped, total TCP sessions: {sessions}");
    }
}

impl IpStackTcpStream {
    fn spawn_tasks(&mut self) -> std::io::Result<()> {
        let network_tuple = self.network_tuple();

        // task: data receiving and processing
        let tcb = self.tcb.clone();
        let stream_receiver = self.stream_receiver.take().unwrap();
        let up_packet_sender = self.up_packet_sender.clone();
        let shutdown = self.shutdown.clone();
        let asked = self.shutdown.clone();
        let write_notify = self.write_notify.clone();
        let read_notify = self.read_notify.clone();
        let inflight_notify = self.inflight_notify.clone();
        let state_notify = self.state_notify.clone();
        let data_tx = self.data_tx.clone();
        let destroy_messenger = self.destroy_messenger.take();
        let (ended_tcb, ended_reader, ended_writer) = (self.tcb.clone(), self.read_notify.clone(), self.write_notify.clone());

        let (exit_task_notifier, exit_monitor) = tokio::sync::mpsc::channel::<()>(10);
        let exit_notifier = exit_task_notifier.clone();
        let config = self.config.clone();
        self.exit_notifier = Some(exit_task_notifier);

        let task_handle = tokio::spawn(async move {
            let v = tcp_main_logic_loop(
                tcb,
                config,
                stream_receiver,
                up_packet_sender,
                exit_notifier,
                network_tuple,
                write_notify,
                read_notify,
                inflight_notify,
                state_notify.clone(),
                data_tx,
                exit_monitor,
                asked,
            )
            .await;
            if let Err(e) = &v {
                log::warn!("{network_tuple} task error: {e}");
            }
            // Sieve (2026-11-09, P2-b): with the task gone nothing is left to carry the
            // connection, so it is closed whatever stopped the task, and whoever waits
            // on its end hears of it now.
            {
                let mut tcb = ended_tcb.lock().unwrap();
                if tcb.get_state() != TcpState::Closed {
                    tcb.close_with(std::io::ErrorKind::ConnectionAborted);
                }
            }
            ended_reader.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
            ended_writer.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
            state_notify.notify_waiters();
            _ = destroy_messenger.map(|m| m.send(())).unwrap_or(Ok(()));
            log::trace!("{network_tuple} task completed, destroy messenger sent successfully");
            shutdown.lock().unwrap().ready();
            log::trace!("{network_tuple} shutdown.lock().unwrap().ready() ==========");
            v
        });
        self.task_handle = Some(task_handle);
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
async fn tcp_main_logic_loop(
    tcb: TcbPtr,
    config: Arc<TcpConfig>,
    mut stream_receiver: PacketReceiver,
    up_packet_sender: PacketSender,
    exit_notifier: tokio::sync::mpsc::Sender<()>,
    network_tuple: NetworkTuple,
    write_notify: std::sync::Arc<std::sync::Mutex<Option<Waker>>>,
    read_notify: std::sync::Arc<std::sync::Mutex<Option<Waker>>>,
    inflight_notify: Arc<tokio::sync::Notify>,
    state_notify: Arc<tokio::sync::Notify>,
    data_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    mut exit_monitor: tokio::sync::mpsc::Receiver<()>,
    shutdown: std::sync::Arc<std::sync::Mutex<Shutdown>>,
) -> std::io::Result<()> {
    {
        let mut tcb = tcb.lock().unwrap();

        let state = tcb.get_state();
        if state != TcpState::Listen {
            log::warn!("{network_tuple} {state:?}: Invalid TCP state, not in Listen state");
            return Ok::<(), std::io::Error>(());
        }

        tcb.increase_ack();
        let (seq, ack) = (tcb.get_seq().0, tcb.get_ack().0);
        log::trace!("{network_tuple} {state:?}: local {{ seq: {seq}, ack: {ack} }} session begins");
        write_packet_to_device(
            &up_packet_sender,
            network_tuple,
            &tcb,
            config.options.as_ref(),
            ACK | SYN,
            None,
            None,
        )?;
        tcb.increase_seq();
        // Sieve (2026-11-08): the SYN takes one sequence number, so the window starts
        // after it; upstream left the last ACK at the ISN, one byte short of the edge.
        let (after_syn, syn_window) = (tcb.get_seq(), tcb.get_send_window());
        tcb.update_peer_window(after_syn, syn_window);
        tcb.change_state(TcpState::SynReceived);
        let state = tcb.get_state();
        log::trace!("{network_tuple} {state:?}: session now in {state:?} state");
    }

    let tcb_clone = tcb.clone();

    async fn task_wait_to_close(tcb: TcbPtr, exit_notifier: tokio::sync::mpsc::Sender<()>, nt: NetworkTuple, two_msl: Duration) {
        tokio::time::sleep(two_msl).await;
        {
            let mut tcb = tcb.lock().unwrap();
            tcb.change_state(TcpState::Closed);
            let state = tcb.get_state();
            log::debug!("{nt} {state:?}: [task_wait_to_close] session closed after {two_msl:?}");
        }
        exit_notifier.send(()).await.unwrap_or(());
    }

    /// Resends our FIN while it is unacknowledged (LAST-ACK, FIN-WAIT-1, CLOSING), at
    /// the FIN's own sequence number, and resets the connection once the resends run
    /// out.
    ///
    /// Sieve (2026-11-09, P2-5): upstream resent it at the next sequence number, one
    /// past the FIN, closed without a reset, and had no resend at all in FIN-WAIT-1.
    /// P3-1: a simultaneous close goes on from FIN-WAIT-1 to CLOSING with our FIN still
    /// unacknowledged, and the resends go on there.
    async fn task_fin_unacked(
        tcb: TcbPtr,
        exit_notifier: tokio::sync::mpsc::Sender<()>,
        nt: NetworkTuple,
        pkt_sdr: PacketSender,
        last_ack_timeout: Duration,
        last_ack_max_retries: usize,
    ) {
        let hint = "[task_fin_unacked]";
        let unacked = |state| matches!(state, TcpState::FinWait1 | TcpState::Closing | TcpState::LastAck);
        for idx in 1..=last_ack_max_retries {
            tokio::time::sleep(last_ack_timeout).await;
            let tcb = tcb.lock().unwrap();
            let state = tcb.get_state();
            if !unacked(state) {
                log::debug!("{nt} {state:?}: {hint} our FIN was acknowledged or the session ended");
                return;
            }
            log::debug!("{nt} {state:?}: {hint} timer expired, resending ACK|FIN (retry {idx}/{last_ack_max_retries})");
            _ = write_packet_to_device(&pkt_sdr, nt, &tcb, None, ACK | FIN, Some(tcb.get_seq() - 1), None);
        }
        tokio::time::sleep(last_ack_timeout).await;
        {
            let mut tcb = tcb.lock().unwrap();
            let state = tcb.get_state();
            if !unacked(state) {
                return;
            }
            reset_and_close(hint, &pkt_sdr, nt, &mut tcb);
            tcb.close_with(std::io::ErrorKind::TimedOut);
            log::warn!("{nt} {state:?}: {hint} our FIN was never acknowledged, the session is reset");
        }
        exit_notifier.send(()).await.unwrap_or(());
    }

    // When the engine let go of the stream: from then on the session has `linger` to
    // finish closing by itself.
    let mut let_go: Option<std::time::Instant> = None;
    loop {
        let exit_notifier = exit_notifier.clone();

        {
            let mut tcb = tcb.lock().unwrap();
            let state = tcb.get_state();
            // Sieve (2026-11-09): an abort, a reset, a timeout or a final ACK ends the task
            // here, not at the next packet.
            if state == TcpState::Closed {
                break;
            }
            // Sieve (2026-11-09): our FIN goes once the engine asked for it (shutdown, or
            // letting go of the stream) and every byte of ours is acknowledged, in
            // ESTABLISHED as after the app's FIN. Upstream sent it from `poll_shutdown`
            // only, or with the ACK of the app's FIN, so a client that half-closed after
            // its request never got the answer (run 7), and a shutdown asked with bytes in
            // flight never sent it (P1-1).
            let asked = matches!(*shutdown.lock().unwrap(), Shutdown::Pending(_)) || data_tx.is_closed();
            if asked && matches!(state, TcpState::Established | TcpState::CloseWait) && tcb.get_inflight_packets_total_len() == 0 {
                write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK | FIN, None, None)?;
                tcb.increase_seq();
                let waiting = if state == TcpState::Established { TcpState::FinWait1 } else { TcpState::LastAck };
                tcb.change_state(waiting);
                log::debug!("{network_tuple} {state:?}: our FIN sent, now {waiting:?}");
                let (tcb, up) = (tcb_clone.clone(), up_packet_sender.clone());
                tokio::spawn(task_fin_unacked(tcb, exit_notifier.clone(), network_tuple, up, config.last_ack_timeout, config.last_ack_max_retries));
                shutdown.lock().unwrap().ready();
            }
        }

        // Sieve (2026-11-08): upstream checked the retransmission timers only when a
        // packet arrived, so a lost segment or ACK with fewer than three duplicate ACKs
        // behind it (two segments fill the window at MTU 9000) waited for the peer's
        // next packet: a browser's keep-alive, 45 s later.
        let (deadline, idle_limit) = {
            let tcb = tcb.lock().unwrap();
            (tcb.next_retransmission_deadline(), tcb.last_activity() + config.timeout)
        };
        // Sieve (2026-11-09, P2-3, P1-2): the idle limit runs here, from the app's last
        // valid segment, keep-alives included, in every state: a half-closed flow whose
        // server never answers ends at it too. Upstream ran it in `poll_read` from the
        // engine's last read or write, so keep-alives never counted, and a flow nothing
        // read had none.
        let give_up = let_go.map_or(idle_limit, |at| idle_limit.min(at + config.linger));
        let network_packet = tokio::select! {
            _ = exit_monitor.recv() => {
                log::debug!("{network_tuple} task exited due to exit signal");
                break;
            }
            () = retransmission_due(deadline) => {
                let mut tcb = tcb.lock().unwrap();
                if tcb.get_state() == TcpState::Closed || !retransmit_timed_out(&up_packet_sender, network_tuple, &mut tcb)? {
                    write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
                    read_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
                    break;
                }
                continue;
            }
            () = tokio::time::sleep_until(give_up.into()) => {
                let mut tcb = tcb.lock().unwrap();
                let state = tcb.get_state();
                if state != TcpState::Closed {
                    let why = if let_go.is_some() { "did not finish closing in time" } else { "idle limit reached" };
                    log::warn!("{network_tuple} {state:?}: {why}, resetting the session");
                    reset_and_close("[timeout]", &up_packet_sender, network_tuple, &mut tcb);
                    tcb.close_with(std::io::ErrorKind::TimedOut);
                }
                break;
            }
            () = data_tx.closed(), if let_go.is_none() => {
                let_go = Some(std::time::Instant::now());
                continue;
            }
            () = inflight_notify.notified() => continue,
            network_packet = stream_receiver.recv() => network_packet,
        };

        let Some(mut network_packet) = network_packet else {
            let state = { tcb.lock().unwrap().get_state() };
            log::debug!("{network_tuple} {state:?}: session closed unexpectedly by pipe broken, exiting task");
            tcb.lock().unwrap().change_state(TcpState::Closed);
            write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
            read_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
            break;
        };

        let payload = network_packet.payload.take().unwrap_or_default();
        let TransportHeader::Tcp(tcp_header) = network_packet.transport_header() else {
            log::warn!("{network_tuple} Invalid TCP packet");
            continue;
        };
        let flags = tcp_header_flags(tcp_header);
        let incoming_ack: SeqNum = tcp_header.acknowledgment_number.into();
        let incoming_seq: SeqNum = tcp_header.sequence_number.into();
        let incoming_win = tcp_header.window_size;

        let mut tcb = tcb.lock().unwrap();

        let state = tcb.get_state();
        if state == TcpState::Closed {
            log::debug!("{network_tuple} {state:?}: session finished, exiting task...");
            break;
        }

        if flags & RST == RST {
            // Sieve (2026-11-09): the reader and the writer hear of it now, not at their
            // timeout, and the reader as a reset (`poll_read`).
            tcb.close_with(std::io::ErrorKind::ConnectionReset);
            read_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
            write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
            continue;
        }

        tcb.update_duplicate_ack_count(incoming_ack);

        let unacked = tcb.get_inflight_packets_total_len();
        tcb.update_inflight_packet_queue(incoming_ack);
        if tcb.get_inflight_packets_total_len() < unacked {
            state_notify.notify_waiters();
        }

        let pkt_type = tcb.check_pkt_type(tcp_header, &payload);

        let (state, seq, ack) = { (tcb.get_state(), tcb.get_seq(), tcb.get_ack()) };
        let len = payload.len();
        log::trace!("{network_tuple} {state:?}: local {{ seq: {seq}, ack: {ack} }} {}, {pkt_type:?}, len = {len}", tcp_header_fmt(tcp_header));
        if pkt_type == PacketType::Invalid {
            continue;
        }
        tcb.touch();

        match state {
            TcpState::SynReceived if flags & ACK == ACK => {
                if len > 0 {
                    tcb.add_unordered_packet(incoming_seq, payload);
                    extract_data_n_write_upstream(&up_packet_sender, &mut tcb, network_tuple, &data_tx, &read_notify)?;
                }
                tcb.change_state(TcpState::Established);
                write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
            }
            TcpState::Established => {
                if flags == ACK {
                    match pkt_type {
                        PacketType::WindowUpdate => {
                            write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
                        }
                        PacketType::KeepAlive => {
                            write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK, None, None)?;
                        }
                        PacketType::RetransmissionRequest => {
                            if let Some(packet) = tcb.fast_retransmit(incoming_ack) {
                                let (s, p) = (packet.seq, packet.payload.clone());
                                log::debug!(
                                    "{network_tuple} {state:?}: local {{ seq: {seq}, ack: {ack} }}, {pkt_type:?}, retransmission request, seq = {s}, len = {}",
                                    p.len()
                                );
                                write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK | PSH, Some(s), Some(p))?;
                            }
                        }
                        PacketType::NewPacket => {
                            tcb.add_unordered_packet(incoming_seq, payload);
                            let nt = network_tuple;
                            extract_data_n_write_upstream(&up_packet_sender, &mut tcb, nt, &data_tx, &read_notify)?;
                            write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
                        }
                        PacketType::Ack => {
                            write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
                        }
                        PacketType::Invalid => {}
                    }
                } else if flags & (ACK | FIN) == (ACK | FIN) {
                    // Sieve (2026-11-09): a FIN can carry the app's last bytes (FIN|PSH|ACK, or
                    // FIN|ACK with data); upstream matched only a bare FIN|ACK, so it dropped
                    // those bytes with the FIN, or counted the FIN and not the bytes. And a FIN
                    // ahead of a gap is not the end yet: the app sends what is missing again.
                    if tcb.get_ack() != incoming_seq {
                        write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK, None, None)?;
                        tcb.update_peer_window(incoming_ack, incoming_win);
                        continue;
                    }
                    if !payload.is_empty() {
                        let last = incoming_seq + u32::try_from(payload.len()).map_err(|e| std::io::Error::new(InvalidInput, e))?;
                        tcb.add_unordered_packet(incoming_seq, payload);
                        while tcb.get_ack() != last && tcb.get_unordered_packets_total_len() > 0 {
                            let before = tcb.get_ack();
                            extract_data_n_write_upstream(&up_packet_sender, &mut tcb, network_tuple, &data_tx, &read_notify)?;
                            if tcb.get_ack() == before {
                                break;
                            }
                        }
                        if tcb.get_state() == TcpState::Closed {
                            continue;
                        }
                    }
                    // The other side is closing the connection, we need to send an ACK and change state to CloseWait
                    tcb.increase_ack();
                    write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK, None, None)?;
                    tcb.change_state(TcpState::CloseWait);
                    // Sieve (2026-11-09): the reader reads the end now (`poll_read`).
                    read_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());

                    // Sieve (2026-11-09): half-closed, not closed. The app may still read: our
                    // FIN goes when the engine shuts its side (the loop's top). A shutdown
                    // already waiting is polled again here.
                    let s = tcb.get_state();
                    log::trace!("{network_tuple} {s:?}: local {{ seq: {seq}, ack: {ack} }}, {pkt_type:?}, half-closed by the other side");
                    write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
                } else if flags == (ACK | PSH) && pkt_type == PacketType::NewPacket {
                    if !payload.is_empty() && tcb.get_ack() == incoming_seq {
                        tcb.add_unordered_packet(incoming_seq, payload);
                        extract_data_n_write_upstream(&up_packet_sender, &mut tcb, network_tuple, &data_tx, &read_notify)?;
                    }
                } else {
                    // unnormal case, we do nothing here
                    log::trace!("{network_tuple} {state:?}: local {{ seq: {seq}, ack: {ack} }}, {pkt_type:?}, unnormal case, we do nothing here");
                }
            }
            TcpState::CloseWait => {
                // Sieve (2026-11-09, P2-4): the app's FIN again means our ACK of it was
                // lost: it is acknowledged again, or the app resends it until it gives up.
                if flags & FIN == FIN {
                    write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK, None, None)?;
                }
                // Our FIN is the loop top's, once the engine shut its side; an ACK here can
                // only let more of our bytes go, or that FIN.
                write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
            }
            TcpState::LastAck => {
                // Sieve (2026-11-09, P2-5): only the ACK of our FIN closes; upstream closed
                // on any ACK, a resent FIN of the app's (ours lost its ACK) among them.
                if flags & ACK == ACK && incoming_ack == tcb.get_seq() {
                    tcb.change_state(TcpState::Closed);
                    tokio::spawn(async move {
                        if let Err(e) = exit_notifier.send(()).await {
                            log::debug!("exit_notifier send failed: {e}");
                        }
                    });
                    let new_state = tcb.get_state();
                    log::trace!("{network_tuple} {state:?}: Received final ACK, transitioned to {new_state:?}");
                } else if flags & FIN == FIN {
                    // The app's FIN again: our FIN, at its own sequence, acknowledges it too.
                    write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK | FIN, Some(tcb.get_seq() - 1), None)?;
                }
            }
            TcpState::FinWait1 | TcpState::FinWait2 => {
                // Sieve (2026-11-09): FIN-WAIT-2 only once our FIN is acknowledged (upstream
                // took any ACK for it), and the app's bytes and FIN taken in order, as in
                // ESTABLISHED: a FIN ahead of a gap is not the end yet (P3; upstream took it,
                // and its sequence number, whatever came before).
                let ours_acked = state == TcpState::FinWait2 || (flags & ACK == ACK && incoming_ack == tcb.get_seq());
                if state == TcpState::FinWait1 && ours_acked {
                    tcb.change_state(TcpState::FinWait2);
                    log::trace!("{network_tuple} {state:?}: our FIN acknowledged, now FinWait2");
                }
                let end = incoming_seq + u32::try_from(len).map_err(|e| std::io::Error::new(InvalidInput, e))?;
                if pkt_type == PacketType::KeepAlive {
                    write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK, None, None)?;
                } else if len > 0 {
                    tcb.add_unordered_packet(incoming_seq, payload);
                    while tcb.get_unordered_packets_total_len() > 0 {
                        let before = tcb.get_ack();
                        extract_data_n_write_upstream(&up_packet_sender, &mut tcb, network_tuple, &data_tx, &read_notify)?;
                        if tcb.get_ack() == before {
                            break;
                        }
                    }
                    if tcb.get_state() == TcpState::Closed {
                        continue;
                    }
                    if tcb.get_ack() != end {
                        // Out of order: the ACK of what is in order asks for the rest.
                        write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK, None, None)?;
                    }
                    write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
                }
                if flags & FIN == FIN && pkt_type != PacketType::KeepAlive && tcb.get_ack() == end {
                    tcb.increase_ack();
                    write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK, None, None)?;
                    read_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
                    if tcb.get_state() == TcpState::FinWait2 {
                        tcb.change_state(TcpState::TimeWait);
                        tokio::spawn(task_wait_to_close(tcb_clone.clone(), exit_notifier, network_tuple, config.two_msl));
                        log::trace!("{network_tuple} {state:?}: the app's FIN taken, now TimeWait");
                    } else {
                        // Sieve (2026-11-09, P3-1): a simultaneous close. Ours is still
                        // unacknowledged, so it waits in CLOSING, resent (`task_fin_unacked`);
                        // upstream went to TIME-WAIT and stopped resending it.
                        tcb.change_state(TcpState::Closing);
                        log::trace!("{network_tuple} {state:?}: the app's FIN crossed ours, now Closing");
                    }
                } else if flags & FIN == FIN && pkt_type != PacketType::KeepAlive && len == 0 {
                    write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK, None, None)?;
                }
            }
            TcpState::Closing => {
                if flags & ACK == ACK && incoming_ack == tcb.get_seq() {
                    tcb.change_state(TcpState::TimeWait);
                    tokio::spawn(task_wait_to_close(tcb_clone.clone(), exit_notifier, network_tuple, config.two_msl));
                    log::trace!("{network_tuple} {state:?}: our FIN acknowledged, now TimeWait");
                } else if flags & FIN == FIN {
                    // The app's FIN again, our ACK of it lost: our FIN, at its own
                    // sequence, acknowledges it too.
                    write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK | FIN, Some(tcb.get_seq() - 1), None)?;
                }
            }
            TcpState::TimeWait if flags & (ACK | FIN) == (ACK | FIN) => {
                write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK, None, None)?;
                // wait to timeout, can't call `tcb.change_state(TcpState::Closed);` to change state here
                // now we need to wait for the timeout to reach...
            }
            _ => {}
        } // end of match state

        tcb.update_peer_window(incoming_ack, incoming_win);
    } // end of loop
    // Sieve (2026-11-09): however the session ended, its reader and writer find out now.
    read_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
    write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
    Ok::<(), std::io::Error>(())
}

fn extract_data_n_write_upstream(
    up_packet_sender: &PacketSender,
    tcb: &mut Tcb,
    network_tuple: NetworkTuple,
    data_tx: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    read_notify: &std::sync::Arc<std::sync::Mutex<Option<Waker>>>,
) -> std::io::Result<()> {
    let (state, seq, ack) = (tcb.get_state(), tcb.get_seq(), tcb.get_ack());
    if state == TcpState::Closed {
        log::debug!("{network_tuple} {state:?}: local {{ seq: {seq}, ack: {ack} }} session closed, exiting \"data extraction task\"...");
        return Ok(());
    }

    if let Some(data) = tcb.consume_unordered_packets(8192) {
        let hint = if state == TcpState::Established { "normally" } else { "still" };
        log::trace!("{network_tuple} {state:?}: local {{ seq: {seq}, ack: {ack} }} {hint} receiving data, len = {}", data.len());
        if data_tx.send(data).is_err() {
            // Sieve (2026-11-09): the engine let go of the stream; bytes no one will read
            // reset the connection (RFC 9293 3.10.7.4, data after CLOSE). Upstream's task
            // ended with an error and left the app's side open.
            log::debug!("{network_tuple} {state:?}: data after the stream was let go of, resetting");
            reset_and_close("[data after close]", up_packet_sender, network_tuple, tcb);
            return Ok(());
        }
        read_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
        write_packet_to_device(up_packet_sender, network_tuple, tcb, None, ACK, None, None)?;
    }
    Ok(())
}

/// Send a TCP packet to the downstream device, with the specified flags, sequence number, and payload.
/// The returned value is the length of the `payload` sent, it may be shorter than the length of the incoming parameter `payload`.
pub(crate) fn write_packet_to_device(
    up_packet_sender: &PacketSender,
    tuple: NetworkTuple,
    tcb: &Tcb,
    options: Option<&Vec<TcpOptions>>,
    flags: u8,
    seq: Option<SeqNum>,
    payload: Option<Vec<u8>>,
) -> std::io::Result<usize> {
    use std::io::Error;
    let seq = seq.unwrap_or(tcb.get_seq()).0;
    let (ack, window_size) = (tcb.get_ack().0, tcb.get_recv_window().max(tcb.get_mtu()));
    let (src, dst) = (tuple.dst, tuple.src); // Note: The address is reversed here
    let calc = |ip_header_len: usize, tcp_header_len: usize| tcb.calculate_payload_max_len(SeqNum(seq), ip_header_len, tcp_header_len);
    let packet = create_raw_packet(
        src,
        dst,
        calc,
        flags,
        TTL,
        seq,
        ack,
        window_size,
        payload.unwrap_or_default(),
        options,
    )?;
    let len = packet.payload.as_ref().map(|p| p.len()).unwrap_or(0);
    up_packet_sender.send(packet).map_err(|e| Error::new(UnexpectedEof, e))?;
    Ok(len)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn create_raw_packet(
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    calculate_payload_max_len: impl Fn(usize, usize) -> usize,
    flags: u8,
    ttl: u8,
    seq: u32,
    ack: u32,
    win: u16,
    mut payload: Vec<u8>,
    options: Option<&Vec<TcpOptions>>,
) -> std::io::Result<NetworkPacket> {
    let mut tcp_header = etherparse::TcpHeader::new(src_addr.port(), dst_addr.port(), seq, win);
    tcp_header.acknowledgment_number = ack;
    tcp_header.syn = flags & SYN != 0;
    tcp_header.ack = flags & ACK != 0;
    tcp_header.rst = flags & RST != 0;
    tcp_header.fin = flags & FIN != 0;
    tcp_header.psh = flags & PSH != 0;

    if let Some(opts) = options {
        let mut tcp_options = Vec::new();
        for opt in opts {
            match opt {
                TcpOptions::MaximumSegmentSize(mss) => tcp_options.push(TcpOptionElement::MaximumSegmentSize(*mss)),
            }
        }
        tcp_header
            .set_options(&tcp_options)
            .map_err(|e| std::io::Error::new(InvalidInput, e))?;
    }
    let ip_header = match (src_addr.ip(), dst_addr.ip()) {
        (std::net::IpAddr::V4(src), std::net::IpAddr::V4(dst)) => {
            let mut ip_h =
                Ipv4Header::new(0, ttl, IpNumber::TCP, src.octets(), dst.octets()).map_err(|e| std::io::Error::new(InvalidInput, e))?;
            let payload_len = calculate_payload_max_len(ip_h.header_len(), tcp_header.header_len());
            payload.truncate(payload_len);
            ip_h.set_payload_len(payload.len() + tcp_header.header_len())
                .map_err(|e| std::io::Error::new(InvalidInput, e))?;
            ip_h.dont_fragment = true;
            IpHeader::Ipv4(ip_h)
        }
        (std::net::IpAddr::V6(src), std::net::IpAddr::V6(dst)) => {
            let mut ip_h = etherparse::Ipv6Header {
                traffic_class: 0,
                flow_label: Ipv6FlowLabel::ZERO,
                payload_length: 0,
                next_header: IpNumber::TCP,
                hop_limit: ttl,
                source: src.octets(),
                destination: dst.octets(),
            };
            let payload_len = calculate_payload_max_len(ip_h.header_len(), tcp_header.header_len());
            payload.truncate(payload_len);
            let len = payload.len() + tcp_header.header_len();
            ip_h.set_payload_length(len).map_err(|e| std::io::Error::new(InvalidInput, e))?;

            IpHeader::Ipv6(ip_h)
        }
        _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "IP version mismatch")),
    };

    match ip_header {
        IpHeader::Ipv4(ref ip_header) => {
            tcp_header.checksum = tcp_header
                .calc_checksum_ipv4(ip_header, &payload)
                .map_err(|e| std::io::Error::new(InvalidInput, e))?;
        }
        IpHeader::Ipv6(ref ip_header) => {
            tcp_header.checksum = tcp_header
                .calc_checksum_ipv6(ip_header, &payload)
                .map_err(|e| std::io::Error::new(InvalidInput, e))?;
        }
    }
    Ok(NetworkPacket {
        ip: ip_header,
        transport: TransportHeader::Tcp(tcp_header),
        payload: Some(payload),
    })
}
