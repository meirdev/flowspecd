//! BGP Finite State Machine implementation per RFC 4271 Section 8

use std::time::Duration;

use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};

use super::session::{Message, Session, SessionError};
use super::{ErrorCode, Notification, Open, Update};

/// BGP FSM states per RFC 4271 Section 8.2.2
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FsmState {
    /// Initial state, refuses all incoming connections
    #[default]
    Idle,
    /// Waiting for TCP connection to complete
    Connect,
    /// Listening for incoming TCP connections
    Active,
    /// OPEN message sent, waiting for peer's OPEN
    OpenSent,
    /// Received valid OPEN, waiting for KEEPALIVE/NOTIFICATION
    OpenConfirm,
    /// BGP connection fully established
    Established,
}

impl std::fmt::Display for FsmState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FsmState::Idle => write!(f, "Idle"),
            FsmState::Connect => write!(f, "Connect"),
            FsmState::Active => write!(f, "Active"),
            FsmState::OpenSent => write!(f, "OpenSent"),
            FsmState::OpenConfirm => write!(f, "OpenConfirm"),
            FsmState::Established => write!(f, "Established"),
        }
    }
}

/// BGP FSM events per RFC 4271 Section 8.1
#[derive(Debug, Clone)]
pub enum FsmEvent {
    // === Administrative Events (1-8) ===
    /// Event 1: Local system administrator manually starts peer
    ManualStart,
    /// Event 2: Local system administrator manually stops peer
    ManualStop,
    /// Event 4: Manual start with passive TCP establishment
    ManualStartWithPassiveTcp,

    // === Timer Events (9-13) ===
    /// Event 9: ConnectRetry timer expires
    ConnectRetryTimerExpires,
    /// Event 10: Hold timer expires
    HoldTimerExpires,
    /// Event 11: Keepalive timer expires
    KeepaliveTimerExpires,

    // === TCP Connection Events (14-18) ===
    /// Event 17: TCP connection confirmed (3-way handshake complete)
    TcpConnectionConfirmed,
    /// Event 18: TCP connection fails
    TcpConnectionFails,

    // === BGP Message Events (19-28) ===
    /// Event 19: Valid OPEN message received
    BgpOpen(Open),
    /// Event 21: BGP header error
    BgpHeaderErr {
        subcode: u8,
        data: Vec<u8>,
    },
    /// Event 22: OPEN message error
    BgpOpenMsgErr {
        subcode: u8,
        data: Vec<u8>,
    },
    /// Event 24: NOTIFICATION with version error
    NotifMsgVerErr,
    /// Event 25: NOTIFICATION message received
    NotifMsg(Notification),
    /// Event 26: KEEPALIVE message received
    KeepAliveMsg,
    /// Event 27: UPDATE message received
    UpdateMsg(Update),
    /// Event 28: UPDATE message error
    UpdateMsgErr {
        subcode: u8,
        data: Vec<u8>,
    },
}

impl std::fmt::Display for FsmEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FsmEvent::ManualStart => write!(f, "ManualStart"),
            FsmEvent::ManualStop => write!(f, "ManualStop"),
            FsmEvent::ManualStartWithPassiveTcp => write!(f, "ManualStartWithPassiveTcp"),
            FsmEvent::ConnectRetryTimerExpires => write!(f, "ConnectRetryTimerExpires"),
            FsmEvent::HoldTimerExpires => write!(f, "HoldTimerExpires"),
            FsmEvent::KeepaliveTimerExpires => write!(f, "KeepaliveTimerExpires"),
            FsmEvent::TcpConnectionConfirmed => write!(f, "TcpConnectionConfirmed"),
            FsmEvent::TcpConnectionFails => write!(f, "TcpConnectionFails"),
            FsmEvent::BgpOpen(_) => write!(f, "BgpOpen"),
            FsmEvent::BgpHeaderErr { .. } => write!(f, "BgpHeaderErr"),
            FsmEvent::BgpOpenMsgErr { .. } => write!(f, "BgpOpenMsgErr"),
            FsmEvent::NotifMsgVerErr => write!(f, "NotifMsgVerErr"),
            FsmEvent::NotifMsg(_) => write!(f, "NotifMsg"),
            FsmEvent::KeepAliveMsg => write!(f, "KeepAliveMsg"),
            FsmEvent::UpdateMsg(_) => write!(f, "UpdateMsg"),
            FsmEvent::UpdateMsgErr { .. } => write!(f, "UpdateMsgErr"),
        }
    }
}

/// Action to be taken after state transition
#[derive(Debug, Clone)]
pub enum FsmAction {
    /// No action required
    None,
    /// Initiate TCP connection to peer
    InitiateTcp,
    /// Listen for incoming TCP connection
    ListenTcp,
    /// Send OPEN message
    SendOpen,
    /// Send KEEPALIVE message
    SendKeepalive,
    /// Send NOTIFICATION message and close connection
    SendNotification {
        error_code: ErrorCode,
        subcode: u8,
        data: Vec<u8>,
    },
    /// Process received UPDATE message
    ProcessUpdate(Update),
    /// Session is now established
    SessionEstablished,
    /// Peer sent NOTIFICATION
    PeerNotification(Notification),
    /// Release all resources
    ReleaseResources,
}

/// FSM error types
#[derive(Debug, Error)]
pub enum FsmError {
    #[error("Session error: {0}")]
    Session(#[from] SessionError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Hold timer expired")]
    HoldTimerExpired,
    #[error("Peer sent NOTIFICATION: {0}")]
    PeerNotification(Notification),
    #[error("Connection closed")]
    ConnectionClosed,
}

/// FSM configuration
#[derive(Debug, Clone)]
pub struct FsmConfig {
    /// Local AS number
    pub my_as: u16,
    /// BGP Router ID
    pub bgp_id: u32,
    /// Configured hold time (will be negotiated)
    pub hold_time: u16,
    /// Peer address to connect to (for active mode)
    pub peer_addr: Option<String>,
    /// Listen address (for passive mode)
    pub listen_addr: Option<String>,
    /// Connect retry time (default: 120 seconds)
    pub connect_retry_time: Duration,
    /// Initial hold time before OPEN received (default: 240 seconds / 4 minutes)
    pub initial_hold_time: Duration,
}

impl FsmConfig {
    pub fn new(my_as: u16, bgp_id: u32, hold_time: u16) -> Self {
        Self {
            my_as,
            bgp_id,
            hold_time,
            peer_addr: None,
            listen_addr: None,
            connect_retry_time: Duration::from_secs(120),
            initial_hold_time: Duration::from_secs(240),
        }
    }

    pub fn with_peer(mut self, addr: String) -> Self {
        self.peer_addr = Some(addr);
        self
    }

    pub fn with_listen(mut self, addr: String) -> Self {
        self.listen_addr = Some(addr);
        self
    }
}

/// Timer state - stores when the timer should fire
#[derive(Debug, Clone)]
struct TimerState {
    /// When the timer should expire (None = timer not running)
    deadline: Option<tokio::time::Instant>,
}

impl TimerState {
    fn new() -> Self {
        Self { deadline: None }
    }

    fn start(&mut self, duration: Duration) {
        if !duration.is_zero() {
            self.deadline = Some(tokio::time::Instant::now() + duration);
        }
    }

    fn start_if_runtime_available(&mut self, duration: Duration) {
        // Only set the deadline if we're in a Tokio runtime
        // This allows tests to run without a runtime
        if !duration.is_zero() {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                let _ = handle; // Just checking if we have a runtime
                self.deadline = Some(tokio::time::Instant::now() + duration);
            }
        }
    }

    fn stop(&mut self) {
        self.deadline = None;
    }

    fn is_running(&self) -> bool {
        self.deadline.is_some()
    }
}

/// BGP Finite State Machine per RFC 4271
pub struct Fsm {
    /// Configuration
    config: FsmConfig,

    /// Current state
    state: FsmState,

    /// Number of times Connect state has been entered (RFC 4271 Section 8)
    connect_retry_counter: u32,

    /// Negotiated hold time (set after OPEN exchange)
    negotiated_hold_time: Option<Duration>,

    /// Peer's OPEN message (set after receiving valid OPEN)
    peer_open: Option<Open>,

    /// Underlying TCP session
    session: Option<Session>,

    /// TCP listener for passive mode
    listener: Option<TcpListener>,

    /// Connect retry timer state
    connect_retry_timer: TimerState,

    /// Hold timer state
    hold_timer: TimerState,

    /// Keepalive timer state
    keepalive_timer: TimerState,
}

impl Fsm {
    /// Create a new FSM in Idle state
    pub fn new(config: FsmConfig) -> Self {
        Self {
            config,
            state: FsmState::Idle,
            connect_retry_counter: 0,
            negotiated_hold_time: None,
            peer_open: None,
            session: None,
            listener: None,
            connect_retry_timer: TimerState::new(),
            hold_timer: TimerState::new(),
            keepalive_timer: TimerState::new(),
        }
    }

    /// Get current state
    pub fn state(&self) -> FsmState {
        self.state
    }

    /// Get peer's OPEN message (if received)
    pub fn peer_open(&self) -> Option<&Open> {
        self.peer_open.as_ref()
    }

    /// Get negotiated hold time
    pub fn negotiated_hold_time(&self) -> Option<Duration> {
        self.negotiated_hold_time
    }

    /// Set the TCP session (used after external TCP connection)
    pub fn set_session(&mut self, session: Session) {
        self.session = Some(session);
    }

    // === Timer Management ===

    fn start_connect_retry_timer(&mut self) {
        self.connect_retry_timer
            .start_if_runtime_available(self.config.connect_retry_time);
    }

    fn stop_connect_retry_timer(&mut self) {
        self.connect_retry_timer.stop();
    }

    fn start_hold_timer(&mut self, duration: Duration) {
        self.hold_timer.start_if_runtime_available(duration);
    }

    fn stop_hold_timer(&mut self) {
        self.hold_timer.stop();
    }

    fn restart_hold_timer(&mut self) {
        if let Some(negotiated) = self.negotiated_hold_time {
            self.hold_timer.start_if_runtime_available(negotiated);
        }
    }

    fn start_keepalive_timer(&mut self) {
        let keepalive_time = self
            .negotiated_hold_time
            .map(|h| h / 3)
            .unwrap_or(Duration::from_secs(30));

        self.keepalive_timer
            .start_if_runtime_available(keepalive_time);
    }

    fn restart_keepalive_timer(&mut self) {
        self.start_keepalive_timer();
    }

    fn stop_all_timers(&mut self) {
        self.connect_retry_timer.stop();
        self.hold_timer.stop();
        self.keepalive_timer.stop();
    }

    // === Hold Time Negotiation ===

    /// Negotiate hold time per RFC 4271 Section 4.2
    fn negotiate_hold_time(&self, peer_open: &Open) -> Duration {
        let local_hold = self.config.hold_time as u64;
        let peer_hold = peer_open.hold_time as u64;

        // Hold time must be 0 (no keepalives) or at least 3 seconds
        if peer_hold == 0 || local_hold == 0 {
            return Duration::ZERO;
        }

        let negotiated = local_hold.min(peer_hold);

        // RFC 4271: Hold Time < 3 seconds is invalid (except 0)
        if negotiated < 3 {
            return Duration::ZERO;
        }

        Duration::from_secs(negotiated)
    }

    // === State Transition Logic ===

    /// Process an event and return the resulting action
    pub fn handle_event(&mut self, event: FsmEvent) -> FsmAction {
        let old_state = self.state;
        let (next_state, action) = self.transition(event);
        self.state = next_state;

        if old_state != next_state {
            eprintln!("FSM: {} -> {}", old_state, next_state);
        }

        action
    }

    fn transition(&mut self, event: FsmEvent) -> (FsmState, FsmAction) {
        match (&self.state, event) {
            // === Idle State ===
            (FsmState::Idle, FsmEvent::ManualStart) => {
                self.connect_retry_counter = 0;
                self.start_connect_retry_timer();
                (FsmState::Connect, FsmAction::InitiateTcp)
            }

            (FsmState::Idle, FsmEvent::ManualStartWithPassiveTcp) => {
                self.connect_retry_counter = 0;
                self.start_connect_retry_timer();
                (FsmState::Active, FsmAction::ListenTcp)
            }

            // Ignore other events in Idle
            (FsmState::Idle, _) => (FsmState::Idle, FsmAction::None),

            // === Connect State ===
            (FsmState::Connect, FsmEvent::ManualStop) => {
                self.stop_all_timers();
                self.connect_retry_counter = 0;
                (FsmState::Idle, FsmAction::ReleaseResources)
            }

            (FsmState::Connect, FsmEvent::ConnectRetryTimerExpires) => {
                self.connect_retry_counter += 1;
                self.start_connect_retry_timer();
                (FsmState::Connect, FsmAction::InitiateTcp)
            }

            (FsmState::Connect, FsmEvent::TcpConnectionConfirmed) => {
                self.stop_connect_retry_timer();
                self.start_hold_timer(self.config.initial_hold_time);
                (FsmState::OpenSent, FsmAction::SendOpen)
            }

            (FsmState::Connect, FsmEvent::TcpConnectionFails) => {
                self.connect_retry_counter += 1;
                self.start_connect_retry_timer();
                (FsmState::Active, FsmAction::ListenTcp)
            }

            (FsmState::Connect, FsmEvent::BgpHeaderErr { subcode, data }) => {
                self.stop_all_timers();
                self.connect_retry_counter += 1;
                (
                    FsmState::Idle,
                    FsmAction::SendNotification {
                        error_code: ErrorCode::MessageHeader,
                        subcode,
                        data,
                    },
                )
            }

            (FsmState::Connect, FsmEvent::BgpOpenMsgErr { subcode, data }) => {
                self.stop_all_timers();
                self.connect_retry_counter += 1;
                (
                    FsmState::Idle,
                    FsmAction::SendNotification {
                        error_code: ErrorCode::OpenMessage,
                        subcode,
                        data,
                    },
                )
            }

            (FsmState::Connect, FsmEvent::NotifMsgVerErr) => {
                self.stop_all_timers();
                (FsmState::Idle, FsmAction::ReleaseResources)
            }

            // Other events in Connect -> go to Idle with FSM error
            (FsmState::Connect, event) => {
                self.stop_all_timers();
                self.connect_retry_counter += 1;
                eprintln!("FSM: Unexpected event {} in Connect state", event);
                (FsmState::Idle, FsmAction::ReleaseResources)
            }

            // === Active State ===
            (FsmState::Active, FsmEvent::ManualStop) => {
                self.stop_all_timers();
                self.connect_retry_counter = 0;
                (FsmState::Idle, FsmAction::ReleaseResources)
            }

            (FsmState::Active, FsmEvent::ConnectRetryTimerExpires) => {
                self.connect_retry_counter += 1;
                self.start_connect_retry_timer();
                (FsmState::Connect, FsmAction::InitiateTcp)
            }

            (FsmState::Active, FsmEvent::TcpConnectionConfirmed) => {
                self.stop_connect_retry_timer();
                self.start_hold_timer(self.config.initial_hold_time);
                (FsmState::OpenSent, FsmAction::SendOpen)
            }

            (FsmState::Active, FsmEvent::TcpConnectionFails) => {
                self.connect_retry_counter += 1;
                self.start_connect_retry_timer();
                (FsmState::Idle, FsmAction::ReleaseResources)
            }

            (FsmState::Active, FsmEvent::BgpHeaderErr { subcode, data }) => {
                self.stop_all_timers();
                self.connect_retry_counter += 1;
                (
                    FsmState::Idle,
                    FsmAction::SendNotification {
                        error_code: ErrorCode::MessageHeader,
                        subcode,
                        data,
                    },
                )
            }

            (FsmState::Active, FsmEvent::BgpOpenMsgErr { subcode, data }) => {
                self.stop_all_timers();
                self.connect_retry_counter += 1;
                (
                    FsmState::Idle,
                    FsmAction::SendNotification {
                        error_code: ErrorCode::OpenMessage,
                        subcode,
                        data,
                    },
                )
            }

            // Other events in Active -> go to Idle
            (FsmState::Active, event) => {
                self.stop_all_timers();
                self.connect_retry_counter += 1;
                eprintln!("FSM: Unexpected event {} in Active state", event);
                (FsmState::Idle, FsmAction::ReleaseResources)
            }

            // === OpenSent State ===
            (FsmState::OpenSent, FsmEvent::ManualStop) => {
                self.stop_all_timers();
                self.connect_retry_counter = 0;
                (
                    FsmState::Idle,
                    FsmAction::SendNotification {
                        error_code: ErrorCode::Cease,
                        subcode: 2, // Administrative Shutdown
                        data: vec![],
                    },
                )
            }

            (FsmState::OpenSent, FsmEvent::HoldTimerExpires) => {
                self.stop_all_timers();
                self.connect_retry_counter += 1;
                (
                    FsmState::Idle,
                    FsmAction::SendNotification {
                        error_code: ErrorCode::HoldTimerExpired,
                        subcode: 0,
                        data: vec![],
                    },
                )
            }

            (FsmState::OpenSent, FsmEvent::TcpConnectionFails) => {
                self.stop_hold_timer();
                self.start_connect_retry_timer();
                (FsmState::Active, FsmAction::ListenTcp)
            }

            (FsmState::OpenSent, FsmEvent::BgpOpen(peer_open)) => {
                self.stop_connect_retry_timer();

                // Negotiate hold time
                let negotiated = self.negotiate_hold_time(&peer_open);
                self.negotiated_hold_time = Some(negotiated);
                self.peer_open = Some(peer_open);

                if negotiated.is_zero() {
                    // HoldTime of 0 means no keepalives
                    self.stop_hold_timer();
                } else {
                    self.start_hold_timer(negotiated);
                    self.start_keepalive_timer();
                }

                (FsmState::OpenConfirm, FsmAction::SendKeepalive)
            }

            (FsmState::OpenSent, FsmEvent::BgpHeaderErr { subcode, data }) => {
                self.stop_all_timers();
                self.connect_retry_counter += 1;
                (
                    FsmState::Idle,
                    FsmAction::SendNotification {
                        error_code: ErrorCode::MessageHeader,
                        subcode,
                        data,
                    },
                )
            }

            (FsmState::OpenSent, FsmEvent::BgpOpenMsgErr { subcode, data }) => {
                self.stop_all_timers();
                self.connect_retry_counter += 1;
                (
                    FsmState::Idle,
                    FsmAction::SendNotification {
                        error_code: ErrorCode::OpenMessage,
                        subcode,
                        data,
                    },
                )
            }

            (FsmState::OpenSent, FsmEvent::NotifMsgVerErr) => {
                self.stop_all_timers();
                (FsmState::Idle, FsmAction::ReleaseResources)
            }

            (FsmState::OpenSent, FsmEvent::NotifMsg(notification)) => {
                self.stop_all_timers();
                self.connect_retry_counter += 1;
                (FsmState::Idle, FsmAction::PeerNotification(notification))
            }

            // Other events in OpenSent -> FSM error
            (FsmState::OpenSent, event) => {
                self.stop_all_timers();
                self.connect_retry_counter += 1;
                eprintln!("FSM: Unexpected event {} in OpenSent state", event);
                (
                    FsmState::Idle,
                    FsmAction::SendNotification {
                        error_code: ErrorCode::FiniteStateMachine,
                        subcode: 1, // Unexpected in OpenSent
                        data: vec![],
                    },
                )
            }

            // === OpenConfirm State ===
            (FsmState::OpenConfirm, FsmEvent::ManualStop) => {
                self.stop_all_timers();
                self.connect_retry_counter = 0;
                (
                    FsmState::Idle,
                    FsmAction::SendNotification {
                        error_code: ErrorCode::Cease,
                        subcode: 2, // Administrative Shutdown
                        data: vec![],
                    },
                )
            }

            (FsmState::OpenConfirm, FsmEvent::HoldTimerExpires) => {
                self.stop_all_timers();
                self.connect_retry_counter += 1;
                (
                    FsmState::Idle,
                    FsmAction::SendNotification {
                        error_code: ErrorCode::HoldTimerExpired,
                        subcode: 0,
                        data: vec![],
                    },
                )
            }

            (FsmState::OpenConfirm, FsmEvent::KeepaliveTimerExpires) => {
                self.restart_keepalive_timer();
                (FsmState::OpenConfirm, FsmAction::SendKeepalive)
            }

            (FsmState::OpenConfirm, FsmEvent::TcpConnectionFails) => {
                self.stop_all_timers();
                self.connect_retry_counter += 1;
                (FsmState::Idle, FsmAction::ReleaseResources)
            }

            (FsmState::OpenConfirm, FsmEvent::KeepAliveMsg) => {
                self.restart_hold_timer();
                (FsmState::Established, FsmAction::SessionEstablished)
            }

            (FsmState::OpenConfirm, FsmEvent::NotifMsgVerErr) => {
                self.stop_all_timers();
                (FsmState::Idle, FsmAction::ReleaseResources)
            }

            (FsmState::OpenConfirm, FsmEvent::NotifMsg(notification)) => {
                self.stop_all_timers();
                self.connect_retry_counter += 1;
                (FsmState::Idle, FsmAction::PeerNotification(notification))
            }

            (FsmState::OpenConfirm, FsmEvent::BgpHeaderErr { subcode, data }) => {
                self.stop_all_timers();
                self.connect_retry_counter += 1;
                (
                    FsmState::Idle,
                    FsmAction::SendNotification {
                        error_code: ErrorCode::MessageHeader,
                        subcode,
                        data,
                    },
                )
            }

            (FsmState::OpenConfirm, FsmEvent::BgpOpenMsgErr { subcode, data }) => {
                self.stop_all_timers();
                self.connect_retry_counter += 1;
                (
                    FsmState::Idle,
                    FsmAction::SendNotification {
                        error_code: ErrorCode::OpenMessage,
                        subcode,
                        data,
                    },
                )
            }

            // Other events in OpenConfirm -> FSM error
            (FsmState::OpenConfirm, event) => {
                self.stop_all_timers();
                self.connect_retry_counter += 1;
                eprintln!("FSM: Unexpected event {} in OpenConfirm state", event);
                (
                    FsmState::Idle,
                    FsmAction::SendNotification {
                        error_code: ErrorCode::FiniteStateMachine,
                        subcode: 2, // Unexpected in OpenConfirm
                        data: vec![],
                    },
                )
            }

            // === Established State ===
            (FsmState::Established, FsmEvent::ManualStop) => {
                self.stop_all_timers();
                self.connect_retry_counter = 0;
                (
                    FsmState::Idle,
                    FsmAction::SendNotification {
                        error_code: ErrorCode::Cease,
                        subcode: 2, // Administrative Shutdown
                        data: vec![],
                    },
                )
            }

            (FsmState::Established, FsmEvent::HoldTimerExpires) => {
                self.stop_all_timers();
                self.connect_retry_counter += 1;
                (
                    FsmState::Idle,
                    FsmAction::SendNotification {
                        error_code: ErrorCode::HoldTimerExpired,
                        subcode: 0,
                        data: vec![],
                    },
                )
            }

            (FsmState::Established, FsmEvent::KeepaliveTimerExpires) => {
                self.restart_keepalive_timer();
                (FsmState::Established, FsmAction::SendKeepalive)
            }

            (FsmState::Established, FsmEvent::TcpConnectionFails) => {
                self.stop_all_timers();
                self.connect_retry_counter += 1;
                (FsmState::Idle, FsmAction::ReleaseResources)
            }

            (FsmState::Established, FsmEvent::KeepAliveMsg) => {
                self.restart_hold_timer();
                (FsmState::Established, FsmAction::None)
            }

            (FsmState::Established, FsmEvent::UpdateMsg(update)) => {
                self.restart_hold_timer();
                (FsmState::Established, FsmAction::ProcessUpdate(update))
            }

            (FsmState::Established, FsmEvent::UpdateMsgErr { subcode, data }) => {
                self.stop_all_timers();
                self.connect_retry_counter += 1;
                (
                    FsmState::Idle,
                    FsmAction::SendNotification {
                        error_code: ErrorCode::UpdateMessage,
                        subcode,
                        data,
                    },
                )
            }

            (FsmState::Established, FsmEvent::NotifMsg(notification)) => {
                self.stop_all_timers();
                self.connect_retry_counter += 1;
                (FsmState::Idle, FsmAction::PeerNotification(notification))
            }

            (FsmState::Established, FsmEvent::NotifMsgVerErr) => {
                self.stop_all_timers();
                self.connect_retry_counter += 1;
                (FsmState::Idle, FsmAction::ReleaseResources)
            }

            (FsmState::Established, FsmEvent::BgpHeaderErr { subcode, data }) => {
                self.stop_all_timers();
                self.connect_retry_counter += 1;
                (
                    FsmState::Idle,
                    FsmAction::SendNotification {
                        error_code: ErrorCode::MessageHeader,
                        subcode,
                        data,
                    },
                )
            }

            // Other events in Established -> FSM error
            (FsmState::Established, event) => {
                self.stop_all_timers();
                self.connect_retry_counter += 1;
                eprintln!("FSM: Unexpected event {} in Established state", event);
                (
                    FsmState::Idle,
                    FsmAction::SendNotification {
                        error_code: ErrorCode::FiniteStateMachine,
                        subcode: 3, // Unexpected in Established
                        data: vec![],
                    },
                )
            }
        }
    }

    // === Event Loop ===

    /// Wait for the next event (timer expiry or message)
    pub async fn wait_for_event(&mut self) -> Result<FsmEvent, FsmError> {
        use tokio::time::sleep_until;

        loop {
            tokio::select! {
                biased;

                // Connect retry timer
                _ = async {
                    if let Some(deadline) = self.connect_retry_timer.deadline {
                        sleep_until(deadline).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    self.connect_retry_timer.stop();
                    return Ok(FsmEvent::ConnectRetryTimerExpires);
                }

                // Hold timer
                _ = async {
                    if let Some(deadline) = self.hold_timer.deadline {
                        sleep_until(deadline).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    self.hold_timer.stop();
                    return Ok(FsmEvent::HoldTimerExpires);
                }

                // Keepalive timer
                _ = async {
                    if let Some(deadline) = self.keepalive_timer.deadline {
                        sleep_until(deadline).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    self.keepalive_timer.stop();
                    return Ok(FsmEvent::KeepaliveTimerExpires);
                }

                // Incoming TCP connection (Active state)
                result = async {
                    if let Some(ref listener) = self.listener {
                        listener.accept().await
                    } else {
                        std::future::pending::<std::io::Result<(TcpStream, std::net::SocketAddr)>>().await
                    }
                } => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            eprintln!("FSM: Accepted connection from {}", peer_addr);
                            let session = Session::new(
                                stream,
                                self.config.my_as,
                                self.config.bgp_id,
                                self.config.hold_time,
                            );
                            self.session = Some(session);
                            self.listener = None; // Stop listening after accepting
                            return Ok(FsmEvent::TcpConnectionConfirmed);
                        }
                        Err(e) => {
                            eprintln!("FSM: Accept failed: {}", e);
                            return Ok(FsmEvent::TcpConnectionFails);
                        }
                    }
                }

                // BGP message from session
                result = async {
                    if let Some(ref mut session) = self.session {
                        session.read_message().await
                    } else {
                        std::future::pending::<Result<Message, SessionError>>().await
                    }
                } => {
                    match result {
                        Ok(Message::Open(open)) => {
                            return Ok(FsmEvent::BgpOpen(open));
                        }
                        Ok(Message::Keepalive) => {
                            return Ok(FsmEvent::KeepAliveMsg);
                        }
                        Ok(Message::Update(update)) => {
                            return Ok(FsmEvent::UpdateMsg(update));
                        }
                        Ok(Message::Notification(n)) => {
                            // Check if it's a version error
                            if n.error_code == ErrorCode::OpenMessage && n.error_subcode == 1 {
                                return Ok(FsmEvent::NotifMsgVerErr);
                            }
                            return Ok(FsmEvent::NotifMsg(n));
                        }
                        Err(SessionError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                            return Ok(FsmEvent::TcpConnectionFails);
                        }
                        Err(SessionError::Parse(_)) => {
                            return Ok(FsmEvent::BgpHeaderErr {
                                subcode: 1, // Connection Not Synchronized
                                data: vec![],
                            });
                        }
                        Err(SessionError::PeerNotification(n)) => {
                            return Ok(FsmEvent::NotifMsg(n));
                        }
                        Err(_) => {
                            return Ok(FsmEvent::TcpConnectionFails);
                        }
                    }
                }
            }
        }
    }

    /// Execute an action returned by handle_event
    /// Returns an optional follow-up event that should be processed
    pub async fn execute_action(&mut self, action: FsmAction) -> Result<Option<FsmEvent>, FsmError> {
        match action {
            FsmAction::None => Ok(None),

            FsmAction::InitiateTcp => {
                if let Some(ref addr) = self.config.peer_addr {
                    eprintln!("FSM: Initiating TCP connection to {}", addr);
                    match TcpStream::connect(addr).await {
                        Ok(stream) => {
                            let session = Session::new(
                                stream,
                                self.config.my_as,
                                self.config.bgp_id,
                                self.config.hold_time,
                            );
                            self.session = Some(session);
                            // Return follow-up event
                            return Ok(Some(FsmEvent::TcpConnectionConfirmed));
                        }
                        Err(e) => {
                            eprintln!("FSM: TCP connect failed: {}", e);
                            return Ok(Some(FsmEvent::TcpConnectionFails));
                        }
                    }
                }
                Ok(None)
            }

            FsmAction::ListenTcp => {
                if let Some(ref addr) = self.config.listen_addr {
                    eprintln!("FSM: Starting TCP listener on {}", addr);
                    match TcpListener::bind(addr).await {
                        Ok(listener) => {
                            self.listener = Some(listener);
                            Ok(None)
                        }
                        Err(e) => {
                            eprintln!("FSM: TCP listen failed: {}", e);
                            Err(FsmError::Io(e))
                        }
                    }
                } else {
                    Ok(None)
                }
            }

            FsmAction::SendOpen => {
                if let Some(ref mut session) = self.session {
                    eprintln!("FSM: Sending OPEN");
                    session.send_open().await?;
                }
                Ok(None)
            }

            FsmAction::SendKeepalive => {
                if let Some(ref mut session) = self.session {
                    eprintln!("FSM: Sending KEEPALIVE");
                    session.send_keepalive().await?;
                }
                Ok(None)
            }

            FsmAction::SendNotification {
                error_code,
                subcode,
                data,
            } => {
                if let Some(ref mut session) = self.session {
                    eprintln!(
                        "FSM: Sending NOTIFICATION {:?} subcode {}",
                        error_code, subcode
                    );
                    session.send_notification(error_code, subcode, data).await?;
                }
                self.release_resources();
                Ok(None)
            }

            FsmAction::ProcessUpdate(update) => {
                // The update is returned to the caller for processing
                // This action is a no-op here; the caller handles it
                let _ = update;
                Ok(None)
            }

            FsmAction::SessionEstablished => {
                eprintln!("FSM: Session ESTABLISHED");
                Ok(None)
            }

            FsmAction::PeerNotification(notification) => {
                eprintln!("FSM: Peer sent NOTIFICATION: {}", notification);
                self.release_resources();
                Err(FsmError::PeerNotification(notification))
            }

            FsmAction::ReleaseResources => {
                self.release_resources();
                Ok(None)
            }
        }
    }

    fn release_resources(&mut self) {
        self.session = None;
        self.listener = None;
        self.peer_open = None;
        self.negotiated_hold_time = None;
    }

    /// Run one iteration of the FSM event loop
    /// Returns the action that was taken (useful for ProcessUpdate and SessionEstablished)
    pub async fn run_once(&mut self) -> Result<FsmAction, FsmError> {
        let event = self.wait_for_event().await?;
        let mut action = self.handle_event(event);

        // For ProcessUpdate and SessionEstablished, return immediately
        // so the caller can handle them
        match &action {
            FsmAction::ProcessUpdate(_) | FsmAction::SessionEstablished => {
                return Ok(action);
            }
            FsmAction::PeerNotification(_) => {
                // Execute to clean up resources, then return
                self.execute_action(action.clone()).await.ok();
                return Ok(action);
            }
            _ => {}
        }

        // Execute actions and handle any follow-up events
        loop {
            match self.execute_action(action).await? {
                Some(follow_up_event) => {
                    action = self.handle_event(follow_up_event);
                    // Check if this new action needs special handling
                    match &action {
                        FsmAction::ProcessUpdate(_) | FsmAction::SessionEstablished => {
                            return Ok(action);
                        }
                        _ => {}
                    }
                }
                None => break,
            }
        }

        Ok(FsmAction::None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> FsmConfig {
        FsmConfig::new(65001, 0x0A000001, 180)
    }

    #[test]
    fn test_idle_to_connect_on_manual_start() {
        let mut fsm = Fsm::new(test_config());
        assert_eq!(fsm.state(), FsmState::Idle);

        let action = fsm.handle_event(FsmEvent::ManualStart);
        assert_eq!(fsm.state(), FsmState::Connect);
        assert!(matches!(action, FsmAction::InitiateTcp));
    }

    #[test]
    fn test_idle_to_active_on_passive_start() {
        let mut fsm = Fsm::new(test_config());
        assert_eq!(fsm.state(), FsmState::Idle);

        let action = fsm.handle_event(FsmEvent::ManualStartWithPassiveTcp);
        assert_eq!(fsm.state(), FsmState::Active);
        assert!(matches!(action, FsmAction::ListenTcp));
    }

    #[test]
    fn test_connect_to_opensent_on_tcp() {
        let mut fsm = Fsm::new(test_config());
        fsm.handle_event(FsmEvent::ManualStart);
        assert_eq!(fsm.state(), FsmState::Connect);

        let action = fsm.handle_event(FsmEvent::TcpConnectionConfirmed);
        assert_eq!(fsm.state(), FsmState::OpenSent);
        assert!(matches!(action, FsmAction::SendOpen));
    }

    #[test]
    fn test_opensent_to_openconfirm_on_open() {
        let mut fsm = Fsm::new(test_config());
        fsm.handle_event(FsmEvent::ManualStart);
        fsm.handle_event(FsmEvent::TcpConnectionConfirmed);
        assert_eq!(fsm.state(), FsmState::OpenSent);

        let peer_open = Open::new(65002, 90, 0x0A000002);
        let action = fsm.handle_event(FsmEvent::BgpOpen(peer_open));
        assert_eq!(fsm.state(), FsmState::OpenConfirm);
        assert!(matches!(action, FsmAction::SendKeepalive));
        assert!(fsm.peer_open().is_some());
    }

    #[test]
    fn test_openconfirm_to_established_on_keepalive() {
        let mut fsm = Fsm::new(test_config());
        fsm.handle_event(FsmEvent::ManualStart);
        fsm.handle_event(FsmEvent::TcpConnectionConfirmed);
        let peer_open = Open::new(65002, 90, 0x0A000002);
        fsm.handle_event(FsmEvent::BgpOpen(peer_open));
        assert_eq!(fsm.state(), FsmState::OpenConfirm);

        let action = fsm.handle_event(FsmEvent::KeepAliveMsg);
        assert_eq!(fsm.state(), FsmState::Established);
        assert!(matches!(action, FsmAction::SessionEstablished));
    }

    #[test]
    fn test_hold_timer_expires() {
        let mut fsm = Fsm::new(test_config());
        fsm.handle_event(FsmEvent::ManualStart);
        fsm.handle_event(FsmEvent::TcpConnectionConfirmed);
        assert_eq!(fsm.state(), FsmState::OpenSent);

        let action = fsm.handle_event(FsmEvent::HoldTimerExpires);
        assert_eq!(fsm.state(), FsmState::Idle);
        assert!(matches!(
            action,
            FsmAction::SendNotification {
                error_code: ErrorCode::HoldTimerExpired,
                ..
            }
        ));
    }

    #[test]
    fn test_hold_time_negotiation() {
        let config = FsmConfig::new(65001, 0x0A000001, 180);
        let fsm = Fsm::new(config);

        // Peer with lower hold time
        let peer_open = Open::new(65002, 90, 0x0A000002);
        let negotiated = fsm.negotiate_hold_time(&peer_open);
        assert_eq!(negotiated, Duration::from_secs(90));

        // Peer with zero hold time
        let peer_open = Open::new(65002, 0, 0x0A000002);
        let negotiated = fsm.negotiate_hold_time(&peer_open);
        assert_eq!(negotiated, Duration::ZERO);
    }

    #[test]
    fn test_established_keepalive_restarts_hold_timer() {
        let mut fsm = Fsm::new(test_config());
        fsm.handle_event(FsmEvent::ManualStart);
        fsm.handle_event(FsmEvent::TcpConnectionConfirmed);
        let peer_open = Open::new(65002, 90, 0x0A000002);
        fsm.handle_event(FsmEvent::BgpOpen(peer_open));
        fsm.handle_event(FsmEvent::KeepAliveMsg);
        assert_eq!(fsm.state(), FsmState::Established);

        // Receiving keepalive should stay in Established
        let action = fsm.handle_event(FsmEvent::KeepAliveMsg);
        assert_eq!(fsm.state(), FsmState::Established);
        assert!(matches!(action, FsmAction::None));
    }
}
