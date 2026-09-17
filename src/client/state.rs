/// Lifecycle state of the EchoMesh client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    Disconnected,
    Connecting,
    Connected,
    Authenticated,
    Closing,
    Closed,
}
