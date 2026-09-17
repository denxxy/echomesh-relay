use bytes::Bytes;

/// Pure domain echo service.
///
/// Contains ZERO network I/O, ZERO socket handling, and ZERO protocol serialization.
#[derive(Debug, Clone, Default)]
pub struct EchoService;

impl EchoService {
    pub fn new() -> Self {
        Self
    }

    /// Processes an echo request and returns the loopback payload.
    pub fn process_echo(&self, payload: Bytes) -> Bytes {
        payload
    }
}
