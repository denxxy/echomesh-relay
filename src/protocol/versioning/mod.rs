use crate::error::ProtocolError;

/// Protocol version identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum ProtocolVersion {
    V1 = 1,
}

impl ProtocolVersion {
    pub const CURRENT: ProtocolVersion = ProtocolVersion::V1;

    pub fn from_u8(v: u8) -> Result<Self, ProtocolError> {
        match v {
            1 => Ok(ProtocolVersion::V1),
            other => Err(ProtocolError::UnsupportedVersion {
                expected: 1,
                actual: other,
            }),
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

impl Default for ProtocolVersion {
    fn default() -> Self {
        Self::CURRENT
    }
}
