use crate::error::ValidationError;
use crate::protocol::envelope::MessageEnvelope;

/// Trait for validating protocol messages and structures.
pub trait Validate {
    fn validate(&self) -> Result<(), ValidationError>;
}

impl Validate for MessageEnvelope {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.message_type.is_response() && self.correlation_id == 0 {
            return Err(ValidationError::MissingCorrelationId);
        }

        Ok(())
    }
}

/// Helper to validate acceptable timestamp skew (e.g. ±300 seconds).
pub fn validate_timestamp(timestamp: u64, now: u64, max_skew_secs: u64) -> Result<(), ValidationError> {
    let diff = timestamp.abs_diff(now);

    if diff > max_skew_secs {
        Err(ValidationError::TimestampSkew { timestamp, now })
    } else {
        Ok(())
    }
}
