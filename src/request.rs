//! Typed requests and their errors.

use bloop_protocol::codec::{Decode, EncodeError};
use bloop_protocol::frame::RawMessage;
use bloop_protocol::message::ErrorResponse;
use bloop_protocol::set::{MessageSetError, Payload, decode_message};
use thiserror::Error;

pub use bloop_protocol::set::Request;

/// Errors that can occur while performing a request.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RequestError {
    /// The client is not connected, or the connection was lost while the
    /// request was in flight.
    #[error("not connected to the server")]
    Disconnected,

    /// The client has been shut down.
    #[error("the client is shut down")]
    Shutdown,

    /// The server answered with a protocol error.
    ///
    /// This covers both standard error codes such as
    /// [`ErrorResponse::UnknownNfcUid`] and extension-defined codes via
    /// [`ErrorResponse::Custom`].
    #[error("server answered with error {0:?}")]
    Error(ErrorResponse),

    /// The server answered with a message of an unexpected type.
    #[error("server sent an unexpected response with opcode 0x{:02x}", .0.message_type)]
    UnexpectedResponse(RawMessage),

    /// The server's response failed to decode.
    #[error("server sent a malformed response")]
    Malformed(#[source] MessageSetError),

    /// The request could not be encoded.
    #[error(transparent)]
    Encode(#[from] EncodeError),
}

/// Decodes a response, routing protocol errors and foreign opcodes.
pub(crate) fn decode_response<M>(raw: RawMessage) -> Result<M, RequestError>
where
    M: Payload + Decode,
{
    if raw.message_type == ErrorResponse::OPCODE {
        return match decode_message::<ErrorResponse>(&raw) {
            Ok(error) => Err(RequestError::Error(error)),
            Err(error) => Err(RequestError::Malformed(error)),
        };
    }

    match decode_message::<M>(&raw) {
        Ok(message) => Ok(message),
        Err(MessageSetError::UnknownOpcode(_)) => Err(RequestError::UnexpectedResponse(raw)),
        Err(error) => Err(RequestError::Malformed(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloop_protocol::message::Pong;
    use bloop_protocol::set::encode_message;

    #[test]
    fn success_response_decodes() {
        let raw = encode_message(&Pong).unwrap();
        assert!(decode_response::<Pong>(raw).is_ok());
    }

    #[test]
    fn error_response_maps_to_request_error() {
        let raw = encode_message(&ErrorResponse::UnknownNfcUid).unwrap();
        let error = decode_response::<Pong>(raw).unwrap_err();

        assert!(matches!(
            error,
            RequestError::Error(ErrorResponse::UnknownNfcUid)
        ));
    }

    #[test]
    fn custom_error_code_survives() {
        let raw = encode_message(&ErrorResponse::Custom(0x90)).unwrap();
        let error = decode_response::<Pong>(raw).unwrap_err();

        assert!(matches!(
            error,
            RequestError::Error(ErrorResponse::Custom(0x90))
        ));
    }

    #[test]
    fn foreign_opcode_is_unexpected() {
        let raw = RawMessage::new(0x42, vec![]);
        let error = decode_response::<Pong>(raw).unwrap_err();

        assert!(matches!(error, RequestError::UnexpectedResponse(_)));
    }

    #[test]
    fn malformed_payload_is_reported() {
        let raw = RawMessage::new(Pong::OPCODE, vec![1, 2, 3]);
        let error = decode_response::<Pong>(raw).unwrap_err();

        assert!(matches!(error, RequestError::Malformed(_)));
    }
}
