//! Minimal NDEF parsing for text records.
//!
//! References:
//!
//! - NDEF parser: <https://github.com/TapTrack/NdefLibrary>
//! - Mifare reader: <https://github.com/hackeriet/pyhackeriet>

use thiserror::Error;

/// Errors that can occur while parsing an NDEF record.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NdefError {
    /// The record ended before the named part.
    #[error("record is truncated: {0} missing")]
    Truncated(&'static str),

    /// Chunked records are not supported.
    #[error("chunked records are not supported")]
    Chunked,

    /// The record does not use the well-known type name format.
    #[error("not a well-known payload type")]
    NotWellKnown,

    /// The record is not a text record.
    #[error("not a text record")]
    NotTextRecord,

    /// The text payload is not valid UTF-8.
    #[error("text payload is not valid UTF-8")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),
}

#[derive(PartialEq)]
enum State {
    Init,
    Length,
    Value,
}

/// Incremental parser extracting an NDEF message from a tag's TLV stream.
///
/// Feed tag data block by block via [`add_data`](Self::add_data) until
/// [`is_done`](Self::is_done); the message bytes are then available through
/// [`data`](Self::data).
pub struct NdefMessageParser {
    state: State,
    length: i32,
    data: Vec<u8>,
}

impl NdefMessageParser {
    /// Creates a parser awaiting the start of an NDEF message.
    pub fn new() -> Self {
        Self {
            state: State::Init,
            length: -1,
            data: Vec::new(),
        }
    }

    /// Feeds the next chunk of tag data into the parser.
    pub fn add_data(&mut self, data: &[u8]) {
        for byte in data {
            match self.state {
                State::Init => {
                    if *byte == 0x00 {
                        continue;
                    }

                    if *byte == 0x03 {
                        self.state = State::Length;
                    }
                }

                State::Length => {
                    if self.length == -1 {
                        if *byte == 0xff {
                            self.length = -2;
                        } else {
                            self.length = *byte as i32;
                            self.state = State::Value;
                        }

                        continue;
                    }

                    if self.length == -2 {
                        self.length = *byte as i32;
                    } else {
                        self.length = (self.length << 8) | *byte as i32;
                        self.state = State::Value;
                    }
                }

                State::Value => {
                    self.data.push(*byte);

                    if self.data.len() as i32 == self.length {
                        return;
                    }
                }
            }
        }
    }

    /// Returns the extracted message bytes.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Reports whether the complete message has been extracted.
    pub fn is_done(&self) -> bool {
        self.data.len() as i32 == self.length
    }

    /// Reports whether the start of an NDEF message has been seen.
    pub fn has_started(&self) -> bool {
        self.state != State::Init
    }
}

impl Default for NdefMessageParser {
    fn default() -> Self {
        Self::new()
    }
}

/// A parsed NDEF text record.
pub struct NdefTextRecord {
    value: Vec<u8>,
}

impl NdefTextRecord {
    /// Returns the record's text, stripped of its language code.
    ///
    /// # Errors
    ///
    /// Returns [`NdefError::InvalidUtf8`] if the payload is not UTF-8.
    pub fn text(&self) -> Result<String, NdefError> {
        if self.value.is_empty() {
            return Ok(String::new());
        }

        let code_length = self.value[0] & 0b0011_1111;
        let text = self
            .value
            .get(code_length as usize + 1..)
            .ok_or(NdefError::Truncated("text payload"))?;

        Ok(String::from_utf8(text.to_vec())?)
    }
}

/// Parses an NDEF message as a single text record.
///
/// # Errors
///
/// Returns an [`NdefError`] if the record is truncated, chunked, or not a
/// well-known text record.
pub fn parse_ndef_text_record(data: &[u8]) -> Result<NdefTextRecord, NdefError> {
    let record_length = data.len();
    let mut index = 0;

    if record_length <= index {
        return Err(NdefError::Truncated("flags"));
    }

    let flags = data[index];

    let is_chunked = (flags & 0b0010_0000) != 0;
    let is_short_record = (flags & 0b0001_0000) != 0;
    let has_id_length = (flags & 0b0000_1000) != 0;
    let type_name_format = flags & 0b0000_0111;

    if is_chunked {
        return Err(NdefError::Chunked);
    }

    index += 1;

    if record_length <= index {
        return Err(NdefError::Truncated("type length"));
    }

    let type_length = data[index];

    index += 1;

    let payload_length = if is_short_record {
        if record_length <= index {
            return Err(NdefError::Truncated("payload length"));
        }

        let payload_length_index = index;
        index += 1;
        data[payload_length_index] as u32
    } else {
        if record_length <= index + 3 {
            return Err(NdefError::Truncated("payload length"));
        }

        let payload_length_index = index;
        index += 4;
        u32::from_be_bytes(
            data[payload_length_index..(payload_length_index + 4)]
                .try_into()
                .expect("length checked"),
        )
    };

    let id_length = if has_id_length {
        if record_length <= index {
            return Err(NdefError::Truncated("ID length"));
        }

        let id_length_index = index;
        index += 1;
        data[id_length_index]
    } else {
        0
    };

    let payload_type = if type_length > 0 {
        let type_index = index;
        index += type_length as usize;

        if record_length < type_index + type_length as usize {
            return Err(NdefError::Truncated("type"));
        }

        data[type_index..(type_index + type_length as usize)].to_vec()
    } else {
        vec![]
    };

    if id_length > 0 {
        index += id_length as usize;

        if record_length < index {
            return Err(NdefError::Truncated("ID"));
        }
    }

    let payload_value = if payload_length > 0 {
        let value_index = index;

        // Compared in u64 so a hostile length cannot overflow usize on
        // 32-bit targets.
        if u64::from(payload_length) > record_length.saturating_sub(value_index) as u64 {
            return Err(NdefError::Truncated("payload"));
        }

        data[value_index..(value_index + payload_length as usize)].to_vec()
    } else {
        vec![]
    };

    if type_name_format != 1 {
        return Err(NdefError::NotWellKnown);
    }

    if payload_type != [0x54] {
        return Err(NdefError::NotTextRecord);
    }

    Ok(NdefTextRecord {
        value: payload_value,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a short text record: "en" language code plus the given text.
    fn text_record(text: &str) -> Vec<u8> {
        let mut record = vec![0xd1, 0x01];
        record.push((text.len() + 3) as u8);
        record.push(0x54);
        record.push(0x02);
        record.extend(b"en");
        record.extend(text.as_bytes());

        record
    }

    #[test]
    fn parses_short_text_record() {
        let record = parse_ndef_text_record(&text_record("bloop")).unwrap();
        assert_eq!(record.text().unwrap(), "bloop");
    }

    #[test]
    fn hostile_language_code_length_is_an_error() {
        // Status byte claims a 63-byte language code in a 1-byte payload.
        let data = [0xd1, 0x01, 0x01, 0x54, 0x3f];
        let record = parse_ndef_text_record(&data).unwrap();

        assert!(matches!(record.text(), Err(NdefError::Truncated(_))));
    }

    #[test]
    fn rejects_non_text_records() {
        // URI record (type 0x55).
        let data = [0xd1, 0x01, 0x01, 0x55, 0x00];
        assert!(matches!(
            parse_ndef_text_record(&data),
            Err(NdefError::NotTextRecord)
        ));
    }

    #[test]
    fn parser_extracts_message_from_tlv_stream() {
        let record = text_record("hello");
        let mut stream = vec![0x00, 0x00, 0x03, record.len() as u8];
        stream.extend(&record);
        stream.push(0xfe);

        let mut parser = NdefMessageParser::new();

        for chunk in stream.chunks(4) {
            parser.add_data(chunk);

            if parser.is_done() {
                break;
            }
        }

        assert!(parser.is_done());
        assert_eq!(parser.data(), record.as_slice());
    }

    #[test]
    fn parser_handles_three_byte_length_form() {
        // 300-byte message requires the 0xff-marked two-byte length.
        let message = vec![0x55; 300];
        let mut stream = vec![0x03, 0xff, 0x01, 0x2c];
        stream.extend(&message);

        let mut parser = NdefMessageParser::new();
        parser.add_data(&stream);

        assert!(parser.is_done());
        assert_eq!(parser.data().len(), 300);
    }
}
