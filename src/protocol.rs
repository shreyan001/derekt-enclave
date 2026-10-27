//! Wire Protocol for USB-CDC / Serial Communication with Dabao Hardware.
//!
//! Handled at line rate by the 700 MHz quad PicoRV32 (BIO) coprocessor cluster
//! on the Baochip-1x, isolating untrusted host I/O before passing parsed packets
//! to the main VexRiscv core.

use crate::error::EnclaveError;

pub const PROTOCOL_MAGIC: [u8; 2] = [0xDE, 0xAA];

pub const CMD_PROVISION_KEY: u8 = 0x01;
pub const CMD_SIGN_TX: u8 = 0x02;
pub const CMD_QUERY_STATE: u8 = 0x03;
pub const CMD_TAMPER_KILL: u8 = 0x04;

/// Framed message packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WirePacket {
    pub command: u8,
    pub payload: Vec<u8>,
}

impl WirePacket {
    /// Encode a packet into wire format: [MAGIC: 2][CMD: 1][LEN: 2][PAYLOAD: N][CHECKSUM: 2]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(7 + self.payload.len());
        buf.extend_from_slice(&PROTOCOL_MAGIC);
        buf.push(self.command);
        let len = self.payload.len() as u16;
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&self.payload);

        let checksum = Self::compute_crc16(&self.payload);
        buf.extend_from_slice(&checksum.to_le_bytes());
        buf
    }

    /// Decode a raw wire buffer into a verified WirePacket.
    pub fn decode(bytes: &[u8]) -> Result<Self, EnclaveError> {
        if bytes.len() < 7 {
            return Err(EnclaveError::BufferUnderflow);
        }
        if bytes[0..2] != PROTOCOL_MAGIC {
            return Err(EnclaveError::MalformedPacket);
        }
        let command = bytes[2];
        let len = u16::from_le_bytes([bytes[3], bytes[4]]) as usize;
        if bytes.len() < 7 + len {
            return Err(EnclaveError::BufferUnderflow);
        }

        let payload = bytes[5..5 + len].to_vec();
        let expected_checksum = u16::from_le_bytes([bytes[5 + len], bytes[6 + len]]);
        let actual_checksum = Self::compute_crc16(&payload);

        if expected_checksum != actual_checksum {
            return Err(EnclaveError::MalformedPacket);
        }

        Ok(Self { command, payload })
    }

    /// Simple deterministic CRC-16 checksum.
    fn compute_crc16(data: &[u8]) -> u16 {
        let mut crc: u16 = 0xFFFF;
        for &byte in data {
            crc ^= (byte as u16) << 8;
            for _ in 0..8 {
                if (crc & 0x8000) != 0 {
                    crc = (crc << 1) ^ 0x1021;
                } else {
                    crc <<= 1;
                }
            }
        }
        crc
    }
}
