//! Error definitions for the derekt-enclave hardware security module.

use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum EnclaveError {
    #[error("Transaction value {attempted} exceeds maximum allowed single spend limit {limit}")]
    SpendLimitExceeded { attempted: u64, limit: u64 },

    #[error("Cumulative spend {attempted} exceeds epoch/daily velocity cap {cap}")]
    VelocityCapExceeded { attempted: u64, cap: u64 },

    #[error("Destination address {0:?} is not present in hardware whitelist")]
    UnauthorizedDestination([u8; 20]),

    #[error("Cooldown period active: {remaining_slots} blocks remaining before next agent action")]
    CooldownActive { remaining_slots: u64 },

    #[error("Hardware tamper flag active: keys zeroized and vault locked")]
    TamperLocked,

    #[error("ReRAM integrity check failed: CRC or memory pattern corrupted")]
    MemoryIntegrityFailure,

    #[error("Signing key has not been provisioned into non-volatile ReRAM")]
    UnprovisionedKey,

    #[error("Wire protocol packet malformed or invalid checksum")]
    MalformedPacket,

    #[error("Buffer too small for payload deserialization")]
    BufferUnderflow,
}
