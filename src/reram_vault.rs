//! ReRAM Non-Volatile Storage Emulation & Tamper Zeroization.
//!
//! Models the 4MB on-chip Resistive RAM (RRAM) subsystem of the Baochip-1x.
//! ReRAM stores state through atomic conductive filament formation rather than
//! trapped electrical charge, offering high endurance, ~20ns read latencies,
//! and natural resistance to power glitching.

use crate::error::EnclaveError;
use sha2::{Digest, Sha256};

pub const RERAM_SECTOR_SIZE: usize = 256;
pub const KEY_PAYLOAD_SIZE: usize = 32;

/// Memory-mapped structure stored inside a dedicated ReRAM page.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ReRamKeyRecord {
    /// Magic identifier ("RRAMVLT1").
    pub magic: [u8; 8],
    /// Provisioned 256-bit private key share.
    pub private_key: [u8; KEY_PAYLOAD_SIZE],
    /// Associated 20-byte public address or agent identifier.
    pub agent_address: [u8; 20],
    /// Monotonic write sequence counter (prevents replay/flashback attacks).
    pub sequence_counter: u64,
    /// Integrity SHA-256 digest over the key record payload.
    pub checksum: [u8; 32],
}

pub const RE_RAM_MAGIC: [u8; 8] = *b"RRAMVLT1";

impl ReRamKeyRecord {
    /// Compute cryptographic checksum over record fields.
    pub fn compute_checksum(magic: &[u8; 8], key: &[u8; 32], addr: &[u8; 20], seq: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(magic);
        hasher.update(key);
        hasher.update(addr);
        hasher.update(&seq.to_le_bytes());
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    /// Create and verify a new valid key record.
    pub fn new(private_key: [u8; 32], agent_address: [u8; 20], sequence_counter: u64) -> Self {
        let checksum = Self::compute_checksum(&RE_RAM_MAGIC, &private_key, &agent_address, sequence_counter);
        Self {
            magic: RE_RAM_MAGIC,
            private_key,
            agent_address,
            sequence_counter,
            checksum,
        }
    }

    /// Verify integrity of the stored record.
    pub fn verify_integrity(&self) -> bool {
        if self.magic != RE_RAM_MAGIC {
            return false;
        }
        let expected = Self::compute_checksum(
            &self.magic,
            &self.private_key,
            &self.agent_address,
            self.sequence_counter,
        );
        self.checksum == expected
    }

    /// Perform secure zeroization of private key bytes in memory.
    pub fn zeroize(&mut self) {
        self.private_key.fill(0);
        self.checksum.fill(0);
        self.magic.fill(0);
        self.sequence_counter = 0;
    }
}

/// Simulated ReRAM storage bank for the Baochip-1x.
pub struct ReRamStorageBank {
    page: ReRamKeyRecord,
    is_tamper_tripped: bool,
}

impl ReRamStorageBank {
    pub const fn empty() -> Self {
        Self {
            page: ReRamKeyRecord {
                magic: [0u8; 8],
                private_key: [0u8; 32],
                agent_address: [0u8; 20],
                sequence_counter: 0,
                checksum: [0u8; 32],
            },
            is_tamper_tripped: false,
        }
    }

    /// Provision or overwrite key share in non-volatile ReRAM.
    pub fn write_key(
        &mut self,
        private_key: [u8; 32],
        agent_address: [u8; 20],
    ) -> Result<(), EnclaveError> {
        if self.is_tamper_tripped {
            return Err(EnclaveError::TamperLocked);
        }
        let next_seq = self.page.sequence_counter.wrapping_add(1);
        self.page = ReRamKeyRecord::new(private_key, agent_address, next_seq);
        Ok(())
    }

    /// Read key share with automatic cryptographic integrity checking.
    pub fn read_key(&self) -> Result<&[u8; 32], EnclaveError> {
        if self.is_tamper_tripped {
            return Err(EnclaveError::TamperLocked);
        }
        if self.page.magic != RE_RAM_MAGIC {
            return Err(EnclaveError::UnprovisionedKey);
        }
        if !self.page.verify_integrity() {
            return Err(EnclaveError::MemoryIntegrityFailure);
        }
        Ok(&self.page.private_key)
    }

    /// Signal hardware tamper event (e.g. physical enclosure breach, voltage spike).
    /// Instantly wipes sensitive key material from memory.
    pub fn trigger_tamper_wipe(&mut self) {
        self.page.zeroize();
        self.is_tamper_tripped = true;
    }

    /// Check if the vault has been locked due to a tamper trigger.
    pub fn is_tampered(&self) -> bool {
        self.is_tamper_tripped
    }
}
