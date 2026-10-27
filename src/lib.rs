//! # derekt-enclave
//!
//! **Verifiable Embedded Hardware Security Module & Policy Enforcer for AI Agent Wallets**
//!
//! Target Hardware: **Baochip-1x / Crossbar Daric (TSMC 22nm)**
//! Development Platform: **Dabao Evaluation Board by Andrew "bunnie" Huang**
//!
//! ### Overview
//! Autonomous on-chain AI agents (like those built in `derekt`) require access to signing
//! keys to execute swaps, rebalances, and contract calls. Today, these keys are stored in
//! plaintext environment variables or hot cloud memory, creating severe attack vectors:
//! prompt-injection drain attacks, runaway loops, and memory dumps.
//!
//! `derekt-enclave` solves this by moving key custody into **physically verifiable open silicon**:
//! 1. **ReRAM Storage**: Private keys are isolated in 4MB non-volatile Resistive RAM.
//! 2. **Hardware Policy Enforcement**: Every signing request must satisfy hardcoded spend limits,
//!    epoch velocity caps, cooldown intervals, and destination whitelists before keys are touched.
//! 3. **BIO Coprocessor Firewall**: USB/Serial I/O is parsed on the 700 MHz quad PicoRV32 cluster
//!    before reaching the core signing engine.
//! 4. **Tamper Zeroization**: Physical tampering or fault injection instantly wipes the ReRAM keys.

pub mod error;
pub mod policy;
pub mod protocol;
pub mod reram_vault;
pub mod signer;

pub use error::EnclaveError;
pub use policy::{AgentPolicyConfig, EnclavePolicyState, PolicyEvaluator};
pub use protocol::{WirePacket, CMD_PROVISION_KEY, CMD_QUERY_STATE, CMD_SIGN_TX, CMD_TAMPER_KILL};
pub use reram_vault::{ReRamKeyRecord, ReRamStorageBank};
pub use signer::{EnclaveAttestation, EnclaveSigner};
