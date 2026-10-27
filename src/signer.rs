//! Cryptographic Signing and Attestation Engine.
//!
//! Produces transaction signatures along with an attestation proof verifying
//! that hardware policy guardrails were evaluated before key release.

use crate::error::EnclaveError;
use crate::policy::{AgentPolicyConfig, EnclavePolicyState, PolicyEvaluator};
use crate::reram_vault::ReRamStorageBank;
use sha2::{Digest, Sha256};

/// Hardware execution attestation receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnclaveAttestation {
    /// 32-byte transaction or message digest signed.
    pub message_hash: [u8; 32],
    /// 64-byte signature produced by the enclave key.
    pub signature: [u8; 64],
    /// Block/Slot height at which the policy was evaluated.
    pub block_height: u64,
    /// Cumulative sequence counter of the signing key.
    pub execution_counter: u64,
    /// 32-byte cryptographic binding proving policy compliance.
    pub compliance_digest: [u8; 32],
}

/// The core Enclave Signer coordinating policy, ReRAM, and signature output.
pub struct EnclaveSigner {
    pub storage: ReRamStorageBank,
    pub policy: AgentPolicyConfig,
    pub state: EnclavePolicyState,
}

impl EnclaveSigner {
    pub fn new(policy: AgentPolicyConfig) -> Self {
        Self {
            storage: ReRamStorageBank::empty(),
            policy,
            state: EnclavePolicyState::new(),
        }
    }

    /// Provision key into the enclave's non-volatile storage.
    pub fn provision_key(&mut self, key: [u8; 32], address: [u8; 20]) -> Result<(), EnclaveError> {
        self.storage.write_key(key, address)
    }

    /// Sign a transaction for an autonomous AI agent, strictly enforcing guardrails.
    pub fn sign_agent_transaction(
        &mut self,
        tx_hash: [u8; 32],
        destination: [u8; 20],
        value: u64,
        current_block: u64,
    ) -> Result<EnclaveAttestation, EnclaveError> {
        // 1. Enforce policy constraints before touching keys
        PolicyEvaluator::verify_transaction(
            &self.policy,
            &self.state,
            &destination,
            value,
            current_block,
        )?;

        // 2. Fetch key from non-volatile ReRAM
        let key_bytes = self.storage.read_key()?;

        // 3. Generate deterministic signature over tx_hash with key
        // (Emulating Ed25519/Schnorr signature scheme: R || S)
        let mut hasher = Sha256::new();
        hasher.update(key_bytes);
        hasher.update(&tx_hash);
        hasher.update(&current_block.to_le_bytes());
        let digest_1 = hasher.finalize();

        let mut hasher_s = Sha256::new();
        hasher_s.update(&digest_1);
        hasher_s.update(key_bytes);
        let digest_2 = hasher_s.finalize();

        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&digest_1);
        signature[32..].copy_from_slice(&digest_2);

        // 4. Compute hardware compliance digest
        let mut comp_hasher = Sha256::new();
        comp_hasher.update(&tx_hash);
        comp_hasher.update(&destination);
        comp_hasher.update(&value.to_le_bytes());
        comp_hasher.update(&current_block.to_le_bytes());
        let comp_result = comp_hasher.finalize();
        let mut compliance_digest = [0u8; 32];
        compliance_digest.copy_from_slice(&comp_result);

        // 5. Commit state updates
        PolicyEvaluator::apply_transaction(&mut self.state, value, current_block);

        Ok(EnclaveAttestation {
            message_hash: tx_hash,
            signature,
            block_height: current_block,
            execution_counter: self.state.total_transactions_signed,
            compliance_digest,
        })
    }
}
