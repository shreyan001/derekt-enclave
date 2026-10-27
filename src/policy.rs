//! Autonomous AI Agent Policy Engine.
//!
//! Enforces hardware-level constraints on autonomous agent transactions before
//! allowing cryptographic signing routines to execute. Prevents runaway agent loops,
//! prompt-injection exploits, and unauthorized destination transfers.

use crate::error::EnclaveError;

pub const MAX_WHITELIST_ENTRIES: usize = 16;

/// Policy configuration enforced by the embedded hardware enclave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentPolicyConfig {
    /// Maximum allowed token/wei transfer in a single transaction.
    pub max_single_spend: u64,
    /// Maximum allowable cumulative spend per epoch window.
    pub epoch_velocity_cap: u64,
    /// Minimum block/slot interval between successive signing requests.
    pub min_block_interval: u64,
    /// Array of approved recipient/contract addresses (20-byte EVM addresses).
    pub whitelisted_targets: [[u8; 20]; MAX_WHITELIST_ENTRIES],
    /// Number of active targets in the whitelist.
    pub whitelist_count: usize,
}

impl Default for AgentPolicyConfig {
    fn default() -> Self {
        Self {
            max_single_spend: 1_000_000,     // e.g. 1 USDC (6 decimals)
            epoch_velocity_cap: 10_000_000,  // e.g. 10 USDC per epoch
            min_block_interval: 5,           // 5 blocks cooldown
            whitelisted_targets: [[0u8; 20]; MAX_WHITELIST_ENTRIES],
            whitelist_count: 0,
        }
    }
}

/// Dynamic runtime state tracked inside protected enclave memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnclavePolicyState {
    pub cumulative_spent_in_epoch: u64,
    pub last_action_block: u64,
    pub total_transactions_signed: u64,
}

impl EnclavePolicyState {
    pub const fn new() -> Self {
        Self {
            cumulative_spent_in_epoch: 0,
            last_action_block: 0,
            total_transactions_signed: 0,
        }
    }

    /// Reset velocity window upon new epoch transition.
    pub fn roll_epoch(&mut self) {
        self.cumulative_spent_in_epoch = 0;
    }
}

/// Evaluator that verifies a transaction request against active policy.
pub struct PolicyEvaluator;

impl PolicyEvaluator {
    /// Verify a transaction request against configuration and current state.
    pub fn verify_transaction(
        config: &AgentPolicyConfig,
        state: &EnclavePolicyState,
        destination: &[u8; 20],
        value: u64,
        current_block: u64,
    ) -> Result<(), EnclaveError> {
        // 1. Single spend limit check
        if value > config.max_single_spend {
            return Err(EnclaveError::SpendLimitExceeded {
                attempted: value,
                limit: config.max_single_spend,
            });
        }

        // 2. Epoch velocity cap check
        let projected_cumulative = state
            .cumulative_spent_in_epoch
            .checked_add(value)
            .ok_or(EnclaveError::VelocityCapExceeded {
                attempted: u64::MAX,
                cap: config.epoch_velocity_cap,
            })?;

        if projected_cumulative > config.epoch_velocity_cap {
            return Err(EnclaveError::VelocityCapExceeded {
                attempted: projected_cumulative,
                cap: config.epoch_velocity_cap,
            });
        }

        // 3. Rate limiting / Cooldown enforcement
        if state.last_action_block != 0 {
            let elapsed_blocks = current_block.saturating_sub(state.last_action_block);
            if elapsed_blocks < config.min_block_interval {
                return Err(EnclaveError::CooldownActive {
                    remaining_slots: config.min_block_interval - elapsed_blocks,
                });
            }
        }

        // 4. Whitelist target enforcement
        if config.whitelist_count > 0 {
            let mut is_authorized = false;
            for i in 0..config.whitelist_count {
                if config.whitelisted_targets[i] == *destination {
                    is_authorized = true;
                    break;
                }
            }
            if !is_authorized {
                return Err(EnclaveError::UnauthorizedDestination(*destination));
            }
        }

        Ok(())
    }

    /// Commit approved state updates after a successful signature.
    pub fn apply_transaction(
        state: &mut EnclavePolicyState,
        value: u64,
        current_block: u64,
    ) {
        state.cumulative_spent_in_epoch = state.cumulative_spent_in_epoch.saturating_add(value);
        state.last_action_block = current_block;
        state.total_transactions_signed = state.total_transactions_signed.saturating_add(1);
    }
}
