//! Test suite for derekt-enclave hardware security module.

use derekt_enclave::error::EnclaveError;
use derekt_enclave::policy::AgentPolicyConfig;
use derekt_enclave::protocol::WirePacket;
use derekt_enclave::signer::EnclaveSigner;

const MOCK_KEY: [u8; 32] = [0x42; 32];
const AGENT_ADDRESS: [u8; 20] = [0xAA; 20];
const APPROVED_TARGET: [u8; 20] = [0xBB; 20];
const UNAPPROVED_TARGET: [u8; 20] = [0xCC; 20];

fn setup_test_enclave() -> EnclaveSigner {
    let mut policy = AgentPolicyConfig::default();
    policy.max_single_spend = 500_000;        // Max 0.5 units
    policy.epoch_velocity_cap = 1_500_000;    // Max 1.5 units per epoch
    policy.min_block_interval = 3;            // 3 blocks cooldown
    policy.whitelisted_targets[0] = APPROVED_TARGET;
    policy.whitelist_count = 1;

    let mut signer = EnclaveSigner::new(policy);
    signer.provision_key(MOCK_KEY, AGENT_ADDRESS).expect("Key provisioning failed");
    signer
}

#[test]
fn test_key_provisioning_and_reram_integrity() {
    let signer = setup_test_enclave();
    let stored_key = signer.storage.read_key().expect("Failed to read key from ReRAM");
    assert_eq!(stored_key, &MOCK_KEY);
}

#[test]
fn test_valid_agent_transaction_signing() {
    let mut signer = setup_test_enclave();
    let tx_hash = [0x11; 32];
    let value = 200_000;
    let block = 100;

    let attestation = signer
        .sign_agent_transaction(tx_hash, APPROVED_TARGET, value, block)
        .expect("Valid transaction was rejected");

    assert_eq!(attestation.message_hash, tx_hash);
    assert_eq!(attestation.block_height, block);
    assert_eq!(attestation.execution_counter, 1);
    assert_eq!(signer.state.cumulative_spent_in_epoch, 200_000);
}

#[test]
fn test_spend_limit_exceeded_rejected() {
    let mut signer = setup_test_enclave();
    let tx_hash = [0x12; 32];
    let excessive_value = 600_000; // Limit is 500_000

    let res = signer.sign_agent_transaction(tx_hash, APPROVED_TARGET, excessive_value, 100);
    assert_eq!(
        res.unwrap_err(),
        EnclaveError::SpendLimitExceeded {
            attempted: 600_000,
            limit: 500_000,
        }
    );

    // Verify zero side-effects
    assert_eq!(signer.state.cumulative_spent_in_epoch, 0);
    assert_eq!(signer.state.total_transactions_signed, 0);
}

#[test]
fn test_velocity_cap_exceeded_rejected() {
    let mut signer = setup_test_enclave();

    // 1st tx: 500_000 (spent: 500_000)
    signer
        .sign_agent_transaction([0x01; 32], APPROVED_TARGET, 500_000, 100)
        .unwrap();

    // 2nd tx: 500_000 (spent: 1_000_000) at block 105 (past cooldown)
    signer
        .sign_agent_transaction([0x02; 32], APPROVED_TARGET, 500_000, 105)
        .unwrap();

    // 3rd tx: 500_000 (spent: 1_500_000) at block 110 (past cooldown)
    signer
        .sign_agent_transaction([0x03; 32], APPROVED_TARGET, 500_000, 110)
        .unwrap();

    // 4th tx: 100_000 -> exceeds 1_500_000 cap!
    let res = signer.sign_agent_transaction([0x04; 32], APPROVED_TARGET, 100_000, 115);
    assert_eq!(
        res.unwrap_err(),
        EnclaveError::VelocityCapExceeded {
            attempted: 1_600_000,
            cap: 1_500_000,
        }
    );
}

#[test]
fn test_cooldown_rate_limit_enforced() {
    let mut signer = setup_test_enclave();

    // 1st tx at block 100
    signer
        .sign_agent_transaction([0x01; 32], APPROVED_TARGET, 100_000, 100)
        .unwrap();

    // Attempt rapid 2nd tx at block 101 (interval is 3, need at least block 103)
    let res = signer.sign_agent_transaction([0x02; 32], APPROVED_TARGET, 100_000, 101);
    assert_eq!(
        res.unwrap_err(),
        EnclaveError::CooldownActive { remaining_slots: 2 }
    );
}

#[test]
fn test_unauthorized_destination_rejected() {
    let mut signer = setup_test_enclave();
    let res = signer.sign_agent_transaction([0x05; 32], UNAPPROVED_TARGET, 100_000, 100);
    assert_eq!(
        res.unwrap_err(),
        EnclaveError::UnauthorizedDestination(UNAPPROVED_TARGET)
    );
}

#[test]
fn test_tamper_wipe_zeroization() {
    let mut signer = setup_test_enclave();
    assert!(!signer.storage.is_tampered());

    // Trigger physical tamper event
    signer.storage.trigger_tamper_wipe();
    assert!(signer.storage.is_tampered());

    // Subsequent reads and signing attempts must fail
    assert_eq!(signer.storage.read_key().unwrap_err(), EnclaveError::TamperLocked);

    let res = signer.sign_agent_transaction([0x06; 32], APPROVED_TARGET, 50_000, 100);
    assert_eq!(res.unwrap_err(), EnclaveError::TamperLocked);
}

#[test]
fn test_wire_packet_roundtrip() {
    let packet = WirePacket {
        command: 0x02,
        payload: vec![1, 2, 3, 4, 5],
    };

    let encoded = packet.encode();
    let decoded = WirePacket::decode(&encoded).expect("Decoding failed");

    assert_eq!(decoded.command, 0x02);
    assert_eq!(decoded.payload, vec![1, 2, 3, 4, 5]);
}

#[test]
fn test_corrupted_wire_packet_rejected() {
    let packet = WirePacket {
        command: 0x02,
        payload: vec![1, 2, 3, 4, 5],
    };

    let mut encoded = packet.encode();
    // Tamper with payload byte
    encoded[6] ^= 0xFF;

    let res = WirePacket::decode(&encoded);
    assert_eq!(res.unwrap_err(), EnclaveError::MalformedPacket);
}
