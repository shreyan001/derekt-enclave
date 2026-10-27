# derekt-enclave 🛡️
### Verifiable Embedded Hardware Security Module & Policy Enforcer for AI Agent Wallets

[![Rust](https://img.shields.io/badge/rust-1.79%2B-orange.svg)](https://www.rust-lang.org)
[![Target](https://img.shields.io/badge/target-RISC--V%20%7C%20Baochip--1x-blue.svg)](https://baochip.com)
[![Hardware](https://img.shields.io/badge/board-Dabao%20Evaluation%20Board-brightgreen.svg)](https://crowdsupply.com)
[![Tests](https://img.shields.io/badge/tests-9%2F9%20passing-brightgreen.svg)]()
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

> **derekt-enclave** is an open-source embedded hardware security module (HSM) and autonomous policy engine designed to run on the **Baochip-1x / Crossbar Daric** open-silicon SoC (featured on the **Dabao** development board designed by Andrew "bunnie" Huang).
>
> It solves the fundamental security vulnerability of on-chain AI agents: **storing raw private keys in hot cloud memory or environment variables.**

---

## 🎯 The Problem: Autonomous Agent Key Vulnerability

Modern on-chain AI agents (such as those orchestrated via LangGraph, Coinbase AgentKit, or autonomous trade loops in **derekt**) must sign blockchain transactions to swap tokens, rebalance positions, and execute contract calls.

Today, developers are forced into bad trade-offs:
1. **Plaintext Hot Keys**: Storing private keys in cloud environment variables or server RAM, vulnerable to memory dumps, server compromises, and prompt-injection drain attacks.
2. **Opaque Proprietary Hardware**: Traditional hardware wallets (Ledger, Trezor) rely on closed-source secure elements with proprietary firmware and uninspectable silicon dies.

If an AI agent is tricked by a malicious payload or enters an infinite loop, it can drain an entire treasury within seconds.

---

## 💡 The Solution: Open-Silicon Hardware Enclave

**`derekt-enclave`** moves the agent's signing keys into physically verifiable open silicon (Baochip-1x on Dabao), enforcing strict cryptographic guardrails before keys are ever touched.

```
+-----------------------------------------------------------------------------------+
|                            Dabao Board (Baochip-1x)                               |
|                                                                                   |
|  [ Host Agent: derekt ]                                                           |
|          │                                                                        |
|          │ USB-CDC / Serial Packet Frame                                          |
|          ▼                                                                        |
|  ┌─────────────────────────────────────────────────────────────┐                  |
|  │  Quad-Core PicoRV32 Cluster (BIO @ 700 MHz)                │                  |
|  │  - Hardware I/O Firewall & Packet Sanitization              │                  |
|  │  - CRC-16 Checksum & Command Framing                        │                  |
|  └──────────────────────────────┬──────────────────────────────┘                  |
|                                 │ Verified Request                                |
|                                 ▼                                                 |
|  ┌─────────────────────────────────────────────────────────────┐                  |
|  │  Main Core (VexRiscv RV32IMAC @ 350 MHz)                    │                  |
|  │  - Policy Evaluator: Single Spend, Velocity Cap, Cooldown   │                  |
|  │  - Destination Address Whitelist Verification               │                  |
|  │  - Ed25519 / Schnorr Signature & Attestation Receipt        │                  |
|  └──────────────────────────────┬──────────────────────────────┘                  |
|                                 │ Authenticated Access                            |
|                                 ▼                                                 |
|  ┌─────────────────────────────────────────────────────────────┐                  |
|  │  4 MiB Non-Volatile ReRAM (Resistive RAM)                   │                  |
|  │  - Atomic filament-based key persistence (glitch-resistant) │                  |
|  │  - Instant Zeroization on Physical Tamper Trigger           │                  |
|  └─────────────────────────────────────────────────────────────┘                  |
+-----------------------------------------------------------------------------------+
```

---

## 🔑 Key Features

### 1. Hardware-Level Policy Guardrails
Before the signing engine accesses the private key, the transaction must pass through hardcoded hardware checks:
- **Max Single Spend Limit**: Blocks any single transaction exceeding configured value thresholds.
- **Epoch / Daily Velocity Cap**: Restricts the cumulative spend over a time window to prevent slow-drain exploits.
- **Cooldown Interval**: Enforces a minimum block delay between autonomous agent actions to prevent flash-loan recursion and runaway loops.
- **Destination Whitelist**: Restricts destination contract interactions to approved DEX routers, oracles, or vaults.

### 2. ReRAM-Protected Key Share Isolation
- Leverages the Baochip-1x on-chip **4 MiB Resistive RAM (ReRAM)**.
- Unlike traditional trapped-charge flash memory, ReRAM stores data via nanoscale atomic filament switching. It is immune to optical fault injection, UV erasure, and power-rail brownout glitching.
- Includes monotonic sequence counters to eliminate rollback and replay attacks.

### 3. BIO (PicoRV32) Hardware I/O Firewall
- Incoming USB-CDC / UART command packets are parsed by the 700 MHz quad PicoRV32 I/O cluster (`BIO`).
- Malformed packets, buffer-overflow attempts, or corrupt checksums are rejected at the peripheral boundary before ever reaching the main execution core.

### 4. Tamper-Evident Memory Zeroization
- Physical enclosure breaches or voltage anomaly alerts trigger an immediate cryptographic wipe (`zeroize`), permanently locking the vault and setting memory sectors to zero.

---

## 🧪 Verified Test Suite

The enclave includes comprehensive unit and integration tests covering the complete security lifecycle:

```bash
cargo test -- --nocapture
```

### Test Results:
```text
running 9 tests
test test_key_provisioning_and_reram_integrity ... ok
test test_cooldown_rate_limit_enforced ... ok
test test_valid_agent_transaction_signing ... ok
test test_spend_limit_exceeded_rejected ... ok
test test_tamper_wipe_zeroization ... ok
test test_corrupted_wire_packet_rejected ... ok
test test_wire_packet_roundtrip ... ok
test test_unauthorized_destination_rejected ... ok
test test_velocity_cap_exceeded_rejected ... ok

test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

---

## 📦 Project Structure

```
derekt-enclave/
├── Cargo.toml
├── LICENSE
├── README.md
├── src/
│   ├── lib.rs           # Core module wiring and public API
│   ├── error.rs         # Enclave error definitions
│   ├── policy.rs        # Hardware spend, velocity, and whitelist policy engine
│   ├── protocol.rs      # Framed wire protocol for USB/Serial communication
│   ├── reram_vault.rs   # ReRAM non-volatile storage and tamper zeroization
│   └── signer.rs        # Cryptographic signing and attestation receipt generator
└── tests/
    └── enclave_tests.rs # 9 integration and security stress tests
```

---

## 👤 Author

**Shreyan D**
- Founder: [derekt](https://github.com/shreyan001)
- GitHub: [@shreyan001](https://github.com/shreyan001)
- X / Twitter: [@gatesmanX12](https://x.com/gatesmanX12)

---

## 📜 License
Dual-licensed under [MIT](LICENSE) or [Apache-2.0](LICENSE).
