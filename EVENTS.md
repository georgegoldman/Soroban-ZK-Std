# Structured ZK Proof Verification Events

## Overview

This document describes the structured event system for ZK proof verification failures introduced in Soroban-ZK-Std. The new event system provides detailed, actionable information when proofs fail verification, significantly improving the developer experience for debugging and monitoring ZK applications.

## Motivation

Previously, ZK proof verification failures provided minimal information:
- Simple success/failure boolean
- Generic error types without context
- No indication of which specific constraint failed
- Difficult to debug verification issues in production

The new structured event system addresses these issues by emitting detailed events at every stage of the verification process.

## Event Structure

### ZkVerificationEvent

The main event type that contains comprehensive verification information:

```rust
pub struct ZkVerificationEvent {
    /// Whether the verification succeeded
    pub success: bool,
    
    /// The type of ZK proof system used (e.g., "groth16")
    pub proof_system: String,
    
    /// Number of public inputs provided
    pub public_inputs_count: u32,
    
    /// Length of the proof in bytes
    pub proof_length: u32,
    
    /// Whether anti-replay protection was enabled
    pub anti_replay: bool,
    
    /// Detailed failure information (None if successful)
    pub failure_details: Option<ZkVerificationFailure>,
    
    /// Additional context about the verification process
    pub context: Option<String>,
}
```

### ZkVerificationFailure

Detailed information about why verification failed:

```rust
pub struct ZkVerificationFailure {
    /// The specific error that caused the failure
    pub error_type: String,
    
    /// Human-readable description of the failure
    pub description: String,
    
    /// The stage of verification where the failure occurred
    pub failure_stage: ZkVerificationStage,
    
    /// Additional context specific to the failure type
    pub additional_info: Option<ZkFailureContext>,
}
```

### ZkVerificationStage

Enum identifying where in the verification pipeline the failure occurred:

```rust
pub enum ZkVerificationStage {
    /// Failure during anti-replay check (before verification)
    AntiReplayCheck,
    
    /// Failure during verifying key loading
    VerifyingKeyLoad,
    
    /// Failure during proof deserialization
    ProofDeserialization,
    
    /// Failure during public inputs validation
    PublicInputsValidation,
    
    /// Failure during curve point validation
    CurveValidation,
    
    /// Failure during the pairing check computation
    PairingCheck,
    
    /// Failure during nullifier recording (after successful verification)
    NullifierRecording,
    
    /// Unknown/unexpected failure
    Unknown,
}
```

### ZkFailureContext

Additional context information for specific failure types:

```rust
pub struct ZkFailureContext {
    /// For field element errors: the invalid input index
    pub invalid_input_index: Option<u32>,
    
    /// For deserialization errors: the problematic byte offset
    pub byte_offset: Option<u32>,
    
    /// For curve validation errors: which point failed (A, B, C for Groth16)
    pub invalid_point: Option<String>,
    
    /// For pairing errors: which pair in the multi-pairing failed
    pub invalid_pair_index: Option<u32>,
    
    /// Generic string context for other error types
    pub context_info: Option<String>,
}
```

## Event Topics

Events are published with the following topics for easy filtering:

```rust
("zk_verification", proof_system, success_bool)
```

For example:
- `("zk_verification", "groth16", true)` - successful Groth16 verification
- `("zk_verification", "groth16", false)` - failed Groth16 verification

## Verification Stages with Event Emission

The verification process emits events at the following stages:

### 1. Anti-Replay Check
**When**: Before expensive verification operations  
**Purpose**: Detect previously verified proofs  
**Event**: Emitted if proof has already been verified

```rust
ZkVerificationStage::AntiReplayCheck
Context: "Proof already verified"
```

### 2. Verifying Key Load
**When**: Loading VK from persistent storage  
**Purpose**: Ensure VK exists and is accessible  
**Event**: Emitted if VK is missing or corrupt

```rust
ZkVerificationStage::VerifyingKeyLoad
Context: "VK not found in storage"
```

### 3. Proof Deserialization
**When**: Decoding proof bytes into curve points  
**Purpose**: Validate proof structure and encoding  
**Event**: Emitted if proof bytes are malformed

```rust
ZkVerificationStage::ProofDeserialization
Context: Invalid proof encoding or curve points
Additional: byte_offset, invalid_point
```

### 4. Public Inputs Validation
**When**: Checking field element bounds  
**Purpose**: Ensure inputs are valid BN254 scalars  
**Event**: Emitted if any input exceeds the field modulus

```rust
ZkVerificationStage::PublicInputsValidation
Context: Input exceeds BN254 scalar field modulus
Additional: invalid_input_index (which input failed)
```

### 5. Curve Validation
**When**: Validating curve points are in correct subgroup  
**Purpose**: Prevent invalid-curve and small-subgroup attacks  
**Event**: Emitted if points are off-curve or invalid

```rust
ZkVerificationStage::CurveValidation
Context: Point not on curve or not in prime-order subgroup
```

### 6. Pairing Check
**When**: Computing the multi-pairing equation  
**Purpose**: Cryptographic verification of the proof  
**Event**: Emitted if pairing check fails or returns false

```rust
ZkVerificationStage::PairingCheck
Context: "e(A,B) * e(-alpha,beta) * e(-acc,gamma) * e(-C,delta) != 1"
```

### 7. Nullifier Recording
**When**: Recording proof to prevent replay (post-verification)  
**Purpose**: Enforce anti-replay protection  
**Event**: Emitted if storage write fails

```rust
ZkVerificationStage::NullifierRecording
Context: "Storage write failed"
```

## Usage Examples

### Using the ZkContract.verify_proof Method

The built-in `ZkContract::verify_proof` method automatically emits structured events:

```rust
use soroban_zk_std::ZkContract;

// Verification with automatic event emission
let result = ZkContract::verify_proof(
    env.clone(),
    proof_bytes,
    public_inputs,
    true,  // enable anti-replay
);

match result {
    Ok(true) => {
        // Proof valid - success event was emitted
        // Event contains: success=true, all metadata
    }
    Ok(false) => {
        // Proof invalid - failure event with pairing details emitted
        // Event contains: failure_stage=PairingCheck
    }
    Err(e) => {
        // Error during verification - detailed failure event emitted
        // Event contains: error_type, failure_stage, additional_info
    }
}
```

### Generated Verifiers (`#[zk_verifier]`)

Contracts generated with `#[zk_verifier(protocol = "groth16", vk = MY_VK, anti_replay = ...)]`
(see `crates/soroban-zk-macros`) publish exactly the same `ZkVerificationEvent`
on the same topics, via `soroban_zk_std::verifier::verify_groth16`. Because the
verifying key is a compile-time constant there is no *Verifying Key Load*
stage; every other stage (anti-replay, proof deserialization, public inputs
validation, pairing check, nullifier recording) emits one event at the first
failure, or a single success event.

### Custom Contract with Manual Event Emission

For custom verification logic, use the event helpers:

```rust
use soroban_zk_std::events::{
    ZkVerificationEvent, ZkVerificationStage, ZkFailureContext,
    publish_verification_event
};
use soroban_zk_std::groth16::groth16_verify;

pub fn custom_verify(env: &Env, proof: &Groth16Proof, vk: &Groth16VerifyingKey, inputs: &[u256]) -> bool {
    match groth16_verify(env, vk, proof, inputs) {
        Ok(true) => {
            // Emit success event
            let event = ZkVerificationEvent::success(
                env,
                "groth16",
                inputs.len() as u32,
                256,
                false,
            );
            publish_verification_event(env, event);
            true
        }
        Ok(false) => {
            // Emit pairing failure event
            let event = ZkVerificationEvent::pairing_failure(
                env,
                "groth16",
                inputs.len() as u32,
                256,
                false,
            );
            publish_verification_event(env, event);
            false
        }
        Err(e) => {
            // Emit error event with context
            let stage = match e {
                ZkError::InvalidFieldElement => ZkVerificationStage::PublicInputsValidation,
                ZkError::DeserializationError => ZkVerificationStage::ProofDeserialization,
                _ => ZkVerificationStage::Unknown,
            };
            
            let event = ZkVerificationEvent::failure(
                env,
                "groth16",
                inputs.len() as u32,
                256,
                false,
                &ZkContractError::from(e),
                stage,
                None,
            );
            publish_verification_event(env, event);
            false
        }
    }
}
```

## Monitoring and Debugging

### Filtering Events

Filter verification events by outcome:

```javascript
// Subscribe to all ZK verification events
const events = await contract.getEvents({
  topics: [["zk_verification"]]
});

// Filter for failures only
const failures = events.filter(e => 
  e.topics[2] === false  // success = false
);

// Filter by proof system
const groth16Events = events.filter(e => 
  e.topics[1] === "groth16"
);
```

### Debugging Common Issues

#### Invalid Field Element
```rust
// Event indicates which input failed
failure_stage: PublicInputsValidation
additional_info.invalid_input_index: 2  // Third input is invalid
description: "One or more public inputs exceed the BN254 scalar field modulus"

// Fix: Check that inputs are < 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
```

#### Proof Deserialization Error
```rust
// Event provides specific context
failure_stage: ProofDeserialization
additional_info.invalid_point: "proof.B"
description: "Proof or point data could not be deserialized"

// Fix: Verify proof bytes are exactly 256 bytes and G2 point B is on-curve
```

#### Pairing Check Failed
```rust
// Event explains the mathematical failure
failure_stage: PairingCheck
additional_info.context_info: "e(A,B) * e(-alpha,beta) * e(-acc,gamma) * e(-C,delta) != 1"
description: "The multi-pairing equation did not equal identity"

// This means the proof is mathematically invalid for the given public inputs
```

## Performance Considerations

Event emission is designed to be lightweight:

1. **Gas Efficient**: Events are only emitted once per verification attempt
2. **Lazy Evaluation**: Additional context is only computed when errors occur
3. **No Storage Impact**: Events are transient and don't consume contract storage
4. **Backward Compatible**: Existing contracts continue to work without changes

## Backward Compatibility

The new event system is fully backward compatible:

- Existing contracts using `groth16_verify` directly continue to work
- No breaking changes to existing APIs
- Legacy simple events can still be emitted alongside structured events
- Opt-in: contracts can choose to emit structured events or not

## Migration Guide

### From Legacy Events

**Before:**
```rust
#[allow(deprecated)]
env.events().publish((sender, receiver), "ZK Proof Verified");
```

**After:**
```rust
use soroban_zk_std::events::{ZkVerificationEvent, publish_verification_event};

let event = ZkVerificationEvent::success(
    &env,
    "groth16",
    public_inputs.len() as u32,
    proof_bytes.len(),
    anti_replay,
);
publish_verification_event(&env, event);
```

### Benefits of Migration

1. **Better Debugging**: Pinpoint exact failure reasons
2. **Production Monitoring**: Track verification success rates by stage
3. **Security Auditing**: Detect attack patterns (invalid curves, field overflows)
4. **UX Improvements**: Provide users with actionable error messages

## Future Extensions

Potential future enhancements to the event system:

- **Timing Information**: Track time spent in each verification stage
- **Gas Reporting**: Report gas consumed per stage
- **Batch Verification Events**: Aggregate events for batch proof verification
- **Custom Event Handlers**: Allow contracts to register event callbacks
- **Event Indexing**: Off-chain indexer integration for historical analysis

## References

- [CAP-0075: BN254 Host Functions](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0075.md)
- [Soroban Events Documentation](https://soroban.stellar.org/docs/fundamentals-and-concepts/events)
- [Groth16 Verification Algorithm](https://eprint.iacr.org/2016/260.pdf)

## Contributing

To add new event types or enhance existing ones:

1. Define new event structures in `crates/soroban-zk-std/src/events.rs`
2. Emit events at appropriate verification stages
3. Update this documentation
4. Add tests in `crates/soroban-zk-std/src/events.rs`
5. Update example contracts to demonstrate usage
