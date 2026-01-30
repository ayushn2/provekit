# ProveKit Protocol-Level Hash Benchmarking

## Overview

This work benchmarks **ProveKit’s protocol-level performance** across multiple cryptographic hash functions.  
The goal is to measure the impact of changing the hash function used inside the **ProveKit protocol**, not inside the Noir circuit.

The Noir circuit itself is **kept unchanged** throughout all experiments.

---

## Task Context

**Repository:** <https://github.com/worldfnd/provekit>
**Circuit used:** `noir-examples/noir-passport-examples/complete_age_check`

### Objective

Benchmark ProveKit across different hash functions where hashing is used at the **protocol level**, primarily affecting:

- Merkle tree construction
- Fiat–Shamir transcript
- Protocol-level commitments and challenges

The task explicitly excludes circuit-level benchmarking.

---

## Hash Functions Benchmarked

The following hash functions are supported and benchmarked:

- **SHA2**
- **SHA3**
- **BLAKE3**
- **SkyscraperV2** (default)

---

## Important Design Decision

### Protocol-Level Hashing Only

- The Noir circuit is **not modified**
- Constraint counts remain unchanged
- No circuit recompilation is required per hash

Only the **protocol layer** is affected. This aligns exactly with the task description:

> “Hash changes will mainly affect the Merkle tree and Fiat–Shamir transcript”

---

## Default Behavior

- **SkyscraperV2 is the default hash**
- If no hash feature is specified, ProveKit runs using SkyscraperV2

---

## Implementation Details

### Hash Abstraction Layer

A unified hash abstraction was introduced under:

```bash
provekit/common/src/hash/
```

Each hash implementation conforms to a shared interface and is integrated into:

- Merkle CRH
- Fiat–Shamir transcript
- Witness generation
- Prover R1CS
- Verifier R1CS

### Added Hash Modules

```bash
provekit/common/src/hash/
├── mod.rs
├── sha2.rs
├── sha3.rs
├── blake3.rs
├── skyscraper.rs
```

The active hash is selected at **compile time** using Cargo feature flags.

---

## Hash Selection via CLI

Hash selection is exposed via **Cargo features**, not runtime CLI flags.

### Example: Prepare using SHA2

```bash
cargo run --release -p provekit-cli --no-default-features --features provekit-common/sha2 --bin provekit-cli -- prepare noir-examples/noir-passport-examples/complete_age_check/target/complete_age_check.json --pkp prover.pkp --pkv verifier.pkv
```

### Example: Prove using BLAKE3

```bash
cargo run --release -p provekit-cli --no-default-features --features provekit-common/blake3 --bin provekit-cli -- prove prover.pkp noir-examples/noir-passport-examples/complete_age_check/Prover.toml -o proof.np
```

### Example: Verify using SHA3

```bash
cargo run --release -p provekit-cli --no-default-features --features provekit-common/sha3 --bin provekit-cli -- verify verifier.pkv proof.np
```

### Supported Feature Flags

```bash
provekit-common/sha2
provekit-common/sha3
provekit-common/blake3
provekit-common/skyscraper
```

---

## Benchmarking Methodology

### Identical Inputs Across Runs

- Same Noir circuit
- Same compiled Noir artifact
- Same witness (`Prover.toml`)
- Same proving and verification keys
- Only the **protocol-level hash function** changes

---

## Automated Benchmarking (`bench.py`)

A Python script is provided to run **repeatable and statistically meaningful benchmarks**.

### Location

```py
bench.py
```

### What the Script Does

For each hash function:

1. Runs `prepare`
2. Runs `prove`
3. Runs `verify`
4. Repeats the above **N times** (default: 20)
5. Aggregates results into a CSV file

---

## Metrics Collected

### Proving Time

- Extracted from ProveKit logs
- Mean and variance reported

### Verification Time

- Extracted from verifier logs
- Mean and variance reported

### Peak Memory (RSS)

- Measured using `psutil`
- Peak resident set size per process
- Reported separately for prover and verifier
- RSS reflects actual memory used by the process (not heap-only)

### Proof and Key Sizes

- Proof size (bytes)
- Proving key (PKP) size
- Verification key (PKV) size

---

## Output Format

Benchmarks are written to a CSV file with the following schema:

```bash
hash,
prover_time_mean_ms,
prover_time_var,
verifier_time_mean_ms,
verifier_time_var,
prover_peak_rss_mean_mb,
verifier_peak_rss_mean_mb,
proof_size_mean_bytes,
proof_size_var,
pkp_size_mean_bytes,
pkv_size_mean_bytes
```

---

## Notes on Interpretation

- Variance reflects OS scheduling and memory allocator behavior
- RSS includes all mapped memory, not just Rust heap
- Hash differences primarily affect transcript and Merkle hashing costs
- Circuit size and constraints remain constant

---

## Summary

This work adds:

- Protocol-level hash selection to ProveKit
- Support for SHA2, SHA3, BLAKE3, and SkyscraperV2
- A reproducible benchmarking framework
- Detailed performance metrics across proving and verification

The implementation strictly adheres to the task requirement of **protocol-level benchmarking only**, with no circuit modifications.
