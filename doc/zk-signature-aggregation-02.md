# ML-DSA-44 block authorization with a STARK

**Status:** architecture proposal; the ML-DSA-44 AIR and block integration do not exist yet.

Nado currently carries one 2,420-byte ML-DSA-44 signature per ordinary transaction. The public key is
1,312 bytes, but PUBKEY-ONCE already removes it after the first confirmed use. This proposal keeps signed
transactions unchanged in wallets and the mempool, then replaces the signatures in a confirmed block with
one post-quantum STARK proof:

> For every authorization entry committed by this block, a valid ML-DSA-44 signature exists over the
> transaction ID under the public key resolved for that sender.

This is a **signature-validity proof**, not initially a full state-transition proof. Nodes still execute all
existing spending, target-height, reserved-recipient, uniqueness, fee, state-root, and transaction-ID
checks. Keeping phase 1 this narrow makes pre-proving possible and avoids putting canonical JSON, BLAKE2b
transaction hashing, and the whole L1 state machine into the first circuit.

## 1. Recommendation in one page

- Build a dedicated, FIPS-204-exact ML-DSA-44 verification AIR. Do not begin with a general RISC-V zkVM.
- Use Nado's existing Goldilocks/alghash2 STARK and recursion stack for the first implementation. Evaluate
  a Plonky3/Circle-STARK backend only as a separate proof-stack migration.
- Use Poseidon2/alghash2 for trace commitments, Merkle trees, Fiat-Shamir, and recursive aggregation.
  **It cannot replace ML-DSA's SHAKE-256 inside the signature verifier.** The SHAKE computation is fixed by
  FIPS 204 and must be proven exactly.
- Keep full signatures in wallet-to-mempool and mempool-to-mempool gossip. Strip them only from a confirmed
  block.
- Make authorization evidence detached from the hashed block core. The core commits `auth_root` and
  `auth_count`; a transport envelope carries either a raw signature bundle or one STARK proof. The block
  hash is identical for both envelopes.
- Roll out raw/STARK evidence as an optional dual path first. Do not send both in the normal proof path.
  Later make the rule deterministic: new blocks with at least `K_required` supported authorization checks
  must use a proof; smaller or unsupported blocks use raw evidence.
- Target a final proof of **100-200 KiB**, verification below **100 ms**, final recursive folding below
  **1.5 seconds p95**, and sustained proving throughput at least **2x the peak signature arrival rate**.
- With a 200 KiB proof, the byte crossover is 85 signatures, or 106 with a 20% safety margin. A sensible
  optional pilot is therefore **128 signatures/block**. At Nado's six-second cadence this is about
  **21 transactions/s** for ordinary single-signature transactions.
- Do not make proofs mandatory until at least three independent operators can meet the proving deadline,
  the circuit has been audited, reorg witness retention is deployed, and proof production succeeds for
  more than 99.9% of eligible testnet blocks.

## 2. What is actually saved

FIPS 204 fixes these ML-DSA-44 sizes:

| item | binary size |
|---|---:|
| public key | 1,312 B |
| signature | 2,420 B |

Nado's API uses hex strings, so a signature looks like 4,840 characters in JSON. That is not the correct
consensus break-even input: block transport/storage compression recovers much of the hex expansion. Use
the 2,420-byte binary payload for conservative planning.

For `K` authorization checks and a final proof of `P` bytes:

```text
signature bytes removed = 2,420 * K
net block saving         = 2,420 * K - P - proof_metadata
byte crossover           = ceil((P + proof_metadata) / 2,420)
```

`K` is a signature count, not necessarily a transaction count. For ordinary transactions, `K = N`.
A 2-of-3 multisig transaction contributes two checks. Public keys are not counted as savings in phase 1:
first-use keys remain in the block because state application needs to establish them.

### 2.1 Size crossover

The table ignores a small fixed metadata envelope. The "20% margin" row requires the proof path to use no
more than 80% of the bytes it replaces.

| final proof | strict crossover | crossover with 20% margin | six-second rate at strict crossover |
|---:|---:|---:|---:|
| 64 KiB | 28 signatures | 34 signatures | 4.7 sig/s |
| 100 KiB | 43 signatures | 53 signatures | 7.2 sig/s |
| 200 KiB | 85 signatures | 106 signatures | 14.2 sig/s |
| 256 KiB | 109 signatures | 136 signatures | 18.2 sig/s |
| 1 MiB | 434 signatures | 542 signatures | 72.3 sig/s |

Nado's current STARK measurements are roughly 1 MiB per proof, so the code as it stands crosses over only
around **434 ordinary transactions/block**. That is not a useful starting point. A dedicated AIR plus a
more compact recursive proof must first bring the final object below about 200 KiB.

If the user's observed transaction size is 5 KiB, an ordinary signature is about 47% of its binary-sized
payload. At 128 transactions:

```text
raw signatures                   128 * 2,420 B = 309,760 B
net saving with a 100 KiB proof                    207,360 B
net saving with a 200 KiB proof                    104,960 B
```

The entire block becomes about 32% smaller with a 100 KiB proof, or about 16% smaller with a 200 KiB proof,
under that 5 KiB/transaction assumption.

### 2.2 CPU crossover is different

The repository records approximately 0.154 ms for one native ML-DSA verify and 12.98 ms for the pure-Python
fallback. Nado's current Python STARK verifier is approximately 100-200 ms; optimized STARK verifiers in
other systems are commonly in the 10-100 ms range.

Consequently:

| verifier assumption | replaces native verification CPU at about | replaces pure-Python CPU at about |
|---|---:|---:|
| 10 ms proof verify | 65 signatures | 1 signature |
| 50 ms proof verify | 325 signatures | 4 signatures |
| 100 ms proof verify | 650 signatures | 8 signatures |
| 200 ms proof verify | 1,299 signatures | 16 signatures |

The initial reason to deploy at 128 signatures/block is therefore **bandwidth, storage, and removing the
global signature-verification lock**, not necessarily lower CPU on a node with the native backend. Phones
and degraded pure-Python nodes benefit much earlier.

## 3. Consensus and wire architecture

### 3.1 Keep transaction submission unchanged

1. A wallet creates the transaction body.
2. It computes the existing BLAKE2b transaction ID.
3. It signs that ID with ML-DSA-44.
4. It sends the full transaction, including the signature and any first-use public key.
5. Every mempool node performs the existing native signature check before relaying it.

The STARK does not make unsigned mempool admission safe. A producer needs the signatures as proof witnesses,
and early validation is still required for spam control.

### 3.2 Define a signature-free block core

Add a versioned block format. Its transaction list contains the existing transaction bodies and transaction
IDs, but no top-level authorization signatures. First-use public keys remain.

The core adds:

```text
auth_version       proof statement/circuit version
auth_root          field-native commitment to the ordered authorization entries
auth_count         exact number K of real signature checks
auth_kind_bitmap   supported authorization kinds, or a compact commitment to them
```

The block hash commits these fields and the signature-free ordered transactions. It does **not** commit the
authorization evidence envelope described below.

This is a deliberate Nado-specific requirement. Nado permits deterministic relay-built blocks for an
offline selected winner. If `auth_mode = raw|stark` were inside the block hash, two honest relays with the
same mempool could construct different block hashes merely because one finished a proof and the other did
not. Detaching the evidence preserves one canonical block identity.

### 3.3 Commit exactly the signatures the block needs

For every transaction, validators resolve the public key using the same PUBKEY-ONCE rule as today and
perform `proof_sender` natively. This is cheap and avoids proving Nado's BLAKE2b address checksum in the
ML-DSA AIR.

Construct an ordered authorization leaf:

```text
auth_leaf_i = H_field(
    AUTH_DOMAIN,
    block_height,
    transaction_index,
    txid_as_field_limbs,
    sender_as_field_limbs,
    H_field(resolved_public_key_bytes),
    authorization_kind,
    signature_count_for_this_transaction
)
```

`H_field` is alghash2 initially, or Poseidon2 if the proof stack migrates to it. `auth_root` is a
field-native Merkle root or length-prefixed sponge over the ordered leaves.

The native block verifier independently:

- recomputes each transaction ID from the signature-free body;
- resolves the public key from the transaction or parent state;
- checks public-key-to-sender binding;
- recomputes every authorization leaf and `auth_root`;
- checks `auth_count` and authorization-kind metadata.

The proof then only needs to establish that every committed `(txid, public key, signature)` tuple passes
the exact ML-DSA-44 verifier.

### 3.4 Detach the evidence envelope

Transport and storage use:

```text
block_core: {
    ...,
    block_transactions: [signature-free transactions],
    auth_version,
    auth_root,
    auth_count
}

auth_evidence: one of
    { type: "raw",   witnesses: [ordered signature entries] }
    { type: "stark", circuit_id, proof }
```

Normal operation sends exactly one evidence type:

- raw path: signature-free core plus an ordered raw witness bundle;
- proof path: signature-free core plus the STARK proof, no raw signatures.

If a peer happens to receive both, it may retain both, but either piece of valid evidence authenticates the
same block core. Invalid evidence is rejected and cached by its own hash; it must not poison the canonical
block hash if alternate valid evidence exists.

Nodes persist at least one valid evidence object with the block. `/get_transaction` should report
`authorization: "stark-proven"` and a proof reference instead of inventing an empty signature.

### 3.5 Proof public statement

The final proof binds:

```text
chain/genesis identifier
block height
parent hash
auth_version and circuit_id
auth_root
auth_count
first and last covered transaction indices
```

Binding height, parent, count, and contiguous index ranges prevents replaying a valid proof onto a different
block, dropping a transaction, duplicating a leaf, or proving only a favorable subset.

The proof must not trust dimensions, query count, blowup, AIR constraints, or hash parameters supplied by
the prover. Those are consensus constants reconstructed by the verifier, following the fail-closed pattern
already used by `execnode/stark`.

## 4. ML-DSA-44 AIR design

### 4.1 Required checks

The AIR must reproduce Nado's FIPS-204 **internal-mode** verification byte-for-byte:

1. Decode the 1,312-byte public key and 2,420-byte signature.
2. Enforce all canonical encodings, hint ordering, coefficient ranges, and norm bounds.
3. Derive the public matrix from `rho` with SHAKE/rejection sampling.
4. Compute the message representative from the public-key hash and 32-byte transaction ID.
5. Perform the ML-DSA-44 NTT and inverse-NTT arithmetic modulo `q = 8,380,417`.
6. Reconstruct the high bits with the signature hint.
7. Recompute the challenge with SHAKE-256.
8. Enforce equality to the challenge encoded in the signature.
9. Feed the committed `(txid, public key, authorization metadata)` into `auth_root`.

Test the AIR against NIST vectors and Nado's pure-Python, native Rust, and browser implementations,
including every known malformed-encoding rejection case.

### 4.2 AIR layout

Use separate trace components joined by lookup/permutation arguments:

- byte/range table and canonical decoder;
- Keccak-f[1600]/SHAKE component with absorb/squeeze scheduling;
- rejection-sampling component for matrix expansion;
- modular arithmetic and reduction component for `q`;
- NTT butterfly component with fixed twiddle-factor periodic columns;
- hint/high-bit reconstruction component;
- per-signature result and ordered authorization-root accumulator.

ML-DSA's modulus fits comfortably inside Goldilocks and 31-bit fields. The main engineering challenge is
not the NTT; it is the bit-oriented SHAKE/rejection-sampling path. A dedicated Keccak AIR with byte/bit
lookups is preferable to interpreting general RISC-V instructions.

### 4.3 What Poseidon2 helps—and what it does not

Poseidon2 is useful for:

- trace and quotient Merkle commitments;
- Fiat-Shamir;
- authorization leaves/root;
- recursive proof aggregation;
- public-input commitments.

It does not remove SHAKE-256 from standard ML-DSA verification. Replacing ML-DSA's hash with Poseidon2
would define a new, non-FIPS signature scheme and require a coordinated wallet/address migration. Do not
mix that protocol change into signature aggregation.

Nado currently uses Goldilocks and alghash2, an x^7 field-native sponge. A 31-bit
BabyBear/KoalaBear/Mersenne31 backend may improve SIMD and GPU throughput, but cross-field recursion and a
second verifier increase risk. Benchmark a complete ML-DSA AIR before choosing a new field merely because
primitive Poseidon2 benchmarks are fast.

### 4.4 STARK versus zk-STARK

Signature aggregation needs computational soundness but not privacy: ML-DSA signatures are already public
witnesses in today's protocol. A transparent STARK is therefore sufficient to remove their bytes and
verification cost.

If the protocol calls the result a **zk-STARK**, the prover must also blind trace and quotient commitments
so sampled openings leak no witness information. Nado's existing FRI stack should not be assumed
zero-knowledge merely because it is a STARK. Add and audit explicit zero-knowledge masking, then include its
proof-size and proving-time overhead in the crossover benchmark. Until that work lands, call the object an
authorization STARK rather than claiming zero knowledge.

## 5. Incremental proving while constructing the template

Yes, most proving work can happen while transactions are collected, but not by repeatedly rebuilding one
monolithic STARK.

Use chunked base proofs and recursive aggregation:

1. On mempool admission, decode the signature once and cache its witness material.
2. Optionally make a one-signature proof immediately, or place transactions into fixed chunks such as
   16, 32, or 64 signature checks.
3. Prove sealed chunks in parallel as the candidate template evolves.
4. Key every cached proof by `(circuit_id, ordered auth leaves, chunk length)`.
5. Maintain a recursive aggregation tree over completed chunk proofs.
6. Shortly before the production deadline, freeze the transaction set. Late transactions roll into the
   next block.
7. Prove the final partial chunk.
8. Fold the chunk proofs to one root proof that enforces contiguous indices, exact total count, and the
   block's `auth_root`.
9. Send the signature-free block core and final proof together.

Chunking permits reuse when only the tail of a template changes. It also allows CPUs/GPUs or an external
proving market to work in parallel.

Padding rows must carry an explicit inactive selector. The AIR enforces that inactive rows contribute
nothing and that exactly `auth_count` active rows form one contiguous sequence; otherwise a prover could
hide a missing signature in padding.

### 5.1 Six-second slot budget

Use a production schedule such as:

```text
t = slot start ... -1.5 s   collect txs; decode and prove chunks continuously
t = -1.5 s                  freeze candidate transaction set
t = -1.5 ... -0.3 s         prove tail chunk and final recursive fold
t = -0.3 s                  serialize and broadcast core + proof
```

The exact times must come from p95/p99 benchmarks. The important limit is not average proving time but the
tail latency before Nado's six-second block deadline.

For 128 signatures/block, arrival is 21.3 signatures/s. Requiring 2x headroom means a proving farm should
sustain at least 42.7 signature checks/s and still finalize the recursive root in under 1.5 seconds. For
256 signatures/block, those targets double.

### 5.2 Offline winners and proving availability

Nado can build a deterministic block for an offline selected winner. Therefore proof construction cannot
depend exclusively on the winner's private infrastructure. Any relay with the signed mempool transactions
must be able to build the same authorization proof, or fetch a proof keyed by `auth_root`.

During the optional phase, a relay that misses the deadline sends raw evidence for the same block core.
After mandatory activation, deploy multiple independent provers and a proof exchange keyed by
`(parent_hash, height, auth_root, circuit_id)`.

## 6. Mandatory or optional?

### 6.1 Recommended rollout

Use both paths during migration, but not as two hashed block formats.

**Phase A — observation only**

- Build the AIR and prover out of consensus.
- For every real block, generate a shadow proof and compare its statement to the native checks.
- Record proof size, p50/p95/p99 prove and verify time, memory, and failure rate by authorization count.

**Phase B — optional detached evidence**

- Activate the signature-free block core and detached evidence envelope.
- Raw evidence remains valid for every block.
- A producer/relay may substitute a STARK proof when it is ready and smaller.
- Start with ordinary single-signature transactions only. Any unsupported authorization type makes the
  whole block use raw evidence in version 1.

**Phase C — proof preferred above the economic threshold**

- Relay policy prefers proof evidence when `P <= 0.8 * 2,420*K` (equivalently,
  `2,420*K >= 1.25*P`).
- Keep raw fallback for liveness while proving operations mature.
- A later proof may replace stored raw evidence for the same block core, subject to reorg/slashing retention.

**Phase D — deterministic mandatory threshold**

- Consensus requires STARK evidence for new blocks when `K >= K_required` and all authorization kinds are
  supported.
- Consensus requires raw evidence below the threshold or for explicitly unsupported legacy kinds.
- Start with `K_required = 128` only if the final proof is at most 200 KiB and the operational gates below
  are met. Otherwise derive `K_required` from the measured proof size and retain at least a 20% margin.

**Phase E — all supported transaction authorization**

- Add multisig and other authorization types to the statement.
- Optionally fold signature validity together with Nado's later L1 state-transition proof.

### 6.2 Why not make it mandatory immediately?

A missing/slow proof would halt production even though every transaction is natively valid. The new AIR is
the least mature and most complicated cryptographic component in the path. Optional detached evidence
allows exact production measurement and rollback without creating alternate block identities.

### 6.3 Why not remain optional forever?

Permanent optionality does not guarantee bandwidth or archival savings, keeps incentives ambiguous, and
forces every new node to exercise two current validation paths indefinitely. A deterministic threshold
eventually gives one expected encoding for each new block size while retaining the raw verifier for
historical blocks.

## 7. Special cases that prevent "strip every signature" in version 1

### 7.1 Reorgs

`core_loop` currently reinjects reverted block transactions into the mempool. A stripped historical
transaction no longer has the signature needed for re-admission.

Keep the raw witness sidecar for at least:

```text
finality depth + maximum rollback margin + operational safety margin
```

On a deeper recovery, do not silently reconstruct unsigned mempool entries; require wallet resubmission or
fetch the witness sidecar from peers.

### 7.2 FFG equivocation slashing

Nado's attestation-equivocation proof contains two fully signed attest/duty transactions. If archival blocks
discard those signatures, a future observer may be unable to construct the portable slash proof even though
the block STARK proved each signature existed.

Version 1 should either:

- retain raw attestation/duty signatures for the entire slashable horizon; or
- exclude those signatures from stripping; or
- redesign slashing to accept two block-auth proofs plus transaction-membership proofs.

The first option is the smallest change.

### 7.3 Detached block-winner signatures

The optional winner signature underpins block equivocation slashing and is outside ordinary transaction
authorization. Keep it unchanged. It is one signature per block, so aggregating it has little size value.

### 7.4 Multisig and nested signature evidence

Nado multisig stores a list of member public keys/signatures, and slash transactions may contain nested
signed objects. A circuit that strips only the top-level `signature` field is incomplete.

Version 1 supports only a precisely enumerated `authorization_kind = single_mldsa44`. Add multisig later,
where `auth_count` counts every required member check and the circuit enforces membership, distinct signers,
and the threshold. Nested signatures used as persistent evidence remain in transaction data until their
semantics are explicitly redesigned.

## 8. Are blocks produced or received faster?

Not automatically.

**Faster:**

- smaller confirmed blocks propagate and store faster;
- pure-Python/phone nodes replace many slow ML-DSA checks with one proof check;
- the global `_CRYPTO_LOCK` is removed from confirmed-block signature validation;
- historical sync can verify one proof per block.

**Slower:**

- the producer must generate the proof;
- an optimized native node may verify 128 ML-DSA signatures in about 20 ms, which can be faster than a
  50-100 ms STARK verification;
- a proof that finishes after the template freezes directly delays broadcast.

The proof path improves block latency only when most proving is precomputed, the final fold fits the slot
budget, and propagation savings exceed the remaining proving/verification overhead. Initially it should be
treated as a bandwidth/storage upgrade, not a promise of faster block production.

## 9. Expected proof, proving, and verification ranges

There is no defensible ML-DSA-specific timing until the AIR exists. Primitive Poseidon2 or generic zkVM
benchmarks do not answer how fast FIPS-204 SHAKE, rejection sampling, hints, and NTTs will prove.

Use these as engineering targets, not claims:

| item | acceptance target | stretch target |
|---|---:|---:|
| final recursive proof | <= 200 KiB | 64-100 KiB |
| proof verification | <= 100 ms | 10-30 ms |
| final tail-chunk + fold, p95 | <= 1.5 s | <= 500 ms |
| sustained proving | >= 2x peak sig/s | >= 4x peak sig/s |
| proof success on eligible testnet blocks | >= 99.9% | >= 99.99% |

For a transparent, hash-based proof at conservative post-quantum security, **100-250 KiB is a realistic
planning band** for a highly optimized final recursive proof. Below 50 KiB should be treated as research,
not a launch assumption. Nado's current 320-query, blowup-2 configuration deliberately spends proof size
for a conservative soundness argument and currently measures around 1 MiB.

Published STARK/zkVM results span roughly 100 KiB to more than 1 MiB, depending on security, commitment
scheme, recursion, workload, and whether the result is a core or compressed proof. They also show verifier
times from about 10 ms to above 100 ms. Use Nado's own serialized proof and end-to-end verifier as the
release metric.

## 10. Implementation sequence

1. **Specification**
   - Freeze the exact Nado ML-DSA internal-mode verifier semantics.
   - Specify `auth_leaf`, `auth_root`, public inputs, padding, and circuit/version IDs.
   - Enumerate supported and excluded authorization kinds.

2. **Reference trace**
   - Produce a non-proving trace generator from valid and invalid NIST/Nado vectors.
   - Differential-test every intermediate SHAKE, NTT, hint, and challenge value.

3. **Dedicated AIR**
   - Implement byte/range lookups, Keccak/SHAKE, modular reduction, NTT, hint checks, and root binding.
   - Prove one signature, then fixed chunks.

4. **Security tests**
   - Mutate every public-key/signature encoding field and require rejection.
   - Test wrong message, wrong key, wrong sender binding, reordered/omitted/duplicated leaves, bad count,
     active-padding gaps, wrong chain/height/parent, and proof-parameter downgrades.

5. **Native prover**
   - Move the full trace/LDE/commitment/composition pipeline out of Python.
   - Add SIMD first; add GPU kernels only after bit-identical CPU conformance.

6. **Recursive aggregation**
   - Prove chunks in parallel.
   - Fold contiguous chunks and bind their ordered leaf ranges to one `auth_root`.
   - Serialize a compact, versioned final proof.

7. **Shadow production**
   - Generate proofs for real blocks without affecting consensus.
   - Publish histograms by `K`, hardware class, and proof version.

8. **Block-core migration**
   - Add signature-free transaction storage, detached evidence, APIs, peer exchange, and proof cache.
   - Make block identity independent of evidence type.

9. **Reorg/slashing retention**
   - Deploy witness sidecars and retention horizons.
   - Prove reorg reinjection and equivocation reporting still work.

10. **Optional activation**
    - Accept raw or proof evidence for the same core.
    - Prefer proofs only above the measured 20%-margin threshold.

11. **Mandatory activation**
    - Audit the AIR and verifier.
    - Require proofs above the deterministic threshold after the operational gates pass.

## 11. Go/no-go gates

Do not make the proof path mandatory until all are true:

- final proof <= 200 KiB at the target soundness;
- verifier <= 100 ms p95 on the slowest supported full-node hardware;
- finalization <= 1.5 s p95 and <= 3 s p99 at `K_required`;
- sustained throughput >= 2x target signature rate;
- at least three independent proving operators can produce the same valid statement;
- 99.9%+ eligible shadow/testnet blocks prove before deadline for at least 100,000 blocks;
- circuit, transcript, recursion, and parser have independent security review;
- historical sync, reorg, slashing, multisig exclusion, and invalid-proof DoS tests pass;
- a circuit-version upgrade and emergency proof-disable mechanism are activated by an explicit consensus
  upgrade, not an operator-local flag.

## 12. Direct answers

- **At what transaction count is a STARK worthwhile?** At 43 ordinary transactions for a 100 KiB proof,
  85 for 200 KiB, or 434 for Nado's current roughly 1 MiB proof. Use 53, 106, and 542 respectively for a
  20% byte-saving margin.
- **What is a feasible starting rate?** Pilot at 128 signatures/block, about 21 ordinary tx/s at six-second
  blocks, only after the proof is <= 200 KiB and proving finalizes within the slot.
- **How small can it get?** Plan for 100-250 KiB; target 100-200 KiB; treat <50 KiB as research.
- **Can the miner prove while collecting?** Yes: precompute witnesses/base proofs, seal fixed chunks, and
  recursively fold after freezing the template. A monolithic proof rebuilt on every mempool change cannot.
- **Does the miner send the proof with the block?** Yes, as detached authorization evidence accompanying
  the signature-free core.
- **Mandatory or optional?** Optional detached evidence first; deterministic mandatory proof above a
  measured threshold later.
- **If optional, proof or signatures?** Send one evidence object, not both. Raw evidence carries all required
  signatures; STARK evidence carries no ordinary transaction signatures.
- **Are blocks produced faster?** Not initially. They propagate faster, but proof finalization can slow
  production. Pre-proving is what can remove that delay.
- **How fast can proving be?** Unknown until the ML-DSA AIR is benchmarked. The release target is sustained
  2x peak load plus a <=1.5 s p95 tail fold, not an unsupported "millisecond" claim.
- **How long does verification take?** Budget <=100 ms; optimize toward 10-30 ms. Nado's current Python
  verifier is roughly 100-200 ms.

## References

- NIST, [FIPS 204: Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final)
- Plonky3, [fields, Poseidon2, Keccak, FRI and STARK toolkit](https://github.com/Plonky3/Plonky3)
- Starknet S-two book, [cross-system CPU benchmark report](https://docs.starknet.io/learn/S-two-book/benchmarks)
- Starknet, [SHARP recursive proof aggregation](https://docs.starknet.io/learn/protocol/sharp)
- Nado, [`doc/zk-execution-proofs.md`](zk-execution-proofs.md)
- Nado, [`doc/zk-recursion.md`](zk-recursion.md)
- Nado, [`doc/scaling-analysis.md`](scaling-analysis.md)
