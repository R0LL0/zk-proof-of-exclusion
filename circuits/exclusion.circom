pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/eddsaposeidon.circom";
include "circomlib/circuits/smt/smtverifier.circom";

/*
 * Proof-of-Exclusion
 * ------------------
 * Prove that a *secret* identity is NOT a member of a blocklist (e.g. an OFAC /
 * sanctions list) that has been committed to by a trusted authority, revealing
 * nothing about the identity itself.
 *
 * Soundness is the whole point here, and it hinges on two links that the naive
 * "verify the signature in JS, then prove a predicate" design breaks:
 *
 *   1. The list is a Sparse Merkle Tree of Poseidon(identity) leaves. The prover
 *      supplies an *exclusion* proof (SMTVerifier, fnc = 1) against `root`.
 *   2. `root` is not trusted blindly: the authority's EdDSA signature over
 *      Poseidon(root, expiry) is verified INSIDE the circuit, against the
 *      authority public key that is a PUBLIC input. A holder therefore cannot
 *      invent a favourable root — they can only use one the authority signed.
 *
 * A `challenge` public input (supplied by the verifier at request time) is bound
 * into the proof so a proof captured for one verification cannot be replayed.
 *
 * PUBLIC  : authorityAx, authorityAy, root, expiry, challenge
 * PRIVATE : identity, S, R8x, R8y, siblings[], oldKey, oldValue, isOld0
 */
template ProofOfExclusion(nLevels) {
    // ---- Public: the authority anyone can look up in a registry ----
    signal input authorityAx;
    signal input authorityAy;
    // ---- Public: the signed list state + a freshness bound ----
    signal input root;
    signal input expiry;
    // ---- Public: verifier-chosen nonce (anti-replay) ----
    signal input challenge;

    // ---- Private: the thing we never reveal ----
    signal input identity;

    // ---- Private: authority signature over Poseidon(root, expiry) ----
    signal input S;
    signal input R8x;
    signal input R8y;

    // ---- Private: SMT non-inclusion witness ----
    signal input siblings[nLevels];
    signal input oldKey;
    signal input oldValue;
    signal input isOld0;

    // 1) Bind the signed message: M = Poseidon(root, expiry)
    component msg = Poseidon(2);
    msg.inputs[0] <== root;
    msg.inputs[1] <== expiry;

    // 2) Verify the authority actually signed this (root, expiry).
    component sig = EdDSAPoseidonVerifier();
    sig.enabled <== 1;
    sig.Ax  <== authorityAx;
    sig.Ay  <== authorityAy;
    sig.S   <== S;
    sig.R8x <== R8x;
    sig.R8y <== R8y;
    sig.M   <== msg.out;

    // 3) The blocklist key is Poseidon(identity) — same as the authority inserts.
    component leaf = Poseidon(1);
    leaf.inputs[0] <== identity;

    // 4) Prove that key is NOT in the tree at `root` (fnc = 1 => exclusion).
    component excl = SMTVerifier(nLevels);
    excl.enabled  <== 1;
    excl.fnc      <== 1;          // 1 = verify exclusion / non-membership
    excl.root     <== root;
    excl.key      <== leaf.out;
    excl.value    <== 0;
    excl.oldKey   <== oldKey;
    excl.oldValue <== oldValue;
    excl.isOld0   <== isOld0;
    for (var i = 0; i < nLevels; i++) {
        excl.siblings[i] <== siblings[i];
    }

    // 5) Bind the verifier's challenge into the constraint system so the proof
    //    is non-transferable to a different challenge value.
    signal challengeBound;
    challengeBound <== challenge * challenge;
}

component main {public [authorityAx, authorityAy, root, expiry, challenge]} =
    ProofOfExclusion(20);
