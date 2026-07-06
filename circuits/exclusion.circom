pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/eddsaposeidon.circom";
include "circomlib/circuits/smt/smtverifier.circom";

/*
 * Proof-of-Exclusion  (v2 — credential-bound)
 * -------------------------------------------
 * Prove that a *secret* identity is NOT a member of an authority-signed
 * blocklist (e.g. sanctions), revealing nothing about the identity — AND that
 * the prover is genuinely entitled to that identity. Three cryptographic links,
 * all checked INSIDE the circuit, close the gaps a naive design leaves open:
 *
 *   1. Blocklist membership. The list is a Sparse Merkle Tree of
 *      Poseidon(identity) leaves; the prover supplies an *exclusion* witness
 *      (SMTVerifier, fnc = 1) against `root`.
 *
 *   2. Root authenticity. `root` is not trusted blindly — the authority's EdDSA
 *      signature over Poseidon(root, expiry) is verified against the authority
 *      public key (a PUBLIC input). A user cannot invent a favourable list.
 *
 *   3. Identity ownership (NEW in v2). `identity` is not free-choice. An issuer
 *      (KYC provider, government, ...) signs a credential over
 *      Poseidon(identity, holderCommit), and holderCommit = Poseidon(holderSecret).
 *      The circuit verifies the issuer signature AND that the prover knows
 *      holderSecret. So a sanctioned user cannot (a) make up a clean identity —
 *      it wouldn't be issuer-signed — nor (b) reuse someone else's credential —
 *      they don't know that holder's secret.
 *
 * A verifier-supplied `challenge` is bound in to stop proof replay.
 *
 * PUBLIC  : authorityAx, authorityAy, issuerAx, issuerAy, root, expiry, challenge
 * PRIVATE : identity, holderSecret,
 *           aS, aR8x, aR8y            (authority signature over the root)
 *           iS, iR8x, iR8y            (issuer signature over the credential)
 *           siblings[], oldKey, oldValue, isOld0   (SMT non-inclusion witness)
 */
template ProofOfExclusion(nLevels) {
    // ---- Public ----
    signal input authorityAx;
    signal input authorityAy;
    signal input issuerAx;
    signal input issuerAy;
    signal input root;
    signal input expiry;
    signal input challenge;

    // ---- Private ----
    signal input identity;
    signal input holderSecret;

    signal input aS;    // authority sig
    signal input aR8x;
    signal input aR8y;

    signal input iS;    // issuer sig
    signal input iR8x;
    signal input iR8y;

    signal input siblings[nLevels];
    signal input oldKey;
    signal input oldValue;
    signal input isOld0;

    // --- (2) Authority signed (root, expiry) ---------------------------------
    component amsg = Poseidon(2);
    amsg.inputs[0] <== root;
    amsg.inputs[1] <== expiry;

    component asig = EdDSAPoseidonVerifier();
    asig.enabled <== 1;
    asig.Ax <== authorityAx;
    asig.Ay <== authorityAy;
    asig.S  <== aS;
    asig.R8x <== aR8x;
    asig.R8y <== aR8y;
    asig.M  <== amsg.out;

    // --- (3) Holder ownership: holderCommit = Poseidon(holderSecret) ----------
    component hc = Poseidon(1);
    hc.inputs[0] <== holderSecret;

    // Issuer signed the credential Poseidon(identity, holderCommit) -----------
    component cmsg = Poseidon(2);
    cmsg.inputs[0] <== identity;
    cmsg.inputs[1] <== hc.out;

    component isig = EdDSAPoseidonVerifier();
    isig.enabled <== 1;
    isig.Ax <== issuerAx;
    isig.Ay <== issuerAy;
    isig.S  <== iS;
    isig.R8x <== iR8x;
    isig.R8y <== iR8y;
    isig.M  <== cmsg.out;

    // --- (1) Non-membership of Poseidon(identity) in the signed tree ----------
    component leaf = Poseidon(1);
    leaf.inputs[0] <== identity;

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

    // --- Bind the verifier challenge so a proof is non-transferable -----------
    signal challengeBound;
    challengeBound <== challenge * challenge;
}

component main {public [authorityAx, authorityAy, issuerAx, issuerAy, root, expiry, challenge]} =
    ProofOfExclusion(20);
