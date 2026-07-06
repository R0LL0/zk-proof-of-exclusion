// Shared Proof-of-Exclusion library: authority (list owner) + prover helpers.
// Pure JS on top of circomlibjs so it runs in Node and (bundled) in the browser.

import { buildPoseidon, buildEddsa, newMemEmptyTrie } from "circomlibjs";

const N_LEVELS = 20; // must match ProofOfExclusion(nLevels) in the circuit

let _poseidon, _eddsa;
async function primitives() {
  if (!_poseidon) _poseidon = await buildPoseidon();
  if (!_eddsa) _eddsa = await buildEddsa();
  return { poseidon: _poseidon, eddsa: _eddsa, F: _poseidon.F };
}

// Turn any identifier (passport hash, DID, wallet, ...) into a field element.
export async function toIdentity(str) {
  const { poseidon, F } = await primitives();
  const bytes = new TextEncoder().encode(str);
  // Fold bytes into a field element deterministically via Poseidon.
  let acc = 0n;
  for (const b of bytes) acc = (acc * 257n + BigInt(b)) % F.p;
  return F.toObject(poseidon([acc]));
}

/**
 * The Authority: owns the blocklist, publishes a signed Sparse Merkle root.
 * `privateKey` is a 32-byte Buffer/Uint8Array (the authority's EdDSA secret).
 */
export class Authority {
  constructor(privateKey) {
    this.privateKey = privateKey;
  }

  async init(identityList /* array of field-element identities */) {
    const { poseidon, eddsa, F } = await primitives();
    this.F = F;
    this.poseidon = poseidon;
    this.eddsa = eddsa;

    this.tree = await newMemEmptyTrie();
    // Leaf key = Poseidon(identity); value = 1 (present).
    for (const id of identityList) {
      const key = F.toObject(poseidon([F.e(id)]));
      await this.tree.insert(key, 1n);
    }
    const pub = eddsa.prv2pub(this.privateKey);
    this.publicKey = { Ax: F.toObject(pub[0]), Ay: F.toObject(pub[1]) };
    return this;
  }

  /** Sign the current root with an expiry → the object a verifier trusts. */
  signedRoot(expiry) {
    const { F, poseidon, eddsa } = this;
    const root = F.toObject(this.tree.root);
    const msg = poseidon([F.e(root), F.e(expiry)]);
    const sig = eddsa.signPoseidon(this.privateKey, msg);
    return {
      root,
      expiry: BigInt(expiry),
      authorityAx: this.publicKey.Ax,
      authorityAy: this.publicKey.Ay,
      signature: {
        R8x: F.toObject(sig.R8[0]),
        R8y: F.toObject(sig.R8[1]),
        S: sig.S,
      },
    };
  }

  /** Produce a non-inclusion witness for `identity` against the current tree. */
  async exclusionWitness(identity) {
    const { F, poseidon } = this;
    const key = F.toObject(poseidon([F.e(identity)]));
    const res = await this.tree.find(key);
    if (res.found) throw new Error("identity IS on the blocklist — cannot prove exclusion");

    const siblings = res.siblings.map((s) => F.toObject(s));
    while (siblings.length < N_LEVELS) siblings.push(0n);
    if (siblings.length > N_LEVELS) throw new Error("tree deeper than N_LEVELS");

    return {
      siblings,
      oldKey: res.isOld0 ? 0n : F.toObject(res.notFoundKey),
      oldValue: res.isOld0 ? 0n : F.toObject(res.notFoundValue),
      isOld0: res.isOld0 ? 1n : 0n,
    };
  }
}

/** Assemble the full circuit input from a signed root + witness + challenge. */
export function buildCircuitInput({ identity, signedRoot, witness, challenge }) {
  return {
    authorityAx: signedRoot.authorityAx,
    authorityAy: signedRoot.authorityAy,
    root: signedRoot.root,
    expiry: signedRoot.expiry,
    challenge: BigInt(challenge),
    identity: BigInt(identity),
    S: signedRoot.signature.S,
    R8x: signedRoot.signature.R8x,
    R8y: signedRoot.signature.R8y,
    siblings: witness.siblings,
    oldKey: witness.oldKey,
    oldValue: witness.oldValue,
    isOld0: witness.isOld0,
  };
}

export { N_LEVELS };
