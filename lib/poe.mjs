// Shared Proof-of-Exclusion library (v2, credential-bound).
//
//   Authority  — owns the blocklist, publishes a signed Sparse Merkle root.
//   Issuer     — certifies a holder's identity by signing a credential.
//   Holder     — a secret whose commitment is bound into the credential.
//
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
  let acc = 0n;
  for (const b of bytes) acc = (acc * 257n + BigInt(b)) % F.p;
  return F.toObject(poseidon([acc]));
}

// A holder is a secret + its Poseidon commitment. The secret never leaves the
// prover; the commitment is what an issuer binds a credential to.
export async function makeHolder(secret) {
  const { poseidon, F } = await primitives();
  const holderSecret = typeof secret === "bigint" ? secret
    : F.toObject(poseidon([F.e(await hashString(secret))]));
  const commit = F.toObject(poseidon([F.e(holderSecret)]));
  return { holderSecret, holderCommit: commit };
}
async function hashString(s) {
  const { poseidon, F } = await primitives();
  const bytes = new TextEncoder().encode(String(s));
  let acc = 0n;
  for (const b of bytes) acc = (acc * 257n + BigInt(b)) % F.p;
  return F.toObject(poseidon([acc]));
}

/**
 * The Issuer: a trusted party (KYC provider, government registry, ...) that
 * certifies "this identity belongs to the holder with this commitment".
 */
export class Issuer {
  constructor(privateKey) { this.privateKey = privateKey; }

  async init() {
    const { eddsa, poseidon, F } = await primitives();
    this.eddsa = eddsa; this.poseidon = poseidon; this.F = F;
    const pub = eddsa.prv2pub(this.privateKey);
    this.publicKey = { Ax: F.toObject(pub[0]), Ay: F.toObject(pub[1]) };
    return this;
  }

  /** Sign a credential binding `identity` to `holderCommit`. */
  issue(identity, holderCommit) {
    const { F, poseidon, eddsa } = this;
    const msg = poseidon([F.e(identity), F.e(holderCommit)]);
    const sig = eddsa.signPoseidon(this.privateKey, msg);
    return {
      issuerAx: this.publicKey.Ax,
      issuerAy: this.publicKey.Ay,
      signature: { R8x: F.toObject(sig.R8[0]), R8y: F.toObject(sig.R8[1]), S: sig.S },
    };
  }
}

/**
 * The Authority: owns the blocklist, publishes a signed Sparse Merkle root.
 */
export class Authority {
  constructor(privateKey) { this.privateKey = privateKey; }

  async init(identityList /* array of field-element identities */) {
    const { poseidon, eddsa, F } = await primitives();
    this.F = F; this.poseidon = poseidon; this.eddsa = eddsa;

    this.tree = await newMemEmptyTrie();
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
      signature: { R8x: F.toObject(sig.R8[0]), R8y: F.toObject(sig.R8[1]), S: sig.S },
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

/** Assemble the full circuit input from all pieces. */
export function buildCircuitInput({ identity, holder, credential, signedRoot, witness, challenge }) {
  return {
    // public
    authorityAx: signedRoot.authorityAx,
    authorityAy: signedRoot.authorityAy,
    issuerAx: credential.issuerAx,
    issuerAy: credential.issuerAy,
    root: signedRoot.root,
    expiry: signedRoot.expiry,
    challenge: BigInt(challenge),
    // private
    identity: BigInt(identity),
    holderSecret: holder.holderSecret,
    aS: signedRoot.signature.S,
    aR8x: signedRoot.signature.R8x,
    aR8y: signedRoot.signature.R8y,
    iS: credential.signature.S,
    iR8x: credential.signature.R8x,
    iR8y: credential.signature.R8y,
    siblings: witness.siblings,
    oldKey: witness.oldKey,
    oldValue: witness.oldValue,
    isOld0: witness.isOld0,
  };
}

export { N_LEVELS };
