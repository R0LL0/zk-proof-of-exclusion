# zk-proof-of-exclusion

**Prove you are _not_ on a list — without revealing who you are.**

A zero-knowledge toolkit for **privacy-preserving denylist / sanctions screening**. A user proves, in their browser, that their identity is **not** a member of an authority-signed blocklist (e.g. an OFAC / sanctions list) and reveals nothing else — not their name, not their ID, only a single boolean.

Most ZK identity projects prove _membership_ ("I am over 18", "I hold credential X"). This proves **non-membership**, which is the primitive that privacy-preserving compliance actually needs — and it's the one almost nobody ships.

```
 Authority (list owner)                 User (browser)                 Verifier
 ─────────────────────                  ──────────────                 ────────
 build Sparse Merkle Tree               fetch signed root              knows only:
 of Poseidon(identity) leaves     ──▶   generate ZK proof of     ──▶     • authority pubkey
 sign the root with EdDSA               NON-membership locally           • root + expiry
 publish {root, sig, expiry}            (identity never leaves)          • challenge (nonce)
                                                                       verify() → true / false
```

## Why this is sound (and why the "obvious" design isn't)

The naive approach — *verify the issuer's signature in JavaScript, then generate a ZK proof of some predicate* — is **broken**: the proof isn't cryptographically bound to the signed data, so a malicious user just feeds in whatever they like.

Here, the authority's **EdDSA signature over the list root is verified _inside_ the circuit**:

1. The blocklist is a **Sparse Merkle Tree** of `Poseidon(identity)` leaves.
2. The prover supplies a **non-inclusion witness** (`SMTVerifier`, exclusion mode).
3. The **root is only trusted because its EdDSA-Poseidon signature is checked in-circuit** against the authority's public key (a public input anyone can look up in a registry).
4. A verifier-supplied **`challenge`** is bound into the proof, so a captured proof can't be replayed.

A user therefore cannot invent a favourable list, cannot forge membership, and cannot reuse a proof out of context. See [`circuits/exclusion.circom`](circuits/exclusion.circom).

## Quick start

```bash
npm install
npm run build:circuit     # compile circom + trusted setup (downloads pot15 once)
npm test                  # 3 end-to-end tests incl. soundness (forged root rejected)
npm run prove:demo        # full authority → prove → verify demo in the terminal
```

Proof generation runs in **~0.6 s** on a laptop (~22k constraints, Groth16).

### Try the browser demo

```bash
node scripts/gen_web_fixtures.mjs      # bundle wasm/zkey + demo fixtures into web/
npx serve web                          # or any static server
```

Open the page, pick a "clean" identity → a zk-SNARK proof is generated **client-side**; pick a blocklisted one → no witness exists and the attempt is refused. The `web/` folder is fully static and **GitHub Pages-ready**.

## How it's built

| Layer | Tech |
| --- | --- |
| Circuit | [Circom](https://docs.circom.io) 2.2, [circomlib](https://github.com/iden3/circomlib) (`SMTVerifier`, `EdDSAPoseidonVerifier`, `Poseidon`) |
| Proving | [snarkjs](https://github.com/iden3/snarkjs) Groth16 (browser + Node) |
| Authority / witnesses | [circomlibjs](https://github.com/iden3/circomlibjs) — see [`lib/poe.mjs`](lib/poe.mjs) |

```
circuits/exclusion.circom     the sound non-membership circuit
lib/poe.mjs                   Authority (signs list) + witness/input helpers
scripts/                      build, trusted setup, CLI demo, web fixtures
test/e2e.test.mjs             clean-proof, blocklisted-rejected, forged-root-rejected
web/                          static client-side demo (GitHub Pages-ready)
```

## Real-world use cases

- **Exchanges / fintechs** — let a user prove "not on the sanctions list" without collecting their identity for every counterparty.
- **DAOs / airdrops** — exclude sanctioned or banned addresses without a public blacklist lookup that deanonymises everyone else.
- **Marketplaces** — prove a seller isn't on a platform ban list across platforms, privately.

## Honest limitations (read before you ship)

This is a working reference implementation, **not audited**. Before production:

- **Trusted setup.** The demo uses a single-contributor Groth16 setup. Run a real multi-party ceremony, or switch to a universal-setup scheme (Plonk/fflonk). The circuit is scheme-agnostic.
- **Identity binding.** The demo hashes a string into a field element. A real deployment must bind `identity` to something the user can't lie about — e.g. a government-signed credential (see [Anon Aadhaar](https://github.com/anon-aadhaar/anon-aadhaar)) or a passport — otherwise a sanctioned person just proves exclusion for a _different_ identity.
- **List freshness & revocation.** The signed `expiry` bounds staleness; verifiers must enforce it and the authority must re-sign on updates.
- **Authority trust.** The verifier trusts the authority to maintain an honest, complete list. This shifts *privacy* off the user, not *trust* off the authority.

Contributions and integrations welcome. MIT licensed.
