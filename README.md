# zk-proof-of-exclusion

**Prove you are _not_ on a list — without revealing who you are.**

A zero-knowledge toolkit for **privacy-preserving denylist / sanctions screening**. A user proves, in their browser, that their identity is **not** a member of an authority-signed blocklist (e.g. an OFAC / sanctions list) and reveals nothing else — not their name, not their ID, only a single boolean.

Most ZK identity projects prove _membership_ ("I am over 18", "I hold credential X"). This proves **non-membership**, which is the primitive that privacy-preserving compliance actually needs — and it's the one almost nobody ships.

```
 Issuer (KYC / registry)     Authority (list owner)      Holder (browser)          Verifier
 ──────────────────────      ──────────────────────      ────────────────          ────────
 signs a credential          builds Sparse Merkle Tree    fetch credential +        knows only:
 over (identity,             of Poseidon(identity)        signed root                • issuer pubkey
 holderCommit)          ──▶  leaves; signs the root  ──▶  generate ZK proof:    ──▶  • authority pubkey
                             publish {root,sig,expiry}    "credentialed AND          • root + expiry
                                                          not on the list"           • challenge (nonce)
                                                          (nothing else leaves)     verify() → true / false
```

## Why this is sound (and why the "obvious" design isn't)

The naive approach — *verify a signature in JavaScript, then generate a ZK proof of some predicate* — is **broken**: the proof isn't cryptographically bound to the signed data, so a malicious user just feeds in whatever they like. This project closes three gaps, all checked **inside the circuit**:

1. **Blocklist membership.** The list is a **Sparse Merkle Tree** of `Poseidon(identity)` leaves; the prover supplies a **non-inclusion witness** (`SMTVerifier`, exclusion mode).
2. **Root authenticity.** The root is trusted only because the **authority's EdDSA-Poseidon signature over `Poseidon(root, expiry)` is verified in-circuit** against the authority public key (a public input, lookup-able in a registry). A user cannot invent a favourable list.
3. **Identity ownership.** `identity` is not free-choice. An **issuer signs a credential over `Poseidon(identity, holderCommit)`**, and `holderCommit = Poseidon(holderSecret)`. The circuit verifies the issuer signature **and** that the prover knows `holderSecret`. So a sanctioned user can neither invent a clean identity (it wouldn't be issuer-signed) nor reuse someone else's credential (they don't know that holder's secret).
4. A verifier-supplied **`challenge`** is bound in, so a captured proof can't be replayed.

See [`circuits/exclusion.circom`](circuits/exclusion.circom) and the five soundness tests in [`test/e2e.test.mjs`](test/e2e.test.mjs) (valid proof · blocklisted-rejected · forged-root-rejected · uncredentialed-rejected · stolen-credential-rejected).

## Quick start

```bash
npm install
npm run build:circuit     # compile circom + trusted setup (downloads pot15 once)
npm test                  # 5 end-to-end tests incl. 4 soundness/attack cases
npm run prove:demo        # full issuer → authority → prove → verify demo in the terminal
```

Proof generation runs in **~0.65 s** on a laptop (~31k constraints, Groth16).

### Try the browser demo

**Live demo:** https://r0ll0.github.io/zk-proof-of-exclusion/

```bash
node scripts/gen_web_fixtures.mjs      # bundle wasm/zkey + demo fixtures into docs/
npx serve docs                         # or any static server
```

Open the page, pick a "clean" identity → a zk-SNARK proof is generated **client-side**; pick a blocklisted one → no witness exists and the attempt is refused. The `docs/` folder is fully static and served directly by **GitHub Pages**.

## How it's built

| Layer | Tech |
| --- | --- |
| Circuit | [Circom](https://docs.circom.io) 2.2, [circomlib](https://github.com/iden3/circomlib) (`SMTVerifier`, `EdDSAPoseidonVerifier`, `Poseidon`) |
| Proving | [snarkjs](https://github.com/iden3/snarkjs) Groth16 (browser + Node) |
| Issuer / Authority / witnesses | [circomlibjs](https://github.com/iden3/circomlibjs) — see [`lib/poe.mjs`](lib/poe.mjs) |

```
circuits/exclusion.circom     the sound, credential-bound non-membership circuit
lib/poe.mjs                   Issuer (signs credentials) + Authority (signs list) + helpers
scripts/                      build, trusted setup, CLI demo, web fixtures
test/e2e.test.mjs             5 cases: valid + 4 attack/soundness rejections
docs/                         static client-side demo (served by GitHub Pages)
```

## Real-world use cases

- **Exchanges / fintechs** — let a user prove "not on the sanctions list" without collecting their identity for every counterparty.
- **DAOs / airdrops** — exclude sanctioned or banned addresses without a public blacklist lookup that deanonymises everyone else.
- **Marketplaces** — prove a seller isn't on a platform ban list across platforms, privately.

## Honest limitations (read before you ship)

This is a working reference implementation, **not audited**. Before production:

- **Trusted setup.** The demo uses a single-contributor Groth16 setup. Run a real multi-party ceremony, or switch to a universal-setup scheme (Plonk/fflonk). The circuit is scheme-agnostic.
- **Issuer trust & identity source.** The circuit binds `identity` to an issuer-signed credential and to a holder secret, so users can't invent or steal identities. What remains a _trust_ (not privacy) assumption is the issuer itself: it must certify exactly one identity per real person. Bind the credential to a strong root of identity — e.g. a passport or a government e-KYC doc (cf. [Anon Aadhaar](https://github.com/anon-aadhaar/anon-aadhaar)).
- **List freshness & revocation.** The signed `expiry` bounds staleness; verifiers must enforce it and the authority must re-sign on updates. There is no per-proof nullifier yet, so add one if you need to prevent a holder proving twice.
- **Authority trust.** The verifier trusts the authority to maintain an honest, complete list. This shifts *privacy* off the user, not *trust* off the authority.

Contributions and integrations welcome. MIT licensed.
