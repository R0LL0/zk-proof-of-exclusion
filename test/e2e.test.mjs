import { test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import fs from "node:fs/promises";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";
import { Authority, Issuer, toIdentity, makeHolder, buildCircuitInput } from "../lib/poe.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const build = path.resolve(__dirname, "..", "build");
const WASM = path.join(build, "exclusion_js", "exclusion.wasm");
const ZKEY = path.join(build, "exclusion_final.zkey");
const VKEY = path.join(build, "verification_key.json");

const AUTH_SK = new Uint8Array(32).fill(7);   // demo authority key
const ISSUER_SK = new Uint8Array(32).fill(9); // demo issuer key
const EXPIRY = 4102444800n;
const CHALLENGE = 1234567890n;

async function setup() {
  const blockedNames = ["alice-bad", "bob-bad", "carol-bad", "dave-bad", "erin-bad"];
  const blockedIds = await Promise.all(blockedNames.map(toIdentity));
  const authority = await new Authority(AUTH_SK).init(blockedIds);
  const issuer = await new Issuer(ISSUER_SK).init();
  const signed = authority.signedRoot(EXPIRY);
  return { authority, issuer, signed, blockedNames };
}

async function verify(publicSignals, proof) {
  const vkey = JSON.parse(await fs.readFile(VKEY, "utf8"));
  return snarkjs.groth16.verify(vkey, publicSignals, proof);
}

test("a credentialed, non-blocklisted holder proves exclusion", async () => {
  const { authority, issuer, signed } = await setup();

  const identity = await toIdentity("frank-clean");
  const holder = await makeHolder("frank-secret-key");
  const credential = issuer.issue(identity, holder.holderCommit);
  const witness = await authority.exclusionWitness(identity);

  const input = buildCircuitInput({ identity, holder, credential, signedRoot: signed, witness, challenge: CHALLENGE });
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);

  assert.equal(await verify(publicSignals, proof), true);
  assert.ok(publicSignals.includes(CHALLENGE.toString()), "challenge is public");
  assert.ok(!publicSignals.includes(identity.toString()), "identity stays private");
  assert.ok(!publicSignals.includes(holder.holderSecret.toString()), "holder secret stays private");
});

test("blocklisted identity cannot get an exclusion witness", async () => {
  const { authority } = await setup();
  const identity = await toIdentity("bob-bad");
  await assert.rejects(() => authority.exclusionWitness(identity), /IS on the blocklist/);
});

test("forged (unsigned) root is rejected inside the circuit", async () => {
  const { authority, issuer, signed } = await setup();
  const identity = await toIdentity("frank-clean");
  const holder = await makeHolder("frank-secret-key");
  const credential = issuer.issue(identity, holder.holderCommit);
  const witness = await authority.exclusionWitness(identity);

  const forged = { ...signed, root: 0n }; // attacker swaps in an empty-list root
  const input = buildCircuitInput({ identity, holder, credential, signedRoot: forged, witness, challenge: CHALLENGE });
  await assert.rejects(() => snarkjs.groth16.fullProve(input, WASM, ZKEY));
});

test("a made-up identity with no issuer credential is rejected", async () => {
  const { authority, issuer, signed } = await setup();
  // Attacker invents a clean identity but has NO valid issuer signature for it.
  const identity = await toIdentity("ghost-nobody-issued");
  const holder = await makeHolder("ghost-secret");
  const realCred = issuer.issue(await toIdentity("someone-else"), holder.holderCommit);
  // Reuse a signature that does not match this identity => issuer check must fail.
  const witness = await authority.exclusionWitness(identity);
  const input = buildCircuitInput({ identity, holder, credential: realCred, signedRoot: signed, witness, challenge: CHALLENGE });
  await assert.rejects(() => snarkjs.groth16.fullProve(input, WASM, ZKEY),
    "issuer signature over a different identity must not satisfy the circuit");
});

test("identity theft: using someone else's credential without their secret fails", async () => {
  const { authority, issuer, signed } = await setup();
  // Victim is a legitimately-credentialed clean holder.
  const victimId = await toIdentity("victim-clean");
  const victim = await makeHolder("victim-only-knows-this");
  const victimCred = issuer.issue(victimId, victim.holderCommit);

  // Attacker steals the credential + identity but NOT the victim's secret,
  // so they must guess a holderSecret. holderCommit won't match => circuit fails.
  const attacker = await makeHolder("attacker-guess");
  const witness = await authority.exclusionWitness(victimId);
  const input = buildCircuitInput({
    identity: victimId, holder: attacker, credential: victimCred,
    signedRoot: signed, witness, challenge: CHALLENGE,
  });
  await assert.rejects(() => snarkjs.groth16.fullProve(input, WASM, ZKEY),
    "a holder secret that doesn't match the credential's commitment must be rejected");
});
