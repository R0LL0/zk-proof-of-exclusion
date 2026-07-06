import { test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";
import { buildEddsa } from "circomlibjs";
import { Authority, toIdentity, buildCircuitInput } from "../lib/poe.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const build = path.resolve(__dirname, "..", "build");
const WASM = path.join(build, "exclusion_js", "exclusion.wasm");
const ZKEY = path.join(build, "exclusion_final.zkey");
const VKEY = path.join(build, "verification_key.json");

// A deterministic 32-byte authority secret key for the test.
const AUTH_SK = new Uint8Array(32).fill(7);

async function makeAuthority() {
  const names = ["alice-bad", "bob-bad", "carol-bad", "dave-bad", "erin-bad"];
  const ids = await Promise.all(names.map(toIdentity));
  const authority = await new Authority(AUTH_SK).init(ids);
  return { authority, blocked: { name: "bob-bad" } };
}

test("clean identity produces a valid exclusion proof", async () => {
  const { authority } = await makeAuthority();
  const expiry = 4102444800n; // 2100-01-01, far future
  const signed = authority.signedRoot(expiry);

  const identity = await toIdentity("frank-clean"); // NOT on the list
  const witness = await authority.exclusionWitness(identity);
  const challenge = 1234567890n; // verifier-chosen nonce

  const input = buildCircuitInput({ identity, signedRoot: signed, witness, challenge });
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);

  const vkey = JSON.parse(await (await import("node:fs/promises")).readFile(VKEY, "utf8"));
  const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
  assert.equal(ok, true, "proof for a clean identity must verify");

  // Public signals must expose the challenge & root — but never the identity.
  assert.ok(publicSignals.includes(challenge.toString()), "challenge is a public signal");
  assert.ok(!publicSignals.includes(identity.toString()), "identity must stay private");
});

test("a blocklisted identity cannot even build a witness (soundness)", async () => {
  const { authority, blocked } = await makeAuthority();
  const identity = await toIdentity(blocked.name);
  await assert.rejects(
    () => authority.exclusionWitness(identity),
    /IS on the blocklist/,
    "the authority must refuse to hand out an exclusion witness for a listed id"
  );
});

test("a forged (unsigned) root is rejected by the circuit", async () => {
  const { authority } = await makeAuthority();
  const expiry = 4102444800n;
  const signed = authority.signedRoot(expiry);

  // Attacker swaps in a root they made up (empty list => everyone excluded),
  // but keeps the authority's real signature. The in-circuit EdDSA check must fail.
  const forged = { ...signed, root: 0n };
  const identity = await toIdentity("frank-clean");
  const witness = await authority.exclusionWitness(identity);
  const input = buildCircuitInput({
    identity, signedRoot: forged, witness, challenge: 42n,
  });

  await assert.rejects(
    () => snarkjs.groth16.fullProve(input, WASM, ZKEY),
    "circuit must reject a root the authority never signed"
  );
});
