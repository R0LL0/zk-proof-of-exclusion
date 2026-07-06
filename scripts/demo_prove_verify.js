// End-to-end demo:  npm run prove:demo
//
//   Issuer certifies a holder's identity (signed credential).
//   Authority publishes a signed blocklist of sanctioned ids.
//   The holder proves in zero knowledge that they are credentialed AND not on
//   the list — revealing neither their identity nor their secret.
//
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
const log = (...a) => console.log(...a);

async function main() {
  // --- ISSUER: certifies real identities ------------------------------------
  const issuer = await new Issuer(new Uint8Array(32).fill(9)).init();

  // --- AUTHORITY: publishes signed blocklist --------------------------------
  const blocked = ["ivan-sanctioned", "olga-sanctioned", "petr-sanctioned",
                   "sveta-sanctioned", "yuri-sanctioned"];
  const authority = await new Authority(new Uint8Array(32).fill(7))
    .init(await Promise.all(blocked.map(toIdentity)));
  const expiry = 4102444800n;
  const signed = authority.signedRoot(expiry);
  log("Authority published a signed blocklist:");
  log("  entries :", blocked.length);
  log("  root    :", signed.root.toString().slice(0, 22) + "...");

  // --- HOLDER: gets a credential, then proves exclusion locally -------------
  const me = await toIdentity("nadia-clean");     // NOT sanctioned
  const holder = await makeHolder("nadia-secret"); // only Nadia knows this
  const credential = issuer.issue(me, holder.holderCommit);
  const witness = await authority.exclusionWitness(me);
  const challenge = 987654321n;

  const input = buildCircuitInput({ identity: me, holder, credential, signedRoot: signed, witness, challenge });
  log("\nHolder generating zero-knowledge proof (credentialed + not on list)...");
  const t0 = Date.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  log(`  proof generated in ${Date.now() - t0}ms`);

  // --- VERIFIER -------------------------------------------------------------
  const vkey = JSON.parse(await fs.readFile(VKEY, "utf8"));
  const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
  log("\nVerifier result:", ok ? "✅ credentialed & NOT on the blocklist" : "❌ invalid");
  log("What the verifier learned about the holder: nothing (no identity, no secret).");
  log("Public signals (authority key, issuer key, root, expiry, challenge):");
  log("  ", publicSignals.join("\n   "));
  process.exit(ok ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
