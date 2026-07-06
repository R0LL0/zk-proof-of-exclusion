// End-to-end demo you can run from the CLI:  npm run prove:demo
//
//   Authority builds a blocklist of 5 sanctioned ids, signs the Merkle root.
//   A clean user generates a zero-knowledge proof that they are NOT on it.
//   A verifier checks the proof knowing ONLY the authority key, root & challenge.
//
import path from "node:path";
import fs from "node:fs/promises";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";
import { Authority, toIdentity, buildCircuitInput } from "../lib/poe.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const build = path.resolve(__dirname, "..", "build");
const WASM = path.join(build, "exclusion_js", "exclusion.wasm");
const ZKEY = path.join(build, "exclusion_final.zkey");
const VKEY = path.join(build, "verification_key.json");

const log = (...a) => console.log(...a);

async function main() {
  // --- AUTHORITY side -------------------------------------------------------
  const authoritySecret = new Uint8Array(32).fill(7); // demo key
  const blocklistNames = ["ivan-sanctioned", "olga-sanctioned", "petr-sanctioned",
                          "sveta-sanctioned", "yuri-sanctioned"];
  const blocklist = await Promise.all(blocklistNames.map(toIdentity));
  const authority = await new Authority(authoritySecret).init(blocklist);

  const expiry = 4102444800n; // 2100-01-01
  const signed = authority.signedRoot(expiry);
  log("Authority published a signed blocklist:");
  log("  entries :", blocklistNames.length);
  log("  root    :", signed.root.toString().slice(0, 24) + "...");
  log("  pubkey  :", signed.authorityAx.toString().slice(0, 16) + "...");

  // --- USER side (all local / in-browser in the real app) -------------------
  const me = await toIdentity("nadia-clean"); // NOT sanctioned
  const witness = await authority.exclusionWitness(me);
  const challenge = 987654321n; // verifier hands this out per request

  const input = buildCircuitInput({ identity: me, signedRoot: signed, witness, challenge });
  log("\nUser generating zero-knowledge proof of NON-membership...");
  const t0 = Date.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  log(`  proof generated in ${Date.now() - t0}ms`);

  // --- VERIFIER side --------------------------------------------------------
  const vkey = JSON.parse(await fs.readFile(VKEY, "utf8"));
  const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
  log("\nVerifier result:", ok ? "✅ NOT on the blocklist (proof valid)" : "❌ invalid");
  log("What the verifier learned about the user's identity: nothing.");
  log("Public signals (authority key, root, expiry, challenge only):");
  log("  ", publicSignals.join("\n   "));

  process.exit(ok ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
