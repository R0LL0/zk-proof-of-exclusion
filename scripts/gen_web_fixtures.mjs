// Prepares the static browser demo:
//   - builds a signed demo blocklist (authority side, runs here in Node)
//   - precomputes circuit inputs for a few "clean" identities
//   - marks some identities as blocklisted (no witness can exist)
//   - copies wasm / zkey / vkey into web/vendor so the page is self-contained
//
// The BROWSER still does the expensive, privacy-critical part — groth16 proof
// generation — entirely client-side. Authority signing & witness derivation are
// precomputed here because in a real deployment the authority is a backend and
// the witness comes from public list data.
import path from "node:path";
import fs from "node:fs";
import fsp from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { Authority, toIdentity, buildCircuitInput } from "../lib/poe.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");
const build = path.join(root, "build");
const web = path.join(root, "web");
const vendor = path.join(web, "vendor");
fs.mkdirSync(vendor, { recursive: true });

// Serialize BigInts as decimal strings for JSON transport.
const S = (obj) => JSON.parse(JSON.stringify(obj, (_, v) =>
  typeof v === "bigint" ? v.toString() : v));

async function main() {
  const authoritySecret = new Uint8Array(32).fill(7);
  const blocked = ["ivan-sanctioned", "olga-sanctioned", "petr-sanctioned"];
  const clean = ["nadia-clean", "leo-clean", "mia-clean"];

  const blockedIds = await Promise.all(blocked.map(toIdentity));
  const authority = await new Authority(authoritySecret).init(blockedIds);
  const expiry = 4102444800n;
  const signed = authority.signedRoot(expiry);
  const challenge = 987654321n;

  const identities = [];
  for (const name of clean) {
    const id = await toIdentity(name);
    const witness = await authority.exclusionWitness(id);
    identities.push({
      name, blocked: false,
      input: S(buildCircuitInput({ identity: id, signedRoot: signed, witness, challenge })),
    });
  }
  for (const name of blocked) {
    identities.push({ name, blocked: true, input: null });
  }

  const vkey = JSON.parse(await fsp.readFile(path.join(build, "verification_key.json"), "utf8"));
  const fixtures = {
    challenge: challenge.toString(),
    authority: { Ax: signed.authorityAx.toString(), Ay: signed.authorityAy.toString() },
    root: signed.root.toString(),
    expiry: expiry.toString(),
    blocklistSize: blocked.length,
    vkey,
    identities,
  };
  await fsp.writeFile(path.join(web, "fixtures.json"), JSON.stringify(fixtures, null, 2));

  // Copy proving artifacts + snarkjs UMD bundle into web/vendor.
  fs.copyFileSync(path.join(build, "exclusion_js", "exclusion.wasm"), path.join(vendor, "exclusion.wasm"));
  fs.copyFileSync(path.join(build, "exclusion_final.zkey"), path.join(vendor, "exclusion_final.zkey"));
  fs.copyFileSync(path.join(root, "node_modules", "snarkjs", "build", "snarkjs.min.js"), path.join(vendor, "snarkjs.min.js"));

  console.log("web/ fixtures + vendor artifacts written:");
  console.log("  identities:", identities.length, "(clean:", clean.length, "blocked:", blocked.length + ")");
  console.log("  wasm/zkey/vkey/snarkjs copied to web/vendor/");
}

main().catch((e) => { console.error(e); process.exit(1); });
