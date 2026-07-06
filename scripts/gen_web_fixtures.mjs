// Prepares the static browser demo (v2, credential-bound):
//   - Issuer certifies each demo holder's identity (signed credential)
//   - Authority builds a signed blocklist
//   - precomputes full circuit inputs for "clean" credentialed holders
//   - marks blocklisted identities (no exclusion witness can exist)
//   - copies wasm / zkey / snarkjs into docs/vendor so the page is self-contained
//
// The BROWSER still does the expensive, privacy-critical part — groth16 proof
// generation — entirely client-side.
import path from "node:path";
import fs from "node:fs";
import fsp from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { Authority, Issuer, toIdentity, makeHolder, buildCircuitInput } from "../lib/poe.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");
const build = path.join(root, "build");
const web = path.join(root, "docs"); // served by GitHub Pages from /docs
const vendor = path.join(web, "vendor");
fs.mkdirSync(vendor, { recursive: true });

const S = (obj) => JSON.parse(JSON.stringify(obj, (_, v) =>
  typeof v === "bigint" ? v.toString() : v));

async function main() {
  const issuer = await new Issuer(new Uint8Array(32).fill(9)).init();
  const blocked = ["ivan-sanctioned", "olga-sanctioned", "petr-sanctioned"];
  const clean = ["nadia-clean", "leo-clean", "mia-clean"];

  const authority = await new Authority(new Uint8Array(32).fill(7))
    .init(await Promise.all(blocked.map(toIdentity)));
  const expiry = 4102444800n;
  const signed = authority.signedRoot(expiry);
  const challenge = 987654321n;

  const identities = [];
  for (const name of clean) {
    const id = await toIdentity(name);
    const holder = await makeHolder(name + "-secret");
    const credential = issuer.issue(id, holder.holderCommit);
    const witness = await authority.exclusionWitness(id);
    identities.push({
      name, blocked: false,
      input: S(buildCircuitInput({ identity: id, holder, credential, signedRoot: signed, witness, challenge })),
    });
  }
  for (const name of blocked) identities.push({ name, blocked: true, input: null });

  const vkey = JSON.parse(await fsp.readFile(path.join(build, "verification_key.json"), "utf8"));
  const fixtures = {
    challenge: challenge.toString(),
    authority: { Ax: signed.authorityAx.toString(), Ay: signed.authorityAy.toString() },
    issuer: { Ax: issuer.publicKey.Ax.toString(), Ay: issuer.publicKey.Ay.toString() },
    root: signed.root.toString(),
    expiry: expiry.toString(),
    blocklistSize: blocked.length,
    vkey,
    identities,
  };
  await fsp.writeFile(path.join(web, "fixtures.json"), JSON.stringify(fixtures, null, 2));

  fs.copyFileSync(path.join(build, "exclusion_js", "exclusion.wasm"), path.join(vendor, "exclusion.wasm"));
  fs.copyFileSync(path.join(build, "exclusion_final.zkey"), path.join(vendor, "exclusion_final.zkey"));
  fs.copyFileSync(path.join(root, "node_modules", "snarkjs", "build", "snarkjs.min.js"), path.join(vendor, "snarkjs.min.js"));

  console.log("docs/ fixtures + vendor artifacts written:");
  console.log("  identities:", identities.length, "(clean:", clean.length, "blocked:", blocked.length + ")");
  console.log("  wasm/zkey/snarkjs copied to docs/vendor/");
}

main().catch((e) => { console.error(e); process.exit(1); });
