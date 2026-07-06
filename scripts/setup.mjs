// Groth16 trusted setup for the exclusion circuit.
//
// NOTE ON TRUST: this script runs a *local, single-contributor* Powers-of-Tau
// phase-2 contribution. That is fine for a demo, but a production deployment
// MUST run a real multi-party ceremony (or switch to a universal-setup scheme
// such as Plonk) so that no single party knows the toxic waste. This is exactly
// the step the original blueprint glossed over.

import * as snarkjs from "snarkjs";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import https from "node:https";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");
const build = path.join(root, "build");

// 2^15 = 32768 constraints of capacity; our circuit uses ~22k.
const PTAU = path.join(build, "pot15_final.ptau");
const PTAU_URL =
  "https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_15.ptau";

function download(url, dest) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    https
      .get(url, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          file.close();
          return download(res.headers.location, dest).then(resolve, reject);
        }
        if (res.statusCode !== 200) {
          reject(new Error(`HTTP ${res.statusCode} for ${url}`));
          return;
        }
        res.pipe(file);
        file.on("finish", () => file.close(resolve));
      })
      .on("error", (err) => {
        fs.rmSync(dest, { force: true });
        reject(err);
      });
  });
}

async function main() {
  if (!fs.existsSync(PTAU)) {
    console.log("Downloading powers-of-tau (pot15, ~30MB)...");
    await download(PTAU_URL, PTAU);
  }

  const r1cs = path.join(build, "exclusion.r1cs");
  const zkey0 = path.join(build, "exclusion_0000.zkey");
  const zkeyFinal = path.join(build, "exclusion_final.zkey");
  const vkey = path.join(build, "verification_key.json");

  console.log("groth16 setup...");
  await snarkjs.zKey.newZKey(r1cs, PTAU, zkey0);

  console.log("phase-2 contribution (demo entropy)...");
  await snarkjs.zKey.contribute(zkey0, zkeyFinal, "poe-demo-1", "not-real-entropy-demo-only");

  console.log("exporting verification key...");
  const vk = await snarkjs.zKey.exportVerificationKey(zkeyFinal);
  fs.writeFileSync(vkey, JSON.stringify(vk, null, 2));

  fs.rmSync(zkey0, { force: true });
  console.log("Done:");
  console.log("  proving key : build/exclusion_final.zkey");
  console.log("  vkey        : build/verification_key.json");
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
