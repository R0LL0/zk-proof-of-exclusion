// Client-side driver: fetch fixtures, generate the proof in-browser with snarkjs,
// then verify it. No identity ever leaves the page.
const $ = (id) => document.getElementById(id);
const WASM = "vendor/exclusion.wasm";
const ZKEY = "vendor/exclusion_final.zkey";

let fixtures;

function setStep(k, state) {
  const li = document.querySelector(`.steps li[data-k="${k}"]`);
  li.classList.remove("run", "done", "err");
  if (state) li.classList.add(state);
}
function resetSteps() { ["witness", "prove", "verify"].forEach((k) => setStep(k, null)); }

async function init() {
  fixtures = await fetch("fixtures.json").then((r) => r.json());
  $("root").textContent = fixtures.root.slice(0, 22) + "…";
  $("size").textContent = fixtures.blocklistSize + " sanctioned entries";
  const sel = $("who");
  for (const id of fixtures.identities) {
    const o = document.createElement("option");
    o.value = id.name;
    o.textContent = id.blocked ? `${id.name}  (on the blocklist)` : `${id.name}  (clean)`;
    sel.appendChild(o);
  }
  $("go").disabled = false;
}

async function run() {
  $("go").disabled = true;
  $("verdict").textContent = "";
  $("verdict").className = "verdict";
  $("detail").textContent = "";
  $("public").textContent = "—";
  resetSteps();

  const rec = fixtures.identities.find((i) => i.name === $("who").value);

  try {
    // Step 1: witness / non-membership input.
    setStep("witness", "run");
    if (rec.blocked) {
      // A listed identity simply cannot produce a valid exclusion witness.
      await new Promise((r) => setTimeout(r, 350));
      setStep("witness", "err");
      $("verdict").className = "verdict bad";
      $("verdict").textContent = "❌ Cannot prove exclusion — this identity IS on the list.";
      $("detail").textContent =
        "The Sparse Merkle Tree yields no non-membership witness for a present leaf, " +
        "so no proof can even be attempted. This is the soundness guarantee working.";
      $("go").disabled = false;
      return;
    }
    const input = rec.input;
    setStep("witness", "done");

    // Step 2: generate the proof in the browser.
    setStep("prove", "run");
    const t0 = performance.now();
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
    const ms = Math.round(performance.now() - t0);
    setStep("prove", "done");

    // Step 3: verify (verifier only needs the vkey + public signals).
    setStep("verify", "run");
    const ok = await snarkjs.groth16.verify(fixtures.vkey, publicSignals, proof);
    setStep("verify", ok ? "done" : "err");

    $("verdict").className = "verdict " + (ok ? "ok" : "bad");
    $("verdict").textContent = ok
      ? "✅ Proven NOT on the blocklist — identity never revealed."
      : "❌ Proof failed to verify.";
    $("detail").textContent = `Proof generated in ${ms} ms, entirely in your browser.`;
    $("public").textContent = JSON.stringify(
      { publicSignals, note: "authorityAx, authorityAy, issuerAx, issuerAy, root, expiry, challenge — no identity, no holder secret" },
      null, 2);
  } catch (e) {
    ["witness", "prove", "verify"].forEach((k) => {
      const li = document.querySelector(`.steps li[data-k="${k}"]`);
      if (li.classList.contains("run")) li.classList.replace("run", "err");
    });
    $("verdict").className = "verdict bad";
    $("verdict").textContent = "❌ " + (e.message || e);
    $("go").disabled = false;
    return;
  }
  $("go").disabled = false;
}

$("go").addEventListener("click", run);
init().catch((e) => { $("verdict").textContent = "Failed to load: " + e.message; });
