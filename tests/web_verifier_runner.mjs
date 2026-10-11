// Runs the verification rules from web-verifier/index.html outside a browser, so the
// tests can compare the page's verdicts with the Python verifier's.
//
//   node web_verifier_runner.mjs verify <document> <proof> <ledger.jsonl> <public key hex> [seq:entry_hash]
//   node web_verifier_runner.mjs canon          (stdin: JSON list of base64 documents)

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const page = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "web-verifier", "index.html"), "utf8");
const core = /\/\/ ==core:start([\s\S]*?)\/\/ ==core:end/.exec(page)[1];
const rules = new Function(`${core}
  return { verifyDocument, canonicalize, parseLedgerLines, parsePin, decodeUtf8, fromHex, toHex, sha256, Malformed };`)();

const [mode, ...args] = process.argv.slice(2);

if (mode === "verify") {
  const [documentPath, proofPath, ledgerPath, publicKey, pin] = args;
  let proofText = null;
  try { proofText = rules.decodeUtf8(readFileSync(proofPath)); } catch { /* reported as PROOF_INVALID */ }
  const result = await rules.verifyDocument({
    document: new Uint8Array(readFileSync(documentPath)),
    proofText,
    entries: rules.parseLedgerLines(rules.decodeUtf8(readFileSync(ledgerPath))),
    publicKey: rules.fromHex(publicKey),
    pin: pin ? rules.parsePin(pin) : null,
  });
  console.log(JSON.stringify(result));
} else if (mode === "canon") {
  const documents = JSON.parse(readFileSync(0, "utf8"));
  const out = [];
  for (const encoded of documents) {
    try {
      const canonical = rules.canonicalize("json-sorted-v1", new Uint8Array(Buffer.from(encoded, "base64")));
      out.push({ fingerprint: rules.toHex(await rules.sha256(canonical)) });
    } catch (error) {
      if (!(error instanceof rules.Malformed)) throw error;
      out.push({ error: error.message });
    }
  }
  console.log(JSON.stringify(out));
} else {
  console.error("usage: web_verifier_runner.mjs verify|canon ...");
  process.exit(2);
}
