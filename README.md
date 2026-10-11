# ProofChain

Verifiable records and tamper detection (problem B-01, Domain 3: Blockchain and Decentralized Trust).

A registry gives every document a SHA-256 fingerprint, groups fingerprints into batches, summarises each batch with a Merkle tree, and publishes the root to a separate, append-only, signed ledger. Each document holder gets a small proof file. Anyone can then check one document against the published root without the registry's database, and is told which check failed.

A pass proves that a document is identical to one registered at a known point in the ledger. It does not prove who created the document or that its contents are true. The records are tamper-evident, not tamper-proof.

## Parts

| Part | Where | What it does |
|---|---|---|
| Core library | `proofchain/core/` | Canonical forms, fingerprint, Merkle tree, proof format. Standard library only. |
| Verifier | `proofchain/verifier/` | The five checks and a command line. Imports the core only. |
| Ledger | `proofchain/ledger/` | Service on port 8001 with its own key. Append and read only. |
| Registry | `proofchain/registry/` | Service on port 8000: upload, confirm, seal, proofs, self-audit, pages. |
| AI helper | `proofchain/ai/` | Suggests metadata and explains results. Advisory only; a person confirms. |
| Browser verifier | `web-verifier/index.html` | A second, independent implementation of the checks. One static file. |
| Demo scripts | `scripts/` | Seed sample data; alter the database as an insider would. |

The full specification is `context/ProofChain_Project_Brief.docx`.

## Install

Python 3.11 or newer.

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
```

## Run

Two services, each in its own terminal with the virtual environment activated.

```powershell
uvicorn proofchain.ledger.app:app --port 8001
```

```powershell
uvicorn proofchain.registry.app:app --port 8000
```

Open http://localhost:8000. Upload a file on **Register**, fill in its details and confirm, seal the batch on **Records and batches**, then download the document and its proof and check them on **Verify**.

Run-time files appear in `data/` (ignored by Git): `registry.db`, `ledger.jsonl`, `ledger_key.pem`. No `.env` file is needed; `.env.example` lists the settings and their defaults.

### AI suggestions (optional)

Without a key the registry uses simple text rules and fixed wording, and says so on the page. To use Claude, set a key in the terminal that starts the registry:

```powershell
$env:ANTHROPIC_API_KEY = "<your key>"
```

Verification results are identical with and without a key.

## Verify independently

From the command line, with the registry stopped if you like:

```powershell
python -m proofchain.verifier pin --ledger http://localhost:8001 --out data/pin.json
python -m proofchain.verifier verify --doc degree.pdf --proof degree.pdf.proof.json --ledger http://localhost:8001 --pin-file data/pin.json
```

`--ledger` also accepts a copy of `ledger.jsonl`, so this works offline. Exit code 0 means every check passed, 1 means verification failed, 2 means an input could not be read.

In a browser: open `web-verifier/index.html` directly from disk. Choose the document, the proof, and either a copy of the ledger file or the ledger's URL, plus a pin file. Nothing is uploaded.

| Code | Meaning |
|---|---|
| `DOCUMENT_MODIFIED` | The document does not hash to the fingerprint in the proof. |
| `PROOF_INVALID` | The proof's path does not reach the proof's root, or the proof is malformed. |
| `BATCH_NOT_PUBLISHED` | The ledger has no entry for the proof's batch. |
| `ROOT_MISMATCH` | The proof's root or tree size differs from the published entry. |
| `LEDGER_INVALID` | A broken link, wrong entry hash or signature, or a pinned checkpoint is missing. |

## Demo

Start from empty data: stop both services and delete `data/registry.db`, `data/ledger.jsonl`, `data/pin.json` and `data/demo/` together. Then start the ledger and the registry again.

**1. Seed.** Registers four sample documents, seals them into a batch, leaves a fifth waiting on the Register page, and writes documents, proofs and `pin.json` to `data/demo/`.

```powershell
python scripts/demo_seed.py
```

**2. Verify an honest document.** Stop the registry first to show it is not needed.

```powershell
python -m proofchain.verifier verify --doc data/demo/degree_asha_rao.txt --proof data/demo/degree_asha_rao.txt.proof.json --ledger http://localhost:8001 --pin-file data/demo/pin.json
```

**3. Edit the document.** Change one character of a copy and verify it: `DOCUMENT_MODIFIED`.

**4. Corrupt the proof.** Change one hash in a copy of the proof: `PROOF_INVALID`.

**5. Attack the database.** Rewrites a record's content, its fingerprint and the batch root with plain SQL, so the database agrees with itself, and issues a fresh proof.

```powershell
python scripts/tamper.py rewrite
python -m proofchain.verifier verify --doc data/demo/forged_transcript_asha_rao.txt --proof data/demo/forged_transcript_asha_rao.txt.proof.json --ledger http://localhost:8001 --pin-file data/demo/pin.json
```

The verifier reports `ROOT_MISMATCH`, and the registry's **Audit** page flags the batch with `BATCH_ROOT_DIVERGED`. Every honest holder's document still verifies.

**6. Attack the ledger.** Models an attacker who also holds the ledger key. It writes a rewritten, re-signed copy and leaves the real ledger alone.

```powershell
python scripts/tamper.py ledger
python -m proofchain.verifier verify --doc data/demo/forged_transcript_asha_rao.txt --proof data/demo/forged_transcript_asha_rao.txt.proof.json --ledger data/demo/ledger_rewritten.jsonl --pin-file data/demo/pin.json
```

With the pin file the result is `LEDGER_INVALID`. Without a pin (pass `--pubkey` instead of `--pin-file`) the forged document passes, which is why verifiers pin checkpoints.

**7. Undo.** Puts the database back as it was before the first change.

```powershell
python scripts/tamper.py restore
```

`tamper.py content` and `tamper.py fingerprint` change one thing at a time, to show `STORED_CONTENT_CHANGED` and `STORED_FINGERPRINT_CHANGED` on the Audit page.

## Tests

```powershell
pytest
```

The end-to-end tests start a real ledger on a spare port and run the demo scripts and the verifier as separate processes. Two of them run the browser verifier's rules under Node.js and compare its verdicts with the Python verifier's; they are skipped if Node.js is not installed.

## Limits

- The registry can register a false document. It will verify, because it matches what was registered.
- A verifier with no pinned checkpoint cannot notice a ledger that was rewritten in full by whoever holds its key.
- The ledger's append endpoint has no authentication, and the registry pages have no login. Both are fine on one machine and need addressing before any shared deployment.
- An AI-written explanation is shown beside the verdict and cannot change it, but its wording is not machine-checked.
