# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Current state

Stage 1 (the core library) is implemented and tested: `proofchain/core/` with `tests/test_canonical.py`, `test_merkle.py`, `test_proof.py` and the format part of `test_ledger.py`. Everything else under `proofchain/`, `scripts/`, `tests/` and `web-verifier/`, plus `README.md`, is still an empty file. Update this file as that changes.

`tests/vectors/examples.json` holds the brief's worked examples (hashes, trees, paths, a three-entry ledger chain) and is exposed as the `vectors` fixture. New code must keep reproducing them.

The specification is `context/ProofChain_Project_Brief.docx` (problem B-01, Domain 3: Blockchain and Decentralized Trust). It is the source of truth for formats, result codes, endpoints and build order. `context/filestructureinfo.docx` explains what each file is intended to hold. Both are `.docx`; extract the text to read them (for example `unzip -p <file> word/document.xml` and strip the tags).

`_build/` is git-ignored. It holds the working files that generated the brief, not project code.

## What ProofChain is

A registry gives every document a SHA-256 fingerprint, groups fingerprints into batches, summarises each batch with a Merkle tree, and publishes the root to a separate append-only signed ledger. Each document holder gets a proof bundle. Anyone can then verify a document against the published root without the registry's database.

The threat model assumes an insider with full read and write access to the registry database. The verdict must therefore depend on the ledger root and never on registry data.

## Commands

Setup and `pytest` work now. The service and verifier commands are the ones planned in the brief and do not work until those stages are written.

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"

# Two services, separate terminals
uvicorn proofchain.ledger.app:app --port 8001
uvicorn proofchain.registry.app:app --port 8000

# Verifier CLI (exit code 0 only when every check passes)
python -m proofchain.verifier verify --doc degree.pdf --proof degree.proof.json --ledger http://localhost:8001 --pin 1:<entry_hash>
python -m proofchain.verifier pin --ledger http://localhost:8001

# Tests
pytest
pytest tests/test_merkle.py
pytest tests/test_merkle.py::test_name
```

`--ledger` must also accept a local copy of the ledger file so verification works offline. Python 3.11+ is required. No linter or formatter has been chosen.

## Architecture

Four components, separated so that the registry (the thing being checked) has no control over the ledger (what it is checked against) and no part in the verifier (the checking).

| Package | May import | Role |
|---|---|---|
| `proofchain/core` | Python standard library only | Canonical forms, fingerprint, Merkle tree, proof format, ledger entry format |
| `proofchain/verifier` | `core`, plus `cryptography` for Ed25519 checks | The five checks and the CLI |
| `proofchain/ledger` | `core` | FastAPI service on 8001, JSONL hash chain, its own Ed25519 key |
| `proofchain/registry` | `core`, `ai`; reaches the ledger over HTTP only | FastAPI service on 8000, SQLite, server-rendered pages, self-audit |
| `proofchain/ai` | not imported by `core` or `verifier` | Metadata suggestions and plain-language explanations |

`web-verifier/index.html` sits outside the package on purpose: it is a second, independent implementation of the verification rules using WebCrypto, with no backend.

### Rules that must not be broken

- `core` and `verifier` never import from `registry` or `ai`. `tests/test_isolation.py` exists to enforce this.
- The verifier never calls the registry or reads its database. It uses only the document, the proof bundle and the ledger.
- The ledger has no update or delete endpoint. Entries are only appended.
- Metadata is not part of the leaf hash, so nothing the AI suggests can change a fingerprint, proof or root.
- AI output is stored as a suggestion. Only an explicit Confirm action by a person writes metadata, and a record cannot enter a batch until then.
- AI explanations are generated after the verifier has finished, from its result codes, and are labelled as AI-written.
- With no API key, or when a call fails, `ai/fallback.py` provides rule-based suggestions and templated explanations. Verification results must be identical with and without a key.

### Cryptographic rules

- Canonical forms, named in every proof: `raw-bytes-v1` (exact file bytes, never normalised) and `json-sorted-v1` (UTF-8, Unicode NFC, sorted keys, no whitespace, integers only; modelled on RFC 8785).
- Leaf = `SHA-256(0x00 || fingerprint)`. Node = `SHA-256(0x01 || left || right)`.
- An unpaired entry at any level is promoted unchanged. It is never duplicated (avoids the CVE-2012-2459 weakness).
- Ledger `entry_hash` is the SHA-256 of the canonical JSON of `seq`, `batch_id`, `root`, `tree_size`, `published_at`, `prev_hash`. The signature is Ed25519 over `entry_hash`.
- Verifiers pin a checkpoint (`seq:entry_hash`) and reject any ledger that does not contain it.
- Ledger `seq` starts at 0 and the first entry's `prev_hash` is 64 zeros.
- A proof's path shape is fixed by `leaf_index` and `tree_size` (`merkle.expected_sides`). `proof.from_dict` rejects a bundle whose sides or length differ, and rejects unknown fields and uppercase hex.
- `core` checks structure and hashes only. Ed25519 signatures and pinned checkpoints are outside it because `core` is standard library only.

### Verifier result codes

All five checks run every time; the verifier does not stop at the first failure. Each check isolates one cause: check 2 folds the path from the bundle's own fingerprint, not from the document, so an edited document does not also raise a proof error.

| Code | Condition |
|---|---|
| `DOCUMENT_MODIFIED` | Hash of the canonical document differs from the bundle's fingerprint |
| `PROOF_INVALID` | Folding the path from the bundle's fingerprint does not give the bundle's root, or the bundle is malformed |
| `BATCH_NOT_PUBLISHED` | The ledger has no entry for the bundle's batch id |
| `ROOT_MISMATCH` | The bundle's root or tree size differs from the ledger entry |
| `LEDGER_INVALID` | Broken `prev_hash` link, wrong entry hash or signature, or pinned checkpoint missing |

Registry self-audit codes: `STORED_CONTENT_CHANGED`, `STORED_FINGERPRINT_CHANGED`, `BATCH_ROOT_DIVERGED`.

## Build order

The brief stages the work so that stages 1 to 3 give a complete, judgeable core: (1) core library, (2) verifier and CLI, (3) ledger service, (4) registry, audit and UI, (5) AI helper, (6) demo scripts, static verifier, README. The brief's worked examples (sections 3.1 to 3.4 and 7.2) contain real hash values to use as test vectors.

## Wording in the product

A pass proves that a document matches a reference registered at a known point in the ledger. It does not prove authorship or that the contents are true, and the UI must say so wherever it shows a result. Use "tamper-evident", not "tamper-proof"; "matches the record registered in batch N", not "authentic"; never "AI verified this document"; never "the ledger is immutable".

## Repository notes

- Remote: `AeroSalu/ProofChain-Verifiable-Records-Tamper-Detection` (public). Branches: `main` and `dev`.
- `data/` holds the runtime SQLite database, ledger JSONL file and ledger key. Its contents are git-ignored. The paths come from `PROOFCHAIN_DB_PATH`, `PROOFCHAIN_LEDGER_PATH` and `PROOFCHAIN_LEDGER_KEY_PATH` (see `.env.example`); nothing reads them yet.
- Work happens on `dev`.
- No public blockchain, tokens or smart contracts: they are explicitly out of scope.
