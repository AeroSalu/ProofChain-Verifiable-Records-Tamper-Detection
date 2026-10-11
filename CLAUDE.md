# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Current state

All six build stages are implemented and tested: `proofchain/core/`, `proofchain/verifier/`, `proofchain/ledger/`, `proofchain/registry/` (service, audit and pages), `proofchain/ai/`, and stage 6: `scripts/demo_seed.py`, `scripts/tamper.py`, `web-verifier/index.html`, `tests/test_end_to_end.py` and `README.md`. Of the optional standout features in section 8 of the brief, salted leaves and the static browser verifier are built; nothing else is. Uploading content that is already registered is allowed but warned about (`models.same_content`, the `warning` banner). Update this file as that changes.

`web-verifier/index.html` re-implements the verification rules in JavaScript between the `// ==core:start` and `// ==core:end` markers. `tests/web_verifier_runner.mjs` runs that block under Node, and `tests/test_end_to_end.py` requires its verdicts, statuses and hashes to equal the Python verifier's. A change to a rule in `core/` or `verifier/` (for example the leaf value or the bundle versions) must be made in that block too, and the parity tests are skipped when Node.js is missing, so run them where it is installed.

The AI helper has only been run against a mock transport. It has not been called with a real credential.

`tests/vectors/examples.json` holds the brief's worked examples (hashes, trees, paths, a three-entry ledger chain) and is exposed as the `vectors` fixture. New code must keep reproducing them.

The specification is `context/ProofChain_Project_Brief.docx` (problem B-01, Domain 3: Blockchain and Decentralized Trust). It is the source of truth for formats, result codes, endpoints and build order. `context/filestructureinfo.docx` explains what each file is intended to hold. Both are `.docx`; extract the text to read them (for example `unzip -p <file> word/document.xml` and strip the tags).

`_build/` is git-ignored. It holds the working files that generated the brief, not project code.

## What ProofChain is

A registry gives every document a SHA-256 fingerprint, groups fingerprints into batches, summarises each batch with a Merkle tree, and publishes the root to a separate append-only signed ledger. Each document holder gets a proof bundle. Anyone can then verify a document against the published root without the registry's database.

The threat model assumes an insider with full read and write access to the registry database. The verdict must therefore depend on the ledger root and never on registry data.

## Commands

Setup, `pytest`, the verifier CLI and both services work now. Start the ledger before sealing a batch; the registry finds it at `PROOFCHAIN_LEDGER_URL` (default `http://localhost:8001`).

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"

# Once: a staff account (prompts for the password; --reset changes one, --admin makes an admin)
python -m proofchain.registry.staff add <username>
python -m proofchain.registry.staff admin <username>     # --revoke to undo
python -m proofchain.registry.staff list

# Two services, separate terminals, the same $env:PROOFCHAIN_LEDGER_TOKEN set in both
uvicorn proofchain.ledger.app:app --port 8001
uvicorn proofchain.registry.app:app --port 8000

# Verifier CLI (exit code 0 only when every check passes)
python -m proofchain.verifier verify --doc degree.pdf --proof degree.proof.json --ledger http://localhost:8001 --pin 1:<entry_hash>
python -m proofchain.verifier pin --ledger http://localhost:8001

# Demo (ledger must be running; see README.md for the full walk-through)
python scripts/demo_seed.py            # needs an empty database, or --add
python scripts/tamper.py rewrite       # also: content, fingerprint, ledger, restore

# Tests
pytest
pytest tests/test_merkle.py
pytest tests/test_merkle.py::test_name
```

`tests/test_end_to_end.py` starts a real ledger on a spare port and runs the scripts and the CLI as subprocesses, so it is the slowest file (about 45 seconds). `tamper.py` copies the database to `<db>.before-tamper` before its first change; `restore` puts it back. `tamper.py ledger` never edits the real ledger file: it writes a re-signed copy to the output folder.

The ledger sends `Access-Control-Allow-Origin: *` for GET only, so the static browser verifier can read it from a `file://` page. Do not widen that to POST.

`--ledger` takes the ledger URL or a local ledger file, so verification works offline. A ledger file needs `--pubkey <hex>` or `--pin-file`; with a URL and neither, the key is fetched from the ledger and a warning is printed. `pin --out FILE` saves the checkpoint together with the public key, and `verify --pin-file FILE` uses both. `--json` prints the result as JSON. Exit codes: 0 verified, 1 verification failed, 2 inputs could not be read (not a verdict).

Python 3.11+ is required. No linter or formatter has been chosen.

## Architecture

Four components, separated so that the registry (the thing being checked) has no control over the ledger (what it is checked against) and no part in the verifier (the checking).

| Package | May import | Role |
|---|---|---|
| `proofchain/core` | Python standard library only | Canonical forms, fingerprint, Merkle tree, proof format, ledger entry format |
| `proofchain/verifier` | `core`, plus `cryptography` for Ed25519 checks | The five checks and the CLI |
| `proofchain/ledger` | `core` | FastAPI service on 8001, JSONL hash chain, its own Ed25519 key |
| `proofchain/registry` | `core`, `verifier`, `ai`; reaches the ledger over HTTP only | FastAPI service on 8000, SQLite, server-rendered pages, self-audit |
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
- Leaf = `SHA-256(0x00 || leaf value)`. Node = `SHA-256(0x01 || left || right)`.
- The leaf value is the fingerprint in an unsalted batch, and `SHA-256(0x02 || salt || fingerprint)` in a salted one (`merkle.leaf_value`, `proof.leaf_values`). The registry gives every record a random 32-byte salt (`models.new_salt`) and always builds salted batches, so two registrations of the same content are different leaves and a sibling hash cannot be matched against a guessed document.
- Proof bundles have two versions. Version 1 is unsalted and has no `salt` field; version 2 has one. Both verify. A version 1 bundle with a salt, a version 2 bundle without one, and any other version are malformed. The brief's worked examples and `tests/vectors/examples.json` are unsalted (version 1); registry roots never equal them.
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

If the proof bundle is malformed or not JSON, the fingerprint, publication and root checks are reported as skipped, the result is `PROOF_INVALID`, and the ledger check still runs. `verifier/verify.py` does no file or network access; `verifier/cli.py` does all of it.

### Ledger service

The verifier and the ledger agree on these, so change them together:

- Signature: Ed25519 over the 32 raw bytes of `entry_hash`, stored as base64 in `signature`.
- Public key: 32 raw bytes, written as 64 hex characters.
- `GET /entries` returns a JSON list of entries in order; `GET /pubkey` returns `{"public_key": "<hex>"}`; `GET /head` returns `{"seq", "entry_hash"}` or 404 when empty.
- Ledger file: one JSON entry per line.

Behaviour:

- `POST /entries` takes `batch_id`, `root`, `tree_size` only. The service sets `seq`, `published_at`, `prev_hash`, `entry_hash` and `signature`. A second POST for the same batch id returns 409. It needs the append token (see below).
- The whole chain and every signature are checked at startup. A damaged file, or one signed by a different key, raises `LedgerCorrupt` and the service does not start.
- A file with its last entries removed is still a sound chain, so the ledger does not notice truncation. Only a verifier holding a pin for a removed entry does.
- Importing `ledger/app.py` opens no files. Tests build their own instance with `create_app(ledger_path, key_path)` inside `with TestClient(...)` so startup runs. Without arguments the paths come from `PROOFCHAIN_LEDGER_PATH` and `PROOFCHAIN_LEDGER_KEY_PATH`, defaulting to `data/`.

### Registry service

- The registry imports the verifier: its Verify page and the audit's ledger check call the same `verify` and `ledger_problems` as the CLI. The reverse is still forbidden, and the registry never imports `proofchain.ledger`; `ledger_client.py` is its only route to the ledger.
- The Verify page is a convenience, not an independent check: it takes the ledger key and checkpoint from the registry's own database, and says so.
- Tables are `records`, `batches` and `meta`. Beyond the brief: `batches.ledger_entry_hash`, and `meta` holds the ledger public key seen at the first seal. Together they are the registry's own checkpoint, used by the audit. They live in the database an insider controls, so they catch a ledger-side rewrite, not one where the insider edits them as well.
- Staff sign in. `registry/staff.py` holds accounts (table `staff`, scrypt hashes, created only by `python -m proofchain.registry.staff add`); `registry/sessions.py` signs the HttpOnly, SameSite=Lax session cookie with `PROOFCHAIN_SESSION_SECRET`, or a secret generated into `session_secret` beside the database. Routes take `user: Staff` (redirects to `/login?next=...` when signed out) or `user: MaybeStaff` (public). `confirmed_by` is the session user; the form has no field for it and a posted value is not read. `batching.confirm_record` is the only place metadata is written.
- Batches are per custodian. `batches.owner` is whoever's confirmations fill the batch; `batching.confirm_record` puts a record in the confirmer's own open batch and opens one if needed. A partial unique index allows one open batch per owner. `batching.seal_batch(conn, batch_id, ledger, sealed_by, admin)` raises `Forbidden` (403) unless the sealer is the owner or `staff.is_admin`; `batches.sealed_by` records who sealed. Batch ids stay `batch-NNNN` in creation order. Owner and sealer live in the registry database only, never in a proof or ledger entry.
- New columns go in `models.ADDED_COLUMNS` as well as `SCHEMA`: `db.init_db` adds any an existing database lacks. When `batches.owner` is first added, a batch whose records were all confirmed under one name gets that name as owner; others stay ownerless and only an admin can seal them.
- Public, and must stay so: `GET`/`POST /verify`, `/login`, `/static`. Everything else on the registry needs a session.
- Sign-in gives accountability for who confirmed a record. It does not change the trust model; do not word it as making records trustworthy.
- `create_app(db_path, ledger, suggest, explain)`: `suggest(filename, content) -> dict` and `explain(result)` are the AI hooks and default to none, so tests build a service without AI. A hook that raises is ignored. The module-level `app` that uvicorn runs passes `ai.suggest_metadata` and `ai.explain_result`.
- Sealing publishes the root to the ledger first, then marks the batch sealed. If the ledger already holds the same root for that batch, the seal adopts it; if it holds a different one, the seal is refused with 409.
- Form posts redirect (303) on success. Errors render a page with a real status code: 404, 409, 413, 422, 502.
- `GET /records/{id}/document` downloads the stored document alongside its proof.

### AI helper

- `ai.suggest_metadata(filename, content) -> dict` and `ai.explain_result(result) -> Explanation(text, source)`. Neither ever raises.
- Claude is called only when `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN` is set. Without one, no client is built and no network call is made. Any failure (no network, bad key, rate limit, refusal, malformed reply) falls back to `ai/fallback.py`: text rules for suggestions, fixed wording for explanations.
- Every result names its source, and the pages show it: suggestions are "by Claude (AI)" or "by simple text rules"; explanations are tagged "written by AI" or "standard wording". Fixed wording must never be presented as AI.
- Requests: `client.beta.messages.parse` / `.create` with model `claude-opus-5-5` (override with `PROOFCHAIN_AI_MODEL`), `output_config={"effort": "low"}`, `betas=["server-side-fallback-2026-07-01"]` with `fallbacks="default"`, no `thinking` parameter. Suggestions use structured output (`output_format=Suggestion`). The client has a 45 second timeout and one retry, and uploads wait for it.
- PDFs and PNG/JPEG images are sent as the file; text is sent as text, capped at the first 20,000 characters with a note; other binary files are not sent.
- The explanation is given only `ok`, `codes` and each check's name, status and detail, never hashes. Its text is not machine-checked: a wrong explanation can be displayed, but the verdict banner and codes come from the verifier and cannot move.
- `ai` imports nothing else from `proofchain`. Tests point the real SDK at an `httpx2.MockTransport` (the SDK is 1.x, built on `httpx2`, not `httpx`).

Self-audit codes: `STORED_CONTENT_CHANGED`, `STORED_FINGERPRINT_CHANGED`, `BATCH_ROOT_DIVERGED`. When content and fingerprint are rewritten consistently, the audit flags the batch and marks its records "not confirmed"; it cannot say which record changed, because the ledger holds only the root.

### Ledger append token

`POST /entries` needs `Authorization: Bearer <PROOFCHAIN_LEDGER_TOKEN>`, compared in constant time: 401 without the right token, and 503 with an explanation if the ledger was started without the setting. Every `GET` on the ledger is open. `LedgerClient` sends the token with the append only. `scripts/demo_seed.py` publishes a root, so it needs the token in its environment too.

### Tests for the services

`tests/conftest.py` sets `PROOFCHAIN_LEDGER_TOKEN` for every test, and the `registry` fixture is already signed in as `helpers.STAFF`. A test that builds its own registry client calls `helpers.sign_in(client)`, which sets a signed cookie directly and avoids a slow password hash; `tests/test_auth.py` covers the real login path. Ledger test clients pass `headers=LEDGER_AUTH`.

`tests/conftest.py` provides `ledger` (a real ledger app in-process behind the registry's client interface; set `ledger.down = True` to simulate an outage), `db_path` and `registry`. `tests/helpers.py` has `upload`, `confirm`, `seal`, `sealed_batch`, and `query`/`execute` for editing SQLite directly, which is how tamper tests act as an insider.

## Build order

The brief stages the work so that stages 1 to 3 give a complete, judgeable core: (1) core library, (2) verifier and CLI, (3) ledger service, (4) registry, audit and UI, (5) AI helper, (6) demo scripts, static verifier, README. The brief's worked examples (sections 3.1 to 3.4 and 7.2) contain real hash values to use as test vectors.

## Wording in the product

A pass proves that a document matches a reference registered at a known point in the ledger. It does not prove authorship or that the contents are true, and the UI must say so wherever it shows a result. Use "tamper-evident", not "tamper-proof"; "matches the record registered in batch N", not "authentic"; never "AI verified this document"; never "the ledger is immutable".

## Repository notes

- Remote: `AeroSalu/ProofChain-Verifiable-Records-Tamper-Detection` (public). Branches: `main` and `dev`.
- `data/` holds the runtime SQLite database, ledger JSONL file and ledger key. Its contents are git-ignored. The paths come from `PROOFCHAIN_DB_PATH`, `PROOFCHAIN_LEDGER_PATH` and `PROOFCHAIN_LEDGER_KEY_PATH` (see `.env.example`). Nothing loads `.env` automatically; these are read from the process environment.
- Work happens on `dev`.
- No public blockchain, tokens or smart contracts: they are explicitly out of scope.
