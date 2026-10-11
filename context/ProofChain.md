# **ProofChain**

## Verifiable Records and Tamper Detection

Project brief for problem B-01  |  Domain 3: Blockchain and Decentralized Trust  |  11 October 2026

This brief explains the problem, the concepts you need, what the problem statement really asks for, how the system flows, how we plan to build it, and which extra features would make the project stand out. Nothing has been built yet; this is the reference to build from.

### **Contents**

1. Summary

2. The problem statement, clarified

3. Background concepts

4. Prerequisites

5. System architecture

6. Flow structure

7. Implementation plan

8. Standout features

9. Risks, limits and honest claims

10. Demo script and judge questions

11. Glossary and references

ProofChain project brief   |   page 1

## **1. Summary**

#### **The problem**

Certificates, contracts and official records usually sit in one organisation's database, and everyone else has to trust that database. Storing a hash next to each record does not help: whoever can change the record can change the hash too, and the two will still match. An outsider learns nothing from that check.

#### **The idea**

Give every document a SHA-256 fingerprint. Group fingerprints into batches and summarise each batch with a Merkle tree, so one short value (the root) commits to every document in it. Publish that root in a separate, append-only, signed ledger that the registry cannot quietly rewrite. Hand each document holder a small proof file. Anyone can then check a single document against the published root, without the registry's database and without downloading the other records.

#### **What gets built**

|**Part**|**Job**|
|---|---|
|Core library|Canonical form, SHA-256 fingerprint, Merkle tree, proof format. Python standard<br>library only.|
|Independent verifier|Command-line tool (and a static browser page) that takes document + proof +<br>published root and says exactly which check failed.|
|Ledger service|Separate process with its own signing key. Stores roots in an append-only hash<br>chain.|
|Registry service and web<br>UI|Upload, confirm metadata, seal batches, download proofs, run a self-audit.|
|AI helper|Suggests metadata and categories, explains failures in plain language. Advisory only;<br>a person confirms.|
|Tamper demo|Script that edits the registry database directly to show the verifier still rejects.|



#### **Decisions already taken**

- **Stack:** Python 3.11+, FastAPI, SQLite, server-rendered web pages.

- **Root store:** separate hash-chained ledger signed with Ed25519, with checkpoints pinned by verifiers. No public blockchain.

- **AI:** Claude API with a rule-based fallback, kept outside the verification path.

**What a pass means.** Verification proves that a document matches a reference registered at a known point in the ledger. It does not prove who created the document or that what it says is true. The product must say this wherever it shows a result.

ProofChain project brief   |   page 2

## **2. The problem statement, clarified**

The statement is short but every sentence carries a requirement. The table below splits it into ten testable requirements, says what each one means in practice, and shows how we meet and demonstrate it.

|**Requirement**|**What it means**|**How we meet it**|**How we demonstrate it**|
|---|---|---|---|
|**R1.**SHA-256<br>fingerprint from a<br>defined,<br>reproducible form|Anyone holding the<br>same document gets the<br>same hash on any<br>machine.|Two named canonical forms.<br>Every proof records which one<br>was used.|Hash the same file with an<br>outside tool (certutilor<br>sha256sum) and get the<br>same value.|
|**R2.**Batches<br>summarised by a<br>Merkle tree, root<br>published|One short value commits<br>to every record in the<br>batch.|Domain-separated Merkle tree.<br>Sealing a batch sends the root<br>to the ledger.|Batch page shows the root;<br>the same root appears in<br>the ledger.|
|**R3.**Every record<br>can produce a<br>membership proof|A single record can be<br>proved without the<br>others.|Downloadable proof bundle<br>(JSON) per record.|Open the bundle: about<br>log2(n) sibling hashes,<br>nothing else from the batch.|
|**R4.**Roots stored<br>where the registry<br>cannot silently<br>rewrite them|A change to history must<br>be visible to outsiders.|Separate ledger process and<br>key, hash chain, signatures,<br>pinned checkpoints.|Edit one ledger entry by<br>hand; the verifier reports<br>LEDGER_INVALID.|
|**R5.**Independent<br>verifier using only<br>document, proof<br>and published root|No call to the registry<br>and no read of its<br>database.|Verifier package imports only<br>the core library. CLI and static<br>page.|Stop the registry service,<br>then verify successfully.|
|**R6.**Report which<br>check failed|Modified document,<br>invalid proof and root<br>mismatch are different<br>answers.|Five named result codes, each<br>with computed and expected<br>hashes.|Three tamper demos give<br>three different codes.|
|**R7.**Detect a stored<br>record that no<br>longer matches its<br>published reference|The registry must notice<br>drift in its own storage.|Audit job recomputes<br>fingerprints and roots from<br>stored content and compares<br>with the ledger.|Run the tamper script, open<br>the Audit page, see the<br>flagged record and batch.|
|**R8.**Reject a<br>tampered<br>document even if<br>the registry<br>database was<br>altered|An attacker with full<br>database access still<br>loses.|The verdict depends on the<br>ledger root, never on registry<br>data.|Tamper script rewrites<br>content, fingerprint and root<br>in SQLite; the verifier<br>reportsROOT_MISMATCH.|
|**R9.**AI assists; a<br>person confirms; AI<br>cannot affect<br>verification|AI is an assistant, not a<br>judge.|Suggestion then confirmation<br>gate. Verifier has no AI import.<br>Metadata is not hashed into the<br>leaf.|Remove the API key:<br>verdicts are identical. An<br>automated test checks the<br>import rule.|



ProofChain project brief   |   page 3

|**Requirement**|**What it means**|**How we meet it**|**How we demonstrate it**|
|---|---|---|---|
|**R10.**No public|Real recomputation, not<br>i|Verifier prints every computed|Show computed versus|
|blockchain; genuine<br>cryptographic<br>checking|a green tick.|hash and returns an exit code.|expected hex for each<br>check.|



### **What is explicitly out of scope**

- A public blockchain, tokens, mining or smart contracts.

- Proving authorship. That would need issuer signatures, listed later as an optional extra.

- Proving the contents are true. No cryptography can do that.

### **Common ways to miss the brief**

|**Mistake**|**Why it fails**|
|---|---|
|Hash stored in the same database as<br>the record, and verification compares<br>the two|This is the exact weakness the problem describes. An insider edits<br>both.|
|Verifier is an API endpoint on the<br>registry that looks up the record|It is not independent, and it trusts the database it is supposed to check.|
|A single "valid / invalid" result|The brief requires the reason: document, proof or root.|
|A UI badge that turns green without<br>recomputing hashes|The brief says verification must be genuine cryptographic checking.|
|AI classifies a document as genuine or<br>fake|AI must not affect whether verification succeeds.|
|AI-extracted metadata saved straight<br>into the record|Extracted data must be confirmed by a person.|
|Root published only inside the registry|The registry could rewrite it silently.|



ProofChain project brief   |   page 4

## **3. Background concepts**

### **3.1 Hash functions and SHA-256**

A cryptographic hash function turns any input, of any size, into a fixed-length output. SHA-256 outputs 256 bits, written as 64 hexadecimal characters. It is specified in FIPS 180-4. Four properties matter here:

- **Deterministic:** the same bytes always give the same hash.

- **Preimage resistant:** given a hash, you cannot find an input that produces it.

- **Second-preimage resistant:** given a document, you cannot find a different document with the same hash. This is what stops a forger swapping in a new document.

- **Collision resistant:** you cannot find any two different inputs with the same hash.

It also shows the avalanche effect: a tiny change in the input changes about half the output bits. The two inputs below differ in one character.

<mark>"Certifcate of Completion: Asha Rao, 2026"</mark> i <mark>d1e9b977c3a3ecaaa8499d445ba43f8569cd57f288ec8518e70bf5c0e7409cb</mark> f

<mark>"Certifcate of Completion: Asha Rao, 2027"</mark> i <mark>07ae032dd691a3f8983386253f912dcfe95525e63c9b383015a603647b4cfa85</mark>

<mark>117 of 256 output bits difer.</mark> f

So a matching fingerprint means the document is the same, bit for bit, as the one that was fingerprinted. A different fingerprint means something changed, but does not say what.

### **3.2 Canonical form**

A hash covers bytes, not meaning. The same logical record can be written as different bytes: different key order, spacing, line endings or Unicode encoding of the same character. If two parties serialise the record differently they get different hashes for the same content, and verification fails for no real reason. The fix is to define one exact byte form, called the canonical form, and always hash that.

We define two canonical forms, and each proof names the one it used:

|**Name**|**Used for**|**Rule**|
|---|---|---|
|raw-bytes-v1|Files such as PDF, images, Word<br>documents|The exact bytes of the file, unchanged.|
|json-sorted-v1|Structured records entered as fields|UTF-8, Unicode NFC, object keys sorted, no<br>whitespace between tokens, integers only<br>(no floating-point numbers). Modelled on<br>RFC 8785.|



Worked example: the same record written two ways gives two different raw hashes, but one canonical form and one fingerprint.

ProofChain project brief   |   page 5

<mark>Written one way: {"name": "Asha Rao", "course": "Data Structures", "year": 2026} raw SHA-256  4052a5132e3df1a9d3f9c7b5c039845c5838f14fa5ea2b7eba49b173972e2e00</mark>

<mark>Written another way (keys reordered, pretty-printed): raw SHA-256  230892b6ae35ee9af0f66c128216d3f979b0f5ef7f1f44cb378124c601f010f</mark> f

<mark>Canonical form of both: {"course":"Data Structures","name":"Asha Rao","year":2026} f</mark> i <mark>ngerprint  cec7f2f6b8ebc0a612fdb3b5fadaa380d1d85be7a6c0412708814054796faba5</mark>

**Design rule.** Never normalise binary files. Re-saving a PDF changes its bytes, and that is correct behaviour: the registered artefact is the exact file that was issued.

### **3.3 Merkle trees**

Publishing one hash per document would work but does not scale, and it reveals how many documents exist and when each was added. A Merkle tree compresses a whole batch into one value.

1. Each document's fingerprint becomes a **leaf** : leaf = SHA-256(0x00 || fingerprint).

2. Leaves are paired left to right. Each pair becomes a **node** : node = SHA-256(0x01 || left || right).

3. Nodes are paired again, level by level, until one value remains. That value is the **root** .

4. If a level has an odd number of entries, the last one moves up unchanged. It is never duplicated.

Changing any document changes its leaf, which changes every node above it, which changes the root. So the root is a commitment to every document in the batch and to their order.



<!-- Start of picture text -->
Four-document batch: proving Document C<br>3a41957e,<br>Node Node<br>s89e2e6F. 1062784.<br>- ~ _——_ —<br>A Leaf B Leaf ¢ Leaf D<br>Leaf ee — =<br>2badsofe. b0d12303, ef6a6of2. 3f3figal.<br>Document A DocumentB<br>fp e39e3d8 fp 80dsts73. | Documenfp 90eafc t . € {Documentfp 8fb7d0d3, D<br>GO recomputed by the verifier D sibling hash supplied in the proof B® published root<br><!-- End of picture text -->

_Figure 1. A four-document batch with real SHA-256 values (first 8 hex characters shown)._

#### **Why the 0x00 and 0x01 prefixes**

Without them, an attacker could present an internal node as if it were a leaf (or the reverse) and build a valid-looking proof for data that was never registered. Tagging leaves and nodes differently,

ProofChain project brief   |   page 6

called domain separation, removes that ambiguity. Certificate Transparency (RFC 6962) uses the same technique.

#### **Why the odd entry is promoted, not duplicated**

Some designs duplicate the last entry to make a pair. That lets two different lists of leaves produce the same root, which caused a real vulnerability in Bitcoin (CVE-2012-2459). Promoting the unpaired entry avoids it.



<!-- Start of picture text -->
Five-document batch: the unpaired leaf is promoted, not duplicated<br>Root<br>3de1575b,<br>Node<br>3a41957e..<br>Node Node<br>s8e2e6F. 1062784..<br>NN a——<br>Leaf A Leaf B Leaf ¢ Leaf D Leaf E (promoted)<br>2badsofe. 0d12303... ef6860f2.. 343f18al. 7e94def2...<br>Document A {Document 8 Document € Document D Document €<br>fp €39e3d8d fp 80461473. fp 906afef. fp 8fb7d043 fp 655b63bd.<br>GO recomputed by the verifier D sibling hash supplied in the proof B® published root<br><!-- End of picture text -->

_Figure 2. Five documents. Leaf E has no partner, so it moves up until it meets the left subtree. Its proof needs one hash._

### **3.4 Membership proofs**

To prove a document is in a batch, you supply the sibling hash at each level on the way from its leaf to the root, plus which side each sibling is on. The verifier recomputes upward and compares the result with the published root. For a batch of n documents the proof holds about log2(n) hashes: 10 for 1,000 documents, 20 for a million.

Worked example: proving Document C in Figure 1. The proof holds two sibling hashes.

ProofChain project brief   |   page 7

<mark>fngerprint(C)</mark> i <mark>90eafcf01a14b00bf7d8e2ab6abd10b1e6944ad0fc3d7ac1dfeacf</mark> f <mark>8976ba4aa leaf = H(0x00 || f</mark> i <mark>ngerprint) ef6860f2459adc96d870eddcf98b4b01437abfb3044db6cfc19786ee44cd53b0 step 1: sibling on the RIGHT 3f3f18a16988ee47522a0f08f4c21bd7687b126030323cb2d3c60b38cae7f494 node = H(0x01 || leaf || sibling) 010b2784e33a8d696e6e1c92bdc8663f5b26d581f1508f6ccc6c9dab5aa6f0e1</mark>

<mark>step 2: sibling on the LEFT 989e2e6fd32d70ca8443ba766cb386a3750c114c5ed75dd38f84495447a4f</mark> f <mark>1</mark> f <mark>root = H(0x01 || sibling || node) 3a41957e48b5aeb1eb57ad1ef8f84e13c2d430783215c136b8efeda95e98c40</mark> f

<mark>published root 3a41957e48b5aeb1eb57ad1ef8f84e13c2d430783215c136b8efeda95e98c40   MATCH</mark> f

If Document C is edited, its fingerprint changes and the same two siblings lead somewhere else:

<mark>fngerprint(edited C)</mark> i <mark>8396bf8447a9109974bf98046d1ef80aa62867afb2d5c007753fd495a11207e6 recomputed root 338d1757c00018ae214501b90edc1f8748fb0b67580b4ce191521cd163054b4e   NO MATCH</mark>

The verifier never sees Documents A, B or D. It sees two hashes that reveal nothing about them.

### **3.5 Making published roots hard to rewrite**

The root is only useful if it lives somewhere the registry cannot quietly change. We use three layers.

#### **Layer 1: hash chain**

Every ledger entry includes the hash of the previous entry. Altering an old entry changes its hash, which breaks the link in the next entry, and so on to the end. A verifier walking the chain notices immediately.



<!-- Start of picture text -->
Each ledger entry commits to the one before it<br>Entry seq 0 Entry seq 1 Entry seq 2<br>batch id batch-2001 batch id batch-0002 batch id batch-2003<br>next 3041957e. ar 3de1575b. En bs62beda..<br>tree size * tree size s tree_size 7<br>prev hash 008000 ae hash _-739eSbed prev hash 9758672.<br>entry hash —-739eSbed. entry hash (7586762. entry hash 139142.<br>econ £d25519(entry_hash) signature £d25519(entry_hash) signature £425519(entry_hash)<br>Checkpoint pinned by a verifier: (seq 1, entry hash).<br>‘Any later ledger that lacks this exact entry is rejected<br><!-- End of picture text -->

_Figure 3. Three ledger entries. Each prev_hash equals the previous entry_hash._

#### **Layer 2: digital signature**

Each entry hash is signed with the ledger's private Ed25519 key (RFC 8032). Anyone with the public key can check the signature; only the key holder can produce it. The ledger runs as its own process with its own key, so the registry cannot forge entries.

ProofChain project brief   |   page 8

#### **Layer 3: pinned checkpoints**

A chain plus signatures still leaves one gap: whoever holds the ledger key could rebuild the entire chain from the start and sign it again. The defence is that verifiers remember. Each verifier saves a checkpoint, the sequence number and entry hash of the latest entry it has seen. From then on it rejects any ledger that does not contain that exact entry. A rewrite therefore cannot stay hidden from anyone who looked before.

**Honest limit.** A verifier that has never seen the ledger before has no checkpoint to compare against. Independent witnesses that co-sign ledger heads close this gap; see Section 8.

ProofChain project brief   |   page 9

#### **How this compares with other approaches**

||**Public blockchain**|**Our signed ledger**|**Certificate Transparency**|
|---|---|---|---|
|Who can write|Anyone, by consensus|One ledger operator|One log operator|
|Rewrite prevented by|Economic cost of redoing<br>consensus|Detection: chain,<br>signature, pinned<br>checkpoints|Detection: Merkle log,<br>gossip, monitors|
|Cost and speed|Fees and confirmation<br>delays|Free and instant|Free and fast|
|Needs network of nodes|Yes|No|Monitors and auditors|
|Fits this brief|Allowed but not required|Yes|Closest real-world model|



### **3.6 Threat model**

Assume the attacker may be an insider with full read and write access to the registry database. The table lists what each attacker can try and what catches it.

|**Attack**|**Caught by**|**Result**|
|---|---|---|
|Holder edits a document after it was<br>issued|Verifier, fingerprint check|DOCUMENT_MODIFIED|
|Someone edits or invents the proof<br>path|Verifier, proof check|PROOF_INVALID|
|Insider changes a record and its stored<br>fingerprint, rebuilds the batch, issues a<br>fresh proof|Verifier, root check|ROOT_MISMATCH|
|Insider changes only the stored content|Registry audit|STORED_CONTENT_CHANGED; the<br>holder's original still verifies|
|Insider issues a proof for a batch that<br>was never published|Verifier, publication check|BATCH_NOT_PUBLISHED|
|Someone edits one ledger entry|Verifier, ledger check|LEDGER_INVALID(broken link or bad<br>signature)|
|Ledger key holder rebuilds and re-signs<br>the whole ledger|Verifier, pinned checkpoint|LEDGER_INVALIDfor anyone who<br>pinned earlier|



ProofChain project brief   |   page 10

## **4. Prerequisites**

### **4.1 Knowledge**

|**Topic**|**Level needed**|**Where it is used**|
|---|---|---|
|Python basics (functions,<br>modules, bytes versus text)|Comfortable|Everything|
|Command line and virtual<br>environments|Basic|Running services, tests and the verifier CLI|
|HTTP and REST APIs|Basic|Registry and ledger services (FastAPI)|
|SQL|Basic|Registry tables in SQLite; the tamper demo edits rows<br>directly|
|HTML and a little JavaScript|Basic|Registry pages and the static browser verifier|
|Hashing, Merkle trees,<br>signatures|Section 3 of this<br>brief|Core library, verifier, ledger|
|Testing with pytest|Basic|Proving each failure code fires for the right reason|



### **4.2 Software**

|**Item**|**Purpose**|
|---|---|
|Python 3.11 or newer|Runtime for all components|
|pip and venv (included with<br>Python)|Installing packages in an isolated environment|
|A modern web browser|Registry UI and the static verifier (needs WebCrypto, present in all current<br>browsers)|
|A code editor|Any; VS Code is fine|
|Git (optional)|Version history for the submission|
|Anthropic API key (optional)|Live AI suggestions. Without it the rule-based fallback is used and everything<br>else works.|



### **4.3 Python packages**

|**Package**|**Purpose**|
|---|---|
|hashlib(standard library)|SHA-256. The core and verifier need nothing else for hashing.|
|fastapi,uvicorn|The registry and ledger web services|
|jinja2,python-multipart|HTML pages and file uploads|



ProofChain project brief   |   page 11

|**Package**|**Purpose**|
|---|---|
|cryptography|Ed25519 signing in the ledger and signature checking in the verifier|
|pypdf|Extracting text from PDFs so the AI helper can read them|
|anthropic|Claude API client for the AI helper|
|pytest|Automated tests|



### **4.4 Setup commands (Windows)**

<mark>python --version python -m venv .venv .venv\Scripts\activate pip install fastapi uvicorn jinja2 python-multipart cryptography pypdf anthropic pytest</mark>

Once built, the two services start in separate terminals:

<mark>uvicorn proofchain.ledger.app:app --port 8001 uvicorn proofchain.registry.app:app --port 8000</mark>

### **4.5 Hardware, accounts and cost**

- Any laptop is enough. SHA-256 over a few megabytes takes milliseconds.

- No cloud account, database server or blockchain node is required. Everything runs locally.

- The only paid item is optional Claude API usage, billed per request. A demo uses very little. The key goes in a local .env file and is never committed to Git.

ProofChain project brief   |   page 12

## **5. System architecture**

Four components, separated so that the one being checked (the registry) has no control over the thing it is checked against (the ledger), and no part in the checking (the verifier).



<!-- Start of picture text -->
REGISTRY (untrusted by the verifier) salboten: | LEDGER (separate process and key)<br>Resist stat load Reisty service + web UI eyed<br>Upload, confirm metadata FastAPl, port 8000 append ae readonly<br>satabase Al beper ledgerison<br>eos veeee advisory only) Merkle roots<br>proof bundle ‘gst + pinned checkpoint<br>Document holder document + proof Independent verifier<br>keeps document CL or static browser page<br>* proof bundle SHA-256 + Merkle fold + chain check<br><!-- End of picture text -->

_Figure 4. Components and trust boundaries._

|**Component**|**Holds**|**Can do**|**Cannot do**|
|---|---|---|---|
|Registry|Documents, fingerprints,<br>metadata, batch<br>membership|Accept uploads, build trees,<br>request publication, issue<br>proofs, audit itself|Sign ledger entries, edit or<br>delete ledger entries,<br>influence a verifier's<br>verdict|
|Ledger|Published roots, its own<br>private key|Append a signed entry,<br>serve entries and its public<br>key|Update or delete an entry<br>(no such endpoint exists)|
|Verifier|Ledger public key, pinned<br>checkpoint|Recompute hashes, fold the<br>proof, check the chain,<br>report the result|Read the registry database,<br>call the AI helper|
|AI helper|Nothing persistent|Suggest metadata and<br>categories, explain a<br>finished result|Write confirmed metadata,<br>change a verdict|



**The key separation.** The verifier and core packages import nothing from the registry or AI packages. An automated test enforces this, so the independence claim is checked on every test run, not just promised.

ProofChain project brief   |   page 13

## **6. Flow structure**

### **6.1 Registering a record and sealing a batch**



<!-- Start of picture text -->
A. Registering a record<br>1 2 ) B ) fa 5 (6 )<br>Upload Convert to SHA-256 Al suggests Person confirms Record joins<br>document canonical form fingerprint metadata or edits the open batch<br>B. Sealing a batch<br>1 2 3 4 5 6<br>Close Build the Send root to Ledger chains Proof bundles Verifiers pin<br>the batch Merkle tree ledger service and signs entry issued the new head<br><!-- End of picture text -->

_Figure 5. Registration (A) and batch sealing (B)._

#### **A. Registering a record**

1. A staff member uploads a file, or fills in a structured record.

2. The registry converts it to its canonical form (raw-bytes-v1 or json-sorted-v1).

3. It computes the SHA-256 fingerprint and shows it on screen.

4. The AI helper reads the text and suggests issuer, date, document type and category. These are marked as suggestions.

5. The staff member checks, corrects and confirms the metadata. Until then the record cannot enter a batch.

6. The confirmed record joins the currently open batch at the next leaf position.

#### **B. Sealing a batch**

1. A staff member (or a size or time limit) closes the batch. No more records can join it.

2. The registry builds the Merkle tree over the fingerprints in leaf order and obtains the root.

3. It sends the batch id, root and tree size to the ledger service.

4. The ledger adds the previous entry's hash, computes the new entry hash, signs it and appends the entry.

5. The registry generates a proof bundle for every record in the batch, ready to download with the document.

6. Verifiers that are watching the ledger pin the new head as their checkpoint.

ProofChain project brief   |   page 14

### **6.2 Verifying a document**



<!-- Start of picture text -->
Inputs: document + proof bundle + published ledger<br>1. Fingerprint check no<br>SHA-256(canonical document) DOCUMENT_MODIFIED<br>equals the fingerprint in the proof?<br>yes<br>2. Proof check no<br>Folding the sibling path from the PROOF_INVALID<br>p=<br>3. Publication check<br>he ledgerfor thishasbatch?an entry no BATCH_WOT_PUBLISHED,<br>yes<br>4, Root check =<br>Proof’ root and tree size equal ROOT_MISMATCH<br>ye<br>5. Ledger check =<br>Chain links, signatures and the LEDGER_INVALID<br>yer<br>VERIFIED: every check passed (exit code 0) Every failure is sted with the<br><!-- End of picture text -->

_Figure 6. The five verification checks and the code each one reports._

Two details make the failure reasons trustworthy:

- **All checks run every time.** The verifier does not stop at the first failure, so a report can list several causes.

- **Each check isolates one cause.** The proof bundle carries the registered fingerprint and the claimed root. Check 1 compares the document with the fingerprint. Check 2 uses the bundle's own fingerprint, not the document, so an edited document does not also raise a proof error. Check 4 compares the bundle's root with the ledger, so a re-issued proof from an altered database is caught there.

### **6.3 Registry self-audit**

The registry also checks itself against the ledger, on demand and on a schedule:

1. For each record, recompute the fingerprint from the stored content and compare it with the stored fingerprint.

2. For each sealed batch, rebuild the Merkle root from the stored fingerprints.

3. Fetch the batch's entry from the ledger and compare roots and tree sizes.

4. Report any difference on the Audit page.

ProofChain project brief   |   page 15

|**Audit code**|**Meaning**|
|---|---|
|STORED_CONTENT_CHANGED|The stored file no longer hashes to the stored fingerprint.|
|STORED_FINGERPRINT_CHANGED|The stored fingerprint no longer fits the batch's published root.|
|BATCH_ROOT_DIVERGED|The root rebuilt from storage differs from the root in the ledger.|



### **6.4 Tamper scenarios, end to end**

|**What is changed**|**Verifier says**|**Registry audit says**|
|---|---|---|
|One byte of the holder's document|DOCUMENT_MODIFIED|Clean (storage untouched)|
|One sibling hash in the proof file|PROOF_INVALID|Clean|
|Stored content only, in SQLite|Original document still verifies|STORED_CONTENT_CHANGED|
|Stored content, fingerprint and<br>batch root, with a new proof issued|ROOT_MISMATCH|BATCH_ROOT_DIVERGED|
|One entry in the ledger file|LEDGER_INVALID|Ledger check fails|
|Whole ledger rebuilt and re-signed|LEDGER_INVALID(checkpoint<br>missing)|Ledger check fails against the<br>registry's own pin|



ProofChain project brief   |   page 16

## **7. Implementation plan**

### **7.1 Project layout**

<mark>proofchain/ core/        canonical.py  merkle.py  proof.py  ledger_format.py    standard library only verifer/    verify.py  cli.py                  imports core only</mark> i <mark>ledger/      app.py  store.py  keys.py          FastAPI on port 8001, JSONL f</mark> i <mark>le, Ed25519 registry/    app.py  db.py  models.py  batching.py  audit.py  ledger_client.py templates/  static/                FastAPI on port 8000, SQLite ai/          extract.py  explain.py  fallback.py scripts/       demo_seed.py  tamper.py tests/ web-verif</mark> i <mark>er/  index.html                         static page, WebCrypto, no backend README.md  pyproject.toml  .env.example</mark>

### **7.2 Data formats**

#### **Proof bundle (given to the document holder)**

<mark>{ "version": 1, "canon": "raw-bytes-v1", "f</mark> i <mark>ngerprint": "90eafcf01a14b00bf7d8e2ab6abd10b1e6944ad0fc3d7ac1dfeacf</mark> f <mark>8976ba4aa", "batch_id": "batch-0001", "leaf_index": 2, "tree_size": 4, "path": [ {"side": "right", "hash": "3f3f18a16988ee47522a0f08f4c21bd7687b126030323cb2d3c60b38cae7f494"}, {"side": "left", "hash": "989e2e6fd32d70ca8443ba766cb386a3750c114c5ed75dd38f84495447a4f</mark> f <mark>1"}</mark> f <mark>], "root": "3a41957e48b5aeb1eb57ad1ef8f84e13c2d430783215c136b8efeda95e98c40"</mark> f <mark>}</mark>

#### **Ledger entry**

<mark>{ "seq": 1, "batch_id": "batch-0002", "root": "3de1575b7131b491d8e4fa6a9bc83aa648776f8be745e1ef1eaae8ec8443316e", "tree_size": 5, "published_at": "2026-10-12T09:00:00Z", "prev_hash": "739e5bedf4deac095f461dbe1ac530539945a5c34974bf0afc5c908285c5f57d", "entry_hash": "075867b2f3e05b9e5413590b2a3c6ae2be637f344be8bde9332b9dbe90d74bec", "signature": "<Ed25519 signature of entry_hash, base64>" }</mark>

entry_hash is the SHA-256 of the canonical JSON of the six fields above it. The version field in the proof lets us change hash function or tree rules later without breaking old proofs.

ProofChain project brief   |   page 17

#### **Registry tables**

|**Table**|**Columns**|
|---|---|
|records|id, filename, content (blob), canon, fingerprint, suggested_metadata (JSON), metadata (JSON),<br>metadata_confirmed, confirmed_by, batch_id, leaf_index, created_at|
|batches|id, status (open or sealed), root, tree_size, ledger_seq, sealed_at|



### **7.3 Verifier result codes**

|**Code**|**Exact condition**|
|---|---|
|DOCUMENT_MODIFIED|SHA-256 of the canonical document differs from the fingerprint in the bundle.|
|PROOF_INVALID|Folding the path from the bundle's fingerprint does not give the bundle's root, or<br>the bundle is malformed (bad hex, index outside tree size, path too long).|
|BATCH_NOT_PUBLISHED|The ledger has no entry for the bundle's batch id.|
|ROOT_MISMATCH|The bundle's root or tree size differs from the ledger entry for that batch.|
|LEDGER_INVALID|A prev_hash link is broken, an entry hash or signature is wrong, or the pinned<br>checkpoint is missing.|



##### Planned command line:

<mark>python -m proofchain.verif</mark> i <mark>er verify --doc degree.pdf --proof degree.proof.json \ --ledger http://localhost:8001 --pin 1:075867b2... python -m proofchain.verif</mark> i <mark>er pin --ledger http://localhost:8001</mark>

The ledger argument also accepts a local copy of the ledger file, so verification works fully offline. Exit code 0 means every check passed.

### **7.4 Service endpoints and pages**

|**Service**|**Endpoint**|**Purpose**|
|---|---|---|
|Ledger|POST /entries|Append a root. The service adds prev_hash, entry_hash<br>and signature.|
|Ledger|GET /entries,GET<br>/entries/{batch_id}|Read the whole chain or one entry|
|Ledger|GET /head,GET /pubkey|Latest checkpoint and the public key|
|Registry|POST /records|Upload, fingerprint, request AI suggestions|
|Registry|POST /records/{id}/confirm|Person confirms metadata; record joins the open batch|
|Registry|POST /batches/{id}/seal|Build tree, publish root|
|Registry|GET /records/{id}/proof|Download the proof bundle|
|Registry|GET /audit|Run and show the self-audit|



ProofChain project brief   |   page 18

|**Page**|**What the user sees**|
|---|---|
|Register|Upload form, live fingerprint, AI suggestions beside editable fields, Confirm button|
|Records and batches|Open batch, sealed batches with roots and ledger sequence, proof download per<br>record|
|Audit|Per-record and per-batch status against the ledger|
|Verify|Upload document and proof; five checks with computed and expected hashes;<br>plain-language explanation underneath|



### **7.5 Keeping AI out of the verdict**

- The verifier and core packages do not import the AI package. A test fails the build if they ever do.

- Metadata is not part of the leaf hash, so nothing the AI suggests can change a fingerprint, proof or root.

- AI output is stored as a suggestion. Only the Confirm action, taken by a signed-in person, writes metadata.

- Explanations are generated after the verifier has finished, from its result codes. The explanation is displayed below the verdict and labelled as AI-written.

- If the API key is missing or a call fails, a rule-based fallback produces suggestions and templated explanations.

### **7.6 Build order**

|**Stage**|**Deliverable**|**Done when**|**Rough effort**|
|---|---|---|---|
|1|Core library|Unit tests pass for canonical forms and for trees<br>of 1 to 9 leaves, checked against hand-<br>computed values|3 to 4 hours|
|2|Verifier and CLI|Each of the five codes has a test that triggers it<br>and only it|3 hours|
|3|Ledger service|Append works; edited, reordered and re-signed<br>chains are rejected|3 hours|
|4|Registry, audit and UI|Upload, confirm, seal, download proof and<br>audit all work in the browser|6 to 8 hours|
|5|AI helper|Suggestions and explanations work with and<br>without an API key|2 to 3 hours|
|6|Demo scripts, static verifier,<br>README|The demo in Section 10 runs start to finish|3 to 4 hours|



ProofChain project brief   |   page 19

Effort figures are estimates for one developer who knows Python. Stages 1 to 3 give a complete, judgeable core even if time runs out.

### **7.7 Test plan**

- **Unit:** canonical forms; tree construction; proof generation and folding for every leaf in trees of 1 to 9 leaves.

- **Negative:** each failure code triggered separately; malformed bundles; wrong side flags; truncated paths.

- **Ledger:** edited entry, deleted entry, swapped entries, fully re-signed chain against a pin.

- **Isolation:** verifier and core import nothing from registry or AI.

- **End to end:** the tamper script against a running system, with the verifier and audit results asserted.

- **AI independence:** the same verification inputs give identical results with the API key present and absent.

ProofChain project brief   |   page 20

## **8. Standout features**

The base build meets the brief. These additions are ordered by how much they strengthen the project for the effort involved.

|**Feature**|**What it adds**|**Effort**|**Priority**|
|---|---|---|---|
|Static in-browser verifier|One HTML file using WebCrypto. Verifies with<br>no server and no project code installed. The<br>strongest proof of independence.|Medium|Do first|
|Tamper lab page|Flip a byte, edit a proof hash or alter the<br>database from the UI and watch the specific<br>check fail with live hash values.|Low|Do first|
|QR code on issued<br>documents|QR links to the proof and the batch id, so a<br>phone can verify a printed certificate.|Low|High|
|Witness co-signing|One or more independent witness processes<br>sign each ledger head. Covers verifiers with no<br>earlier checkpoint.|Medium|High|
|Revocation and<br>supersession|A record is revoked or replaced by a new signed<br>ledger entry, never by deletion. The verifier<br>reports "valid but revoked".|Medium|High|
|Consistency proofs|The ledger becomes a Merkle log, so it can<br>prove a new head extends an old one without<br>sending every entry (as in RFC 6962).|High|Medium|
|Selective disclosure|Each field is hashed with its own random salt. A<br>holder can prove one field (for example, the<br>degree title) and keep the rest private.|High|Medium|
|Salted leaves|A random salt per record stops anyone<br>guessing a document's contents from its hash.|Low|Medium|
|Issuer signatures|The issuer signs each fingerprint, adding<br>evidence of who registered it. Presented as a<br>separate layer from the base claim.|Medium|Medium|
|Trusted timestamps or<br>public anchoring|An RFC 3161 timestamp, or the ledger head<br>published somewhere public, gives outside<br>evidence of when a root existed.|Medium|Low|
|Bulk verification|Verify a folder of documents and proofs in one<br>run, with a summary report.|Low|Low|
|Verification receipt|A downloadable report of the checks run and<br>the hashes computed, itself hashed.|Low|Low|



ProofChain project brief   |   page 21

### **The four to prioritise**

**Static in-browser verifier.** Judges can open one file, drop in a document and a proof, and see every hash computed on their own machine. It is a second, separate implementation of the verification rules, which also guards against a bug shared by registry and verifier.

**Tamper lab.** The brief is about detection, so make detection visible. A page with three buttons (modify document, corrupt proof, alter database) that shows the before and after hashes turns the threat table in Section 3.6 into a live demo.

**Witness co-signing.** This answers the hardest question a judge can ask: what if the ledger operator is the attacker? With witnesses, a rewrite needs the operator and every witness to collude. **Revocation by ledger entry.** Real registries need to withdraw records. Doing it with a new signed entry, never a deletion, shows the append-only principle applied to a real requirement.

ProofChain project brief   |   page 22

## **9. Risks, limits and honest claims**

|**Risk or limit**|**Consequence**|**Mitigation**|
|---|---|---|
|Ledger key is stolen or misused|The key holder can append false<br>entries or rebuild the chain|Separate process and key file; pinned<br>checkpoints; witnesses as an<br>extension|
|First-time verifier has no<br>checkpoint|Cannot detect a rewrite that<br>happened before first contact|Publish heads through a second<br>channel; witness co-signing|
|Canonical form defined loosely|Honest documents fail to verify|Raw bytes for files; strict rules and<br>test vectors for JSON; canon name<br>recorded in each proof|
|Re-saved or re-exported files|Bytes change, so verification fails<br>although the text looks the same|State clearly that the registered<br>artefact is the exact file; holders keep<br>the original|
|Hashes of predictable<br>documents|Someone could guess contents by<br>hashing candidates|Salted leaves (Section 8)|
|Registry registers a false<br>document|It verifies, because it matches what<br>was registered|State the claim precisely; issuer<br>signatures add accountability, not<br>truth|
|AI suggests wrong metadata|Wrong labels on a record|Human confirmation gate; metadata<br>never affects verification|
|SHA-256 weakened in future|Fingerprints lose strength|Version field in proofs and ledger<br>entries allows migration|
|Loss of the ledger file|Published roots are gone|Verifiers and witnesses hold copies;<br>routine backups|



### **Wording to use, and to avoid**

|**Say**|**Do not say**|
|---|---|
|"This document matches the record registered in batch<br>12."|"This certificate is authentic."|
|"Any change to the ledger is detectable by anyone who<br>pinned an earlier checkpoint."|"The ledger is immutable."|
|"AI suggested this metadata; a person confirmed it."|"AI verified this document."|
|"Tamper-evident."|"Tamper-proof."|



ProofChain project brief   |   page 23

## **10. Demo script and judge questions**

### **Five-minute demo**

1. **Set the scene.** Show a database row where the record and its hash sit side by side, and explain why matching them proves nothing.

2. **Register.** Upload two or three documents. Show the fingerprint, the AI suggestions, and a person confirming them.

3. **Seal.** Seal the batch. Show the root in the registry and the same root appearing as a new signed entry in the ledger.

4. **Verify honestly.** Stop the registry service. Run the verifier on an untouched document: five checks pass, with hashes shown.

5. **Modify the document.** Change one character. Result: DOCUMENT_MODIFIED.

6. **Corrupt the proof.** Change one sibling hash. Result: PROOF_INVALID.

7. **Attack the database.** Run the tamper script, which rewrites content, fingerprint and root in SQLite and issues a fresh proof. Result: ROOT_MISMATCH, and the Audit page flags the batch.

8. **Attack the ledger.** Rebuild and re-sign the ledger file. Result: LEDGER_INVALID against the pinned checkpoint.

9. **Close.** Show the plain-language explanation, then state what a pass does and does not prove.

ProofChain project brief   |   page 24

### **Questions to expect**

|**Question**|**Answer**|
|---|---|
|Why not use a blockchain?|The brief does not need one. What matters is that roots are published<br>somewhere the registry cannot silently rewrite. A signed hash chain with<br>pinned checkpoints gives that, with no fees or network. The ledger head<br>could be anchored publicly later without changing the design.|
|What if the ledger operator is<br>malicious?|They cannot alter history without breaking the chain for everyone who<br>pinned a checkpoint. Witness co-signing extends this to first-time<br>verifiers.|
|Does a pass mean the certificate is<br>genuine?|It means the document is identical to one registered in a published batch.<br>Authorship and truth are outside what hashing can show.|
|How do you tell a modified<br>document from a bad proof?|The proof carries the registered fingerprint. The document is checked<br>against that fingerprint, and the path is checked from that fingerprint, as<br>two separate steps.|
|Why batches and not one hash per<br>document?|One published value per batch keeps the ledger small, and a proof stays<br>around log2(n) hashes however large the batch is.|
|What exactly does the AI do?|It suggests metadata and categories for a person to confirm and writes a<br>plain-language explanation after the verdict. The verifier contains no AI<br>code.|
|What if the registry database is<br>wiped or rewritten?|Holders still have their documents and proofs, and the ledger still has the<br>roots. Verification keeps working without the registry.|
|Can two different batches give the<br>same root?|Not in practice: leaf and node hashes are domain-separated, unpaired<br>entries are promoted, and the tree size is published with the root.|



ProofChain project brief   |   page 25

## **11. Glossary and references**

|**Term**|**Meaning**|
|---|---|
|Fingerprint|SHA-256 hash of a document's canonical form|
|Canonical form|The single agreed byte representation of a document that is hashed|
|Leaf|Hash of a fingerprint with the 0x00 prefix; the bottom level of the tree|
|Node|Hash of two child hashes with the 0x01 prefix|
|Root|The single hash at the top of a Merkle tree; commits to the whole batch|
|Batch|A group of records sealed together under one root|
|Membership proof|The sibling hashes needed to recompute the root from one leaf|
|Proof bundle|The JSON file holding fingerprint, batch id, leaf index, path and root|
|Ledger|Append-only, hash-chained, signed list of published roots|
|Checkpoint (pin)|A ledger sequence number and entry hash that a verifier remembers|
|Witness|An independent party that co-signs ledger heads|
|Domain separation|Using different prefixes so leaf and node hashes cannot be confused|
|Ed25519|A fast, widely used digital signature scheme|
|Tamper-evident|Changes can be detected, as opposed to being impossible|



### **References**

- FIPS 180-4, Secure Hash Standard (SHA-256).

- RFC 6962, Certificate Transparency (Merkle tree hashing, audit and consistency proofs).

- RFC 8785, JSON Canonicalization Scheme.

- RFC 8032, Edwards-Curve Digital Signature Algorithm (Ed25519).

- RFC 3161, Time-Stamp Protocol.

- CVE-2012-2459, duplicate-leaf weakness in Bitcoin's Merkle tree construction.

ProofChain project brief   |   page 26 

