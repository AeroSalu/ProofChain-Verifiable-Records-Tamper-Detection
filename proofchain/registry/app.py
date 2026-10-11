import os
import sys
from pathlib import Path
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify

# Ensure repo root is in python path for core package imports
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from proofchain.core.canonical import (
    RAW_BYTES_V1,
    JSON_SORTED_V1,
    CANONS,
    canonicalize,
    fingerprint,
    CanonicalError,
)
from proofchain.core.merkle import leaf_hash, merkle_root, merkle_path

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "templates"),
    static_folder=os.path.join(os.path.dirname(__file__), "static")
)
app.secret_key = "proofchain-secret-key-development"

# In-memory mock records aligned with the canonical hashing architecture
RECORDS = [
    {
        "record_id": "REC-2026-00891",
        "record_type": "contract",
        "canon": JSON_SORTED_V1,
        "hash": "4a5f3e9b10c842d76a11bfa8294e015d38f7c9e2b10a4857d9f2e3c0184a5f91",
        "leaf_hash": "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
        "status": "verified",
        "created_at": "2026-10-11 13:42 UTC",
        "issuer": "Global Enterprise Corp",
        "merkle_root": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "block_height": 4821,
        "canonical_summary": '{"compliance":1,"id":"REC-00891","vendor":"Global Enterprise Corp"}',
    },
    {
        "record_id": "REC-2026-00890",
        "record_type": "invoice",
        "canon": JSON_SORTED_V1,
        "hash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "leaf_hash": "b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef01a",
        "status": "verified",
        "created_at": "2026-10-11 12:15 UTC",
        "issuer": "Stripe Invoicing Gateway",
        "merkle_root": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "block_height": 4820,
        "canonical_summary": '{"amount":145000,"currency":"USD","invoice_id":"INV-9021"}',
    },
    {
        "record_id": "REC-2026-00889",
        "record_type": "certificate",
        "canon": RAW_BYTES_V1,
        "hash": "e6c279f6283b6320573e35ef74f07a2a5a54b3838ce105d1bb5e33d0696a40c9",
        "leaf_hash": "c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef01a2b",
        "status": "tampered",
        "created_at": "2026-10-11 10:04 UTC",
        "issuer": "National Tech Academy",
        "merkle_root": "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
        "block_height": 4815,
        "tamper_detected_at": "2026-10-11 11:15 UTC",
        "tamper_reason": "Byte-level payload divergence: computed hash does not match anchored Merkle leaf",
        "canonical_summary": "Binary PDF document payload (raw bytes)",
    },
    {
        "record_id": "REC-2026-00888",
        "record_type": "medical",
        "canon": JSON_SORTED_V1,
        "hash": "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
        "leaf_hash": "d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef01a2b3c",
        "status": "verified",
        "created_at": "2026-10-11 09:30 UTC",
        "issuer": "Apex Health Systems",
        "merkle_root": "b8a6148332bc67cd426d4c1f93f5a2f58e1c6cb053ab520448135824ee184c71",
        "block_height": 4812,
        "canonical_summary": '{"department":"Radiology","patient_ref":"PX-89102","status":"APPROVED"}',
    },
    {
        "record_id": "REC-2026-00887",
        "record_type": "financial",
        "canon": JSON_SORTED_V1,
        "hash": "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35",
        "leaf_hash": "e5f67890123456789abcdef0123456789abcdef0123456789abcdef01a2b3c4d",
        "status": "pending",
        "created_at": "2026-10-11 08:14 UTC",
        "issuer": "Ledger Batch Worker #2",
        "merkle_root": "Pending batch commitment",
        "block_height": None,
        "canonical_summary": '{"fiscal_year":2026,"period":"Q3","reported_cents":98500200}',
    },
    {
        "record_id": "REC-2026-00886",
        "record_type": "legal",
        "canon": RAW_BYTES_V1,
        "hash": "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce",
        "leaf_hash": "f67890123456789abcdef0123456789abcdef0123456789abcdef01a2b3c4d5e",
        "status": "verified",
        "created_at": "2026-10-10 17:50 UTC",
        "issuer": "Department of Commerce",
        "merkle_root": "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
        "block_height": 4805,
        "canonical_summary": "Signed affidavit PDF document (raw bytes)",
    },
]

AUDIT_LOGS = [
    {
        "id": "AUD-9941",
        "timestamp": "2026-10-11 13:42:19 UTC",
        "event": "RECORD_ANCHORED",
        "record_id": "REC-2026-00891",
        "canon": JSON_SORTED_V1,
        "details": f"Fingerprinted under {JSON_SORTED_V1} (RFC 8785) & committed to Merkle leaf #4, Block 4821",
        "severity": "info",
    },
    {
        "id": "AUD-9940",
        "timestamp": "2026-10-11 11:15:02 UTC",
        "event": "TAMPER_DETECTED",
        "record_id": "REC-2026-00889",
        "canon": RAW_BYTES_V1,
        "details": f"Fingerprint mismatch under {RAW_BYTES_V1}: current byte stream does not match anchored Merkle leaf hash",
        "severity": "danger",
    },
    {
        "id": "AUD-9939",
        "timestamp": "2026-10-11 10:04:45 UTC",
        "event": "RECORD_REGISTERED",
        "record_id": "REC-2026-00889",
        "canon": RAW_BYTES_V1,
        "details": f"Raw document ingested with scheme {RAW_BYTES_V1}. Awaiting batch anchor.",
        "severity": "info",
    },
    {
        "id": "AUD-9938",
        "timestamp": "2026-10-11 09:30:11 UTC",
        "event": "MERKLE_ROOT_PUBLISHED",
        "record_id": "BATCH-4812",
        "canon": JSON_SORTED_V1,
        "details": "Batch root b8a61483... anchored with RFC 6962 domain-separated leaves (prefix 0x00)",
        "severity": "success",
    },
]

def get_stats():
    total = len(RECORDS)
    verified = sum(1 for r in RECORDS if r["status"] == "verified")
    pending = sum(1 for r in RECORDS if r["status"] == "pending")
    tampered = sum(1 for r in RECORDS if r["status"] == "tampered")
    json_canon_count = sum(1 for r in RECORDS if r.get("canon") == JSON_SORTED_V1)
    raw_canon_count = sum(1 for r in RECORDS if r.get("canon") == RAW_BYTES_V1)
    return {
        "total": total,
        "verified": verified,
        "pending": pending,
        "tampered": tampered,
        "new_today": 5,
        "json_canon_count": json_canon_count,
        "raw_canon_count": raw_canon_count,
    }

@app.route("/")
def index():
    return redirect(url_for("records"))

@app.route("/records")
def records():
    return render_template(
        "records.html",
        active_page="records",
        records=RECORDS,
        stats=get_stats(),
        canons=CANONS,
        raw_bytes_v1=RAW_BYTES_V1,
        json_sorted_v1=JSON_SORTED_V1,
    )

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        rec_id = request.form.get("record_id") or f"REC-2026-{len(RECORDS) + 1:05d}"
        rec_type = request.form.get("record_type") or "contract"
        canon_form = request.form.get("canon") or JSON_SORTED_V1
        issuer = request.form.get("issuer") or "ProofChain Web Client"
        json_payload = request.form.get("json_content", "").strip()
        
        file = request.files.get("record_file")
        
        try:
            if canon_form == JSON_SORTED_V1:
                # Expect JSON payload (from text or uploaded file)
                if file and file.filename:
                    raw_data = file.read()
                elif json_payload:
                    raw_data = json_payload.encode("utf-8")
                else:
                    # Default structured template
                    default_obj = {
                        "record_id": rec_id,
                        "type": rec_type,
                        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "issuer": issuer,
                    }
                    import json
                    raw_data = json.dumps(default_obj).encode("utf-8")
                
                # Canonicalize using teammate's core engine
                canonical_bytes = canonicalize(JSON_SORTED_V1, raw_data)
                rec_hash = fingerprint(JSON_SORTED_V1, raw_data)
                canonical_summary = canonical_bytes.decode("utf-8")
            else:
                # RAW_BYTES_V1
                if file and file.filename:
                    raw_data = file.read()
                elif json_payload:
                    raw_data = json_payload.encode("utf-8")
                else:
                    raw_data = f"{rec_id}:{datetime.utcnow().isoformat()}".encode("utf-8")
                
                canonical_bytes = canonicalize(RAW_BYTES_V1, raw_data)
                rec_hash = fingerprint(RAW_BYTES_V1, raw_data)
                canonical_summary = f"Raw binary ({len(raw_data)} bytes)"

            # Domain-separated leaf hash under RFC 6962
            leaf_digest = leaf_hash(bytes.fromhex(rec_hash)).hex()

            new_record = {
                "record_id": rec_id,
                "record_type": rec_type,
                "canon": canon_form,
                "hash": rec_hash,
                "leaf_hash": leaf_digest,
                "status": "verified",
                "created_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
                "issuer": issuer,
                "merkle_root": leaf_digest,  # single-leaf root for demo batch
                "block_height": 4822,
                "canonical_summary": canonical_summary[:120] + ("..." if len(canonical_summary) > 120 else ""),
            }
            RECORDS.insert(0, new_record)
            flash(
                f"Record {rec_id} fingerprinted under '{canon_form}'! SHA-256: {rec_hash[:16]}... Leaf: {leaf_digest[:16]}...",
                "success"
            )
            return redirect(url_for("records"))

        except CanonicalError as exc:
            flash(f"Canonicalization Failed ({canon_form}): {str(exc)}", "danger")
            return render_template(
                "register.html",
                active_page="register",
                stats=get_stats(),
                canons=CANONS,
                raw_bytes_v1=RAW_BYTES_V1,
                json_sorted_v1=JSON_SORTED_V1,
                form_error=str(exc),
            )

    return render_template(
        "register.html",
        active_page="register",
        stats=get_stats(),
        canons=CANONS,
        raw_bytes_v1=RAW_BYTES_V1,
        json_sorted_v1=JSON_SORTED_V1,
    )

@app.route("/verify")
def verify():
    record_id = request.args.get("id")
    selected_record = None
    if record_id:
        selected_record = next((r for r in RECORDS if r["record_id"] == record_id), None)
    return render_template(
        "verify.html",
        active_page="verify",
        selected_record=selected_record,
        records=RECORDS,
        raw_bytes_v1=RAW_BYTES_V1,
        json_sorted_v1=JSON_SORTED_V1,
    )

@app.route("/audit")
def audit():
    return render_template(
        "audit.html",
        active_page="audit",
        audit_logs=AUDIT_LOGS,
        stats=get_stats(),
        raw_bytes_v1=RAW_BYTES_V1,
        json_sorted_v1=JSON_SORTED_V1,
    )

@app.route("/api/fingerprint", methods=["POST"])
def api_fingerprint():
    """Real-time API to canonicalize and compute fingerprint according to core/canonical.py."""
    data = request.get_json(silent=True) or {}
    canon = data.get("canon", JSON_SORTED_V1)
    text = data.get("payload", "")

    try:
        raw_bytes = text.encode("utf-8")
        canonical_b = canonicalize(canon, raw_bytes)
        fp = fingerprint(canon, raw_bytes)
        leaf = leaf_hash(bytes.fromhex(fp)).hex()
        return jsonify({
            "success": True,
            "canon": canon,
            "canonical_text": canonical_b.decode("utf-8", errors="replace") if canon == JSON_SORTED_V1 else None,
            "fingerprint": fp,
            "leaf_hash": leaf,
        })
    except CanonicalError as exc:
        return jsonify({
            "success": False,
            "error": str(exc),
            "canon": canon,
        }), 400

@app.route("/api/records")
def api_records():
    return jsonify(RECORDS)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n=======================================================")
    print(f" ProofChain Registry running at: http://127.0.0.1:{port}/")
    print(f" Hashing Engine: raw-bytes-v1 & json-sorted-v1 (RFC 8785)")
    print(f"=======================================================\n")
    app.run(host="127.0.0.1", port=port, debug=True)
