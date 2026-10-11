"""Confirming records into the open batch, sealing a batch, issuing proofs.

Sealing is the step that turns stored records into a published root:

    fingerprints in leaf order -> Merkle root -> ledger entry -> batch sealed

The root goes to the ledger before the batch is marked sealed. If the registry
stops between the two, sealing again finds the entry already there and adopts
it, provided it is the same root.
"""

from ..core.merkle import merkle_root
from ..core.proof import ProofBundle, create_bundle
from . import models
from .db import transaction
from .ledger_client import LedgerConflict


class NotFound(Exception):
    """No such record or batch."""


class Conflict(Exception):
    """The record or batch is not in a state that allows this."""


def confirm_record(conn, record_id: int, metadata: dict, confirmed_by: str) -> str:
    """Store the metadata a person confirmed and put the record in the open batch.

    This is the only place metadata is written. Returns the batch id.
    """
    with transaction(conn):
        record = models.get_record(conn, record_id)
        if record is None:
            raise NotFound(f"there is no record {record_id}")
        if record["metadata_confirmed"]:
            raise Conflict(f"record {record_id} was already confirmed")
        batch = models.open_batch(conn)
        batch_id = batch["id"] if batch else models.create_batch(conn)
        leaf_index = len(models.batch_records(conn, batch_id))
        models.place_in_batch(conn, record_id, metadata, confirmed_by, batch_id, leaf_index)
    return batch_id


def _fingerprints(conn, batch_id: str) -> list[str]:
    return [record["fingerprint"] for record in models.batch_records(conn, batch_id)]


def seal_batch(conn, batch_id: str, ledger) -> dict:
    """Build the batch's Merkle tree and publish its root. Returns the ledger entry."""
    with transaction(conn):
        batch = models.get_batch(conn, batch_id)
        if batch is None:
            raise NotFound(f"there is no batch {batch_id}")
        if batch["status"] != "open":
            raise Conflict(f"{batch_id} is already sealed")
        fingerprints = _fingerprints(conn, batch_id)
        if not fingerprints:
            raise Conflict(f"{batch_id} has no records to seal")
        root = merkle_root([bytes.fromhex(fp) for fp in fingerprints]).hex()

        if models.get_meta(conn, models.LEDGER_PUBLIC_KEY) is None:
            models.set_meta(conn, models.LEDGER_PUBLIC_KEY, ledger.public_key())
        try:
            entry = ledger.publish(batch_id, root, len(fingerprints))
        except LedgerConflict:
            entry = ledger.entry(batch_id)
            if entry is None or entry["root"] != root or entry["tree_size"] != len(fingerprints):
                raise Conflict(f"the ledger already holds a different root for {batch_id}; "
                               "a published root cannot be replaced") from None
        models.mark_sealed(conn, batch_id, root, len(fingerprints), entry)
    return entry


def build_proof(conn, record_id: int) -> tuple[dict, ProofBundle]:
    """The proof bundle for one record of a sealed batch, built from stored data.

    If the stored fingerprints were altered after sealing, the bundle this
    returns leads to a root that was never published, and a verifier reports
    ROOT_MISMATCH.
    """
    record = models.get_record(conn, record_id)
    if record is None:
        raise NotFound(f"there is no record {record_id}")
    batch = models.get_batch(conn, record["batch_id"]) if record["batch_id"] else None
    if batch is None or batch["status"] != "sealed":
        raise Conflict("a proof exists only after the record's batch is sealed")
    try:
        bundle = create_bundle(record["canon"], batch["id"], _fingerprints(conn, batch["id"]), record["leaf_index"])
    except (ValueError, IndexError, TypeError) as exc:
        raise Conflict(f"the stored data for {batch['id']} is inconsistent ({exc}); run the audit") from exc
    return record, bundle
