"""A plain-language explanation of a finished verification.

This runs after the verifier has returned. It is handed the result and returns
words about it; it has no way to alter the checks or the verdict, which the
page prints separately from the verifier's own result.
"""

import json
from dataclasses import dataclass

from . import fallback
from .extract import FALLBACK_BETA, ai_enabled, model, new_client

CLAUDE = "claude"
TEMPLATE = "template"

SYSTEM = """You explain the result of a document verification to someone who is not technical, such \
as an employer checking a certificate. You are given the finished result as JSON: whether it passed, \
the codes of any checks that failed, and what each check found.

Write two to four plain sentences. Say first whether the document was verified. Then say, in \
everyday words, what the failed checks mean and what the person could do next. Do not use the code \
names, hashes or the word "Merkle".

The result is final and you are describing it, not judging it. Never state or imply a different \
outcome from the one in the JSON.

A pass means the document is identical to one that was registered and that the registration is in \
the published ledger. It does not show who created the document or that its contents are true, so \
do not call a document "authentic" or "genuine", and when the result is a pass, say this limit in \
one sentence.

What each failed check means:
DOCUMENT_MODIFIED: the file is not the one that was registered; even one changed character, or \
re-saving in another format, causes this.
PROOF_INVALID: the proof file is damaged or altered and cannot show membership of any batch.
BATCH_NOT_PUBLISHED: the proof refers to a batch the public ledger has no record of.
ROOT_MISMATCH: the proof is self-consistent but leads to a different root from the one published; \
this is what a proof issued from altered records looks like.
LEDGER_INVALID: the ledger itself failed its checks, so nothing that depends on it can be trusted \
until that is explained."""


@dataclass(frozen=True)
class Explanation:
    text: str
    source: str  # CLAUDE or TEMPLATE


def summarise(result) -> dict:
    """The parts of a verifier result that an explanation needs."""
    data = result.to_dict()
    return {
        "ok": data["ok"],
        "codes": data["codes"],
        "checks": [{"name": c["name"], "status": c["status"], "detail": c["detail"]} for c in data["checks"]],
    }


def explain_with_claude(summary: dict, client=None) -> str | None:
    """Ask Claude for an explanation. None means it declined or wrote nothing."""
    response = (client or new_client()).beta.messages.create(
        model=model(),
        max_tokens=4000,
        betas=[FALLBACK_BETA],
        fallbacks="default",
        output_config={"effort": "low"},
        system=SYSTEM,
        messages=[{"role": "user", "content": json.dumps(summary, indent=2)}],
    )
    if response.stop_reason in ("refusal", "max_tokens"):
        return None
    text = " ".join(block.text.strip() for block in response.content if block.type == "text").strip()
    return text or None


def explain_result(result) -> Explanation:
    """Explain a finished verification. Never raises."""
    summary = summarise(result)
    if ai_enabled():
        try:
            text = explain_with_claude(summary)
            if text:
                return Explanation(text, CLAUDE)
        except Exception:  # no network, bad key, rate limit: use the fixed wording
            pass
    return Explanation(fallback.explain_from_template(summary), TEMPLATE)
