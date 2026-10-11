"""Rule-based suggestions and templated explanations.

Used when there is no API key, when a call to Claude fails, and when Claude
declines. Nothing here calls a network service, so the registry works fully
without the Claude API.
"""

import re
from datetime import date

SOURCE = "rules"

# First match wins, so the more specific words come first.
_TYPES = (
    (r"transcript", "Transcript"),
    (r"degree", "Degree certificate"),
    (r"diploma", "Diploma"),
    (r"invoice", "Invoice"),
    (r"receipt", "Receipt"),
    (r"contract|agreement", "Contract"),
    (r"licen[cs]e", "Licence"),
    (r"permit", "Permit"),
    (r"certificate", "Certificate"),
    (r"letter", "Letter"),
    (r"report", "Report"),
)
_CATEGORIES = {
    "Transcript": "Education", "Degree certificate": "Education", "Diploma": "Education",
    "Invoice": "Finance", "Receipt": "Finance", "Contract": "Legal",
    "Licence": "Licensing", "Permit": "Licensing",
}
_MONTHS = {name: number for number, name in enumerate(
    ("january", "february", "march", "april", "may", "june", "july", "august",
     "september", "october", "november", "december"), start=1)}
_MONTH = "|".join(_MONTHS)

_ISO_DATE = re.compile(r"\b(\d{4})-(\d{2})-(\d{2})\b")
_DAY_MONTH_YEAR = re.compile(rf"\b(\d{{1,2}})(?:st|nd|rd|th)?\s+({_MONTH})\s+(\d{{4}})\b", re.IGNORECASE)
_MONTH_DAY_YEAR = re.compile(rf"\b({_MONTH})\s+(\d{{1,2}})(?:st|nd|rd|th)?,?\s+(\d{{4}})\b", re.IGNORECASE)
_ISSUER_LABEL = re.compile(r"^\s*(?:issued by|issuer|issuing authority)\s*[:\-]\s*(.+?)\s*$",
                           re.IGNORECASE | re.MULTILINE)
_ORGANISATION = re.compile(
    r"\b(university|college|institute|school|academy|ministry|department|board|council|authority|"
    r"office|limited|ltd|inc|llc|corporation|company|bank|hospital)\b", re.IGNORECASE)


def _iso(year, month, day) -> str | None:
    try:
        return date(int(year), int(month), int(day)).isoformat()
    except ValueError:
        return None


def find_date(text: str) -> str | None:
    """The first unambiguous date in the text, as YYYY-MM-DD.

    Numeric dates such as 03/04/2026 are skipped: they read differently in
    different countries, and a wrong guess is worse than none.
    """
    found = []
    for match in _ISO_DATE.finditer(text):
        found.append((match.start(), _iso(*match.groups())))
    for match in _DAY_MONTH_YEAR.finditer(text):
        day, month, year = match.groups()
        found.append((match.start(), _iso(year, _MONTHS[month.lower()], day)))
    for match in _MONTH_DAY_YEAR.finditer(text):
        month, day, year = match.groups()
        found.append((match.start(), _iso(year, _MONTHS[month.lower()], day)))
    for _, value in sorted(item for item in found if item[1]):
        return value
    return None


def find_document_type(filename: str, text: str) -> str | None:
    for source in (text[:2000], filename.replace("_", " ").replace("-", " ")):
        for pattern, label in _TYPES:
            if re.search(rf"\b(?:{pattern})\b", source, re.IGNORECASE):
                return label
    return None


def find_issuer(text: str) -> str | None:
    labelled = _ISSUER_LABEL.search(text)
    if labelled:
        return labelled.group(1)[:120]
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    for line in lines[:15]:
        if len(line) <= 80 and _ORGANISATION.search(line):
            return line
    return None


def suggest_from_text(filename: str, text: str) -> dict:
    """Suggestions found by simple text rules. Empty when nothing was found."""
    suggestion = {}
    issuer = find_issuer(text)
    if issuer:
        suggestion["issuer"] = issuer
    found_date = find_date(text)
    if found_date:
        suggestion["date"] = found_date
    document_type = find_document_type(filename, text)
    if document_type:
        suggestion["document_type"] = document_type
        if document_type in _CATEGORIES:
            suggestion["category"] = _CATEGORIES[document_type]
    if suggestion:
        suggestion["source"] = SOURCE
    return suggestion


_PASS = ("Every check passed. The document you gave is identical, byte for byte, to one that was registered, "
         "and the registration is recorded in the published ledger. This shows the document has not changed "
         "since it was registered. It does not show who created it or that what it says is true.")

_REASONS = {
    "DOCUMENT_MODIFIED": "The document is not the one that was registered. Its fingerprint differs from the one in "
                         "the proof, which happens when even a single character has changed or the file was "
                         "saved again in a different format. Check that you have the original file.",
    "PROOF_INVALID": "The proof file is damaged or was altered. Its steps do not lead to the root it claims, so it "
                     "cannot show that any document belongs to a batch. Ask the registry for a fresh copy of the proof.",
    "BATCH_NOT_PUBLISHED": "The proof refers to a batch that the public ledger has no record of. A proof only "
                           "counts once its batch has been published, so this one cannot be relied on.",
    "ROOT_MISMATCH": "The proof is consistent with itself, but it leads to a different root from the one that was "
                     "published for this batch. That is what happens when records are changed after publication "
                     "and a new proof is issued, so treat this proof as unreliable.",
    "LEDGER_INVALID": "The ledger itself failed its checks: an entry was changed, removed or re-signed, or an entry "
                      "seen earlier is missing. Results that depend on this ledger cannot be trusted until that is "
                      "explained.",
}


def explain_from_template(summary: dict) -> str:
    """A fixed explanation for a finished verification, chosen by its result codes."""
    if summary.get("ok"):
        return _PASS
    reasons = [_REASONS[code] for code in summary.get("codes", []) if code in _REASONS]
    if not reasons:
        return "The document was not verified. See the checks above for the one that failed."
    return "The document was not verified. " + " ".join(reasons)
