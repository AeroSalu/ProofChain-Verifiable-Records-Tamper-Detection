"""The registry service and its pages.

    uvicorn proofchain.registry.app:app --port 8000

The registry stores documents, collects confirmed records into batches and asks
the ledger to publish each batch root. It reaches the ledger over HTTP only.

Its Verify page runs the same five checks as the command-line verifier. That is
a convenience: a check run by the registry is not an independent one.

The custodian pages need a signed-in staff account, so that a confirmation
names the person who made it. The Verify page does not: checking a document
never needs an account.
"""

import json
import re
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated
from urllib.parse import urlencode

from fastapi import Depends, FastAPI, File, Form, Request, UploadFile
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ..ai import explain_result, suggest_metadata
from ..core.canonical import CANONS, RAW_BYTES_V1, CanonicalError, fingerprint
from ..verifier.verify import verify
from . import audit, batching, db, models, sessions, staff
from .ledger_client import LedgerClient, LedgerError

HERE = Path(__file__).parent
MAX_UPLOAD_BYTES = 10 * 1024 * 1024

FIELD_LABELS = (("issuer", "Issuer"), ("date", "Date"), ("document_type", "Document type"), ("category", "Category"))
REQUIRED_FIELDS = ("issuer", "document_type")

templates = Jinja2Templates(directory=HERE / "templates")
templates.env.filters["short"] = lambda value: f"{value[:12]}…" if isinstance(value, str) and len(value) > 12 else value
templates.env.filters["sentence"] = lambda text: text[:1].upper() + text[1:]


class Problem(Exception):
    """A request that cannot be carried out, shown to the user as a page."""

    def __init__(self, status: int, message: str):
        self.status, self.message = status, message


class LoginRequired(Exception):
    """A custodian page was asked for without a session."""

    def __init__(self, next_path: str | None):
        self.next_path = next_path


def get_conn(request: Request):
    conn = db.connect(request.app.state.db_path)
    try:
        yield conn
    finally:
        conn.close()


Conn = Annotated[sqlite3.Connection, Depends(get_conn)]


def session_user(request: Request, conn: Conn) -> str | None:
    """The signed-in account, if the request carries a session this registry issued."""
    username = sessions.read(request.cookies.get(sessions.COOKIE), request.app.state.session_secret)
    if username is not None and not staff.exists(conn, username):
        username = None  # the account was removed after the cookie was issued
    request.state.user = username
    return username


def require_staff(request: Request, user: Annotated[str | None, Depends(session_user)]) -> str:
    if user is None:
        # Only a page can be returned to; a form post lands on the Register page after signing in.
        back = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        raise LoginRequired(back if request.method == "GET" else None)
    return user


Staff = Annotated[str, Depends(require_staff)]
MaybeStaff = Annotated[str | None, Depends(session_user)]


def _safe_next(path) -> str:
    """Where to go after signing in: a path on this site, never another site."""
    if isinstance(path, str) and path.startswith("/") and not path.startswith("//") and chr(92) not in path:
        return path
    return "/register"


def render(request: Request, name: str, page: str, **context):
    context.update(page=page)
    context.setdefault("notice", request.query_params.get("notice"))
    context.setdefault("warning", request.query_params.get("warning"))
    context.setdefault("error", request.query_params.get("error"))
    context.setdefault("user", getattr(request.state, "user", None))
    return templates.TemplateResponse(request, name, context)


def go(path: str, notice: str, warning: str | None = None) -> RedirectResponse:
    params = {"notice": notice} if warning is None else {"notice": notice, "warning": warning}
    return RedirectResponse(f"{path}?{urlencode(params)}", status_code=303)


def _where(record: dict) -> str:
    place = record["batch_id"] if record["batch_id"] else "waiting for confirmation"
    return f"record {record['id']} ({place})"


def _duplicate_warning(earlier: list[dict]) -> str:
    """Said once, when content that is already registered is uploaded again."""
    return ("This exact content is already registered as " + ", ".join(_where(r) for r in earlier) + ". "
            "It was stored again as a separate record with its own salt, so it would become a distinct leaf. "
            "Confirm it only if a second registration is intended.")


def _safe_name(filename: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", filename) or "document"


def _download(body, media_type: str, filename: str) -> Response:
    return Response(body, media_type=media_type,
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


def _explanation(value) -> dict | None:
    """An explain hook may return plain text, or an object with text and source."""
    if not value:
        return None
    if isinstance(value, str):
        return {"text": value, "source": "claude"}
    return {"text": value.text, "source": value.source}


def create_app(db_path=None, ledger=None, suggest=None, explain=None, session_secret=None) -> FastAPI:
    """Build the service.

    ledger   anything with publish, entries, entry and public_key (the HTTP
             client by default)
    session_secret  bytes used to sign session cookies (by default taken from
             PROOFCHAIN_SESSION_SECRET, or generated beside the database)
    suggest  optional callable(filename, content) -> dict of suggested metadata
    explain  optional callable(result) -> plain-language text for a finished
             verification
    Both hooks belong to the AI helper. Neither can change a fingerprint, a
    proof or a verdict: suggestions wait for a person, and explanations are
    produced only after the checks have run.
    """

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        db.init_db(app.state.db_path)
        app.state.session_secret = session_secret or sessions.load_secret(app.state.db_path)
        yield

    app = FastAPI(title="ProofChain registry", lifespan=lifespan)
    app.state.db_path = db_path or db.default_path()
    app.state.ledger = ledger or LedgerClient()
    app.state.suggest = suggest
    app.state.explain = explain
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")

    @app.exception_handler(Problem)
    def show_problem(request: Request, exc: Problem):
        return templates.TemplateResponse(request, "base.html",
                                          {"page": "", "notice": None, "warning": None, "error": exc.message,
                                           "user": getattr(request.state, "user", None)},
                                          status_code=exc.status)

    @app.exception_handler(LoginRequired)
    def ask_to_sign_in(request: Request, exc: LoginRequired):
        query = f"?{urlencode({'next': exc.next_path})}" if exc.next_path else ""
        return RedirectResponse(f"/login{query}", status_code=303)

    @app.get("/")
    def home():
        return RedirectResponse("/register")

    # ---- signing in and out

    @app.get("/login")
    def login_page(request: Request, user: MaybeStaff, next: str = "/register"):
        if user is not None:
            return RedirectResponse(_safe_next(next), status_code=303)
        return render(request, "login.html", "login", next=_safe_next(next))

    @app.post("/login")
    def login(request: Request, conn: Conn, username: Annotated[str, Form()] = "",
              password: Annotated[str, Form()] = "", next: Annotated[str, Form()] = "/register"):
        account = staff.authenticate(conn, username, password)
        if account is None:
            # One message for both cases, so the page does not reveal which usernames exist.
            response = render(request, "login.html", "login", next=_safe_next(next), user=None,
                              error="Wrong username or password.", username=username[:64])
            response.status_code = 401
            return response
        response = RedirectResponse(_safe_next(next), status_code=303)
        response.set_cookie(sessions.COOKIE, sessions.issue(account, request.app.state.session_secret),
                            max_age=sessions.MAX_AGE, httponly=True, samesite="lax",
                            secure=request.url.scheme == "https", path="/")
        return response

    @app.post("/logout")
    def logout():
        response = RedirectResponse(f"/login?{urlencode({'notice': 'Signed out.'})}", status_code=303)
        response.delete_cookie(sessions.COOKIE, path="/")
        return response

    # ---- register

    @app.get("/register")
    def register_page(request: Request, conn: Conn, user: Staff):
        pending = models.pending_records(conn)
        for record in pending:
            record["same_content"] = [_where(r) for r in models.same_content(conn, record["fingerprint"], record["id"])]
        return render(request, "register.html", "register", pending=pending,
                      fields=FIELD_LABELS, required=REQUIRED_FIELDS)

    @app.post("/records")
    def upload(request: Request, conn: Conn, user: Staff, file: Annotated[UploadFile, File()],
               canon: Annotated[str, Form()] = RAW_BYTES_V1):
        content = file.file.read(MAX_UPLOAD_BYTES + 1)
        if not content:
            raise Problem(422, "The file is empty.")
        if len(content) > MAX_UPLOAD_BYTES:
            raise Problem(413, "The file is larger than 10 MB.")
        if canon not in CANONS:
            raise Problem(422, f"Unknown canonical form: {canon}")
        try:
            digest = fingerprint(canon, content)
        except CanonicalError as exc:
            raise Problem(422, f"This file cannot be registered as {canon}: {exc}") from exc

        filename = Path(file.filename or "document").name
        suggested = {}
        if request.app.state.suggest is not None:
            try:
                suggested = dict(request.app.state.suggest(filename, content))
            except Exception:  # suggestions are optional; registration must not depend on them
                suggested = {}
        record_id = models.add_record(conn, filename, content, canon, digest, suggested)
        earlier = models.same_content(conn, digest, record_id)
        return go("/register", f"Stored {filename}. Check its details and confirm them.",
                  _duplicate_warning(earlier) if earlier else None)

    @app.post("/records/{record_id}/confirm")
    def confirm(record_id: int, conn: Conn, user: Staff,
                issuer: Annotated[str, Form()] = "", date: Annotated[str, Form()] = "",
                document_type: Annotated[str, Form()] = "", category: Annotated[str, Form()] = ""):
        # Who confirmed is the signed-in account. The form has no field for it, and one posted anyway is not read.
        metadata = {"issuer": issuer.strip(), "date": date.strip(),
                    "document_type": document_type.strip(), "category": category.strip()}
        if not all(metadata[name] for name in REQUIRED_FIELDS):
            raise Problem(422, "Issuer and document type are required.")
        try:
            batch_id = batching.confirm_record(conn, record_id, metadata, user)
        except batching.NotFound as exc:
            raise Problem(404, str(exc)) from exc
        except batching.Conflict as exc:
            raise Problem(409, str(exc)) from exc
        return go("/records", f"Confirmed. The record joined {batch_id}.")

    @app.post("/records/{record_id}/discard")
    def discard(record_id: int, conn: Conn, user: Staff):
        record = models.get_record(conn, record_id)
        if record is None:
            raise Problem(404, f"There is no record {record_id}.")
        if not models.discard_pending(conn, record_id):
            raise Problem(409, f"Record {record_id} has been confirmed. A registered record cannot be removed.")
        return go("/register", f"Discarded {record['filename']}. It was never registered.")

    # ---- records and batches

    @app.get("/records")
    def records_page(request: Request, conn: Conn, user: Staff):
        admin = staff.is_admin(conn, user)
        batches = models.list_batches(conn)
        for batch in batches:
            batch["records"] = models.batch_records(conn, batch["id"])
            batch["can_seal"] = batching.may_seal(batch, user, admin)
        mine = [batch for batch in batches if batch["owner"] == user]
        others = [batch for batch in batches if batch["owner"] != user]
        return render(request, "records.html", "records", mine=mine, others=others, is_admin=admin)

    @app.post("/batches/{batch_id}/seal")
    def seal(batch_id: str, request: Request, conn: Conn, user: Staff):
        try:
            entry = batching.seal_batch(conn, batch_id, request.app.state.ledger, user, staff.is_admin(conn, user))
        except batching.NotFound as exc:
            raise Problem(404, str(exc)) from exc
        except batching.Forbidden as exc:
            raise Problem(403, str(exc)) from exc
        except batching.Conflict as exc:
            raise Problem(409, str(exc)) from exc
        except LedgerError as exc:
            raise Problem(502, f"The batch was not sealed and is still open. {exc}") from exc
        return go("/records", f"Sealed {batch_id}. Its root is ledger entry {entry['seq']}.")

    @app.get("/records/{record_id}/proof")
    def proof(record_id: int, conn: Conn, user: Staff):
        try:
            record, bundle = batching.build_proof(conn, record_id)
        except batching.NotFound as exc:
            raise Problem(404, str(exc)) from exc
        except batching.Conflict as exc:
            raise Problem(409, str(exc)) from exc
        return _download(bundle.dumps(), "application/json", _safe_name(record["filename"]) + ".proof.json")

    @app.get("/records/{record_id}/document")
    def document(record_id: int, conn: Conn, user: Staff):
        record = models.get_record(conn, record_id)
        if record is None:
            raise Problem(404, f"There is no record {record_id}.")
        return _download(models.record_content(conn, record_id), "application/octet-stream",
                         _safe_name(record["filename"]))

    # ---- audit

    @app.get("/audit")
    def audit_page(request: Request, conn: Conn, user: Staff):
        return render(request, "audit.html", "audit", report=audit.run_audit(conn, request.app.state.ledger))

    # ---- verify (public: checking a document never needs an account)

    @app.get("/verify")
    def verify_page(request: Request, user: MaybeStaff):
        return render(request, "verify.html", "verify", result=None)

    @app.post("/verify")
    def run_verify(request: Request, conn: Conn, user: MaybeStaff, document: Annotated[UploadFile, File()],
                   proof: Annotated[UploadFile, File()]):
        content = document.file.read(MAX_UPLOAD_BYTES + 1)
        try:
            bundle = json.loads(proof.file.read(MAX_UPLOAD_BYTES).decode("utf-8"))
        except ValueError:
            bundle = None  # unreadable proof: the verifier reports PROOF_INVALID
        ledger = request.app.state.ledger
        try:
            entries = ledger.entries()
            public_key = audit.known_public_key(conn, ledger)
        except LedgerError as exc:
            raise Problem(502, f"No verdict: the ledger could not be read. {exc}") from exc

        result = verify(content, bundle, entries, public_key, audit.registry_pin(conn))
        explanation = None
        if request.app.state.explain is not None:
            try:
                explanation = _explanation(request.app.state.explain(result))
            except Exception:  # an explanation is optional; the verdict above already stands
                explanation = None
        return render(request, "verify.html", "verify", result=result, explanation=explanation,
                      document_name=Path(document.filename or "document").name)

    return app


app = create_app(suggest=suggest_metadata, explain=explain_result)
