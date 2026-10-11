"""Who may do what: staff sign-in on the registry, and the ledger's append token.

Signing in gives accountability for who registered and confirmed a record. It
has no part in verification, so everything a verifier uses must keep working
with no account and no token.
"""

import io
import json
import logging
import subprocess
import sys
import urllib.error
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from proofchain.ledger import app as ledger_app
from proofchain.registry import app as registry_app
from proofchain.registry import db, sessions, staff
from proofchain.registry.ledger_client import LedgerClient, LedgerError
from proofchain.verifier.verify import verify

from .helpers import (
    LEDGER_AUTH,
    LEDGER_TOKEN,
    STAFF,
    STAFF_PASSWORD,
    InProcessLedger,
    add_staff,
    confirm,
    ledger_view,
    proof_of,
    query,
    seal,
    sealed_batch,
    sign_in,
    sign_out,
    upload,
)
from .test_registry import ledger_url  # noqa: F401  (a real ledger process, as a fixture)

ROOT = Path(__file__).resolve().parent.parent
ROOT_A = "3a41957e48b5aeb1eb57ad1ef8f84e13c2d430783215c136b8effeda95e98c40"
NEW_ENTRY = {"batch_id": "batch-0001", "root": ROOT_A, "tree_size": 4}


@pytest.fixture
def visitor(db_path, ledger):
    """The registry as someone with no session sees it. The staff account exists."""
    with TestClient(registry_app.create_app(db_path, ledger)) as client:
        add_staff(db_path)
        yield client


def log_in(client, username=STAFF, password=STAFF_PASSWORD, next=None, **kwargs):
    data = {"username": username, "password": password}
    if next is not None:
        data["next"] = next
    return client.post("/login", data=data, follow_redirects=False, **kwargs)


def cookie_header(reply) -> str:
    return reply.headers.get("set-cookie", "")


# ---- signing in


def test_right_password_signs_in_with_a_protected_cookie(visitor):
    reply = log_in(visitor)
    assert reply.status_code == 303 and reply.headers["location"] == "/register"
    header = cookie_header(reply)
    assert header.startswith(f"{sessions.COOKIE}=")
    flags = [part.strip().lower() for part in header.split(";")[1:]]
    assert "httponly" in flags and "samesite=lax" in flags and "path=/" in flags
    assert f"max-age={sessions.MAX_AGE}" in flags
    assert "secure" not in flags  # plain http in tests; set when the request arrives over https

    page = visitor.get("/register")
    assert page.status_code == 200 and page.url.path == "/register"
    assert f'Signed in as <span class="who">{STAFF}</span>' in page.text and "Sign out" in page.text


def test_cookie_is_marked_secure_over_https(db_path, ledger):
    with TestClient(registry_app.create_app(db_path, ledger), base_url="https://registry.example") as client:
        add_staff(db_path)
        flags = [part.strip().lower() for part in cookie_header(log_in(client)).split(";")[1:]]
        assert "secure" in flags and "httponly" in flags


@pytest.mark.parametrize("username, password", [
    (STAFF, "wrong password"),
    (STAFF, STAFF_PASSWORD + " "),
    (STAFF, STAFF_PASSWORD.upper()),
    (STAFF, ""),
    ("nobody", STAFF_PASSWORD),
    ("", ""),
    ("' OR 1=1 --", "sql-injection-attempt"),
], ids=["wrong", "trailing-space", "wrong-case", "empty", "unknown-user", "nothing", "sql"])
def test_wrong_password_is_rejected(username, password, visitor):
    reply = log_in(visitor, username, password)
    assert reply.status_code == 401
    assert "Wrong username or password." in reply.text
    assert sessions.COOKIE not in cookie_header(reply)
    assert password == "" or password not in reply.text
    # Still signed out.
    assert visitor.get("/register", follow_redirects=False).status_code == 303


def test_unknown_user_and_wrong_password_give_the_same_answer(visitor):
    unknown, wrong = log_in(visitor, "nobody", "whatever-1"), log_in(visitor, STAFF, "whatever-1")
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.text.replace('value="nobody"', "") == wrong.text.replace(f'value="{STAFF}"', "")


def test_usernames_are_not_case_sensitive(visitor, db_path):
    assert log_in(visitor, "  Asha ").status_code == 303
    upload(visitor, "a.txt", b"Document A")
    confirm(visitor, 1)
    assert query(db_path, "SELECT confirmed_by FROM records")[0]["confirmed_by"] == STAFF


def test_login_page_is_public_and_skipped_when_already_signed_in(visitor):
    page = visitor.get("/login")
    assert page.status_code == 200 and 'name="password"' in page.text and "There is no sign-up page." in page.text
    log_in(visitor)
    again = visitor.get("/login?next=/audit", follow_redirects=False)
    assert again.status_code == 303 and again.headers["location"] == "/audit"


def test_there_is_no_way_to_sign_up_over_http(visitor, db_path):
    for path in ("/signup", "/register/account", "/staff", "/users"):
        assert visitor.post(path, data={"username": "mallory", "password": "password-1"}).status_code in (404, 405)
    assert [row["username"] for row in query(db_path, "SELECT username FROM staff")] == [STAFF]


# ---- protected routes

PROTECTED = [
    ("GET", "/register"),
    ("POST", "/records"),
    ("POST", "/records/5/confirm"),
    ("POST", "/records/5/discard"),
    ("GET", "/records"),
    ("POST", "/batches/batch-0002/seal"),
    ("GET", "/records/3/proof"),
    ("GET", "/records/3/document"),
    ("GET", "/audit"),
]


@pytest.fixture
def populated(visitor, db_path):
    """A sealed batch (records 1 to 4), an open batch-0002 holding record 6, and record 5 waiting."""
    sign_in(visitor)
    sealed_batch(visitor, db_path)
    upload(visitor, "waiting.txt", b"Document E")
    upload(visitor, "open.txt", b"Document F")
    confirm(visitor, 6)
    return sign_out(visitor)


def snapshot(db_path, ledger):
    return (query(db_path, "SELECT id, metadata_confirmed, batch_id, confirmed_by FROM records ORDER BY id"),
            query(db_path, "SELECT id, status, root FROM batches ORDER BY id"), ledger.entries())


@pytest.mark.parametrize("method, path", PROTECTED, ids=[f"{m} {p}" for m, p in PROTECTED])
def test_protected_route_redirects_to_login_when_signed_out(method, path, populated, db_path, ledger):
    before = snapshot(db_path, ledger)
    body = {"files": {"file": ("x.txt", b"Document X")}} if path == "/records" and method == "POST" else \
           {"data": {"issuer": "X", "document_type": "Y", "confirmed_by": "Mallory"}} if method == "POST" else {}
    reply = populated.request(method, path, follow_redirects=False, **body)

    assert reply.status_code == 303
    expected = "/login?next=" + path.replace("/", "%2F") if method == "GET" else "/login"
    assert reply.headers["location"] == expected
    assert reply.content == b""  # no page, no document, no proof
    assert snapshot(db_path, ledger) == before


@pytest.mark.parametrize("method, path", PROTECTED, ids=[f"{m} {p}" for m, p in PROTECTED])
def test_protected_route_works_once_signed_in(method, path, populated):
    sign_in(populated)
    body = {"files": {"file": ("x.txt", b"Document X")}} if path == "/records" and method == "POST" else \
           {"data": {"issuer": "X", "document_type": "Y"}} if method == "POST" else {}
    reply = populated.request(method, path, **body)
    assert reply.status_code == 200 and reply.url.path != "/login"


def test_home_leads_a_visitor_to_the_login_page(visitor):
    reply = visitor.get("/")
    assert reply.status_code == 200 and reply.url.path == "/login"
    assert "Custodian Login" in reply.text and "Signed in as" not in reply.text
    # The custodian pages are not offered to someone who is not signed in.
    assert 'href="/audit"' not in reply.text and 'href="/verify"' in reply.text


@pytest.mark.parametrize("wanted", ["/audit", "/records", "/records?notice=Sealed+batch-0001.", "/records/3/proof"])
def test_signing_in_returns_to_the_page_that_was_asked_for(wanted, populated):
    bounced = populated.get(wanted, follow_redirects=False)
    assert bounced.status_code == 303
    login_page = populated.get(bounced.headers["location"])
    assert login_page.status_code == 200
    hidden = wanted.replace("&", "&amp;")
    assert f'name="next" value="{hidden}"' in login_page.text

    reply = log_in(populated, next=wanted)
    assert reply.status_code == 303 and reply.headers["location"] == wanted
    assert populated.get(wanted).status_code == 200


@pytest.mark.parametrize("next_path", [
    "https://evil.example/", "//evil.example/", "/\\evil.example", "evil.example", "javascript:alert(1)", "",
])
def test_signing_in_never_redirects_to_another_site(next_path, visitor):
    assert log_in(visitor, next=next_path).headers["location"] == "/register"
    page = visitor.get("/login", params={"next": next_path}, follow_redirects=False)
    assert page.headers.get("location", "/register") == "/register"


def test_a_failed_login_keeps_the_page_to_return_to(visitor):
    reply = log_in(visitor, password="wrong password", next="/audit")
    assert reply.status_code == 401 and 'name="next" value="/audit"' in reply.text


# ---- sessions


def test_signing_out_ends_the_session(visitor):
    log_in(visitor)
    assert visitor.get("/audit", follow_redirects=False).status_code == 200
    reply = visitor.post("/logout", follow_redirects=False)
    assert reply.status_code == 303 and reply.headers["location"].startswith("/login")
    assert f'{sessions.COOKIE}=""' in cookie_header(reply) or "Max-Age=0" in cookie_header(reply)
    assert visitor.get("/audit", follow_redirects=False).status_code == 303
    assert "Signed out." in visitor.get(reply.headers["location"]).text


def test_signing_out_is_a_post(visitor):
    log_in(visitor)
    assert visitor.get("/logout").status_code == 405
    assert visitor.get("/audit", follow_redirects=False).status_code == 200


def forged_cookies(secret):
    good = sessions.issue(STAFF, secret)
    payload, signature = good.split(".")
    other = sessions.issue("root", b"x" * 32).split(".")[0]
    return {
        "garbage": "not-a-session",
        "empty": "",
        "no-signature": payload,
        "empty-signature": payload + ".",
        "flipped-signature": payload + "." + ("0" if signature[0] != "0" else "1") + signature[1:],
        "another-users-payload": other + "." + signature,
        "signed-with-another-secret": sessions.issue(STAFF, b"y" * 32),
        "expired": sessions.issue(STAFF, secret, now=0),
        "just-expired": sessions.issue(STAFF, secret, now=__import__("time").time() - sessions.MAX_AGE - 1),
        "three-parts": good + ".extra",
        "not-ascii": "café." + signature,
    }


@pytest.mark.parametrize("kind", list(forged_cookies(b"k" * 32)))
def test_a_forged_altered_or_expired_cookie_is_not_a_session(kind, visitor):
    cookie = forged_cookies(visitor.app.state.session_secret)[kind]
    reply = visitor.get("/audit", headers={"Cookie": f"{sessions.COOKIE}={cookie}".encode("utf-8")},
                        follow_redirects=False)
    assert reply.status_code == 303 and reply.headers["location"].startswith("/login")


def test_session_read_accepts_only_what_it_issued():
    secret = b"s" * 32
    assert sessions.read(sessions.issue("asha", secret), secret) == "asha"
    assert sessions.read(sessions.issue("asha", secret, now=1000), secret, now=1000 + sessions.MAX_AGE - 1) == "asha"
    assert sessions.read(sessions.issue("asha", secret, now=1000), secret, now=1000 + sessions.MAX_AGE) is None
    for bad in (None, 7, b"bytes", "a.b", ".", "..", "e30=." + "0" * 64):
        assert sessions.read(bad, secret) is None


def test_a_session_for_a_removed_account_stops_working(visitor, db_path):
    log_in(visitor)
    assert visitor.get("/audit", follow_redirects=False).status_code == 200
    conn = db.connect(db_path)
    conn.execute("DELETE FROM staff WHERE username = ?", (STAFF,))
    conn.close()
    assert visitor.get("/audit", follow_redirects=False).status_code == 303


def test_session_secret_is_generated_beside_the_database_and_reused(db_path, ledger):
    secret_file = db_path.parent / sessions.SECRET_FILE
    assert not secret_file.exists()
    with TestClient(registry_app.create_app(db_path, ledger)) as first:
        add_staff(db_path)
        log_in(first)
        cookie = first.cookies.get(sessions.COOKIE)
    stored = secret_file.read_text().strip()
    assert len(stored) == 64 and first.app.state.session_secret == stored.encode()

    with TestClient(registry_app.create_app(db_path, ledger)) as second:  # restart: same secret, session still good
        assert second.app.state.session_secret == stored.encode()
        second.cookies.set(sessions.COOKIE, cookie)
        assert second.get("/audit", follow_redirects=False).status_code == 200
    assert secret_file.read_text().strip() == stored


def test_session_secret_can_come_from_the_environment(db_path, ledger, monkeypatch):
    monkeypatch.setenv("PROOFCHAIN_SESSION_SECRET", "e" * 40)
    with TestClient(registry_app.create_app(db_path, ledger)) as client:
        assert client.app.state.session_secret == b"e" * 40
    assert not (db_path.parent / sessions.SECRET_FILE).exists()


def test_a_short_session_secret_stops_the_registry_from_starting(db_path, ledger, monkeypatch):
    monkeypatch.setenv("PROOFCHAIN_SESSION_SECRET", "too-short")
    with pytest.raises(RuntimeError, match="at least 32 characters"):
        with TestClient(registry_app.create_app(db_path, ledger)):
            pass


def test_two_registries_do_not_accept_each_others_sessions(tmp_path, ledger):
    with TestClient(registry_app.create_app(tmp_path / "one" / "r.db", ledger)) as one, \
         TestClient(registry_app.create_app(tmp_path / "two" / "r.db", ledger)) as two:
        add_staff(one.app.state.db_path)
        add_staff(two.app.state.db_path)
        log_in(one)
        two.cookies.set(sessions.COOKIE, one.cookies.get(sessions.COOKIE))
        assert one.get("/audit", follow_redirects=False).status_code == 200
        assert two.get("/audit", follow_redirects=False).status_code == 303


# ---- accountability


def test_confirmed_by_is_the_signed_in_account_and_a_posted_value_is_ignored(visitor, db_path):
    log_in(visitor)
    upload(visitor, "a.txt", b"Document A")
    reply = confirm(visitor, 1, confirmed_by="The Registrar Herself")
    assert reply.status_code == 200

    row = query(db_path, "SELECT confirmed_by, metadata FROM records")[0]
    assert row["confirmed_by"] == STAFF
    assert "Registrar" not in json.dumps(row)
    page = visitor.get("/records").text
    assert f"<td>{STAFF}</td>" in page and "The Registrar Herself" not in page


def test_the_confirm_form_has_no_field_for_a_name(visitor):
    log_in(visitor)
    upload(visitor, "a.txt", b"Document A")
    page = visitor.get("/register").text
    assert 'name="confirmed_by"' not in page and "Your name" not in page
    assert f"checked by <strong>{STAFF}</strong>" in page


def test_each_confirmation_names_whoever_was_signed_in(visitor, db_path):
    add_staff(db_path, "bilal")
    upload(sign_in(visitor, STAFF), "a.txt", b"Document A")
    confirm(visitor, 1)
    upload(sign_in(visitor, "bilal"), "b.txt", b"Document B")
    confirm(visitor, 2, confirmed_by=STAFF)  # claiming to be someone else changes nothing
    assert [row["confirmed_by"] for row in query(db_path, "SELECT confirmed_by FROM records ORDER BY id")] == [
        STAFF, "bilal"]


def test_signing_in_changes_nothing_about_proofs_or_verdicts(visitor, db_path, ledger):
    add_staff(db_path, "bilal")
    sign_in(visitor, "bilal")
    sealed_batch(visitor, db_path)
    proof = proof_of(visitor, 3)
    assert set(proof) == {"version", "canon", "fingerprint", "salt", "batch_id", "leaf_index", "tree_size",
                          "path", "root"}
    assert "bilal" not in json.dumps(proof) and "bilal" not in json.dumps(ledger.entries())
    entries, public_key, pin = ledger_view(ledger)
    assert verify(b"Document C", proof, entries, public_key, pin).ok


# ---- what must stay public


def test_verify_page_works_signed_out(populated, db_path):
    sign_in(populated)
    proof = json.dumps(proof_of(populated, 3)).encode()
    sign_out(populated)

    page = populated.get("/verify", follow_redirects=False)
    assert page.status_code == 200 and "Run the five checks" in page.text
    assert "Custodian Login" in page.text and "Signed in as" not in page.text

    files = {"document": ("c.txt", b"Document C"), "proof": ("c.proof.json", proof)}
    good = populated.post("/verify", files=files, follow_redirects=False)
    assert good.status_code == 200 and "<strong>Verified.</strong>" in good.text
    files["document"] = ("c.txt", b"Document C!")
    bad = populated.post("/verify", files=files, follow_redirects=False)
    assert bad.status_code == 200 and "DOCUMENT_MODIFIED" in bad.text


def test_static_files_and_the_login_page_need_no_session(visitor):
    assert visitor.get("/static/style.css", follow_redirects=False).status_code == 200
    assert visitor.get("/login", follow_redirects=False).status_code == 200


@pytest.fixture
def ledger_client(ledger_paths):
    """The ledger service itself, with no token attached to the client."""
    with TestClient(ledger_app.create_app(*ledger_paths)) as client:
        yield client


@pytest.mark.parametrize("path", ["/entries", "/entries/batch-0001", "/head", "/pubkey"])
def test_ledger_reads_need_no_token(path, ledger_client):
    assert ledger_client.post("/entries", json=NEW_ENTRY, headers=LEDGER_AUTH).status_code == 201
    reply = ledger_client.get(path)
    assert reply.status_code == 200 and "www-authenticate" not in reply.headers


def test_cli_verifier_needs_no_account_or_token(ledger_url, db_path, tmp_path, monkeypatch):  # noqa: F811
    with TestClient(registry_app.create_app(db_path, LedgerClient(ledger_url))) as registry:
        sign_in(registry)
        sealed_batch(registry, db_path)
        (tmp_path / "c.proof.json").write_bytes(registry.get("/records/3/proof").content)
    (tmp_path / "c.txt").write_bytes(b"Document C")

    env = {k: v for k, v in __import__("os").environ.items()
           if k not in ("PROOFCHAIN_LEDGER_TOKEN", "PROOFCHAIN_SESSION_SECRET")}
    done = subprocess.run([sys.executable, "-m", "proofchain.verifier", "verify", "--doc", tmp_path / "c.txt",
                           "--proof", tmp_path / "c.proof.json", "--ledger", ledger_url],
                          capture_output=True, text=True, env=env, cwd=tmp_path)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "VERIFIED" in done.stdout


# ---- the ledger's append token


@pytest.mark.parametrize("headers", [
    {},
    {"Authorization": "Bearer wrong-token"},
    {"Authorization": f"Bearer {LEDGER_TOKEN}x"},
    {"Authorization": f"Bearer {LEDGER_TOKEN[:-1]}"},
    {"Authorization": "Bearer "},
    {"Authorization": "Bearer"},
    {"Authorization": LEDGER_TOKEN},
    {"Authorization": f"Basic {LEDGER_TOKEN}"},
    {"Authorization": f"Token {LEDGER_TOKEN}"},
    {"X-Ledger-Token": LEDGER_TOKEN},
    {"Cookie": f"token={LEDGER_TOKEN}"},
], ids=["none", "wrong", "longer", "shorter", "empty", "scheme-only", "no-scheme", "basic", "other-scheme",
        "other-header", "cookie"])
def test_append_is_rejected_without_the_right_token(headers, ledger_client, ledger_paths):
    reply = ledger_client.post("/entries", json=NEW_ENTRY, headers=headers)
    assert reply.status_code == 401
    assert reply.headers["www-authenticate"] == "Bearer"
    assert LEDGER_TOKEN not in reply.text
    assert ledger_client.get("/entries").json() == []
    assert not ledger_paths[0].exists()


def test_append_is_accepted_with_the_token(ledger_client):
    reply = ledger_client.post("/entries", json=NEW_ENTRY, headers=LEDGER_AUTH)
    assert reply.status_code == 201 and reply.json()["root"] == ROOT_A
    lower = ledger_client.post("/entries", json=dict(NEW_ENTRY, batch_id="batch-0002"),
                               headers={"authorization": f"bearer {LEDGER_TOKEN}"})
    assert lower.status_code == 201  # the scheme name is case-insensitive


def test_the_token_is_checked_before_the_request_is_looked_at(ledger_client):
    assert ledger_client.post("/entries", json={"batch_id": ""}).status_code == 401
    assert ledger_client.post("/entries", json={"batch_id": ""}, headers=LEDGER_AUTH).status_code == 422


def test_the_token_can_be_given_directly_instead_of_through_the_environment(ledger_paths):
    with TestClient(ledger_app.create_app(*ledger_paths, token="given-directly-0123456789")) as client:
        assert client.post("/entries", json=NEW_ENTRY, headers=LEDGER_AUTH).status_code == 401
        assert client.post("/entries", json=NEW_ENTRY,
                           headers={"Authorization": "Bearer given-directly-0123456789"}).status_code == 201


@pytest.mark.parametrize("configured", [None, ""], ids=["unset", "empty"])
def test_a_ledger_started_without_a_token_refuses_appends_and_says_why(
    configured, ledger_paths, monkeypatch, caplog
):
    if configured is None:
        monkeypatch.delenv("PROOFCHAIN_LEDGER_TOKEN")
    else:
        monkeypatch.setenv("PROOFCHAIN_LEDGER_TOKEN", configured)
    with caplog.at_level(logging.WARNING, logger="proofchain.ledger"):
        with TestClient(ledger_app.create_app(*ledger_paths)) as client:
            assert "PROOFCHAIN_LEDGER_TOKEN" in caplog.text and "appends are disabled" in caplog.text

            for headers in ({}, LEDGER_AUTH, {"Authorization": "Bearer "}, {"Authorization": "Bearer None"}):
                reply = client.post("/entries", json=NEW_ENTRY, headers=headers)
                assert reply.status_code == 503
                assert "PROOFCHAIN_LEDGER_TOKEN" in reply.json()["detail"]
            # Reading is unaffected, and nothing was appended.
            assert client.get("/entries").json() == []
            assert client.get("/pubkey").status_code == 200
            assert client.get("/head").status_code == 404
    assert not ledger_paths[0].exists()


def test_a_ledger_with_a_token_does_not_warn(ledger_paths, caplog):
    with caplog.at_level(logging.WARNING, logger="proofchain.ledger"):
        with TestClient(ledger_app.create_app(*ledger_paths)):
            pass
    assert caplog.text == ""


# ---- the registry's client and the token


class Recorder:
    """Stands in for urllib's urlopen: records each request and answers with a status."""

    def __init__(self, status=200, body=b"[]"):
        self.requests, self.status, self.body = [], status, body

    def __call__(self, request, timeout=None):
        self.requests.append(request)
        if self.status >= 400:
            raise urllib.error.HTTPError(request.full_url, self.status, "error", {}, io.BytesIO(b"{}"))
        reply = io.BytesIO(self.body)
        reply.status = self.status
        return reply


def test_client_sends_the_token_only_when_appending(monkeypatch):
    recorder = Recorder()
    monkeypatch.setattr("urllib.request.urlopen", recorder)
    client = LedgerClient("http://ledger.example")
    assert client.token == LEDGER_TOKEN  # from the environment

    client.entries()
    recorder.body = b'{"public_key": "ab"}'
    client.public_key()
    recorder.body = b"{}"
    client.entry("batch-0001")
    assert [r.get_header("Authorization") for r in recorder.requests] == [None, None, None]

    recorder.status = 201
    client.publish("batch-0001", ROOT_A, 4)
    assert recorder.requests[-1].get_method() == "POST"
    assert recorder.requests[-1].get_header("Authorization") == f"Bearer {LEDGER_TOKEN}"


def test_client_without_a_token_sends_none(monkeypatch):
    monkeypatch.delenv("PROOFCHAIN_LEDGER_TOKEN")
    recorder = Recorder(status=401)
    monkeypatch.setattr("urllib.request.urlopen", recorder)
    client = LedgerClient("http://ledger.example")
    assert client.token is None
    with pytest.raises(LedgerError, match="not set for the registry"):
        client.publish("batch-0001", ROOT_A, 4)
    assert recorder.requests[-1].get_header("Authorization") is None


@pytest.mark.parametrize("status, message", [
    (401, "rejected the registry's token"),
    (503, "started without PROOFCHAIN_LEDGER_TOKEN"),
])
def test_client_explains_a_refused_append(status, message, monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen", Recorder(status=status))
    with pytest.raises(LedgerError, match=message) as refused:
        LedgerClient("http://ledger.example").publish("batch-0001", ROOT_A, 4)
    assert LEDGER_TOKEN not in str(refused.value)


def test_registry_cannot_seal_with_the_wrong_token(ledger_url, db_path):  # noqa: F811
    with TestClient(registry_app.create_app(db_path, LedgerClient(ledger_url, token="not-the-token"))) as registry:
        sign_in(registry)
        upload(registry, "a.txt", b"Document A")
        confirm(registry, 1)
        reply = seal(registry)
        assert reply.status_code == 502
        assert "still open" in reply.text and "rejected the registry" in reply.text
        assert "not-the-token" not in reply.text
        assert query(db_path, "SELECT status, root FROM batches") == [{"status": "open", "root": None}]
    assert LedgerClient(ledger_url).entries() == []

    with TestClient(registry_app.create_app(db_path, LedgerClient(ledger_url))) as registry:  # the right token
        assert seal(sign_in(registry)).status_code == 200
    assert len(LedgerClient(ledger_url).entries()) == 1


def test_registry_cannot_seal_when_the_ledger_has_no_token(db_path, ledger_paths, monkeypatch):
    monkeypatch.delenv("PROOFCHAIN_LEDGER_TOKEN")
    with TestClient(ledger_app.create_app(*ledger_paths)) as ledger_service:
        with TestClient(registry_app.create_app(db_path, InProcessLedger(ledger_service))) as registry:
            sign_in(registry)
            upload(registry, "a.txt", b"Document A")
            confirm(registry, 1)
            reply = seal(registry)
            assert reply.status_code == 502 and "PROOFCHAIN_LEDGER_TOKEN" in reply.text
            assert query(db_path, "SELECT status FROM batches") == [{"status": "open"}]


# ---- passwords and accounts


def test_only_a_salted_hash_is_stored(db_path, registry):
    conn = db.connect(db_path)
    try:
        staff.add_staff(conn, "Bilal", "a long passphrase")
        staff.add_staff(conn, "chen", "a long passphrase")
        rows = {r["username"]: r["password_hash"] for r in conn.execute("SELECT * FROM staff")}
    finally:
        conn.close()
    assert set(rows) == {STAFF, "bilal", "chen"}
    for stored in (rows["bilal"], rows["chen"]):
        scheme, n, r, p, salt, digest = stored.split("$")
        assert (scheme, n, r, p) == ("scrypt", "16384", "8", "1")
        assert len(bytes.fromhex(salt)) == 16 and len(bytes.fromhex(digest)) == 32
        assert "passphrase" not in stored
    assert rows["bilal"] != rows["chen"]  # same password, different salt
    assert b"a long passphrase" not in Path(db_path).read_bytes()


def test_verify_password():
    stored = staff.hash_password("s3cret-enough")
    assert staff.verify_password("s3cret-enough", stored)
    assert not staff.verify_password("s3cret-enougH", stored)
    assert not staff.verify_password("", stored)
    for broken in (None, "", "plain-text-password", "scrypt$1$2", "md5$1$1$1$00$00", "scrypt$x$8$1$00$00",
                   "scrypt$16384$8$1$zz$00", stored + "$extra"):
        assert not staff.verify_password("s3cret-enough", broken)


def test_authenticate(db_path, registry):
    conn = db.connect(db_path)
    try:
        assert staff.authenticate(conn, STAFF, STAFF_PASSWORD) == STAFF
        assert staff.authenticate(conn, STAFF.upper(), STAFF_PASSWORD) == STAFF
        assert staff.authenticate(conn, STAFF, "nope") is None
        assert staff.authenticate(conn, "nobody", STAFF_PASSWORD) is None
        assert staff.authenticate(conn, None, None) is None
    finally:
        conn.close()


@pytest.mark.parametrize("username, password, message", [
    ("", "long-enough-1", "a username is"),
    ("has space", "long-enough-1", "a username is"),
    ("-dash", "long-enough-1", "a username is"),
    ("x" * 65, "long-enough-1", "a username is"),
    ("asha/../x", "long-enough-1", "a username is"),
    ("bilal", "short", "at least 8 characters"),
    ("bilal", "", "at least 8 characters"),
    (STAFF, "long-enough-1", "already exists"),
])
def test_accounts_that_cannot_be_created(username, password, message, db_path, registry):
    conn = db.connect(db_path)
    try:
        with pytest.raises(staff.StaffError, match=message):
            staff.add_staff(conn, username, password)
        assert [r["username"] for r in conn.execute("SELECT username FROM staff")] == [STAFF]
    finally:
        conn.close()


def staff_cli(*args, password, cwd):
    return subprocess.run([sys.executable, "-m", "proofchain.registry.staff", *[str(a) for a in args]],
                          input=password + "\n", capture_output=True, text=True, cwd=cwd, timeout=60)


def test_account_command_creates_an_account_that_can_sign_in(tmp_path, ledger):
    database = tmp_path / "fresh" / "registry.db"
    done = staff_cli("add", "Asha", "--db", database, password="kept off the command line", cwd=tmp_path)
    assert done.returncode == 0, done.stderr
    assert "Created account asha" in done.stdout
    assert "kept off the command line" not in done.stdout + done.stderr

    with TestClient(registry_app.create_app(database, ledger)) as client:
        assert log_in(client, "asha", "kept off the command line").status_code == 303
        assert client.get("/register").status_code == 200

    again = staff_cli("add", "asha", "--db", database, password="another password", cwd=tmp_path)
    assert again.returncode == 2 and "already exists" in again.stderr

    reset = staff_cli("add", "asha", "--db", database, "--reset", password="another password", cwd=tmp_path)
    assert reset.returncode == 0 and "Changed the password of asha" in reset.stdout
    with TestClient(registry_app.create_app(database, ledger)) as client:
        assert log_in(client, "asha", "kept off the command line").status_code == 401
        assert log_in(client, "asha", "another password").status_code == 303


@pytest.mark.parametrize("args, password, message", [
    (["add", "bilal"], "short", "at least 8 characters"),
    (["add", "not valid!"], "long-enough-1", "a username is"),
    (["add", "ghost", "--reset"], "long-enough-1", "no account named ghost"),
])
def test_account_command_reports_what_it_cannot_do(args, password, message, tmp_path):
    database = tmp_path / "registry.db"
    done = staff_cli(*args, "--db", database, password=password, cwd=tmp_path)
    assert done.returncode == 2 and message in done.stderr
    assert not database.exists() or query(database, "SELECT username FROM staff") == []


def test_account_command_takes_no_password_argument(tmp_path):
    done = staff_cli("add", "bilal", "--password", "on-the-command-line", "--db", tmp_path / "r.db",
                     password="", cwd=tmp_path)
    assert done.returncode == 2 and "unrecognized arguments" in done.stderr


# ---- the demo scripts


def seed(tmp_path, ledger_url, token=LEDGER_TOKEN):  # noqa: F811
    env = dict(__import__("os").environ)
    env.pop("PROOFCHAIN_LEDGER_TOKEN", None)
    if token is not None:
        env["PROOFCHAIN_LEDGER_TOKEN"] = token
    return subprocess.run([sys.executable, str(ROOT / "scripts" / "demo_seed.py"), "--db", str(tmp_path / "registry.db"),
                           "--ledger", ledger_url, "--out", str(tmp_path / "demo")],
                          capture_output=True, text=True, env=env, cwd=ROOT, timeout=120)


def test_seed_creates_a_demo_account_that_can_sign_in(tmp_path, ledger_url):  # noqa: F811
    done = seed(tmp_path, ledger_url)
    assert done.returncode == 0, done.stderr
    line = next(l for l in done.stdout.splitlines() if l.startswith("Sign in to the registry pages as:"))
    account, password = [part.strip() for part in line.split(":", 1)[1].split("/")]
    assert account == "demo" and len(password) >= 12

    database = tmp_path / "registry.db"
    assert [r["confirmed_by"] for r in query(database, "SELECT confirmed_by FROM records WHERE batch_id IS NOT NULL")] \
        == ["demo"] * 4
    assert password.encode() not in database.read_bytes()

    with TestClient(registry_app.create_app(database, LedgerClient(ledger_url))) as registry:
        assert log_in(registry, "demo", "not the password").status_code == 401
        assert log_in(registry, account, password).status_code == 303
        page = registry.get("/register").text
        assert "award_letter.txt" in page and 'Signed in as <span class="who">demo</span>' in page
        assert "Everything stored here matches its published reference." in registry.get("/audit").text


def test_seed_needs_the_ledger_token(tmp_path, ledger_url):  # noqa: F811
    done = seed(tmp_path, ledger_url, token=None)
    assert done.returncode == 2 and "PROOFCHAIN_LEDGER_TOKEN is not set" in done.stderr
    assert not (tmp_path / "registry.db").exists() and not (tmp_path / "demo").exists()


def test_seed_with_the_wrong_token_publishes_nothing(tmp_path, ledger_url):  # noqa: F811
    done = seed(tmp_path, ledger_url, token="not-the-ledger-token")
    assert done.returncode == 2 and "rejected the registry's token" in done.stderr
    assert "not-the-ledger-token" not in done.stderr
    assert LedgerClient(ledger_url).entries() == []
    assert not (tmp_path / "demo").exists()
