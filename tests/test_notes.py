import re

from conftest import add_note, csrf_of, logged_in

from app.db import SessionLocal
from app.models import Note


def note_id(title: str) -> int:
    with SessionLocal() as db:
        return db.query(Note).filter_by(title=title).one().id


def test_create_and_list_notes():
    alice = logged_in("alice")
    assert add_note(alice, "Shopping", "milk").status_code == 303
    page = alice.get("/notes").text
    assert "Shopping" in page and "milk" in page


def test_users_only_see_their_own_notes():
    alice, bob = logged_in("alice"), logged_in("bob")
    add_note(alice, "Alice secret")
    assert "Alice secret" not in bob.get("/notes").text


def test_cannot_open_someone_elses_note():
    alice, bob = logged_in("alice"), logged_in("bob")
    add_note(alice, "Alice secret")
    assert bob.get(f"/notes/{note_id('Alice secret')}/edit").status_code == 404


def test_cannot_edit_someone_elses_note():
    alice, bob = logged_in("alice"), logged_in("bob")
    add_note(alice, "Alice secret", "original")
    nid = note_id("Alice secret")
    resp = bob.post(f"/notes/{nid}", data={"title": "hacked", "body": "x", "csrf": csrf_of(bob, "/notes")})
    assert resp.status_code == 404
    with SessionLocal() as db:
        assert db.get(Note, nid).title == "Alice secret"


def test_cannot_delete_someone_elses_note():
    alice, bob = logged_in("alice"), logged_in("bob")
    add_note(alice, "Alice secret")
    nid = note_id("Alice secret")
    resp = bob.post(f"/notes/{nid}/delete", data={"csrf": csrf_of(bob, "/notes")})
    assert resp.status_code == 404
    with SessionLocal() as db:
        assert db.get(Note, nid) is not None


def test_note_content_is_html_escaped():
    alice = logged_in("alice")
    add_note(alice, "<script>alert(1)</script>", "<img src=x onerror=alert(1)>")
    page = alice.get("/notes").text
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page
    assert "<img src=x" not in page


def test_overlong_note_rejected():
    alice = logged_in("alice")
    assert add_note(alice, "x" * 201).status_code == 400
    assert add_note(alice, "ok", "y" * 10_001).status_code == 400


def test_empty_title_rejected():
    alice = logged_in("alice")
    assert add_note(alice, "   ").status_code == 400


def test_security_headers_present():
    resp = logged_in("alice").get("/notes")
    csp = resp.headers["content-security-policy"]
    assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["cache-control"] == "no-store"


def test_session_cookie_flags():
    from conftest import PASSWORD, new_client, signup

    # Starlette only sends Set-Cookie when the session changes, so check the two
    # responses that change it: the first page view (CSRF token) and the login.
    client = new_client()
    created = client.get("/login").headers.get("set-cookie", "")
    signup(client, "alice")
    logged_in = client.post(
        "/login", data={"username": "alice", "password": PASSWORD, "csrf": csrf_of(client, "/login")}
    ).headers.get("set-cookie", "")
    for cookie in (created, logged_in):
        assert cookie.startswith("securenotes_session=")
        assert "httponly" in cookie.lower()
        assert re.search(r"samesite=lax", cookie, re.I)
