from conftest import PASSWORD, csrf_of, login, logged_in, new_client, signup

from app.models import User
from app.db import SessionLocal


def test_signup_and_login(client):
    assert signup(client, "alice").status_code == 303
    resp = login(client, "alice")
    assert resp.status_code == 303 and resp.headers["location"] == "/notes"
    assert client.get("/notes").status_code == 200


def test_password_is_hashed_with_argon2(client):
    signup(client, "alice")
    with SessionLocal() as db:
        stored = db.query(User).filter_by(username="alice").one().password_hash
    assert PASSWORD not in stored
    assert stored.startswith("$argon2")


def test_weak_password_rejected(client):
    resp = signup(client, "alice", "short")
    assert resp.status_code == 400
    assert "between 12 and 128" in resp.text


def test_password_equal_to_username_rejected(client):
    assert signup(client, "longusername", "LongUsername").status_code == 400


def test_invalid_username_rejected(client):
    assert signup(client, "<script>").status_code == 400


def test_duplicate_username_rejected(client):
    signup(client, "alice")
    assert signup(new_client(), "alice").status_code == 400


def test_login_error_does_not_reveal_which_part_was_wrong(client):
    signup(client, "alice")
    wrong_password = login(new_client(), "alice", "not the right password")
    no_such_user = login(new_client(), "nobody_here", "not the right password")
    assert wrong_password.status_code == no_such_user.status_code == 401
    assert "Wrong username or password." in wrong_password.text
    assert "Wrong username or password." in no_such_user.text


def test_login_is_throttled_after_five_failures(client):
    signup(client, "alice")
    for _ in range(5):
        assert login(client, "alice", "wrong password here").status_code == 401
    # Even the right password is refused while the lock lasts.
    assert login(client, "alice").status_code == 429


def test_post_without_csrf_token_is_rejected(client):
    signup(client, "alice")
    resp = client.post("/login", data={"username": "alice", "password": PASSWORD})
    assert resp.status_code == 403


def test_post_with_wrong_csrf_token_is_rejected(client):
    csrf_of(client)  # the session now holds a real token
    resp = client.post("/login", data={"username": "a", "password": "b", "csrf": "forged"})
    assert resp.status_code == 403


def test_session_is_renewed_on_login(client):
    signup(client, "alice")
    token_before = csrf_of(client)
    login(client, "alice")
    assert csrf_of(client, "/notes") != token_before


def test_logout_ends_the_session():
    client = logged_in("alice")
    client.post("/logout", data={"csrf": csrf_of(client, "/notes")})
    resp = client.get("/notes")
    assert resp.status_code == 303 and resp.headers["location"] == "/login"


def test_notes_require_login(client):
    resp = client.get("/notes")
    assert resp.status_code == 303 and resp.headers["location"] == "/login"
