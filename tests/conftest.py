import os
import re
import tempfile

import pytest

# Point the app at a throwaway database before it is imported.
_db_file = os.path.join(tempfile.mkdtemp(), "test.db")
os.environ["DATABASE_URL"] = f"sqlite:///{_db_file}"
os.environ["SECRET_KEY"] = "test-secret-key-not-for-production"

from fastapi.testclient import TestClient  # noqa: E402

from app.db import Base, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.security import login_throttle  # noqa: E402

PASSWORD = "correct horse battery staple"
CSRF_RE = re.compile(r'name="csrf" value="([^"]+)"')


@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    login_throttle._failures.clear()
    yield


def new_client() -> TestClient:
    return TestClient(app, follow_redirects=False)


def csrf_of(client: TestClient, path: str = "/login") -> str:
    match = CSRF_RE.search(client.get(path).text)
    assert match, f"no CSRF token on {path}"
    return match.group(1)


def signup(client: TestClient, username: str, password: str = PASSWORD):
    return client.post(
        "/signup",
        data={"username": username, "password": password, "csrf": csrf_of(client, "/signup")},
    )


def login(client: TestClient, username: str, password: str = PASSWORD):
    return client.post(
        "/login",
        data={"username": username, "password": password, "csrf": csrf_of(client, "/login")},
    )


def logged_in(username: str) -> TestClient:
    client = new_client()
    assert signup(client, username).status_code == 303
    assert login(client, username).status_code == 303
    return client


def add_note(client: TestClient, title: str, body: str = ""):
    return client.post("/notes", data={"title": title, "body": body, "csrf": csrf_of(client, "/notes")})


@pytest.fixture
def client():
    return new_client()
