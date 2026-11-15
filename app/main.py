"""SecureNotes: a small notes app built to be secured end to end."""

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from app.config import settings
from app.db import Base, engine, get_db
from app.models import Note, User
from app.security import (
    SecurityHeadersMiddleware,
    check_csrf,
    csrf_token,
    hash_password,
    login_throttle,
    validate_credentials,
    verify_password,
)

BASE_DIR = Path(__file__).parent
TITLE_MAX, BODY_MAX = 200, 10_000


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(engine)
    yield


app = FastAPI(
    title="SecureNotes",
    lifespan=lifespan,
    # The interactive API docs are a free map of the app for attackers; keep them local.
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None,
    openapi_url=None if settings.is_production else "/openapi.json",
)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    session_cookie="securenotes_session",
    max_age=settings.session_max_age,
    same_site="lax",
    https_only=settings.is_production,
)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")

DB = Annotated[Session, Depends(get_db)]


def render(request: Request, name: str, status_code: int = 200, **context) -> HTMLResponse:
    context.update(csrf=csrf_token(request), user=getattr(request.state, "user", None))
    return templates.TemplateResponse(request, name, context, status_code=status_code)


def redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


def optional_user(request: Request, db: DB) -> User | None:
    user = None
    user_id = request.session.get("user_id")
    if user_id is not None:
        user = db.get(User, user_id)
        if user is None:  # account deleted while the cookie was still valid
            request.session.clear()
    request.state.user = user
    return user


def current_user(user: Annotated[User | None, Depends(optional_user)]) -> User:
    if user is None:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return user


OptionalUser = Annotated[User | None, Depends(optional_user)]
CurrentUser = Annotated[User, Depends(current_user)]


def own_note(db: Session, user: User, note_id: int) -> Note:
    # Ownership is part of the query: another user's note looks exactly like a missing one.
    note = db.scalar(select(Note).where(Note.id == note_id, Note.owner_id == user.id))
    if note is None:
        raise HTTPException(status_code=404, detail="Note not found")
    return note


def clean_note(title: str, body: str) -> tuple[str, str]:
    title, body = title.strip(), body.strip()
    if not title:
        raise HTTPException(status_code=400, detail="Title is required")
    if len(title) > TITLE_MAX or len(body) > BODY_MAX:
        raise HTTPException(status_code=400, detail="Note is too long")
    return title, body


# ── Pages ─────────────────────────────────────────────────────


@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"status": "ok"}


@app.get("/")
def home(user: OptionalUser):
    return redirect("/notes" if user else "/login")


@app.get("/signup")
def signup_page(request: Request):
    return render(request, "signup.html")


@app.post("/signup")
def signup(
    request: Request,
    db: DB,
    username: Annotated[str, Form(max_length=64)],
    password: Annotated[str, Form(max_length=256)],
    csrf: Annotated[str, Form()] = "",
):
    check_csrf(request, csrf)
    username = username.strip()
    error = validate_credentials(username, password)
    if error:
        return render(request, "signup.html", 400, error=error, username=username)
    db.add(User(username=username, password_hash=hash_password(password)))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return render(request, "signup.html", 400, error="That username is taken.", username=username)
    return redirect("/login?created=1")


@app.get("/login")
def login_page(request: Request, created: int = 0):
    return render(request, "login.html", created=bool(created))


@app.post("/login")
def login(
    request: Request,
    db: DB,
    username: Annotated[str, Form(max_length=64)],
    password: Annotated[str, Form(max_length=256)],
    csrf: Annotated[str, Form()] = "",
):
    check_csrf(request, csrf)
    username = username.strip()
    client = request.client.host if request.client else "unknown"
    key = f"{username.lower()}|{client}"
    generic_error = "Wrong username or password."
    if login_throttle.blocked(key):
        return render(request, "login.html", 429, error="Too many attempts. Try again in 15 minutes.")
    user = db.scalar(select(User).where(User.username == username))
    if not verify_password(user.password_hash if user else None, password):
        login_throttle.record_failure(key)
        return render(request, "login.html", 401, error=generic_error, username=username)
    login_throttle.reset(key)
    # New session on login: a session id planted before login is worthless afterwards.
    request.session.clear()
    request.session["user_id"] = user.id
    return redirect("/notes")


@app.post("/logout")
def logout(request: Request, csrf: Annotated[str, Form()] = ""):
    check_csrf(request, csrf)
    request.session.clear()
    return redirect("/login")


@app.get("/notes")
def list_notes(request: Request, db: DB, user: CurrentUser):
    notes = db.scalars(select(Note).where(Note.owner_id == user.id).order_by(Note.updated_at.desc())).all()
    return render(request, "notes.html", notes=notes, title_max=TITLE_MAX, body_max=BODY_MAX)


def like_pattern(term: str) -> str:
    """Match `term` anywhere, treating LIKE wildcards in it as plain characters."""
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


@app.get("/notes/search")
def search_notes(request: Request, db: DB, user: CurrentUser, q: str = ""):
    q = q.strip()[:TITLE_MAX]
    # The search term travels as a bound parameter, never as SQL text (finding 001).
    notes = db.scalars(
        select(Note)
        .where(Note.owner_id == user.id, Note.title.ilike(like_pattern(q), escape="\\"))
        .order_by(Note.updated_at.desc())
    ).all()
    return render(request, "notes.html", notes=notes, q=q, title_max=TITLE_MAX, body_max=BODY_MAX)


@app.post("/notes")
def create_note(
    request: Request,
    db: DB,
    user: CurrentUser,
    title: Annotated[str, Form()],
    body: Annotated[str, Form()] = "",
    csrf: Annotated[str, Form()] = "",
):
    check_csrf(request, csrf)
    title, body = clean_note(title, body)
    db.add(Note(owner_id=user.id, title=title, body=body))
    db.commit()
    return redirect("/notes")


@app.get("/notes/{note_id}/edit")
def edit_page(request: Request, db: DB, user: CurrentUser, note_id: int):
    note = own_note(db, user, note_id)
    return render(request, "note_edit.html", note=note, title_max=TITLE_MAX, body_max=BODY_MAX)


@app.post("/notes/{note_id}")
def update_note(
    request: Request,
    db: DB,
    user: CurrentUser,
    note_id: int,
    title: Annotated[str, Form()],
    body: Annotated[str, Form()] = "",
    csrf: Annotated[str, Form()] = "",
):
    check_csrf(request, csrf)
    note = own_note(db, user, note_id)
    note.title, note.body = clean_note(title, body)
    db.commit()
    return redirect("/notes")


@app.post("/notes/{note_id}/delete")
def delete_note(request: Request, db: DB, user: CurrentUser, note_id: int, csrf: Annotated[str, Form()] = ""):
    check_csrf(request, csrf)
    db.delete(own_note(db, user, note_id))
    db.commit()
    return redirect("/notes")
