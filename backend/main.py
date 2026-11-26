"""Lost & Found Intelligence API. Run with: uvicorn backend.main:app --reload"""
from datetime import datetime
from pathlib import Path
import re
import secrets
import sqlite3
import hashlib
import hmac
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

DB_PATH = Path(__file__).with_name("lost_found.db")
app = FastAPI(title="Foundly API", version="1.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://localhost:4173"], allow_methods=["*"], allow_headers=["*"])

def connect():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    with connect() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL CHECK(type IN ('lost','found')),
            name TEXT NOT NULL, category TEXT NOT NULL, color TEXT DEFAULT '', place TEXT NOT NULL,
            description TEXT DEFAULT '', created_at TEXT NOT NULL)""")
        db.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL, created_at TEXT NOT NULL)""")
        db.execute("""CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY, user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id))""")
        db.execute("""CREATE TABLE IF NOT EXISTS saved_reports (
            user_id INTEGER NOT NULL, report_id INTEGER NOT NULL,
            created_at TEXT NOT NULL, PRIMARY KEY(user_id, report_id),
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(report_id) REFERENCES reports(id))""")
        existing_report_columns = {row["name"] for row in db.execute("PRAGMA table_info(reports)").fetchall()}
        if "user_id" not in existing_report_columns:
            db.execute("ALTER TABLE reports ADD COLUMN user_id INTEGER")

init_db()

class ReportIn(BaseModel):
    type: str = Field(pattern="^(lost|found)$")
    name: str = Field(min_length=2, max_length=120)
    category: str = Field(min_length=2, max_length=40)
    color: str = Field(default="", max_length=50)
    place: str = Field(min_length=2, max_length=160)
    description: str = Field(default="", max_length=1000)

class RegisterIn(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    email: str = Field(min_length=5, max_length=160)
    password: str = Field(min_length=6, max_length=128)

class LoginIn(BaseModel):
    email: str = Field(min_length=5, max_length=160)
    password: str = Field(min_length=6, max_length=128)

def password_hash(password: str, salt: Optional[str] = None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000).hex()
    return f"{salt}${digest}"

def password_matches(password: str, stored: str):
    try:
        salt, digest = stored.split("$", 1)
    except ValueError:
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000).hex()
    return hmac.compare_digest(candidate, digest)

def current_user(authorization: Optional[str] = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Please sign in")
    token = authorization.removeprefix("Bearer ").strip()
    with connect() as db:
        row = db.execute("""
            SELECT users.id, users.name, users.email, users.created_at
            FROM sessions JOIN users ON users.id = sessions.user_id
            WHERE sessions.token = ?
        """, (token,)).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Session expired")
    return dict(row)

def terms(report):
    text = " ".join(str(report.get(k, "")) for k in ("name", "category", "color", "place", "description")).lower()
    return {w for w in re.findall(r"[a-z0-9]+", text) if len(w) > 2}

def similarity(a, b):
    left, right = terms(a), terms(b)
    if not left or not right: return 0
    score = len(left & right) / ((len(left) * len(right)) ** 0.5)
    if a["category"].lower() == b["category"].lower(): score += .1
    if a.get("color") and b.get("color") and a["color"].lower() == b["color"].lower(): score += .1
    return min(99, round(score * 100))

def serialize(row):
    return dict(row)

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "Foundly API"}

@app.post("/api/auth/register", status_code=201)
def register(payload: RegisterIn):
    email = payload.email.strip().lower()
    if "@" not in email:
        raise HTTPException(status_code=422, detail="Enter a valid email address")
    with connect() as db:
        existing = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="An account already exists with this email")
        cur = db.execute(
            "INSERT INTO users(name,email,password_hash,created_at) VALUES(?,?,?,?)",
            (payload.name.strip(), email, password_hash(payload.password), datetime.now().isoformat(timespec="minutes")),
        )
        user_id = cur.lastrowid
        token = secrets.token_urlsafe(32)
        db.execute("INSERT INTO sessions(token,user_id,created_at) VALUES(?,?,?)",
                   (token, user_id, datetime.now().isoformat(timespec="minutes")))
    return {"token": token, "user": {"id": user_id, "name": payload.name.strip(), "email": email}}

@app.post("/api/auth/login")
def login(payload: LoginIn):
    email = payload.email.strip().lower()
    with connect() as db:
        row = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not row or not password_matches(payload.password, row["password_hash"]):
            raise HTTPException(status_code=401, detail="Incorrect email or password")
        token = secrets.token_urlsafe(32)
        db.execute("INSERT INTO sessions(token,user_id,created_at) VALUES(?,?,?)",
                   (token, row["id"], datetime.now().isoformat(timespec="minutes")))
    return {"token": token, "user": {"id": row["id"], "name": row["name"], "email": row["email"]}}

@app.get("/api/auth/me")
def me(authorization: Optional[str] = Header(default=None)):
    return {"user": current_user(authorization)}

@app.post("/api/auth/logout")
def logout(authorization: Optional[str] = Header(default=None)):
    user = current_user(authorization)
    token = authorization.removeprefix("Bearer ").strip()
    with connect() as db:
        db.execute("DELETE FROM sessions WHERE token=?", (token,))
    return {"ok": True, "user": user}

@app.get("/api/reports")
def reports(type: Optional[str] = None, category: Optional[str] = None, q: Optional[str] = None):
    with connect() as db:
        rows = [serialize(r) for r in db.execute("SELECT * FROM reports ORDER BY id DESC")]
    if type: rows = [r for r in rows if r["type"] == type]
    if category: rows = [r for r in rows if r["category"].lower() == category.lower()]
    if q:
        needle = q.lower()
        rows = [r for r in rows if needle in " ".join(str(r[k]) for k in ("name", "category", "color", "place", "description")).lower()]
    return rows

@app.post("/api/reports", status_code=201)
def create_report(report: ReportIn, authorization: Optional[str] = Header(default=None)):
    user = current_user(authorization)
    payload = report.model_dump()
    with connect() as db:
        cur = db.execute("INSERT INTO reports(type,name,category,color,place,description,created_at,user_id) VALUES(?,?,?,?,?,?,?,?)",
                         (payload["type"], payload["name"], payload["category"], payload["color"], payload["place"], payload["description"], datetime.now().isoformat(timespec="minutes"), user["id"]))
        payload["id"] = cur.lastrowid
        matches = [dict(item, score=similarity(payload, item)) for item in db.execute("SELECT * FROM reports WHERE type != ?", (payload["type"],))]
    matches = sorted((m for m in matches if m["score"] > 0), key=lambda m: m["score"], reverse=True)
    return {"report": payload, "matches": matches[:5]}

@app.get("/api/reports/{report_id}/matches")
def report_matches(report_id: int):
    with connect() as db:
        row = db.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
        if not row: raise HTTPException(404, "Report not found")
        report = serialize(row)
        candidates = [serialize(r) for r in db.execute("SELECT * FROM reports WHERE type != ? AND id != ?", (report["type"], report_id))]
    return sorted((dict(item, score=similarity(report, item)) for item in candidates), key=lambda m: m["score"], reverse=True)[:10]
