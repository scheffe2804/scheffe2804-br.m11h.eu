import hmac
import json
import os
import secrets
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psycopg
from fastapi import FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeSerializer
from weasyprint import HTML

from retrieval import concise_source_statement, detect_law_refs, distinctive_keywords, diverse_chunks, fallback_keywords, norm_locator
from export_manifest import write_export_manifest


APP_TITLE = os.getenv("BR_APP_TITLE", "Betriebsrats-Wissensdatenbank")
STORAGE_ROOT = Path(os.getenv("BR_STORAGE_ROOT", "/srv/br-wissensdatenbank"))
ADMIN_PASSWORD_FILE = Path(os.getenv("BR_ADMIN_PASSWORD_FILE", "/run/br-secrets/app-admin-password.txt"))
SESSION_SECRET_FILE = Path(os.getenv("BR_SESSION_SECRET_FILE", "/run/br-secrets/session-secret.txt"))
DATABASE_URL = os.getenv("BR_DATABASE_URL", "")
COOKIE_NAME = "br_session"
CSRF_FIELD_NAME = "csrf_token"

templates = Jinja2Templates(directory="/app/templates")
app = FastAPI(title=APP_TITLE)


def source_redirect(source_uid: str) -> RedirectResponse:
    return RedirectResponse("/sources#source-%s" % source_uid, status_code=303)


def safe_reference(value: str | None) -> str:
    if not value:
        return "—"
    text = str(value).strip()
    if text.startswith(("/srv/", "/home/", "/run/", "/etc/")) or ":\\" in text or text.startswith(("C:\\", "D:\\")):
        return "interner Speicherort redigiert"
    return text


def read_secret(path: Path) -> str:
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise RuntimeError("Secret file is empty: %s" % path)
    return value


def serializer() -> URLSafeSerializer:
    return URLSafeSerializer(read_secret(SESSION_SECRET_FILE), salt="br-session-v1")


def current_user(request: Request) -> str | None:
    cookie = request.cookies.get(COOKIE_NAME)
    if not cookie:
        return None
    try:
        data = serializer().loads(cookie)
    except BadSignature:
        return None
    if data.get("role") != "admin":
        return None
    return data.get("user") or "admin"


def csrf_token_for_cookie(cookie: str | None) -> str:
    if not cookie:
        return ""
    secret = read_secret(SESSION_SECRET_FILE).encode("utf-8")
    return hmac.new(secret, cookie.encode("utf-8"), hashlib.sha256).hexdigest()


def csrf_token(request: Request) -> str:
    return csrf_token_for_cookie(request.cookies.get(COOKIE_NAME))


def verify_csrf_token(request: Request, submitted_token: str | None) -> bool:
    expected = csrf_token(request)
    if not expected or not submitted_token:
        return False
    return hmac.compare_digest(submitted_token, expected)


templates.env.globals["csrf_token"] = csrf_token
templates.env.globals["safe_reference"] = safe_reference


def require_user(request: Request) -> str:
    user = current_user(request)
    if not user:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return user


def db_rows(sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    if not DATABASE_URL:
        return []
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            columns = [desc.name for desc in cur.description] if cur.description else []
            return [dict(zip(columns, row)) for row in cur.fetchall()]


def db_execute(sql: str, params: tuple[Any, ...] = ()) -> None:
    if not DATABASE_URL:
        return
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
        conn.commit()


def db_one(sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
    rows = db_rows(sql, params)
    return rows[0] if rows else None


def create_cited_answer_record(
    *,
    query_id: int,
    answer_uid: str,
    status: str,
    fingerprint: str,
    statement_items: list[dict[str, Any]],
    actor: str,
    audit_action: str,
) -> int | None:
    """Create answer, statements, citations and audit entry atomically.

    Guards may run concurrently via systemd or manual status checks. Keeping the
    answer row invisible until all statements/citations and its audit row are
    committed avoids transient false failures such as answers without statements.
    """
    if not DATABASE_URL:
        return None
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO answers (query_id, answer_uid, status, fingerprint) VALUES (%s,%s,%s,%s) RETURNING id",
                (query_id, answer_uid, status, fingerprint),
            )
            answer_id = int(cur.fetchone()[0])
            for item in statement_items:
                chunk = item["chunk"]
                cur.execute(
                    "INSERT INTO answer_statements (answer_id, section, statement_text) VALUES (%s,%s,%s) RETURNING id",
                    (answer_id, item["section"], item["statement"]),
                )
                statement_id = int(cur.fetchone()[0])
                cur.execute(
                    "INSERT INTO answer_citations (statement_id, chunk_id, citation_label, citation_url, internal_ref, source_class) VALUES (%s,%s,%s,%s,%s,%s)",
                    (
                        statement_id,
                        chunk["chunk_id"],
                        chunk["citation_label"],
                        chunk["citation_url"],
                        chunk["internal_ref"],
                        chunk["source_class"],
                    ),
                )
            cur.execute(
                "INSERT INTO audit_log (actor, action, object_type, object_uid) VALUES (%s,%s,%s,%s)",
                (actor, audit_action, "answer", answer_uid),
            )
        conn.commit()
    return answer_id


def recommended_answer_mode(source_profile: str | None) -> str:
    """Return the safest implemented answer generator for a query profile."""
    normalized = (source_profile or "").strip().lower()
    if normalized in {"tariffrage_db_evg", "gruen_blau", "gruen+blau", "grün+blau"}:
        return "tariff"
    if normalized in {"streng_amtlich", "gruen", "grün"}:
        return "official"
    return "unsupported"


def recommended_answer_label(source_profile: str | None) -> str:
    mode = recommended_answer_mode(source_profile)
    if mode == "tariff":
        return "Empfohlen: GRÜN+BLAU-Antwort aus amtlichen und freigegebenen Tarifquellen"
    if mode == "official":
        return "Empfohlen: GRÜN-only-Antwort aus freigegebenen amtlichen Quellen"
    return "Für dieses Quellenprofil ist noch kein sicherer empfohlener Generator aktiv"


def is_case_law_query(query: dict[str, Any]) -> bool:
    text = "%s %s" % (query.get("query_type") or "", query.get("question") or "")
    text = text.lower()
    return any(token in text for token in ["urteilssuche", "bag", "rechtsprechung", "entscheidung", "aktenzeichen", "ecli"])


def green_source_filter_sql(case_law_only: bool) -> str:
    if case_law_only:
        return "s.source_class='GRUEN' AND s.source_type='rechtsprechung_bag'"
    return "s.source_class='GRUEN'"


def answer_section_for_chunk(chunk: dict[str, Any]) -> str:
    if (chunk.get("citation_label") or "").startswith("BAG ") or "bag-entscheidung-" in (chunk.get("internal_ref") or ""):
        return "Rechtsprechung"
    return "Geltendes Recht"


def source_hit_chunks(chunks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return chunks for detailed source-hit sections.

    Structured answer generators cite the first chunk in the Kurzantwort as the
    central hit. To avoid repeating the exact same chunk immediately in the
    detailed source sections, omit that chunk when enough other hits remain. If
    the central hit is the only available source, keep it so every answer still
    has a cited source excerpt.
    """
    if len(chunks) <= 1:
        return chunks
    intro_chunk_id = chunks[0].get("chunk_id")
    if not intro_chunk_id:
        return chunks[1:]
    return [chunk for chunk in chunks[1:] if chunk.get("chunk_id") != intro_chunk_id]


CHUNK_SELECT_SQL = """
SELECT c.id AS chunk_id, c.chunk_uid, c.heading, c.locator, c.content,
       c.citation_label, c.citation_url, c.internal_ref, c.source_class,
       s.source_uid, s.title AS source_title, s.source_type,
       d.sha256 AS document_sha256
FROM chunks c
JOIN documents d ON d.id=c.document_id
JOIN sources s ON s.id=d.source_id
"""


SOURCE_TYPE_FILTERS = {
    "ALL": {"label": "Alle Typen", "types": None},
    "laws": {"label": "Gesetze", "types": ["gesetz", "eurlex_verordnung"]},
    "bag": {"label": "BAG-Rechtsprechung", "types": ["rechtsprechung_bag"]},
    "evg_member": {"label": "EVG/Tailshare intern", "types": ["evg_member_download"]},
    "evg_public": {"label": "EVG öffentlich", "types": ["evg_public_page", "evg_public_pdf"]},
    "m00h_import": {"label": "m00h/DemoTV Import", "types": ["m00h_import"]},
}


def source_type_options() -> list[dict[str, str]]:
    return [{"value": key, "label": str(value["label"])} for key, value in SOURCE_TYPE_FILTERS.items()]


def apply_source_type_filter(clauses: list[str], params: list[Any], source_type_group: str) -> str:
    if source_type_group not in SOURCE_TYPE_FILTERS:
        source_type_group = "ALL"
    types = SOURCE_TYPE_FILTERS[source_type_group]["types"]
    if types:
        clauses.append("s.source_type = ANY(%s)")
        params.append(types)
    return source_type_group


def source_metadata_items(source: dict[str, Any]) -> list[dict[str, str]]:
    metadata = source.get("metadata") or {}
    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except json.JSONDecodeError:
            metadata = {}
    if not isinstance(metadata, dict):
        return []
    label_map = {
        "gericht": "Gericht",
        "aktenzeichen": "Aktenzeichen",
        "ecli": "ECLI",
        "art": "Entscheidungsart",
        "datum": "Datum",
        "senat": "Senat",
        "feed_description": "Thema",
        "feed_pub_date": "Feed-Datum",
        "celex": "CELEX",
        "source": "Quelle",
    }
    preferred = ["gericht", "aktenzeichen", "ecli", "art", "datum", "senat", "feed_description", "feed_pub_date", "celex", "source"]
    items: list[dict[str, str]] = []
    for key in preferred:
        value = metadata.get(key)
        if value:
            items.append({"label": label_map.get(key, key), "value": str(value)})
    for key in sorted(metadata.keys()):
        if key in preferred or key == "feed":
            continue
        value = metadata.get(key)
        if value:
            items.append({"label": label_map.get(key, key), "value": str(value)})
    return items


def text_file_quality(text_path: str | None) -> dict[str, Any]:
    """Classify a stored text extraction path without exposing file content."""
    if not text_path:
        return {"text_status": "Textpfad fehlt", "text_status_class": "red", "text_size": None}
    path = Path(text_path)
    if not path.exists():
        return {"text_status": "Textdatei fehlt", "text_status_class": "red", "text_size": None}
    size = path.stat().st_size
    if size == 0:
        return {"text_status": "Textdatei leer", "text_status_class": "red", "text_size": size}
    if size < 80:
        return {"text_status": "Text sehr kurz", "text_status_class": "yellow", "text_size": size}
    return {"text_status": "Text vorhanden", "text_status_class": "green", "text_size": size}


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive, nosnippet, noimageindex"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.middleware("http")
async def csrf_protection(request: Request, call_next):
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.url.path != "/login":
        submitted_token = None
        content_type = request.headers.get("content-type", "")
        if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
            form = await request.form()
            value = form.get(CSRF_FIELD_NAME)
            submitted_token = str(value) if value is not None else None
        else:
            submitted_token = request.headers.get("X-CSRF-Token")
        if not verify_csrf_token(request, submitted_token):
            return PlainTextResponse("csrf_failed", status_code=403)
    return await call_next(request)


@app.get("/healthz", response_class=PlainTextResponse)
def healthz() -> str:
    return "ok"


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    user = require_user(request)
    counts = {"sources": 0, "queries": 0, "answers": 0, "cases": 0}
    try:
        for key, table in [("sources", "sources"), ("queries", "queries"), ("answers", "answers"), ("cases", "cases")]:
            rows = db_rows("SELECT count(*) AS count FROM %s" % table)
            counts[key] = rows[0]["count"] if rows else 0
    except Exception:
        counts["db_warning"] = 1
    return templates.TemplateResponse("dashboard.html", {"request": request, "title": APP_TITLE, "user": user, "counts": counts})


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    if current_user(request):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request, "title": APP_TITLE, "error": None})


@app.post("/login")
def login(request: Request, password: str = Form(...)):
    expected = read_secret(ADMIN_PASSWORD_FILE)
    if not hmac.compare_digest(password, expected):
        return templates.TemplateResponse("login.html", {"request": request, "title": APP_TITLE, "error": "Login fehlgeschlagen"}, status_code=401)
    token = serializer().dumps({"user": "admin", "role": "admin", "iat": datetime.now(timezone.utc).isoformat()})
    redirect = RedirectResponse("/", status_code=303)
    redirect.set_cookie(COOKIE_NAME, token, httponly=True, secure=True, samesite="strict", path="/")
    return redirect


@app.post("/logout")
def logout():
    redirect = RedirectResponse("/login", status_code=303)
    redirect.delete_cookie(COOKIE_NAME, path="/")
    return redirect


@app.get("/sources", response_class=HTMLResponse)
def sources(request: Request, q: str = "", source_class: str = "ALL", source_type_group: str = "ALL", approval: str = "all"):
    user = require_user(request)
    rows = []
    allowed_classes = {"ALL", "GRUEN", "BLAU", "GELB", "GRAU", "ROT"}
    if source_class not in allowed_classes:
        source_class = "ALL"
    if approval not in {"all", "approved", "not_approved", "blocked"}:
        approval = "all"
    try:
        clauses = []
        params: list[Any] = []
        if q.strip():
            clauses.append("(s.title ILIKE %s OR s.source_uid ILIKE %s OR s.source_type ILIKE %s OR coalesce(s.internal_ref,'') ILIKE %s)")
            like = "%" + q.strip() + "%"
            params.extend([like, like, like, like])
        if source_class != "ALL":
            clauses.append("s.source_class=%s")
            params.append(source_class)
        source_type_group = apply_source_type_filter(clauses, params, source_type_group)
        if approval == "approved":
            clauses.append("s.citation_allowed=true")
        elif approval == "not_approved":
            clauses.append("s.citation_allowed=false AND s.status != 'gesperrt'")
        elif approval == "blocked":
            clauses.append("s.status='gesperrt'")
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        rows = db_rows("""
            SELECT s.source_uid, s.title, s.source_class, s.source_type, s.status, s.confidentiality,
                   s.citation_allowed, s.hint_only, s.public_url, s.internal_ref, s.last_checked_at,
                   count(c.id) AS chunk_count
            FROM sources s
            LEFT JOIN documents d ON d.source_id = s.id
            LEFT JOIN chunks c ON c.document_id = d.id
            """ + where + """
            GROUP BY s.id
            ORDER BY s.citation_allowed DESC, s.source_class, s.source_type, s.title
            LIMIT 500
        """, tuple(params))
    except Exception as exc:
        rows = [{"source_uid": "db-error", "title": "Datenbankabfrage fehlgeschlagen", "source_class": "ROT", "source_type": "system", "status": "fehler"}]
    return templates.TemplateResponse("sources.html", {"request": request, "title": APP_TITLE, "user": user, "sources": rows, "q": q, "source_class": source_class, "source_type_group": source_type_group, "source_type_options": source_type_options(), "approval": approval})


@app.get("/source-quality", response_class=HTMLResponse)
def source_quality(request: Request):
    user = require_user(request)
    stats = db_one(
        """
        WITH source_counts AS (
          SELECT s.id, s.citation_allowed,
                 count(DISTINCT d.id) AS document_count,
                 count(c.id) AS chunk_count
          FROM sources s
          LEFT JOIN documents d ON d.source_id=s.id
          LEFT JOIN chunks c ON c.document_id=d.id
          GROUP BY s.id
        ), duplicate_sha AS (
          SELECT sha256
          FROM documents
          WHERE sha256 IS NOT NULL AND sha256 <> ''
          GROUP BY sha256
          HAVING count(*) > 1
        )
        SELECT (SELECT count(*) FROM sources) AS sources,
               (SELECT count(*) FROM documents) AS documents,
               (SELECT count(*) FROM chunks) AS chunks,
               (SELECT count(*) FROM sources WHERE citation_allowed=true) AS approved_sources,
               sum(CASE WHEN document_count=0 THEN 1 ELSE 0 END) AS without_documents,
               sum(CASE WHEN chunk_count=0 THEN 1 ELSE 0 END) AS without_chunks,
               sum(CASE WHEN citation_allowed AND chunk_count=0 THEN 1 ELSE 0 END) AS approved_without_chunks,
               (SELECT count(*) FROM duplicate_sha) AS duplicate_sha_groups
        FROM source_counts
        """
    ) or {}
    stats = {key: int(value or 0) for key, value in stats.items()}
    approved_without_chunks = db_rows(
        """
        SELECT s.source_uid, s.title, s.source_class, s.source_type, s.status,
               count(DISTINCT d.id) AS document_count, count(c.id) AS chunk_count,
               min(d.text_path) AS sample_text_path,
               string_agg(DISTINCT d.ocr_status, ', ' ORDER BY d.ocr_status) AS ocr_statuses
        FROM sources s
        LEFT JOIN documents d ON d.source_id=s.id
        LEFT JOIN chunks c ON c.document_id=d.id
        WHERE s.citation_allowed=true
        GROUP BY s.id
        HAVING count(c.id)=0
        ORDER BY s.source_class, s.source_type, s.title
        LIMIT 100
        """
    )
    for source in approved_without_chunks:
        source.update(text_file_quality(source.get("sample_text_path")))
    duplicate_documents = db_rows(
        """
        SELECT d.sha256, count(*) AS document_count, count(DISTINCT d.source_id) AS source_count,
               string_agg(DISTINCT s.source_uid, ', ' ORDER BY s.source_uid) AS examples
        FROM documents d
        JOIN sources s ON s.id=d.source_id
        WHERE d.sha256 IS NOT NULL AND d.sha256 <> ''
        GROUP BY d.sha256
        HAVING count(*) > 1
        ORDER BY document_count DESC, source_count DESC, min(d.created_at)
        LIMIT 50
        """
    )
    chunk_heavy_sources = db_rows(
        """
        SELECT s.source_uid, s.title, s.source_class, s.source_type, s.citation_allowed,
               count(DISTINCT d.id) AS document_count, count(c.id) AS chunk_count
        FROM sources s
        LEFT JOIN documents d ON d.source_id=s.id
        LEFT JOIN chunks c ON c.document_id=d.id
        GROUP BY s.id
        HAVING count(c.id) > 0
        ORDER BY chunk_count DESC, document_count DESC, s.title
        LIMIT 25
        """
    )
    document_issues = db_rows(
        """
        SELECT d.document_uid, d.title, d.text_path, d.ocr_status,
               s.source_uid, s.title AS source_title,
               count(c.id) AS chunk_count
        FROM documents d
        JOIN sources s ON s.id=d.source_id
        LEFT JOIN chunks c ON c.document_id=d.id
        GROUP BY d.id, s.id
        HAVING d.text_path IS NULL OR d.text_path='' OR count(c.id)=0
        ORDER BY count(c.id), s.source_class, s.source_type, s.title, d.title
        LIMIT 100
        """
    )
    for document in document_issues:
        document.update(text_file_quality(document.get("text_path")))
    return templates.TemplateResponse(
        "source_quality.html",
        {
            "request": request,
            "title": APP_TITLE,
            "user": user,
            "stats": stats,
            "approved_without_chunks": approved_without_chunks,
            "duplicate_documents": duplicate_documents,
            "chunk_heavy_sources": chunk_heavy_sources,
            "document_issues": document_issues,
        },
    )


@app.get("/queries", response_class=HTMLResponse)
def queries(request: Request):
    user = require_user(request)
    rows = db_rows(
        """
        SELECT q.query_uid, q.query_type, q.title, q.status, q.selected_source_profile, q.created_at,
               count(a.id) AS answer_count
        FROM queries q
        LEFT JOIN answers a ON a.query_id=q.id
        GROUP BY q.id
        ORDER BY q.created_at DESC
        LIMIT 200
        """
    )
    return templates.TemplateResponse("queries.html", {"request": request, "title": APP_TITLE, "user": user, "queries": rows})


@app.post("/sources/{source_uid}/technical-approve")
def technical_approve_source(request: Request, source_uid: str):
    user = require_user(request)
    db_execute(
        "UPDATE sources SET status=%s, citation_allowed=%s, updated_at=now() WHERE source_uid=%s AND source_class IN ('BLAU','GRUEN')",
        ("freigegeben", True, source_uid),
    )
    db_execute("INSERT INTO audit_log (actor, action, object_type, object_uid) VALUES (%s,%s,%s,%s)", (user, "source_technical_approve", "source", source_uid))
    return source_redirect(source_uid)


@app.post("/sources/{source_uid}/block")
def block_source(request: Request, source_uid: str):
    user = require_user(request)
    db_execute("UPDATE sources SET status=%s, citation_allowed=false, updated_at=now() WHERE source_uid=%s", ("gesperrt", source_uid))
    db_execute("INSERT INTO audit_log (actor, action, object_type, object_uid) VALUES (%s,%s,%s,%s)", (user, "source_block", "source", source_uid))
    return source_redirect(source_uid)


@app.post("/sources/{source_uid}/unblock")
def unblock_source(request: Request, source_uid: str):
    user = require_user(request)
    db_execute(
        "UPDATE sources SET status=%s, citation_allowed=false, updated_at=now() WHERE source_uid=%s AND status='gesperrt'",
        ("technisch_geprueft", source_uid),
    )
    db_execute("INSERT INTO audit_log (actor, action, object_type, object_uid) VALUES (%s,%s,%s,%s)", (user, "source_unblock", "source", source_uid))
    return source_redirect(source_uid)


@app.post("/sources/{source_uid}/unblock-and-approve")
def unblock_and_approve_source(request: Request, source_uid: str):
    user = require_user(request)
    db_execute(
        "UPDATE sources SET status=%s, citation_allowed=true, updated_at=now() WHERE source_uid=%s AND status='gesperrt' AND source_class IN ('GRUEN','BLAU','GELB')",
        ("freigegeben", source_uid),
    )
    db_execute("INSERT INTO audit_log (actor, action, object_type, object_uid) VALUES (%s,%s,%s,%s)", (user, "source_unblock_and_approve", "source", source_uid))
    return source_redirect(source_uid)


@app.post("/sources/approve-evg-all")
def approve_all_evg_sources(request: Request):
    user = require_user(request)
    db_execute(
        """
        UPDATE sources
        SET status='freigegeben', citation_allowed=true, updated_at=now()
        WHERE source_uid LIKE 'evg-%' AND source_class IN ('BLAU','GELB') AND status != 'gesperrt'
        """
    )
    db_execute("INSERT INTO audit_log (actor, action, object_type, object_uid) VALUES (%s,%s,%s,%s)", (user, "source_approve_all_evg", "source_group", "evg-*"))
    return RedirectResponse("/sources", status_code=303)


@app.get("/sources/{source_uid}", response_class=HTMLResponse)
def source_detail(request: Request, source_uid: str, q: str = ""):
    user = require_user(request)
    source = db_one(
        """
        SELECT s.*, count(c.id) AS chunk_count, count(DISTINCT d.id) AS document_count
        FROM sources s
        LEFT JOIN documents d ON d.source_id=s.id
        LEFT JOIN chunks c ON c.document_id=d.id
        WHERE s.source_uid=%s
        GROUP BY s.id
        """,
        (source_uid,),
    )
    if not source:
        raise HTTPException(status_code=404, detail="Quelle nicht gefunden")
    documents = db_rows("SELECT * FROM documents WHERE source_id=%s ORDER BY title", (source["id"],))
    chunk_params: list[Any] = [source["id"]]
    where = "d.source_id=%s"
    if q.strip():
        where += " AND c.content ILIKE %s"
        chunk_params.append("%" + q.strip() + "%")
    chunks = db_rows(
        """
        SELECT c.chunk_uid, c.heading, c.locator, left(c.content, 1200) AS snippet,
               c.citation_label, c.citation_url, c.internal_ref, c.source_class, d.title AS document_title
        FROM chunks c
        JOIN documents d ON d.id=c.document_id
        WHERE """ + where + """
        ORDER BY d.title, c.id
        LIMIT 80
        """,
        tuple(chunk_params),
    )
    return templates.TemplateResponse(
        "source_detail.html",
        {"request": request, "title": APP_TITLE, "user": user, "source": source, "source_metadata_items": source_metadata_items(source), "documents": documents, "chunks": chunks, "q": q},
    )


@app.get("/queries/new", response_class=HTMLResponse)
def new_query(request: Request):
    user = require_user(request)
    return templates.TemplateResponse("new_query.html", {"request": request, "title": APP_TITLE, "user": user})


@app.post("/queries")
def create_query(request: Request, query_type: str = Form(...), title: str = Form(...), question: str = Form(...), selected_source_profile: str = Form(...)):
    user = require_user(request)
    query_uid = "q-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(4)
    db_execute(
        "INSERT INTO queries (query_uid, query_type, title, question, selected_source_profile, created_by) VALUES (%s,%s,%s,%s,%s,%s)",
        (query_uid, query_type, title, question, selected_source_profile, user),
    )
    return RedirectResponse("/queries/%s" % query_uid, status_code=303)


@app.get("/queries/{query_uid}", response_class=HTMLResponse)
def query_detail(request: Request, query_uid: str):
    user = require_user(request)
    rows = db_rows("SELECT * FROM queries WHERE query_uid=%s", (query_uid,))
    if not rows:
        raise HTTPException(status_code=404, detail="Anfrage nicht gefunden")
    answers = db_rows(
        """
        SELECT a.answer_uid, a.status, a.html_path, a.pdf_path, a.created_at, a.updated_at,
               count(st.id) AS statement_count,
               count(cit.id) AS citation_count,
               sum(CASE WHEN cit.id IS NULL THEN 1 ELSE 0 END) AS statements_without_citation
        FROM answers a
        LEFT JOIN answer_statements st ON st.answer_id=a.id
        LEFT JOIN answer_citations cit ON cit.statement_id=st.id
        WHERE a.query_id=%s
        GROUP BY a.id
        ORDER BY a.created_at DESC
        """,
        (rows[0]["id"],),
    )
    recommendation = {
        "mode": recommended_answer_mode(rows[0].get("selected_source_profile")),
        "label": recommended_answer_label(rows[0].get("selected_source_profile")),
    }
    return templates.TemplateResponse("query_detail.html", {"request": request, "title": APP_TITLE, "user": user, "query": rows[0], "answers": answers, "recommendation": recommendation})


@app.post("/queries/{query_uid}/draft-export")
def create_draft_export(request: Request, query_uid: str):
    user = require_user(request)
    query = db_one("SELECT * FROM queries WHERE query_uid=%s", (query_uid,))
    if not query:
        raise HTTPException(status_code=404, detail="Anfrage nicht gefunden")
    sources = db_rows("SELECT * FROM sources WHERE citation_allowed=true ORDER BY source_class, title LIMIT 50")
    if not sources:
        raise HTTPException(status_code=400, detail="Kein freigegebener Quellenbestand vorhanden. Export mit fachlicher Aussage blockiert.")

    answer_uid = "a-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(4)
    export_dir = STORAGE_ROOT / "exports" / answer_uid
    export_dir.mkdir(parents=True, exist_ok=True)
    fingerprint = hashlib.sha256((answer_uid + query["query_uid"] + datetime.now(timezone.utc).isoformat()).encode()).hexdigest()
    html_path = export_dir / "index.html"
    pdf_path = export_dir / "export.pdf"
    rendered = templates.get_template("export_answer.html").render(
        title=APP_TITLE,
        query=query,
        answer_uid=answer_uid,
        fingerprint=fingerprint,
        created_at=datetime.now(timezone.utc).isoformat(),
        sources=sources,
    )
    html_path.write_text(rendered, encoding="utf-8")
    HTML(string=rendered, base_url=str(export_dir)).write_pdf(str(pdf_path))
    os.chmod(html_path, 0o640)
    os.chmod(pdf_path, 0o640)
    db_execute("INSERT INTO answers (query_id, answer_uid, status, html_path, pdf_path, fingerprint) VALUES (%s,%s,%s,%s,%s,%s)", (query["id"], answer_uid, "entwurf", str(html_path), str(pdf_path), fingerprint))
    db_execute("INSERT INTO audit_log (actor, action, object_type, object_uid) VALUES (%s,%s,%s,%s)", (user, "draft_export_create", "answer", answer_uid))
    return RedirectResponse("/queries/%s" % query_uid, status_code=303)


@app.post("/queries/{query_uid}/recommended-answer")
def create_recommended_answer(request: Request, query_uid: str):
    require_user(request)
    query = db_one("SELECT selected_source_profile FROM queries WHERE query_uid=%s", (query_uid,))
    if not query:
        raise HTTPException(status_code=404, detail="Anfrage nicht gefunden")
    mode = recommended_answer_mode(query.get("selected_source_profile"))
    if mode == "tariff":
        return create_structured_tariff_answer(request, query_uid)
    if mode == "official":
        return create_structured_source_answer(request, query_uid)
    raise HTTPException(
        status_code=400,
        detail="Für dieses Quellenprofil ist noch kein sicherer empfohlener Generator aktiv. Bitte bewusst einen der manuellen Generatoren wählen.",
    )


@app.post("/queries/{query_uid}/source-snippet-answer")
def create_source_snippet_answer(request: Request, query_uid: str):
    user = require_user(request)
    query = db_one("SELECT * FROM queries WHERE query_uid=%s", (query_uid,))
    if not query:
        raise HTTPException(status_code=404, detail="Anfrage nicht gefunden")
    case_law_only = is_case_law_query(query)
    source_filter = green_source_filter_sql(case_law_only)
    chunks: list[dict[str, Any]] = db_rows(
        ("""
        """ + CHUNK_SELECT_SQL + """
        WHERE s.citation_allowed=true
          AND """ + source_filter + """
          AND c.content_tsv @@ plainto_tsquery('german', %s)
        ORDER BY ts_rank(c.content_tsv, plainto_tsquery('german', %s)) DESC
        LIMIT 5
        """),
        (query["question"], query["question"]),
    )
    if len(chunks) < 3:
        for keyword in fallback_keywords(query["question"]):
            chunks.extend(
                db_rows(
                    ("""
                    """ + CHUNK_SELECT_SQL + """
                    WHERE s.citation_allowed=true
                      AND """ + source_filter + """
                      AND c.content ILIKE %s
                    ORDER BY c.id
                    LIMIT 5
                    """),
                    ("%" + keyword + "%",),
                )
            )
            if len(chunks) >= 5:
                break
    chunks = diverse_chunks(chunks, max_total=5, per_source_limit=2)
    if not chunks:
        raise HTTPException(status_code=400, detail="Keine freigegebenen amtlichen Treffer gefunden. Keine Antwort ohne Quelle.")
    answer_uid = "a-src-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(4)
    fingerprint = hashlib.sha256((answer_uid + query["query_uid"]).encode()).hexdigest()
    statement_items: list[dict[str, Any]] = []
    for idx, ch in enumerate(chunks, start=1):
        # Conservative statement: explicitly says this is a source hit, not a free legal conclusion.
        snippet = ch["content"][:900].strip()
        statement = "Amtlicher Treffer %d: %s\n%s" % (idx, ch["citation_label"], snippet)
        statement_items.append({"section": answer_section_for_chunk(ch), "statement": statement, "chunk": ch})
    answer_id = create_cited_answer_record(
        query_id=query["id"],
        answer_uid=answer_uid,
        status="quellengeprueft",
        fingerprint=fingerprint,
        statement_items=statement_items,
        actor=user,
        audit_action="source_snippet_answer_create",
    )
    if not answer_id:
        raise HTTPException(status_code=500, detail="Antwort konnte nicht gespeichert werden")
    return RedirectResponse("/answers/%s" % answer_uid, status_code=303)


@app.post("/queries/{query_uid}/structured-source-answer")
def create_structured_source_answer(request: Request, query_uid: str):
    user = require_user(request)
    query = db_one("SELECT * FROM queries WHERE query_uid=%s", (query_uid,))
    if not query:
        raise HTTPException(status_code=404, detail="Anfrage nicht gefunden")

    refs = detect_law_refs(query["question"])
    chunks: list[dict[str, Any]] = []
    case_law_only = is_case_law_query(query)
    source_filter = green_source_filter_sql(case_law_only)
    # Exact paragraph/article law retrieval first. For Urteilssuche/BAG queries
    # this is deliberately skipped: those answers must stay BAG-only and must
    # not mix in law chunks just because a norm (e.g. § 4a TVG) is mentioned.
    if not case_law_only:
        for source_uid, ref_value in refs[:8]:
            locator = norm_locator(source_uid, ref_value)
            if source_uid:
                rows = db_rows(
                    """
                    """ + CHUNK_SELECT_SQL + """
                    WHERE s.citation_allowed=true AND s.source_uid=%s AND lower(c.locator)=lower(%s)
                    LIMIT 3
                    """,
                    (source_uid, locator),
                )
            else:
                rows = db_rows(
                    ("""
                    """ + CHUNK_SELECT_SQL + """
                    WHERE s.citation_allowed=true AND """ + source_filter + """ AND lower(c.locator)=lower(%s)
                    LIMIT 5
                    """),
                    (locator,),
                )
            chunks.extend(rows)
    # Then full-text retrieval if needed.
    if len(chunks) < 3:
        chunks.extend(
            db_rows(
                ("""
                """ + CHUNK_SELECT_SQL + """
                WHERE s.citation_allowed=true
                  AND """ + source_filter + """
                  AND c.content_tsv @@ plainto_tsquery('german', %s)
                ORDER BY ts_rank(c.content_tsv, plainto_tsquery('german', %s)) DESC
                LIMIT 6
                """),
                (query["question"], query["question"]),
            )
        )
    # Conservative keyword fallback for long natural-language official/BAG
    # questions where plainto_tsquery is too strict. Only approved GRUEN sources.
    if len(chunks) < 3:
        for keyword in fallback_keywords(query["question"]):
            chunks.extend(
                db_rows(
                    ("""
                    """ + CHUNK_SELECT_SQL + """
                    WHERE s.citation_allowed=true
                      AND """ + source_filter + """
                      AND c.content ILIKE %s
                    ORDER BY c.id
                    LIMIT 5
                    """),
                    ("%" + keyword + "%",),
                )
            )
            if len(chunks) >= 6:
                break
    unique_chunks = diverse_chunks(chunks, max_total=6, per_source_limit=2)
    if not unique_chunks:
        raise HTTPException(status_code=400, detail="Keine freigegebene amtliche Quelle gefunden. Keine Antwort ohne Quelle.")

    answer_uid = "a-struct-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(4)
    fingerprint = hashlib.sha256((answer_uid + query["query_uid"]).encode()).hexdigest()
    intro_chunk = unique_chunks[0]
    intro = "Kurzantwort: Im freigegebenen amtlichen Quellenbestand wurde als zentraler Treffer %s gefunden. Eine weitergehende Bewertung wird hier nicht frei ergänzt." % intro_chunk["citation_label"]
    statement_items: list[dict[str, Any]] = [{"section": "Kurzantwort", "statement": intro, "chunk": intro_chunk}]

    for ch in source_hit_chunks(unique_chunks):
        statement = "Auszug/amtlicher Treffer: %s\n%s" % (ch["citation_label"], concise_source_statement(ch))
        statement_items.append({"section": answer_section_for_chunk(ch), "statement": statement, "chunk": ch})

    answer_id = create_cited_answer_record(
        query_id=query["id"],
        answer_uid=answer_uid,
        status="quellengeprueft",
        fingerprint=fingerprint,
        statement_items=statement_items,
        actor=user,
        audit_action="structured_source_answer_create",
    )
    if not answer_id:
        raise HTTPException(status_code=500, detail="Antwort konnte nicht gespeichert werden")
    return RedirectResponse("/answers/%s" % answer_uid, status_code=303)


@app.post("/queries/{query_uid}/structured-tariff-answer")
def create_structured_tariff_answer(request: Request, query_uid: str):
    user = require_user(request)
    query = db_one("SELECT * FROM queries WHERE query_uid=%s", (query_uid,))
    if not query:
        raise HTTPException(status_code=404, detail="Anfrage nicht gefunden")

    refs = detect_law_refs(query["question"])
    chunks: list[dict[str, Any]] = []
    # Exact law paragraph/article retrieval for official law sources first.
    for source_uid, ref_value in refs[:8]:
        locator = norm_locator(source_uid, ref_value)
        if source_uid:
            rows = db_rows(
                """
                """ + CHUNK_SELECT_SQL + """
                WHERE s.citation_allowed=true AND s.source_uid=%s AND lower(c.locator)=lower(%s)
                LIMIT 3
                """,
                (source_uid, locator),
            )
        else:
            rows = db_rows(
                """
                """ + CHUNK_SELECT_SQL + """
                WHERE s.citation_allowed=true AND s.source_class='GRUEN' AND lower(c.locator)=lower(%s)
                LIMIT 5
                """,
                (locator,),
            )
        chunks.extend(rows)

    # Search approved official law and approved internal tariff sources. GELB is
    # deliberately excluded here: hint sources are not legal/tariff basis.
    chunks.extend(
        db_rows(
            """
            """ + CHUNK_SELECT_SQL + """
            WHERE s.citation_allowed=true
              AND s.source_class IN ('GRUEN','BLAU')
              AND c.content_tsv @@ plainto_tsquery('german', %s)
            ORDER BY
              CASE WHEN s.source_class='GRUEN' THEN 0 ELSE 1 END,
              ts_rank(c.content_tsv, plainto_tsquery('german', %s)) DESC
            LIMIT 30
            """,
            (query["question"], query["question"]),
        )
    )

    and_terms = distinctive_keywords(query["question"], limit=5)
    if len(and_terms) >= 2:
        and_clauses = ["c.content ILIKE %s" for _ in and_terms]
        chunks.extend(
            db_rows(
                ("""
                """ + CHUNK_SELECT_SQL + """
                WHERE s.citation_allowed=true
                  AND s.source_class IN ('GRUEN','BLAU')
                  AND """ + " AND ".join(and_clauses) + """
                ORDER BY
                  CASE WHEN d.ocr_status='ocr_repaired_tesseract' THEN 0 ELSE 1 END,
                  CASE WHEN s.source_class='BLAU' THEN 0 ELSE 1 END,
                  c.id
                LIMIT 20
                """),
                tuple("%" + term + "%" for term in and_terms),
            )
        )

    # Fallback for long natural-language tariff questions where plainto_tsquery
    # is too strict. Use only approved GRUEN/BLAU sources, never GELB.
    if len(chunks) < 3:
        for keyword in fallback_keywords(query["question"]):
            chunks.extend(
                db_rows(
                    """
                    """ + CHUNK_SELECT_SQL + """
                    WHERE s.citation_allowed=true
                      AND s.source_class IN ('GRUEN','BLAU')
                      AND c.content ILIKE %s
                    ORDER BY CASE WHEN s.source_class='GRUEN' THEN 0 ELSE 1 END, c.id
                    LIMIT 12
                    """,
                    ("%" + keyword + "%",),
                )
            )
            if len(chunks) >= 6:
                break

    unique_chunks = diverse_chunks(chunks, max_total=10, per_source_limit=2, class_limits={"BLAU": 7})
    if not unique_chunks:
        raise HTTPException(status_code=400, detail="Keine freigegebene amtliche oder BLAUE Tarifquelle gefunden. Keine Antwort ohne Quelle.")

    answer_uid = "a-tariff-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(4)
    fingerprint = hashlib.sha256((answer_uid + query["query_uid"]).encode()).hexdigest()
    intro_chunk = unique_chunks[0]
    intro = "Kurzantwort: Im freigegebenen Quellenbestand aus amtlichen Quellen und internen/offiziellen Tarifquellen wurde als zentraler Treffer %s gefunden. Eine freie Bewertung wird nicht ergänzt." % intro_chunk["citation_label"]
    statement_items: list[dict[str, Any]] = [{"section": "Kurzantwort", "statement": intro, "chunk": intro_chunk}]

    section_for_class = {"GRUEN": "Geltendes Recht", "BLAU": "Tarifquelle / interne Quelle"}
    for ch in source_hit_chunks(unique_chunks):
        section = section_for_class.get(ch["source_class"], "Quelle")
        statement = "Auszug/Quellentreffer: %s\n%s" % (ch["citation_label"], concise_source_statement(ch))
        statement_items.append({"section": section, "statement": statement, "chunk": ch})

    answer_id = create_cited_answer_record(
        query_id=query["id"],
        answer_uid=answer_uid,
        status="quellengeprueft",
        fingerprint=fingerprint,
        statement_items=statement_items,
        actor=user,
        audit_action="structured_tariff_answer_create",
    )
    if not answer_id:
        raise HTTPException(status_code=500, detail="Antwort konnte nicht gespeichert werden")
    return RedirectResponse("/answers/%s" % answer_uid, status_code=303)


@app.get("/answers", response_class=HTMLResponse)
def answers(request: Request):
    user = require_user(request)
    rows = db_rows(
        """
        SELECT a.answer_uid, a.status, a.html_path, a.pdf_path, a.created_at, a.updated_at,
               q.query_uid, q.title,
               count(st.id) AS statement_count,
               count(cit.id) AS citation_count,
               sum(CASE WHEN cit.id IS NULL THEN 1 ELSE 0 END) AS statements_without_citation
        FROM answers a
        JOIN queries q ON q.id=a.query_id
        LEFT JOIN answer_statements st ON st.answer_id=a.id
        LEFT JOIN answer_citations cit ON cit.statement_id=st.id
        GROUP BY a.id, q.id
        ORDER BY a.created_at DESC
        LIMIT 200
        """
    )
    return templates.TemplateResponse("answers.html", {"request": request, "title": APP_TITLE, "user": user, "answers": rows})


def answer_validation(answer_id: int) -> dict[str, int]:
    row = db_one(
        """
        SELECT count(st.id) AS statement_count,
               count(cit.id) AS citation_count,
               sum(CASE WHEN cit.id IS NULL THEN 1 ELSE 0 END) AS statements_without_citation
        FROM answer_statements st
        LEFT JOIN answer_citations cit ON cit.statement_id=st.id
        WHERE st.answer_id=%s
        """,
        (answer_id,),
    ) or {"statement_count": 0, "citation_count": 0, "statements_without_citation": 0}
    return {k: int(row[k] or 0) for k in ["statement_count", "citation_count", "statements_without_citation"]}


@app.post("/answers/{answer_uid}/export")
def export_answer(request: Request, answer_uid: str):
    user = require_user(request)
    answer = db_one("SELECT a.*, q.query_uid, q.title, q.question FROM answers a JOIN queries q ON q.id=a.query_id WHERE a.answer_uid=%s", (answer_uid,))
    if not answer:
        raise HTTPException(status_code=404, detail="Antwort nicht gefunden")
    validation = answer_validation(answer["id"])
    if validation["statement_count"] <= 0 or validation["statements_without_citation"] > 0:
        raise HTTPException(status_code=400, detail="Export blockiert: Jede Aussage braucht mindestens eine Citation.")
    statements = db_rows(
        """
        SELECT st.id, st.section, st.statement_text,
               cit.citation_label, cit.citation_url, cit.internal_ref, cit.source_class,
               COALESCE(c.chunk_uid, c_ref.chunk_uid) AS chunk_uid,
               COALESCE(c.locator, c_ref.locator) AS locator,
               COALESCE(d.title, d_ref.title) AS document_title,
               COALESCE(s.source_uid, s_ref.source_uid) AS source_uid,
               COALESCE(s.title, s_ref.title) AS source_title,
               COALESCE(s.source_type, s_ref.source_type) AS source_type
        FROM answer_statements st
        JOIN answer_citations cit ON cit.statement_id=st.id
        LEFT JOIN chunks c ON c.id=cit.chunk_id
        LEFT JOIN documents d ON d.id=c.document_id
        LEFT JOIN sources s ON s.id=d.source_id
        LEFT JOIN sources s_ref ON c.id IS NULL AND s_ref.source_uid=split_part(cit.internal_ref, ':', 1)
        LEFT JOIN documents d_ref ON c.id IS NULL AND d_ref.source_id=s_ref.id
        LEFT JOIN chunks c_ref ON c.id IS NULL AND c_ref.document_id=d_ref.id AND replace(c_ref.locator, ' ', '')=replace(split_part(cit.internal_ref, ':', 2), ' ', '')
        WHERE st.answer_id=%s
        ORDER BY st.id
        """,
        (answer["id"],),
    )
    export_dir = STORAGE_ROOT / "exports" / answer_uid
    export_dir.mkdir(parents=True, exist_ok=True)
    html_path = export_dir / "index.html"
    pdf_path = export_dir / "export.pdf"
    rendered = templates.get_template("export_validated_answer.html").render(
        title=APP_TITLE,
        answer=answer,
        statements=statements,
        validation=validation,
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    html_path.write_text(rendered, encoding="utf-8")
    HTML(string=rendered, base_url=str(export_dir)).write_pdf(str(pdf_path))
    os.chmod(html_path, 0o640)
    os.chmod(pdf_path, 0o640)
    manifest_path = write_export_manifest(
        export_dir=export_dir,
        answer=answer,
        statements=statements,
        validation=validation,
        html_path=html_path,
        pdf_path=pdf_path,
        generated_by="web-export",
    )
    os.chmod(manifest_path, 0o640)
    db_execute("UPDATE answers SET html_path=%s, pdf_path=%s, updated_at=now() WHERE id=%s", (str(html_path), str(pdf_path), answer["id"]))
    db_execute(
        """
        INSERT INTO audit_log (actor, action, object_type, object_uid, details)
        VALUES (%s,%s,%s,%s,%s::jsonb)
        """,
        (
            user,
            "validated_answer_export",
            "answer",
            answer_uid,
            json.dumps(
                {
                    "html_file": "index.html",
                    "pdf_file": "export.pdf",
                    "manifest_file": "manifest.json",
                    "statement_count": validation["statement_count"],
                    "citation_count": validation["citation_count"],
                    "statements_without_citation": validation["statements_without_citation"],
                    "source_classes": sorted({str(item.get("source_class")) for item in statements if item.get("source_class")}),
                    "manifest_version": 1,
                },
                ensure_ascii=False,
            ),
        ),
    )
    return RedirectResponse("/answers/%s" % answer_uid, status_code=303)


@app.get("/answers/{answer_uid}", response_class=HTMLResponse)
def answer_detail(request: Request, answer_uid: str):
    user = require_user(request)
    answer = db_one("SELECT a.*, q.query_uid, q.title, q.question FROM answers a JOIN queries q ON q.id=a.query_id WHERE a.answer_uid=%s", (answer_uid,))
    if not answer:
        raise HTTPException(status_code=404, detail="Antwort nicht gefunden")
    statements = db_rows(
        """
        SELECT st.id, st.section, st.statement_text,
               cit.citation_label, cit.citation_url, cit.internal_ref, cit.source_class,
               COALESCE(c.chunk_uid, c_ref.chunk_uid) AS chunk_uid,
               COALESCE(c.locator, c_ref.locator) AS locator,
               COALESCE(d.title, d_ref.title) AS document_title,
               COALESCE(s.source_uid, s_ref.source_uid) AS source_uid,
               COALESCE(s.title, s_ref.title) AS source_title,
               COALESCE(s.source_type, s_ref.source_type) AS source_type
        FROM answer_statements st
        LEFT JOIN answer_citations cit ON cit.statement_id=st.id
        LEFT JOIN chunks c ON c.id=cit.chunk_id
        LEFT JOIN documents d ON d.id=c.document_id
        LEFT JOIN sources s ON s.id=d.source_id
        LEFT JOIN sources s_ref ON c.id IS NULL AND s_ref.source_uid=split_part(cit.internal_ref, ':', 1)
        LEFT JOIN documents d_ref ON c.id IS NULL AND d_ref.source_id=s_ref.id
        LEFT JOIN chunks c_ref ON c.id IS NULL AND c_ref.document_id=d_ref.id AND replace(c_ref.locator, ' ', '')=replace(split_part(cit.internal_ref, ':', 2), ' ', '')
        WHERE st.answer_id=%s
        ORDER BY st.id
        """,
        (answer["id"],),
    )
    validation = answer_validation(answer["id"])
    source_classes = sorted({s["source_class"] for s in statements if s.get("source_class")})
    return templates.TemplateResponse("answer_detail.html", {"request": request, "title": APP_TITLE, "user": user, "answer": answer, "statements": statements, "validation": validation, "source_classes": source_classes})


@app.get("/security-rules", response_class=HTMLResponse)
def security_rules(request: Request):
    user = require_user(request)
    return templates.TemplateResponse("security_rules.html", {"request": request, "title": APP_TITLE, "user": user})


@app.get("/search", response_class=HTMLResponse)
def search(request: Request, q: str = "", source_class: str = "ALL", source_type_group: str = "ALL", approval: str = "approved"):
    user = require_user(request)
    results: list[dict[str, Any]] = []
    allowed_classes = {"ALL", "GRUEN", "BLAU", "GELB", "GRAU", "ROT"}
    if source_class not in allowed_classes:
        source_class = "ALL"
    if approval not in {"approved", "all", "blocked"}:
        approval = "approved"
    if q.strip():
        clauses = ["c.content_tsv @@ plainto_tsquery('german', %s)"]
        params: list[Any] = [q]
        if source_class != "ALL":
            clauses.append("s.source_class=%s")
            params.append(source_class)
        source_type_group = apply_source_type_filter(clauses, params, source_type_group)
        if approval == "approved":
            clauses.append("s.citation_allowed=true")
        elif approval == "blocked":
            clauses.append("s.status='gesperrt'")
        params.append(q)
        results = db_rows(
            ("""
            SELECT c.chunk_uid, c.heading, c.locator, left(c.content, 700) AS snippet,
                   c.citation_label, c.citation_url, c.internal_ref, c.source_class,
                   s.source_uid, s.status, s.citation_allowed, s.title AS source_title, s.source_type
            FROM chunks c
            JOIN documents d ON d.id = c.document_id
            JOIN sources s ON s.id = d.source_id
            WHERE """ + " AND ".join(clauses) + """
            ORDER BY ts_rank(c.content_tsv, plainto_tsquery('german', %s)) DESC
            LIMIT 30
            """),
            tuple(params),
        )
    return templates.TemplateResponse("search.html", {"request": request, "title": APP_TITLE, "user": user, "q": q, "source_class": source_class, "source_type_group": source_type_group, "source_type_options": source_type_options(), "approval": approval, "results": results})


@app.get("/validation", response_class=HTMLResponse)
def validation(request: Request):
    user = require_user(request)
    rows = db_rows(
        """
        SELECT a.answer_uid, a.status,
               count(st.id) AS statement_count,
               count(cit.id) AS citation_count,
               sum(CASE WHEN cit.id IS NULL THEN 1 ELSE 0 END) AS statements_without_citation
        FROM answers a
        LEFT JOIN answer_statements st ON st.answer_id = a.id
        LEFT JOIN answer_citations cit ON cit.statement_id = st.id
        GROUP BY a.id
        ORDER BY a.created_at DESC
        LIMIT 100
        """
    )
    return templates.TemplateResponse("validation.html", {"request": request, "title": APP_TITLE, "user": user, "answers": rows})
