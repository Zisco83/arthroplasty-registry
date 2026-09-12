import os
import base64
import json
import secrets

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import jwt
from fastapi import FastAPI, HTTPException, Request, Response, Depends
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from passlib.hash import argon2


# ============================================================
# APPLICATION PATHS / CONFIGURATION
# ============================================================

BASE = Path(__file__).resolve().parent
STATIC = BASE / "static"

DATABASE_URL = os.environ.get("DATABASE_URL")
SECRET_KEY = os.environ.get("SECRET_KEY")
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "false").lower() == "true"

# Fail safely before attempting to manipulate DATABASE_URL.
if not DATABASE_URL or not SECRET_KEY:
    raise RuntimeError("DATABASE_URL and SECRET_KEY are required")

# Render/PostgreSQL commonly supplies:
#   postgresql://...
# or:
#   postgres://...
#
# SQLAlchemy with psycopg3 should explicitly use:
#   postgresql+psycopg://...
#
# Normalize both forms automatically.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = (
        "postgresql+psycopg://"
        + DATABASE_URL[len("postgres://"):]
    )
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = (
        "postgresql+psycopg://"
        + DATABASE_URL[len("postgresql://"):]
    )


# ============================================================
# DATABASE / FASTAPI
# ============================================================

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=1800,
)

app = FastAPI(
    title="Arthroplasty Registry Cloud",
    version="1.0.0",
)

app.mount(
    "/static",
    StaticFiles(directory=str(STATIC)),
    name="static",
)


# ============================================================
# REQUEST MODELS
# ============================================================

class LoginIn(BaseModel):
    username: str
    password: str


class UserIn(BaseModel):
    username: str
    password: str
    full_name: str
    role: str = "data_entry"


class RecordIn(BaseModel):
    id: Optional[str] = None
    record: dict


class ImageIn(BaseModel):
    key: str
    registry_id: str
    section: str
    data_url: str


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def init_db():
    """
    Apply the initial database migration and create the
    bootstrap administrator if configured and not already present.
    """

    migration_path = (
        BASE.parent
        / "db"
        / "migrations"
        / "001_initial.sql"
    )

    if not migration_path.exists():
        raise RuntimeError(
            f"Database migration not found: {migration_path}"
        )

    migration = migration_path.read_text(encoding="utf-8")

    with engine.begin() as connection:

        # Execute migration statements.
        for statement in [
            part.strip()
            for part in migration.split(";")
            if part.strip()
        ]:
            connection.execute(text(statement))

        # Bootstrap administrator.
        username = os.getenv("BOOTSTRAP_ADMIN_USERNAME")
        password = os.getenv("BOOTSTRAP_ADMIN_PASSWORD")
        name = os.getenv(
            "BOOTSTRAP_ADMIN_NAME",
            "Registry Administrator",
        )

        if username and password:

            username = username.strip()

            exists = connection.execute(
                text(
                    "SELECT 1 "
                    "FROM users "
                    "WHERE username = :username"
                ),
                {"username": username},
            ).scalar()

            if not exists:

                connection.execute(
                    text(
                        """
                        INSERT INTO users
                            (
                                username,
                                full_name,
                                role,
                                password_hash
                            )
                        VALUES
                            (
                                :username,
                                :full_name,
                                'admin',
                                :password_hash
                            )
                        """
                    ),
                    {
                        "username": username,
                        "full_name": name,
                        "password_hash": argon2.hash(password),
                    },
                )


@app.on_event("startup")
def startup():
    init_db()


# ============================================================
# AUTHENTICATION
# ============================================================

def token_for(user):
    """
    Generate a signed 12-hour JWT session token.
    """

    now = datetime.now(timezone.utc)

    payload = {
        "sub": str(user["user_id"]),
        "username": user["username"],
        "role": user["role"],
        "exp": now + timedelta(hours=12),
    }

    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm="HS256",
    )


def current_user(request: Request):
    """
    Validate the HttpOnly session cookie and confirm that
    the corresponding database account remains active.
    """

    token = request.cookies.get("registry_session")

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Not authenticated",
        )

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=["HS256"],
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=401,
            detail="Session expired",
        )

    try:
        user_id = int(payload["sub"])
    except (KeyError, TypeError, ValueError):
        raise HTTPException(
            status_code=401,
            detail="Invalid session",
        )

    with engine.begin() as connection:

        row = connection.execute(
            text(
                """
                SELECT
                    user_id,
                    username,
                    full_name,
                    role,
                    is_active
                FROM users
                WHERE user_id = :user_id
                """
            ),
            {"user_id": user_id},
        ).mappings().first()

    if not row:
        raise HTTPException(
            status_code=401,
            detail="Account not found",
        )

    if not row["is_active"]:
        raise HTTPException(
            status_code=401,
            detail="Account inactive",
        )

    return dict(row)


def admin_only(user=Depends(current_user)):
    """
    Restrict endpoint access to administrators.
    """

    if user["role"] != "admin":
        raise HTTPException(
            status_code=403,
            detail="Administrator access required",
        )

    return user


# ============================================================
# FRONTEND / HEALTH
# ============================================================

@app.get("/")
def index():
    return FileResponse(
        STATIC / "index.html"
    )


@app.get("/healthz")
def healthz():
    """
    Render health-check endpoint.

    A successful database query is required for a healthy response.
    """

    with engine.begin() as connection:
        connection.execute(text("SELECT 1"))

    return {
        "status": "ok",
        "database": "ok",
        "version": "1.0.0",
    }


# ============================================================
# LOGIN / LOGOUT
# ============================================================

@app.post("/api/login")
def login(
    data: LoginIn,
    response: Response,
):
    username = data.username.strip()

    if not username or not data.password:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
        )

    with engine.begin() as connection:

        row = connection.execute(
            text(
                """
                SELECT *
                FROM users
                WHERE username = :username
                  AND is_active = true
                """
            ),
            {"username": username},
        ).mappings().first()

    if not row:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
        )

    try:
        password_valid = argon2.verify(
            data.password,
            row["password_hash"],
        )
    except Exception:
        password_valid = False

    if not password_valid:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
        )

    response.set_cookie(
        key="registry_session",
        value=token_for(row),
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=43200,
        path="/",
    )

    return {
        "user": {
            "name": row["full_name"],
            "username": row["username"],
            "role": row["role"],
        }
    }


@app.post("/api/logout")
def logout(response: Response):

    response.delete_cookie(
        key="registry_session",
        path="/",
    )

    return {
        "ok": True
    }


@app.get("/api/me")
def me(user=Depends(current_user)):

    return {
        "user": {
            "name": user["full_name"],
            "username": user["username"],
            "role": user["role"],
        }
    }


# ============================================================
# REGISTRY RECORDS
# ============================================================

@app.get("/api/records")
def records(user=Depends(current_user)):

    with engine.begin() as connection:

        rows = connection.execute(
            text(
                """
                SELECT record
                FROM registry_records
                ORDER BY
                    (record->>'surgeryDate') DESC NULLS LAST,
                    record_id DESC
                """
            )
        ).mappings().all()

    return [
        row["record"]
        for row in rows
    ]


@app.get("/api/records/{registry_id}")
def get_record(
    registry_id: str,
    user=Depends(current_user),
):

    with engine.begin() as connection:

        row = connection.execute(
            text(
                """
                SELECT record
                FROM registry_records
                WHERE registry_id = :registry_id
                """
            ),
            {"registry_id": registry_id},
        ).mappings().first()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Record not found",
        )

    return row["record"]


@app.post("/api/records")
def create_record(
    data: RecordIn,
    user=Depends(current_user),
):

    record = dict(data.record)

    registry_id = (
        record.get("id")
        or ("P-" + secrets.token_hex(4).upper())
    )

    record["id"] = registry_id

    record_json = json.dumps(record)

    with engine.begin() as connection:

        exists = connection.execute(
            text(
                """
                SELECT 1
                FROM registry_records
                WHERE registry_id = :registry_id
                """
            ),
            {"registry_id": registry_id},
        ).scalar()

        if exists:
            raise HTTPException(
                status_code=409,
                detail="Registry ID already exists",
            )

        connection.execute(
            text(
                """
                INSERT INTO registry_records
                    (
                        registry_id,
                        mrn,
                        record,
                        created_by
                    )
                VALUES
                    (
                        :registry_id,
                        :mrn,
                        CAST(:record AS jsonb),
                        :created_by
                    )
                """
            ),
            {
                "registry_id": registry_id,
                "mrn": record.get("mrn"),
                "record": record_json,
                "created_by": user["user_id"],
            },
        )

        audit(
            connection,
            user,
            "created",
            "registry_records",
            registry_id,
            {
                "mrn": record.get("mrn")
            },
        )

    return record


@app.put("/api/records/{registry_id}")
def update_record(
    registry_id: str,
    data: RecordIn,
    user=Depends(current_user),
):

    record = dict(data.record)

    record["id"] = registry_id

    record_json = json.dumps(record)

    with engine.begin() as connection:

        exists = connection.execute(
            text(
                """
                SELECT 1
                FROM registry_records
                WHERE registry_id = :registry_id
                """
            ),
            {"registry_id": registry_id},
        ).scalar()

        if not exists:
            raise HTTPException(
                status_code=404,
                detail="Record not found",
            )

        connection.execute(
            text(
                """
                UPDATE registry_records
                SET
                    mrn = :mrn,
                    record = CAST(:record AS jsonb),
                    updated_at = NOW()
                WHERE registry_id = :registry_id
                """
            ),
            {
                "registry_id": registry_id,
                "mrn": record.get("mrn"),
                "record": record_json,
            },
        )

        audit(
            connection,
            user,
            "edited",
            "registry_records",
            registry_id,
            {
                "mrn": record.get("mrn")
            },
        )

    return record


@app.delete("/api/records/{registry_id}")
def delete_record(
    registry_id: str,
    user=Depends(admin_only),
):

    with engine.begin() as connection:

        result = connection.execute(
            text(
                """
                DELETE FROM registry_records
                WHERE registry_id = :registry_id
                """
            ),
            {"registry_id": registry_id},
        )

        if result.rowcount == 0:
            raise HTTPException(
                status_code=404,
                detail="Record not found",
            )

        audit(
            connection,
            user,
            "deleted",
            "registry_records",
            registry_id,
            {},
        )

    return {
        "ok": True
    }


# ============================================================
# AUDIT / ACTIVITY
# ============================================================

def audit(
    connection,
    user,
    action,
    table_name,
    record_id,
    details,
):
    """
    Write an audit event within the same database transaction
    as the clinical operation.
    """

    connection.execute(
        text(
            """
            INSERT INTO audit_log
                (
                    user_id,
                    action,
                    table_name,
                    record_id,
                    details
                )
            VALUES
                (
                    :user_id,
                    :action,
                    :table_name,
                    :record_id,
                    CAST(:details AS jsonb)
                )
            """
        ),
        {
            "user_id": user["user_id"],
            "action": action,
            "table_name": table_name,
            "record_id": record_id,
            "details": json.dumps(details),
        },
    )


@app.get("/api/activity")
def activity(user=Depends(current_user)):

    with engine.begin() as connection:

        rows = connection.execute(
            text(
                """
                SELECT
                    a.timestamp,
                    a.action,
                    a.record_id,
                    a.details,
                    u.full_name
                FROM audit_log a
                LEFT JOIN users u
                    ON u.user_id = a.user_id
                ORDER BY a.timestamp DESC
                LIMIT 2000
                """
            )
        ).mappings().all()

    return [
        {
            "user": row["full_name"] or "Unknown",
            "action": row["action"],
            "patientId": row["record_id"],
            "at": row["timestamp"].isoformat(),
            "details": row["details"],
        }
        for row in rows
    ]


# ============================================================
# IMAGES
# ============================================================

@app.get("/api/images")
def image_list(
    registry_id: str,
    user=Depends(current_user),
):

    with engine.begin() as connection:

        rows = connection.execute(
            text(
                """
                SELECT
                    image_key,
                    section
                FROM images
                WHERE registry_id = :registry_id
                ORDER BY image_id
                """
            ),
            {"registry_id": registry_id},
        ).mappings().all()

    return [
        {
            "key": row["image_key"],
            "section": row["section"],
        }
        for row in rows
    ]


@app.get("/api/images/{image_key}")
def image_get(
    image_key: str,
    user=Depends(current_user),
):

    with engine.begin() as connection:

        row = connection.execute(
            text(
                """
                SELECT
                    image_data,
                    mime_type
                FROM images
                WHERE image_key = :image_key
                """
            ),
            {"image_key": image_key},
        ).mappings().first()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Image not found",
        )

    return Response(
        content=bytes(row["image_data"]),
        media_type=row["mime_type"],
        headers={
            "Cache-Control": "private, max-age=3600"
        },
    )


@app.post("/api/images")
def image_create(
    data: ImageIn,
    user=Depends(current_user),
):

    if data.section not in (
        "preop",
        "postop",
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid section",
        )

    if not data.data_url.startswith("data:image/"):
        raise HTTPException(
            status_code=400,
            detail="Invalid image data",
        )

    if "," not in data.data_url:
        raise HTTPException(
            status_code=400,
            detail="Invalid image data",
        )

    head, encoded_data = data.data_url.split(
        ",",
        1,
    )

    try:

        mime = (
            head
            .split(";", 1)[0]
            .split(":", 1)[1]
        )

    except (IndexError, ValueError):

        raise HTTPException(
            status_code=400,
            detail="Invalid image MIME type",
        )

    if not mime.startswith("image/"):
        raise HTTPException(
            status_code=400,
            detail="Invalid image MIME type",
        )

    try:

        raw = base64.b64decode(
            encoded_data,
            validate=True,
        )

    except Exception:

        raise HTTPException(
            status_code=400,
            detail="Invalid base64 image data",
        )

    if len(raw) > 8 * 1024 * 1024:

        raise HTTPException(
            status_code=413,
            detail="Image exceeds 8MB",
        )

    with engine.begin() as connection:

        exists = connection.execute(
            text(
                """
                SELECT 1
                FROM registry_records
                WHERE registry_id = :registry_id
                """
            ),
            {"registry_id": data.registry_id},
        ).scalar()

        if not exists:
            raise HTTPException(
                status_code=404,
                detail="Record not found",
            )

        connection.execute(
            text(
                """
                INSERT INTO images
                    (
                        image_key,
                        registry_id,
                        section,
                        mime_type,
                        image_data,
                        created_by
                    )
                VALUES
                    (
                        :image_key,
                        :registry_id,
                        :section,
                        :mime_type,
                        :image_data,
                        :created_by
                    )
                ON CONFLICT(image_key)
                DO UPDATE SET
                    registry_id = EXCLUDED.registry_id,
                    section = EXCLUDED.section,
                    mime_type = EXCLUDED.mime_type,
                    image_data = EXCLUDED.image_data
                """
            ),
            {
                "image_key": data.key,
                "registry_id": data.registry_id,
                "section": data.section,
                "mime_type": mime,
                "image_data": raw,
                "created_by": user["user_id"],
            },
        )

    return {
        "key": data.key
    }


@app.delete("/api/images/{image_key}")
def image_delete(
    image_key: str,
    user=Depends(current_user),
):

    with engine.begin() as connection:

        connection.execute(
            text(
                """
                DELETE FROM images
                WHERE image_key = :image_key
                """
            ),
            {"image_key": image_key},
        )

    return {
        "ok": True
    }


# ============================================================
# USER MANAGEMENT
# ============================================================

@app.get("/api/users")
def list_users(
    user=Depends(admin_only),
):

    with engine.begin() as connection:

        rows = connection.execute(
            text(
                """
                SELECT
                    user_id,
                    username,
                    full_name,
                    role,
                    is_active,
                    created_at
                FROM users
                ORDER BY user_id
                """
            )
        ).mappings().all()

    return [
        dict(row)
        for row in rows
    ]


@app.post("/api/users")
def create_user(
    data: UserIn,
    user=Depends(admin_only),
):

    if data.role not in (
        "data_entry",
        "admin",
        "surgeon",
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid role",
        )

    username = data.username.strip()
    full_name = data.full_name.strip()

    if not username:
        raise HTTPException(
            status_code=400,
            detail="Username is required",
        )

    if not data.password:
        raise HTTPException(
            status_code=400,
            detail="Password is required",
        )

    if not full_name:
        raise HTTPException(
            status_code=400,
            detail="Full name is required",
        )

    password_hash = argon2.hash(
        data.password
    )

    try:

        with engine.begin() as connection:

            row = connection.execute(
                text(
                    """
                    INSERT INTO users
                        (
                            username,
                            full_name,
                            role,
                            password_hash
                        )
                    VALUES
                        (
                            :username,
                            :full_name,
                            :role,
                            :password_hash
                        )
                    RETURNING
                        user_id,
                        username,
                        full_name,
                        role,
                        is_active,
                        created_at
                    """
                ),
                {
                    "username": username,
                    "full_name": full_name,
                    "role": data.role,
                    "password_hash": password_hash,
                },
            ).mappings().first()

    except IntegrityError:

        raise HTTPException(
            status_code=409,
            detail="Username already exists",
        )

    return dict(row)


@app.post("/api/users/{user_id}/disable")
def disable_user(
    user_id: int,
    user=Depends(admin_only),
):

    if user_id == user["user_id"]:
        raise HTTPException(
            status_code=400,
            detail="Cannot disable your own account",
        )

    with engine.begin() as connection:

        result = connection.execute(
            text(
                """
                UPDATE users
                SET is_active = false
                WHERE user_id = :user_id
                """
            ),
            {"user_id": user_id},
        )

        if result.rowcount == 0:
            raise HTTPException(
                status_code=404,
                detail="User not found",
            )

    return {
        "ok": True
    }