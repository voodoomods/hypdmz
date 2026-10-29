"""
Credential vault — AES-256-GCM at rest, write-only via UI, audit-trailed.

Schema:
  credentials       — encrypted leaf values + injection spec
  credential_audit  — append-only log of every read/write/rotate

Design:
  - Master key lives in /app/data/.master.key (0400, root-owned in
    container). Auto-generated on first init if missing. Never logged,
    never exposed via API. Agent container has no path to it.
  - Each credential value is AES-256-GCM encrypted with a per-record
    12-byte nonce and AAD = "name:type" (binds ciphertext to identity).
  - Plaintext is only ever materialised inside `decrypt_for_inject()`;
    callers must not retain it.
  - Audit table records action and credential name, never values.
  - UI is write-only: operators can rotate but never read the value back.

Bootstrap:
  On startup, env vars VAULT_BOOTSTRAP_<NAME> trigger one-time imports
  of values that don't yet exist. After import, the operator should
  remove them from .env (the proxy logs a warning if they're still
  present on subsequent boots).
"""

import base64
import json
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


DB_PATH         = os.getenv("VAULT_DB_PATH", "/app/data/vault.db")
MASTER_KEY_PATH = os.getenv("VAULT_MASTER_KEY", "/app/data/.master.key")

_init_lock = threading.Lock()
_initialized = False
_master_key: bytes | None = None


SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS credentials (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        name             TEXT UNIQUE NOT NULL,
        type             TEXT NOT NULL,
        ciphertext       BLOB NOT NULL,
        nonce            BLOB NOT NULL,
        aad              BLOB NOT NULL,
        inject_location  TEXT NOT NULL DEFAULT 'header',
        inject_name      TEXT NOT NULL DEFAULT 'Authorization',
        inject_template  TEXT NOT NULL DEFAULT 'Bearer {value}',
        inject_overwrite INTEGER NOT NULL DEFAULT 1,
        scope_host       TEXT,
        scope_path       TEXT,
        expires_at       TEXT,
        rotation_due     TEXT,
        created_at       TEXT NOT NULL,
        updated_at       TEXT NOT NULL,
        last_used_at     TEXT,
        use_count        INTEGER NOT NULL DEFAULT 0,
        created_by       TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS credential_audit (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        credential_id   INTEGER,
        credential_name TEXT NOT NULL,
        action          TEXT NOT NULL,
        actor           TEXT,
        timestamp       TEXT NOT NULL,
        detail          TEXT
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_cred_audit_ts ON credential_audit(timestamp DESC);",
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=5, isolation_level=None, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode = WAL;")
    con.execute("PRAGMA synchronous = NORMAL;")
    return con


def _ensure_master_key() -> bytes:
    """Load or generate the 32-byte master key.

    First-run: create with cryptographically-secure randomness, mode 0400.
    Returned bytes are kept module-private; never logged.
    """
    global _master_key
    if _master_key is not None:
        return _master_key
    p = Path(MASTER_KEY_PATH)
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.exists():
        data = p.read_bytes()
        if len(data) != 32:
            raise RuntimeError(
                f"Vault master key at {MASTER_KEY_PATH} is {len(data)} bytes; expected 32."
            )
        _master_key = data
    else:
        key = secrets.token_bytes(32)
        p.write_bytes(key)
        try:
            os.chmod(p, 0o400)
        except Exception:
            pass
        print(f"[vault] generated new master key at {MASTER_KEY_PATH} (0400). Back this up.")
        _master_key = key
    return _master_key


def init_db() -> None:
    global _initialized
    if _initialized:
        return
    with _init_lock:
        if _initialized:
            return
        _ensure_master_key()
        with _connect() as con:
            for stmt in SCHEMA:
                con.execute(stmt)
        _initialized = True
        _bootstrap_from_env()


def is_available() -> bool:
    try:
        init_db()
        return True
    except Exception as e:
        print(f"[vault] unavailable: {e}")
        return False


# ── encryption primitives ────────────────────────────────────────────

def _encrypt(value: str, name: str, type_: str) -> tuple[bytes, bytes, bytes]:
    """Returns (ciphertext, nonce, aad)."""
    aad = f"{name}:{type_}".encode("utf-8")
    nonce = secrets.token_bytes(12)
    aes = AESGCM(_ensure_master_key())
    ct = aes.encrypt(nonce, value.encode("utf-8"), aad)
    return ct, nonce, aad


def _decrypt(ct: bytes, nonce: bytes, aad: bytes) -> str:
    aes = AESGCM(_ensure_master_key())
    return aes.decrypt(nonce, ct, aad).decode("utf-8")


# ── audit ───────────────────────────────────────────────────────────

def _audit(con: sqlite3.Connection, *, name: str, action: str,
           credential_id: int | None = None, actor: str = "operator",
           detail: str = "") -> None:
    con.execute(
        """INSERT INTO credential_audit
           (credential_id, credential_name, action, actor, timestamp, detail)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (credential_id, name, action, actor, _now(), detail or None),
    )


# ── CRUD ────────────────────────────────────────────────────────────

def list_credentials() -> list[dict]:
    """Return metadata for all credentials. Never includes plaintext."""
    init_db()
    with _connect() as con:
        cur = con.execute("SELECT * FROM credentials ORDER BY name")
        out = []
        for r in cur.fetchall():
            out.append({
                "id":               r["id"],
                "name":             r["name"],
                "type":             r["type"],
                "inject_location":  r["inject_location"],
                "inject_name":      r["inject_name"],
                "inject_template":  r["inject_template"],
                "inject_overwrite": bool(r["inject_overwrite"]),
                "scope_host":       r["scope_host"],
                "scope_path":       r["scope_path"],
                "expires_at":       r["expires_at"],
                "rotation_due":     r["rotation_due"],
                "created_at":       r["created_at"],
                "updated_at":       r["updated_at"],
                "last_used_at":     r["last_used_at"],
                "use_count":        r["use_count"],
                "created_by":       r["created_by"],
                # No ciphertext, no nonce, no value.
            })
        return out


def create_credential(payload: dict, actor: str = "operator") -> dict:
    init_db()
    name = (payload.get("name") or "").strip()
    value = payload.get("value") or ""
    type_ = (payload.get("type") or "bearer").strip()
    if not name or not value:
        raise ValueError("name and value are required")

    ct, nonce, aad = _encrypt(value, name, type_)
    spec = payload.get("injection_spec") or {}
    loc = spec.get("location", "header")
    iname = spec.get("name") or _default_inject_name(type_)
    tmpl = spec.get("template") or _default_inject_template(type_)
    over = 1 if spec.get("overwrite", True) else 0

    with _connect() as con:
        cur = con.execute(
            """INSERT INTO credentials
               (name, type, ciphertext, nonce, aad,
                inject_location, inject_name, inject_template, inject_overwrite,
                scope_host, scope_path, expires_at, rotation_due,
                created_at, updated_at, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                name, type_, ct, nonce, aad,
                loc, iname, tmpl, over,
                payload.get("scope_host"), payload.get("scope_path"),
                payload.get("expires_at"), payload.get("rotation_due"),
                _now(), _now(), actor,
            ),
        )
        new_id = cur.lastrowid
        _audit(con, name=name, action="CREATE", credential_id=new_id, actor=actor,
               detail=f"type={type_} loc={loc} name={iname}")
    links = _recipe_links_for(name)
    if links:
        _link_to_rules(name, links)
    return {"id": new_id, "name": name}


def update_metadata(cred_id: int, payload: dict, actor: str = "operator") -> bool:
    """Update non-secret metadata. Use rotate_credential() for value changes."""
    init_db()
    allowed = {"inject_location", "inject_name", "inject_template",
               "inject_overwrite", "scope_host", "scope_path",
               "expires_at", "rotation_due"}
    sets, values = [], []
    for k, v in payload.items():
        if k not in allowed:
            continue
        if k == "inject_overwrite":
            v = 1 if v else 0
        sets.append(f"{k} = ?")
        values.append(v)
    if not sets:
        return False
    sets.append("updated_at = ?")
    values.append(_now())
    values.append(cred_id)
    with _connect() as con:
        cur = con.execute("SELECT name FROM credentials WHERE id = ?", (cred_id,))
        row = cur.fetchone()
        if not row:
            return False
        con.execute(f"UPDATE credentials SET {', '.join(sets)} WHERE id = ?", values)
        _audit(con, name=row["name"], action="UPDATE_META", credential_id=cred_id, actor=actor)
    return True


def rotate_credential(cred_id: int, new_value: str, actor: str = "operator") -> bool:
    init_db()
    if not new_value:
        raise ValueError("new_value is required")
    with _connect() as con:
        cur = con.execute("SELECT name, type FROM credentials WHERE id = ?", (cred_id,))
        row = cur.fetchone()
        if not row:
            return False
        ct, nonce, aad = _encrypt(new_value, row["name"], row["type"])
        con.execute(
            "UPDATE credentials SET ciphertext=?, nonce=?, aad=?, updated_at=?, rotation_due=NULL WHERE id=?",
            (ct, nonce, aad, _now(), cred_id),
        )
        _audit(con, name=row["name"], action="ROTATE", credential_id=cred_id, actor=actor)
    return True


def delete_credential(cred_id: int, actor: str = "operator") -> bool:
    init_db()
    with _connect() as con:
        cur = con.execute("SELECT name FROM credentials WHERE id = ?", (cred_id,))
        row = cur.fetchone()
        if not row:
            return False
        con.execute("DELETE FROM credentials WHERE id = ?", (cred_id,))
        _audit(con, name=row["name"], action="DELETE", credential_id=cred_id, actor=actor)
    return True


# ── inject path (hot — keep it tight) ────────────────────────────────

def get_for_inject(name: str) -> dict | None:
    """Decrypt a credential for a single in-flight injection.

    Increments use_count and last_used_at, and writes a READ_FOR_INJECT
    audit row (without the value).

    Returns: { value, inject_location, inject_name, inject_template,
               inject_overwrite, scope_host, scope_path } — or None.
    """
    init_db()
    with _connect() as con:
        cur = con.execute("SELECT * FROM credentials WHERE name = ?", (name,))
        r = cur.fetchone()
        if not r:
            return None
        try:
            value = _decrypt(bytes(r["ciphertext"]), bytes(r["nonce"]), bytes(r["aad"]))
        except Exception as e:
            print(f"[vault] decrypt failed for {name}: {e}")
            return None
        con.execute(
            "UPDATE credentials SET last_used_at=?, use_count=use_count+1 WHERE id=?",
            (_now(), r["id"]),
        )
        _audit(con, name=name, action="READ_FOR_INJECT", credential_id=r["id"], actor="proxy")
    return {
        "value":            value,
        "inject_location":  r["inject_location"],
        "inject_name":      r["inject_name"],
        "inject_template":  r["inject_template"],
        "inject_overwrite": bool(r["inject_overwrite"]),
        "scope_host":       r["scope_host"],
        "scope_path":       r["scope_path"],
    }


# ── audit reader ────────────────────────────────────────────────────

def recent_audit(n: int = 100, name: str | None = None) -> list[dict]:
    init_db()
    with _connect() as con:
        if name:
            cur = con.execute(
                "SELECT * FROM credential_audit WHERE credential_name=? ORDER BY id DESC LIMIT ?",
                (name, n),
            )
        else:
            cur = con.execute("SELECT * FROM credential_audit ORDER BY id DESC LIMIT ?", (n,))
        return [dict(r) for r in cur.fetchall()]


# ── helpers ─────────────────────────────────────────────────────────

def _default_inject_name(type_: str) -> str:
    return {
        "bearer":            "Authorization",
        "api_key_header":    "X-API-Key",
        "basic":             "Authorization",
        "query_param":       "api_key",
        "custom_header":     "X-Custom",
    }.get(type_, "Authorization")


def _default_inject_template(type_: str) -> str:
    return {
        "bearer":            "Bearer {value}",
        "api_key_header":    "{value}",
        "basic":             "Basic {value}",
        "query_param":       "{value}",
        "custom_header":     "{value}",
    }.get(type_, "Bearer {value}")


# ── env bootstrap ───────────────────────────────────────────────────

# (name, env var, type, default injection_spec, scope, rule names) — HypDMZ vaults one credential from the
# environment: the model API key, scoped to the host of MODEL_BASE_URL. Rules name it in firewall.json ("injects").
_BOOTSTRAP_RECIPES = [
    ("model_api_key", "VAULT_BOOTSTRAP_MODEL",
     "bearer", {"location": "header", "name": "Authorization", "template": "Bearer {value}", "overwrite": True},
     {"scope_host": (os.getenv("VAULT_BOOTSTRAP_MODEL_HOST") or "").strip() or None},
     []),
]


def _recipe_links_for(name: str) -> list[str]:
    """Return the rule_names list from the bootstrap recipe for `name`, or []."""
    for rec_name, _, _, _, _, rule_links in _BOOTSTRAP_RECIPES:
        if rec_name == name:
            return rule_links
    return []


def _link_to_rules(cred_name: str, rule_names: list[str]) -> None:
    """Rules name their credentials in firewall.json ("injects"); there is nothing to link at runtime."""
    return


def _bootstrap_from_env() -> None:
    existing = {c["name"] for c in list_credentials()}
    for name, env, type_, spec, scope, rule_links in _BOOTSTRAP_RECIPES:
        # Preferred: a podman secret mounted as a file (never in the environment, never in `podman inspect`),
        # named by <ENV>_FILE. Fallback: the environment variable itself.
        val, source = "", ""
        path = (os.getenv(env + "_FILE") or "").strip()
        if path:
            try:
                val, source = Path(path).read_text(encoding="utf-8").strip(), f"secret file {path}"
            except OSError as e:
                print(f"[vault] {env}_FILE={path} unreadable: {e}")
        if not val:
            val, source = (os.getenv(env) or "").strip(), f"env {env}"
        if not val or val == "__hypdmz_inject__":
            continue
        if name in existing:
            print(f"[vault] {source} present but '{name}' already vaulted — ignoring it")
            _link_to_rules(name, rule_links)  # keep links fresh even if already vaulted
            continue
        try:
            create_credential(
                {"name": name, "value": val, "type": type_,
                 "injection_spec": spec, **scope},
                actor="bootstrap:env",
            )
            print(f"[vault] bootstrapped credential '{name}' from {source}")
            _link_to_rules(name, rule_links)
        except Exception as e:
            print(f"[vault] bootstrap failed for {name}: {e}")
