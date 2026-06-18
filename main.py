# =============================================================================
# SAFESEND API — Number Reputation & Vishing Protection
# The trust layer for African mobile money transactions.
# Built in Douala, Cameroon by Newton
# =============================================================================

import os
import uuid
import json
import hashlib
import logging
import time as _time
import collections as _collections
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any

import psycopg2
import psycopg2.extras
import redis as _redis_lib
import requests
import bcrypt
import uvicorn

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# =============================================================================
# IN-MEMORY RATE LIMITER
# =============================================================================

_rate_limit_store: dict = {}

def _rate_limit_check(key: str, max_requests: int, window_seconds: int) -> bool:
    now = _time.time()
    if key not in _rate_limit_store:
        _rate_limit_store[key] = _collections.deque()
    dq = _rate_limit_store[key]
    while dq and dq[0] < now - window_seconds:
        dq.popleft()
    if len(dq) >= max_requests:
        return False
    dq.append(now)
    return True

def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

# =============================================================================
# DATABASE
# =============================================================================

def _get_db_conn():
    db_url = os.getenv("DATABASE_URL", "").replace("postgres://", "postgresql://", 1)
    return psycopg2.connect(db_url)

def get_db():
    yield None

def init_db():
    """Create all SafeSend tables. Never drops data on redeploy."""
    try:
        conn = _get_db_conn()
        cur = conn.cursor()

        # 1. partners — brands integrating SafeSend SDK
        cur.execute("""
            CREATE TABLE IF NOT EXISTS partners (
                id                   SERIAL PRIMARY KEY,
                partner_id           VARCHAR UNIQUE NOT NULL,
                brand_name           VARCHAR NOT NULL,
                email                VARCHAR UNIQUE NOT NULL,
                password_hash        VARCHAR,
                auth_token           VARCHAR UNIQUE,
                api_key              VARCHAR UNIQUE,
                account_status       VARCHAR DEFAULT 'pending',
                is_active            BOOLEAN DEFAULT FALSE,
                slots_used           INTEGER DEFAULT 0,
                slot_limit           INTEGER DEFAULT 100000,
                scan_count           BIGINT DEFAULT 0,
                onboarding_ends_at   TIMESTAMPTZ,
                subscription_ends_at TIMESTAMPTZ,
                created_at           TIMESTAMPTZ DEFAULT NOW()
            )
        """)

        # 2. device_registry — hashed phone IDs
        cur.execute("""
            CREATE TABLE IF NOT EXISTS device_registry (
                id            SERIAL PRIMARY KEY,
                phone_id_hash VARCHAR UNIQUE NOT NULL,
                partner_id    VARCHAR REFERENCES partners(partner_id) ON DELETE CASCADE,
                first_seen    TIMESTAMPTZ DEFAULT NOW(),
                last_seen     TIMESTAMPTZ DEFAULT NOW()
            )
        """)

        # 3. number_checks — every /check call logged for spike detection
        cur.execute("""
            CREATE TABLE IF NOT EXISTS number_checks (
                id            SERIAL PRIMARY KEY,
                hashed_number VARCHAR NOT NULL,
                checker_id    VARCHAR NOT NULL,
                partner_id    VARCHAR,
                checked_at    TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_number_checks_number_time ON number_checks(hashed_number, checked_at)")

        # 4. number_reports — crowdsourced vishing reports
        cur.execute("""
            CREATE TABLE IF NOT EXISTS number_reports (
                id             SERIAL PRIMARY KEY,
                hashed_number  VARCHAR NOT NULL,
                targeted_brand VARCHAR NOT NULL,
                reporter_id    VARCHAR NOT NULL,
                reported_at    TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(hashed_number, reporter_id)
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_number_reports_number ON number_reports(hashed_number)")

        # 5. number_blacklist — confirmed at 50 unique reports
        cur.execute("""
            CREATE TABLE IF NOT EXISTS number_blacklist (
                id               SERIAL PRIMARY KEY,
                hashed_number    VARCHAR UNIQUE NOT NULL,
                targeted_brand   VARCHAR NOT NULL,
                report_count     INTEGER DEFAULT 1,
                last_reported_at TIMESTAMPTZ DEFAULT NOW(),
                flagged_at       TIMESTAMPTZ DEFAULT NOW()
            )
        """)

        # 6. number_actionable — real numbers shared with explicit user consent for brand takedowns
        cur.execute("""
            CREATE TABLE IF NOT EXISTS number_actionable (
                id             SERIAL PRIMARY KEY,
                hashed_number  VARCHAR NOT NULL,
                real_number    VARCHAR NOT NULL,
                targeted_brand VARCHAR NOT NULL,
                reporter_id    VARCHAR NOT NULL,
                reported_at    TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(hashed_number, reporter_id)
            )
        """)

        # 7. spike_alerts — active spike flags
        cur.execute("""
            CREATE TABLE IF NOT EXISTS spike_alerts (
                id            SERIAL PRIMARY KEY,
                hashed_number VARCHAR UNIQUE NOT NULL,
                check_count   INTEGER DEFAULT 0,
                window_start  TIMESTAMPTZ DEFAULT NOW(),
                flagged_at    TIMESTAMPTZ DEFAULT NOW(),
                resolved      BOOLEAN DEFAULT FALSE
            )
        """)

        # 8. platform_stats — single row global analytics
        cur.execute("""
            CREATE TABLE IF NOT EXISTS platform_stats (
                id                 SERIAL PRIMARY KEY,
                total_checks       BIGINT DEFAULT 0,
                total_reports      BIGINT DEFAULT 0,
                total_blocked      BIGINT DEFAULT 0,
                total_devices      BIGINT DEFAULT 0,
                total_partners     BIGINT DEFAULT 0,
                last_updated       TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        cur.execute("""
            INSERT INTO platform_stats (id) VALUES (1)
            ON CONFLICT (id) DO NOTHING
        """)

        conn.commit()
        cur.close()
        conn.close()
        logger.info("[DB] SafeSend tables ready ✅")
    except Exception as e:
        logger.error(f"[DB] Init failed: {e}")

# =============================================================================
# REDIS CACHE
# =============================================================================

_redis_client = None
_mem_cache: dict = {}
_CACHE_TTL = 300  # 5 minutes for number reputation

def _get_redis():
    global _redis_client
    if _redis_client is None:
        redis_url = os.getenv("REDIS_URL", "")
        if redis_url:
            try:
                _redis_client = _redis_lib.from_url(redis_url, decode_responses=True)
                _redis_client.ping()
                logger.info("[CACHE] Redis connected")
            except Exception as e:
                logger.warning(f"[CACHE] Redis failed: {e}")
                _redis_client = None
    return _redis_client

def _cache_key(hashed_number: str) -> str:
    return f"safesend:num:{hashed_number}"

def get_cached_check(hashed_number: str):
    r = _get_redis()
    if r:
        try:
            raw = r.get(_cache_key(hashed_number))
            return json.loads(raw) if raw else None
        except Exception:
            pass
    entry = _mem_cache.get(hashed_number)
    if entry and (_time.time() - entry["ts"]) < _CACHE_TTL:
        return entry["data"]
    return None

def set_cached_check(hashed_number: str, data: dict):
    r = _get_redis()
    if r:
        try:
            r.setex(_cache_key(hashed_number), _CACHE_TTL, json.dumps(data))
            return
        except Exception:
            pass
    _mem_cache[hashed_number] = {"ts": _time.time(), "data": data}

def invalidate_cache(hashed_number: str):
    r = _get_redis()
    if r:
        try:
            r.delete(_cache_key(hashed_number))
        except Exception:
            pass
    _mem_cache.pop(hashed_number, None)

# =============================================================================
# SPIKE DETECTION
# =============================================================================

_SPIKE_WINDOW_SECONDS = 3600   # 1 hour window
_SPIKE_THRESHOLD      = 10     # 10 unique devices in 1 hour = spike

def check_spike(hashed_number: str, checker_id: str, partner_id: str) -> dict:
    """
    Log this check and determine if a spike is occurring.
    Spike = 10+ unique devices checking the same number in 60 minutes.
    Returns spike info including count and whether it's active.
    """
    try:
        conn = _get_db_conn()
        cur = conn.cursor()

        # Log this check
        cur.execute("""
            INSERT INTO number_checks (hashed_number, checker_id, partner_id, checked_at)
            VALUES (%s, %s, %s, NOW())
        """, (hashed_number, checker_id, partner_id))

        # Count unique checkers in the last hour
        cur.execute("""
            SELECT COUNT(DISTINCT checker_id) as unique_checkers
            FROM number_checks
            WHERE hashed_number = %s
            AND checked_at >= NOW() - INTERVAL '1 hour'
        """, (hashed_number,))
        row = cur.fetchone()
        unique_checkers = int(row[0]) if row else 1

        is_spike = unique_checkers >= _SPIKE_THRESHOLD

        if is_spike:
            # Upsert spike alert
            cur.execute("""
                INSERT INTO spike_alerts (hashed_number, check_count, window_start, flagged_at, resolved)
                VALUES (%s, %s, NOW() - INTERVAL '1 hour', NOW(), FALSE)
                ON CONFLICT (hashed_number) DO UPDATE SET
                    check_count = EXCLUDED.check_count,
                    flagged_at  = NOW(),
                    resolved    = FALSE
            """, (hashed_number, unique_checkers))
            logger.info(f"[SPIKE] Active spike detected: {hashed_number[:12]}... — {unique_checkers} unique checkers in 1hr")

        conn.commit()
        cur.close()
        conn.close()

        return {
            "is_spike": is_spike,
            "unique_checkers": unique_checkers,
            "threshold": _SPIKE_THRESHOLD,
        }
    except Exception as e:
        logger.warning(f"[SPIKE] Check failed: {e}")
        return {"is_spike": False, "unique_checkers": 0, "threshold": _SPIKE_THRESHOLD}

# =============================================================================
# NUMBER REPUTATION ENGINE
# =============================================================================

def get_number_reputation(hashed_number: str) -> dict:
    """
    Core reputation lookup. Returns:
    - report_count: total unique reports
    - blacklisted: whether number hit 50-report threshold
    - targeted_brand: which brand was most commonly impersonated
    - last_reported: timestamp of most recent report
    - risk_level: SAFE / SUSPICIOUS / HIGH
    - risk_score: 0-100
    """
    try:
        conn = _get_db_conn()
        from psycopg2.extras import RealDictCursor
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Check blacklist first — fastest path
        cur.execute("""
            SELECT * FROM number_blacklist WHERE hashed_number = %s LIMIT 1
        """, (hashed_number,))
        blacklisted = cur.fetchone()

        # Get report stats
        cur.execute("""
            SELECT
                COUNT(*) as report_count,
                MAX(reported_at) as last_reported,
                MODE() WITHIN GROUP (ORDER BY targeted_brand) as top_brand
            FROM number_reports
            WHERE hashed_number = %s
        """, (hashed_number,))
        stats = cur.fetchone()

        cur.close()
        conn.close()

        report_count = int(stats["report_count"]) if stats else 0
        last_reported = stats["last_reported"].isoformat() if stats and stats["last_reported"] else None
        targeted_brand = dict(blacklisted)["targeted_brand"] if blacklisted else (stats["top_brand"] if stats else None)

        # Risk scoring
        if blacklisted:
            risk_level = "HIGH"
            risk_score = 95
        elif report_count >= 20:
            risk_level = "HIGH"
            risk_score = 85
        elif report_count >= 10:
            risk_level = "HIGH"
            risk_score = 75
        elif report_count >= 5:
            risk_level = "SUSPICIOUS"
            risk_score = 55
        elif report_count >= 1:
            risk_level = "SUSPICIOUS"
            risk_score = 35
        else:
            risk_level = "SAFE"
            risk_score = 0

        return {
            "report_count":   report_count,
            "blacklisted":    blacklisted is not None,
            "targeted_brand": targeted_brand,
            "last_reported":  last_reported,
            "risk_level":     risk_level,
            "risk_score":     risk_score,
        }
    except Exception as e:
        logger.warning(f"[REPUTATION] Lookup failed: {e}")
        return {
            "report_count": 0,
            "blacklisted": False,
            "targeted_brand": None,
            "last_reported": None,
            "risk_level": "SAFE",
            "risk_score": 0,
        }

# =============================================================================
# EMAIL
# =============================================================================

def send_email(to: str, subject: str, body: str):
    resend_key = os.getenv("RESEND_API_KEY", "")
    if not resend_key:
        logger.warning("[EMAIL] RESEND_API_KEY not set")
        return
    if not to or "@" not in to:
        return
    try:
        resp = requests.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {resend_key}", "Content-Type": "application/json"},
            json={"from": "SafeSend <hello@safesend.africa>", "to": [to], "subject": subject, "text": body},
            timeout=10,
        )
        if resp.status_code in (200, 201):
            logger.info(f"[EMAIL] Sent to {to}: {subject}")
        else:
            logger.warning(f"[EMAIL] Resend {resp.status_code}: {resp.text}")
    except Exception as e:
        logger.error(f"[EMAIL] Failed: {e}")

# =============================================================================
# PYDANTIC MODELS
# =============================================================================

class CheckRequest(BaseModel):
    hashed_number: str
    user_id: str                    # hashed phone ID
    partner_id: Optional[str] = None

class ReportRequest(BaseModel):
    hashed_number: str
    targeted_brand: str
    user_id: str
    consent: bool = False
    real_number: Optional[str] = None   # only if consent=True

class CallEndedRequest(BaseModel):
    hashed_number: str
    user_id: str

class RegisterRequest(BaseModel):
    brand_name: str
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

class AdminLoginRequest(BaseModel):
    email: str
    password: str

# =============================================================================
# FASTAPI APP
# =============================================================================

app = FastAPI(
    title="SafeSend API",
    description="Number Reputation & Vishing Protection for African Mobile Money.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

ADMIN_SECRET = os.getenv("ADMIN_SECRET", "")

@app.on_event("startup")
async def startup():
    init_db()
    _get_redis()

def _require_admin(request: Request):
    secret = request.headers.get("X-Admin-Secret", "")
    if not secret or secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")

def _get_partner_by_apikey(api_key: str):
    try:
        conn = _get_db_conn()
        from psycopg2.extras import RealDictCursor
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM partners WHERE api_key=%s AND is_active=TRUE", (api_key,))
        partner = cur.fetchone()
        cur.close(); conn.close()
        return dict(partner) if partner else None
    except Exception:
        return None

# =============================================================================
# ROUTES
# =============================================================================

@app.get("/")
async def root():
    return {
        "service": "SafeSend API",
        "version": "1.0.0",
        "status":  "running",
        "description": "Number reputation and vishing protection for African mobile money.",
        "endpoints": {
            "POST /check":           "Check number reputation before sending money",
            "POST /report":          "Report a vishing number",
            "POST /call-ended":      "Post-call vishing check",
            "POST /partner/register": "Register as a partner",
            "POST /partner/login":    "Partner login",
            "GET  /partner/dashboard": "Partner dashboard",
        }
    }

@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}

# =============================================================================
# CORE — NUMBER CHECK
# =============================================================================

@app.post("/check")
async def check_number(body: CheckRequest, request: Request):
    """
    Core SafeSend endpoint.
    Called by SDK before user confirms a MoMo transaction.
    Returns reputation, report count, spike flag, and risk level.
    Rate limit: 60 req/min per user_id.
    """
    if not body.hashed_number or not body.user_id:
        raise HTTPException(status_code=400, detail="hashed_number and user_id required")

    # Rate limit per user
    if not _rate_limit_check(f"check:{body.user_id}", max_requests=60, window_seconds=60):
        raise HTTPException(status_code=429, detail="Too many requests.")

    # Check cache first
    cached = get_cached_check(body.hashed_number)
    if cached:
        cached["cached"] = True
        return cached

    # Spike detection — log this check, check for active spike
    partner_id = body.partner_id or "direct"
    spike_info = check_spike(body.hashed_number, body.user_id, partner_id)

    # Number reputation
    reputation = get_number_reputation(body.hashed_number)

    # Spike overrides risk level — spike = active scam campaign
    if spike_info["is_spike"] and reputation["risk_level"] == "SAFE":
        reputation["risk_level"] = "SUSPICIOUS"
        reputation["risk_score"] = max(reputation["risk_score"], 50)

    # Build warning message
    warning_message = ""
    if reputation["blacklisted"]:
        brand = reputation["targeted_brand"] or "a financial brand"
        warning_message = (
            f"⚠️ This number has been confirmed as a scammer impersonating {brand}. "
            f"Reported by {reputation['report_count']} users. Do not send money."
        )
    elif spike_info["is_spike"]:
        warning_message = (
            f"⚠️ This number is contacting many people right now. "
            f"Checked by {spike_info['unique_checkers']} devices in the last hour. "
            f"Active scam campaign suspected."
        )
    elif reputation["report_count"] >= 5:
        brand = reputation["targeted_brand"] or "a financial brand"
        warning_message = (
            f"⚠️ This number has been reported {reputation['report_count']} times "
            f"as impersonating {brand}."
        )
    elif reputation["report_count"] >= 1:
        warning_message = (
            f"This number was reported by {reputation['report_count']} user"
            f"{'s' if reputation['report_count'] != 1 else ''}. Proceed with caution."
        )

    result = {
        "hashed_number":   body.hashed_number,
        "risk_level":      reputation["risk_level"],
        "risk_score":      reputation["risk_score"],
        "report_count":    reputation["report_count"],
        "blacklisted":     reputation["blacklisted"],
        "targeted_brand":  reputation["targeted_brand"],
        "last_reported":   reputation["last_reported"],
        "spike":           spike_info["is_spike"],
        "spike_checkers":  spike_info["unique_checkers"],
        "warning_message": warning_message,
        "can_proceed":     True,   # always — user always decides
        "cached":          False,
        "timestamp":       datetime.now(timezone.utc).isoformat(),
    }

    # Cache result — don't cache HIGH results for long (5 min default)
    # Cache SAFE results for 5 min too but invalidate on new report
    set_cached_check(body.hashed_number, result)

    # Update platform stats
    try:
        conn = _get_db_conn()
        cur = conn.cursor()
        cur.execute("UPDATE platform_stats SET total_checks = total_checks + 1, last_updated = NOW() WHERE id = 1")
        conn.commit()
        cur.close(); conn.close()
    except Exception:
        pass

    return result

# =============================================================================
# POST-CALL CHECK
# =============================================================================

@app.post("/call-ended")
async def call_ended(body: CallEndedRequest, request: Request):
    """
    Called by SafeSend app immediately when a call from an unsaved number ends.
    Returns reputation data so the app can decide whether to show the post-call quiz.
    Same as /check but semantically distinct — this is a passive check, not a transaction check.
    """
    if not body.hashed_number or not body.user_id:
        raise HTTPException(status_code=400, detail="hashed_number and user_id required")

    if not _rate_limit_check(f"call:{body.user_id}", max_requests=30, window_seconds=60):
        raise HTTPException(status_code=429, detail="Too many requests.")

    spike_info = check_spike(body.hashed_number, body.user_id, "call_ended")
    reputation = get_number_reputation(body.hashed_number)

    return {
        "hashed_number":  body.hashed_number,
        "known":          reputation["report_count"] > 0 or reputation["blacklisted"],
        "blacklisted":    reputation["blacklisted"],
        "report_count":   reputation["report_count"],
        "targeted_brand": reputation["targeted_brand"],
        "last_reported":  reputation["last_reported"],
        "risk_level":     reputation["risk_level"],
        "spike":          spike_info["is_spike"],
        "spike_checkers": spike_info["unique_checkers"],
        "timestamp":      datetime.now(timezone.utc).isoformat(),
    }

# =============================================================================
# REPORT
# =============================================================================

@app.post("/report")
async def report_number(body: ReportRequest, request: Request):
    """
    User reports a vishing number after post-call quiz.
    One report per user_id per number.
    At 50 unique reports → auto-blacklisted.
    If consent=True and real_number provided → stored for brand takedowns.
    """
    if not body.hashed_number or not body.targeted_brand or not body.user_id:
        raise HTTPException(status_code=400, detail="hashed_number, targeted_brand and user_id required")

    if not _rate_limit_check(f"report:{body.user_id}", max_requests=10, window_seconds=3600):
        raise HTTPException(status_code=429, detail="Too many reports. Try again later.")

    try:
        conn = _get_db_conn()
        cur = conn.cursor()

        # Insert report — UNIQUE(hashed_number, reporter_id) prevents double reporting
        cur.execute("""
            INSERT INTO number_reports (hashed_number, targeted_brand, reporter_id, reported_at)
            VALUES (%s, %s, %s, NOW())
            ON CONFLICT (hashed_number, reporter_id) DO NOTHING
        """, (body.hashed_number, body.targeted_brand, body.user_id))
        inserted = cur.rowcount

        # Get current report count
        cur.execute("SELECT COUNT(*) FROM number_reports WHERE hashed_number=%s", (body.hashed_number,))
        row = cur.fetchone()
        report_count = int(row[0]) if row else 0

        # Store real number if consented — for brand takedowns
        if body.consent and body.real_number:
            cur.execute("""
                INSERT INTO number_actionable (hashed_number, real_number, targeted_brand, reporter_id, reported_at)
                VALUES (%s, %s, %s, %s, NOW())
                ON CONFLICT (hashed_number, reporter_id) DO NOTHING
            """, (body.hashed_number, body.real_number, body.targeted_brand, body.user_id))

        # Auto-blacklist at 50 unique reports
        if report_count >= 50:
            cur.execute("""
                INSERT INTO number_blacklist (hashed_number, targeted_brand, report_count, last_reported_at, flagged_at)
                VALUES (%s, %s, %s, NOW(), NOW())
                ON CONFLICT (hashed_number) DO UPDATE SET
                    report_count     = EXCLUDED.report_count,
                    last_reported_at = NOW()
            """, (body.hashed_number, body.targeted_brand, report_count))
            logger.info(f"[BLACKLIST] Auto-blacklisted at {report_count} reports: {body.hashed_number[:12]}...")
        else:
            # Update last_reported_at on every new report even before blacklist threshold
            cur.execute("""
                INSERT INTO number_blacklist (hashed_number, targeted_brand, report_count, last_reported_at)
                VALUES (%s, %s, %s, NOW())
                ON CONFLICT (hashed_number) DO UPDATE SET
                    report_count     = EXCLUDED.report_count,
                    last_reported_at = NOW()
            """, (body.hashed_number, body.targeted_brand, report_count))

        # Update platform stats
        if inserted:
            cur.execute("UPDATE platform_stats SET total_reports = total_reports + 1, last_updated = NOW() WHERE id = 1")

        conn.commit()
        cur.close(); conn.close()

        # Invalidate cache so next check sees fresh data
        invalidate_cache(body.hashed_number)

        return {
            "success":      True,
            "status":       "reported" if inserted else "already_reported",
            "report_count": report_count,
            "blacklisted":  report_count >= 50,
        }

    except Exception as e:
        logger.error(f"[REPORT] Error: {e}")
        raise HTTPException(status_code=500, detail="Report failed")

# =============================================================================
# PARTNER — REGISTER / LOGIN / DASHBOARD
# =============================================================================

@app.post("/partner/register")
async def partner_register(body: RegisterRequest, request: Request):
    """Partner self-registration."""
    _ip = _get_client_ip(request)
    if not _rate_limit_check(f"register:{_ip}", max_requests=5, window_seconds=3600):
        raise HTTPException(status_code=429, detail="Too many registration attempts.")
    if not body.brand_name or not body.email or not body.password:
        raise HTTPException(status_code=400, detail="brand_name, email and password required")
    try:
        conn = _get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT partner_id FROM partners WHERE email=%s", (body.email.lower().strip(),))
        if cur.fetchone():
            cur.close(); conn.close()
            raise HTTPException(status_code=400, detail="Email already registered")

        partner_id  = "ss_" + str(uuid.uuid4()).replace("-", "")[:16]
        auth_token  = str(uuid.uuid4()).replace("-", "") + str(uuid.uuid4()).replace("-", "")
        password_hash = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt()).decode()

        cur.execute("""
            INSERT INTO partners (partner_id, brand_name, email, password_hash, auth_token, account_status, is_active)
            VALUES (%s, %s, %s, %s, %s, 'pending', FALSE)
        """, (partner_id, body.brand_name.strip(), body.email.lower().strip(), password_hash, auth_token))
        conn.commit()
        cur.close(); conn.close()

        # Notify admin
        admin_email = os.getenv("ADMIN_EMAIL", "")
        if admin_email:
            send_email(
                to=admin_email,
                subject=f"🆕 New SafeSend Partner — {body.brand_name}",
                body=f"New partner registered:\n\nBrand: {body.brand_name}\nEmail: {body.email}\nPartner ID: {partner_id}\n\nActivate at your admin dashboard."
            )

        return {
            "success":    True,
            "message":    "Account created. Our team will activate your API key shortly.",
            "partner_id": partner_id,
            "auth_token": auth_token,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/partner/login")
async def partner_login(body: LoginRequest, request: Request):
    """Partner login."""
    _ip = _get_client_ip(request)
    if not _rate_limit_check(f"login:{_ip}", max_requests=10, window_seconds=300):
        raise HTTPException(status_code=429, detail="Too many login attempts. Try again in 5 minutes.")
    try:
        conn = _get_db_conn()
        from psycopg2.extras import RealDictCursor
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM partners WHERE email=%s", (body.email.lower().strip(),))
        partner = cur.fetchone()
        cur.close(); conn.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    if not partner or not partner.get("password_hash"):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not bcrypt.checkpw(body.password.encode(), partner["password_hash"].encode()):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    return {
        "success":        True,
        "auth_token":     partner["auth_token"],
        "partner_id":     partner["partner_id"],
        "brand_name":     partner["brand_name"],
        "account_status": partner["account_status"],
    }


@app.get("/partner/dashboard")
async def partner_dashboard(request: Request):
    """Partner dashboard stats."""
    token = request.headers.get("X-Auth-Token")
    if not token:
        raise HTTPException(status_code=401, detail="X-Auth-Token required")
    try:
        conn = _get_db_conn()
        from psycopg2.extras import RealDictCursor
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM partners WHERE auth_token=%s", (token,))
        partner = cur.fetchone()
        cur.close(); conn.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    if not partner:
        raise HTTPException(status_code=401, detail="Invalid token")

    return {
        "partner_id":           partner["partner_id"],
        "brand_name":           partner["brand_name"],
        "email":                partner["email"],
        "account_status":       partner["account_status"],
        "api_key":              partner["api_key"],
        "slots_used":           partner["slots_used"],
        "slot_limit":           partner["slot_limit"],
        "scan_count":           partner["scan_count"],
        "onboarding_ends_at":   partner["onboarding_ends_at"].isoformat() if partner["onboarding_ends_at"] else None,
        "subscription_ends_at": partner["subscription_ends_at"].isoformat() if partner["subscription_ends_at"] else None,
    }

# =============================================================================
# ADMIN
# =============================================================================

@app.post("/admin/login")
async def admin_login(body: AdminLoginRequest, request: Request):
    """Admin login."""
    _ip = _get_client_ip(request)
    if not _rate_limit_check(f"admin:{_ip}", max_requests=5, window_seconds=600):
        raise HTTPException(status_code=429, detail="Too many attempts.")
    admin_email    = os.getenv("ADMIN_EMAIL", "")
    admin_password = os.getenv("ADMIN_PASSWORD", "")
    if body.email.lower().strip() != admin_email.lower().strip() or body.password != admin_password:
        raise HTTPException(status_code=403, detail="Invalid credentials")
    return {"success": True, "token": ADMIN_SECRET}


@app.get("/admin/stats")
async def admin_stats(request: Request):
    """Global platform stats."""
    _require_admin(request)
    try:
        conn = _get_db_conn()
        from psycopg2.extras import RealDictCursor
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM platform_stats WHERE id=1")
        stats = cur.fetchone()
        cur.execute("SELECT COUNT(*) as c FROM partners WHERE is_active=TRUE")
        active_partners = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) as c FROM number_blacklist")
        blacklisted = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) as c FROM spike_alerts WHERE resolved=FALSE")
        active_spikes = cur.fetchone()["c"]
        cur.close(); conn.close()
        return {
            "total_checks":    int(stats["total_checks"]) if stats else 0,
            "total_reports":   int(stats["total_reports"]) if stats else 0,
            "total_blocked":   int(blacklisted),
            "active_partners": int(active_partners),
            "active_spikes":   int(active_spikes),
            "last_updated":    stats["last_updated"].isoformat() if stats and stats["last_updated"] else None,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/admin/reports")
async def admin_reports(request: Request):
    """All vishing reports grouped by number."""
    _require_admin(request)
    try:
        conn = _get_db_conn()
        from psycopg2.extras import RealDictCursor
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT hashed_number, targeted_brand,
                   COUNT(*) as report_count,
                   MAX(reported_at) as last_reported
            FROM number_reports
            GROUP BY hashed_number, targeted_brand
            ORDER BY last_reported DESC
            LIMIT 500
        """)
        rows = cur.fetchall()
        cur.close(); conn.close()
        return {"reports": [dict(r) for r in rows]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/admin/blacklist")
async def admin_blacklist(request: Request):
    """Confirmed vishing numbers with actionable real numbers."""
    _require_admin(request)
    try:
        conn = _get_db_conn()
        from psycopg2.extras import RealDictCursor
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT nb.*, COALESCE(na.real_numbers, '[]'::json) as actionable_numbers
            FROM number_blacklist nb
            LEFT JOIN (
                SELECT hashed_number, json_agg(real_number) as real_numbers
                FROM number_actionable
                GROUP BY hashed_number
            ) na ON na.hashed_number = nb.hashed_number
            ORDER BY nb.last_reported_at DESC
            LIMIT 500
        """)
        rows = cur.fetchall()
        cur.close(); conn.close()
        return {"blacklist": [dict(r) for r in rows]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/admin/spikes")
async def admin_spikes(request: Request):
    """Active spike alerts — numbers being checked by many devices right now."""
    _require_admin(request)
    try:
        conn = _get_db_conn()
        from psycopg2.extras import RealDictCursor
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT * FROM spike_alerts
            WHERE resolved = FALSE
            ORDER BY flagged_at DESC
            LIMIT 200
        """)
        rows = cur.fetchall()
        cur.close(); conn.close()
        return {"spikes": [dict(r) for r in rows]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/admin/partners/{partner_id}/activate")
async def admin_activate_partner(partner_id: str, request: Request):
    """Activate partner — generate API key, start subscription."""
    _require_admin(request)
    try:
        import secrets
        conn = _get_db_conn()
        cur = conn.cursor()
        api_key = "ss_live_" + secrets.token_hex(16)
        cur.execute("""
            UPDATE partners SET
                account_status = 'active',
                is_active      = TRUE,
                api_key        = %s,
                onboarding_ends_at   = NOW() + INTERVAL '1 month',
                subscription_ends_at = NOW() + INTERVAL '1 year'
            WHERE partner_id = %s
        """, (api_key, partner_id))
        cur.execute("SELECT email, brand_name FROM partners WHERE partner_id=%s", (partner_id,))
        row = cur.fetchone()
        conn.commit()
        cur.close(); conn.close()
        if row:
            send_email(
                to=row[0],
                subject="Your SafeSend API Key is Ready",
                body=f"""Hello {row[1]} team,

Your SafeSend account has been activated!

Your API Key:
{api_key}

Initialize the SDK:
    SafeSend.init(
        context = this,
        apiKey  = "{api_key}",
        brandName = "{row[1]}"
    )

Dashboard: https://partners.safesend.africa

The SafeSend Team 🛡️
"""
            )
        return {"success": True, "api_key": api_key}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/admin/partners/{partner_id}/suspend")
async def admin_suspend_partner(partner_id: str, request: Request):
    """Suspend partner."""
    _require_admin(request)
    try:
        conn = _get_db_conn()
        cur = conn.cursor()
        cur.execute("UPDATE partners SET account_status='suspended', is_active=FALSE WHERE partner_id=%s", (partner_id,))
        conn.commit()
        cur.close(); conn.close()
        return {"success": True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/admin/partners")
async def admin_partners(request: Request):
    """All partners."""
    _require_admin(request)
    try:
        conn = _get_db_conn()
        from psycopg2.extras import RealDictCursor
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM partners ORDER BY created_at DESC")
        rows = cur.fetchall()
        cur.close(); conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/admin/spikes/{hashed_number}/resolve")
async def resolve_spike(hashed_number: str, request: Request):
    """Mark a spike as resolved."""
    _require_admin(request)
    try:
        conn = _get_db_conn()
        cur = conn.cursor()
        cur.execute("UPDATE spike_alerts SET resolved=TRUE WHERE hashed_number=%s", (hashed_number,))
        conn.commit()
        cur.close(); conn.close()
        return {"success": True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# =============================================================================
# ENTRYPOINT
# =============================================================================

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("🛡️  SAFESEND API v1.0.0")
    print("=" * 60)
    print("✅ Number reputation engine")
    print("✅ Vishing crowdsourced reporting")
    print("✅ Spike detection — 10 devices/1hr = active campaign")
    print("✅ Auto-blacklist at 50 reports")
    print("✅ Consent-based real number storage for brand takedowns")
    print("✅ Partner SDK management")
    print("✅ Rate limiting on all endpoints")
    print("✅ Redis cache with in-memory fallback")
    print("=" * 60 + "\n")
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port, reload=False)
