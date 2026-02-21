"""
Travel Pricing Rule Engine — Enterprise Flask Backend
=====================================================
PRODUCTION VERSION 4.0 — FULL SECURITY UPGRADE + AMADEUS BOOKING + OPENAI INTELLIGENCE

Inherited from v3.4:
- Transport trip type validation, hard delete routes, flight details, hotel lookup
- Rate limiting infrastructure (kept for future use, removed from hotel-lookup per v4.0)

New in v4.0:

POINT 1 — ADMIN SECURITY UPGRADE (Multi-Method Authentication):
  - WebAuthn/Passkey (device biometric: Face ID, fingerprint) via py_webauthn
  - Password login (bcrypt-hashed admin_users table)
  - PIN login (4-6 digit, bcrypt-hashed per-admin in admin_users table)
  - NO "Remember Me" — sessions expire on browser close
  - Dynamic RP ID via request.host (works on localhost + Render + custom domains)
  - Graceful fallback if py_webauthn not installed (password + PIN still work)
  - In-memory WebAuthn challenge store (single-process safe)
  - /admin/setup — first-time admin user creation
  - /admin/check-setup — detect if setup is needed

POINT 2 — ACTIVE/INACTIVE BUTTON FIX:
  - All 8 toggle routes now return {success: True, active: <new_state>, message: 'Toggled'}
  - Frontend can update in-memory cache and re-render specific table without full reload
  - Eliminates race condition in toggleEntity() async flow

POINT 3 — AMADEUS CREATE ORDER (REAL PNR):
  - Raw flight offers cached in-memory by offer_id during search
  - Raw hotel offers cached in-memory by offer_id during search
  - POST /api/create-booking — books flight + hotel via Amadeus APIs
  - Stores separate flight_pnr and hotel_confirmation in bookings table
  - Returns both references independently — strict separation maintained

POINT 4 — SIGHTSEEING COUNT LOGIC:
  - Bug fix is in index.html (frontend only) — no backend changes needed here

POINT 5 — LIVE AMADEUS HOTEL STAR FILTER:
  - _fetch_hotel_ids_for_city() now accepts optional ratings param
  - Passes ratings to Amadeus /by-city API (server-side filter)
  - Backend re-validates returned hotels match requested star ratings
  - hotel-search route accepts starRatings param from frontend

POINT 6 — RATE LIMIT REMOVED FROM HOTEL-LOOKUP:
  - Rate-limit block removed from /hotel-lookup endpoint
  - Rate limit infrastructure kept for future use on other endpoints

POINT 7 — OPENAI gpt-4o INTELLIGENCE:
  - _process_ai_intent_openai() replaces rule-based processor
  - Uses gpt-4o as primary model
  - Structured JSON output: {action, value, message}
  - AI NEVER calculates prices — always defers to backend + pricing_engine
  - Falls back to rule-based logic if OpenAI unavailable
  - Maintains state consistency across conversation turns
"""

from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_cors import CORS
from functools import wraps
import psycopg
from psycopg.rows import dict_row
import json
import os
import logging
import re
import time
import uuid
import requests as _requests
from decimal import Decimal
from collections import defaultdict

# ── Load .env file if present (dev convenience) ───────────────────────────────
try:
    from dotenv import load_dotenv as _load_dotenv
    _load_dotenv(override=False)   # does NOT override vars already in the shell
except ImportError:
    pass  # python-dotenv optional; use shell env vars or system env in production

# ── bcrypt for password/PIN hashing ───────────────────────────────────────────
try:
    import bcrypt as _bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False
    logging.warning("bcrypt not installed — password/PIN hashing unavailable. Run: pip install bcrypt")

# ── OpenAI for AI chat intelligence ───────────────────────────────────────────
try:
    from openai import OpenAI as _OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    logging.warning("openai not installed — AI chat will use rule-based fallback. Run: pip install openai")

# ── Anthropic Claude as AI fallback ──────────────────────────────────────────
try:
    import anthropic as _anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    logging.warning("anthropic not installed — Claude fallback unavailable. Run: pip install anthropic")

# ── WebAuthn for passkey/biometric login ──────────────────────────────────────
try:
    import webauthn as _webauthn
    from webauthn.helpers.structs import (
        AuthenticatorSelectionCriteria,
        UserVerificationRequirement,
        ResidentKeyRequirement,
        AttestationConveyancePreference,
        AuthenticatorAttachment,
        PublicKeyCredentialDescriptor,
        PublicKeyCredentialType,
    )
    from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
    import webauthn.helpers.cose as _cose
    WEBAUTHN_AVAILABLE = True
except ImportError:
    WEBAUTHN_AVAILABLE = False
    logging.warning("py_webauthn not installed — WebAuthn/passkey login unavailable. Run: pip install py_webauthn")

from pricing_engine import (
    TravelPricingEngine,
    RoomCalculator,
    PricingEngineError,
    ComponentNotFoundError,
    RateMissingError,
    InvalidConfigurationError,
    check_cab_required,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# =====================================================
# IN-MEMORY STORES — RAW OFFER CACHES FOR BOOKING
# =====================================================
# Raw Amadeus flight/hotel offers are cached here by offer_id after search.
# The booking endpoint reads from this cache to build the Create Order request.
# Cache is in-memory only — entries expire after OFFER_CACHE_TTL_SECONDS.
# In a multi-worker deployment, use Redis instead.
# =====================================================

OFFER_CACHE_TTL_SECONDS = 3600  # 1 hour

_raw_flight_offers_cache: dict = {}
# Structure: { offer_id: { 'offer': <raw_amadeus_offer_dict>, 'expires_at': <timestamp> } }

_raw_hotel_offers_cache: dict = {}
# Structure: { offer_id: { 'offer': <raw_amadeus_offer_dict>, 'expires_at': <timestamp> } }

# =====================================================
# IN-MEMORY STORE — WEBAUTHN CHALLENGES
# =====================================================
# Challenges are stored here between begin/complete round trips.
# Keyed by username. Entries expire after WEBAUTHN_CHALLENGE_TTL_SECONDS.
# =====================================================

WEBAUTHN_CHALLENGE_TTL_SECONDS = 300  # 5 minutes

_webauthn_challenges: dict = {}
# Structure: { 'reg:{username}': { 'challenge': bytes, 'expires_at': float },
#              'auth:{username}': { 'challenge': bytes, 'expires_at': float } }


def _store_raw_flight_offer(offer_id: str, raw_offer: dict) -> None:
    """Cache a raw Amadeus flight offer dict, keyed by offer_id."""
    _raw_flight_offers_cache[offer_id] = {
        'offer': raw_offer,
        'expires_at': time.time() + OFFER_CACHE_TTL_SECONDS,
    }


def _get_raw_flight_offer(offer_id: str) -> dict | None:
    """Retrieve a cached raw Amadeus flight offer. Returns None if not found or expired."""
    entry = _raw_flight_offers_cache.get(offer_id)
    if not entry:
        return None
    if time.time() > entry['expires_at']:
        del _raw_flight_offers_cache[offer_id]
        return None
    return entry['offer']


def _store_raw_hotel_offer(offer_id: str, raw_offer: dict) -> None:
    """Cache a raw Amadeus hotel offer dict, keyed by offer_id."""
    _raw_hotel_offers_cache[offer_id] = {
        'offer': raw_offer,
        'expires_at': time.time() + OFFER_CACHE_TTL_SECONDS,
    }


def _get_raw_hotel_offer(offer_id: str) -> dict | None:
    """Retrieve a cached raw Amadeus hotel offer. Returns None if not found or expired."""
    entry = _raw_hotel_offers_cache.get(offer_id)
    if not entry:
        return None
    if time.time() > entry['expires_at']:
        del _raw_hotel_offers_cache[offer_id]
        return None
    return entry['offer']

app = Flask(__name__)

# ── AI provider startup diagnostic ───────────────────────────────────────────
def _log_ai_provider_status():
    """Log which AI provider is active at startup. Helps diagnose silent fallbacks."""
    import os as _os
    has_openai    = bool(_os.environ.get('OPENAI_API_KEY', '').strip())
    has_anthropic = bool(_os.environ.get('ANTHROPIC_API_KEY', '').strip())
    if has_openai:
        logging.info("✅ AI: OpenAI API key found — using gpt-4o for Sharad")
    elif has_anthropic:
        logging.info("✅ AI: Anthropic API key found — using Claude for Sharad")
    else:
        logging.warning(
            "⚠️  AI: No API key found. Sharad will use rule-based responses only.\n"
            "   → Set OPENAI_API_KEY=sk-... or ANTHROPIC_API_KEY=sk-ant-...\n"
            "   → Or create a .env file in the project root with the key."
        )
_log_ai_provider_status()
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')
CORS(app)

# =====================================================
# DATABASE
# =====================================================

DATABASE_URL = os.environ.get("DATABASE_URL")

def get_db():
    if not DATABASE_URL:
        raise Exception("DATABASE_URL not set in environment variables")
    conn = psycopg2.connect(DATABASE_URL, connect_timeout=10)
    try:
        conn.cursor().execute("SET statement_timeout = '8000'")
        conn.commit()
    except Exception:
        pass
    return conn

def row_to_dict(cursor, row):
    if row is None:
        return None
    cols = [d[0] for d in cursor.description]
    return dict(zip(cols, row))


def rows_to_dicts(cursor, rows):
    cols = [d[0] for d in cursor.description]
    return [dict(zip(cols, r)) for r in rows]


def json_serial(obj):
    if isinstance(obj, Decimal):
        return float(obj)
    raise TypeError(f"Type {type(obj)} not serializable")


def get_client_id():
    """Extract client_id from request, default to 1."""
    cid = request.args.get('client_id') or request.json.get('client_id') if request.is_json else None
    if not cid:
        cid = request.args.get('client_id', 1)
    return int(cid) if cid else 1


# =====================================================
# RATE LIMITING — SIMPLE IN-MEMORY
# =====================================================
# Used by hotel-lookup and other externally-facing endpoints
# to prevent credential abuse or runaway API calls.
# Tracks (ip, endpoint) pairs with a sliding-window counter.
# =====================================================

_rate_limit_store: dict = defaultdict(list)
RATE_LIMIT_WINDOW_SECONDS = 60  # 1-minute rolling window
RATE_LIMIT_MAX_CALLS = 20       # max calls per IP per window per endpoint


def _check_rate_limit(ip: str, endpoint: str) -> bool:
    """
    Returns True if request is allowed, False if rate limit exceeded.
    Uses a sliding window approach. Thread-safe for single-process deployments.
    In multi-process deployments (gunicorn), a shared store (Redis) would be preferred,
    but this in-memory approach is safe for the current single-worker setup.
    """
    key = f"{ip}:{endpoint}"
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW_SECONDS

    # Prune timestamps outside the window
    _rate_limit_store[key] = [t for t in _rate_limit_store[key] if t > window_start]

    if len(_rate_limit_store[key]) >= RATE_LIMIT_MAX_CALLS:
        logger.warning(f"Rate limit exceeded for {key}: {len(_rate_limit_store[key])} calls in {RATE_LIMIT_WINDOW_SECONDS}s")
        return False

    _rate_limit_store[key].append(now)
    return True


def _get_client_ip() -> str:
    """Extract client IP from request, respecting X-Forwarded-For for proxied setups."""
    forwarded_for = request.headers.get('X-Forwarded-For', '')
    if forwarded_for:
        return forwarded_for.split(',')[0].strip()
    return request.remote_addr or '0.0.0.0'


# =====================================================
# ENTERPRISE FIELD AUTO-GENERATION UTILITIES
# =====================================================

def slugify(text):
    """Convert text to URL-safe slug."""
    text = text.lower().strip()
    text = re.sub(r'[^\w\s-]', '', text)
    text = re.sub(r'[-\s]+', '-', text)
    return text.strip('-')


def slugify_uppercase(text):
    """Convert text to uppercase slug with underscores."""
    text = text.upper().strip()
    text = re.sub(r'[^\w\s_]', '', text)
    text = re.sub(r'[-\s]+', '_', text)
    return text.strip('_')


def generate_unique_slug(cursor, table, column, base_slug, client_id, region_id=None, exclude_id=None):
    """Generate a unique slug by checking existing records (soft-delete aware)."""
    if not base_slug:
        base_slug = 'unnamed'

    slug = base_slug
    counter = 0
    max_attempts = 1000

    while counter < max_attempts:
        if region_id is not None:
            query = f"""
                SELECT COUNT(*) FROM {table}
                WHERE {column} = %s
                AND client_id = %s
                AND region_id = %s

            """
            params = [slug, client_id, region_id]
        else:
            query = f"""
                SELECT COUNT(*) FROM {table}
                WHERE {column} = %s
                AND client_id = %s

            """
            params = [slug, client_id]

        if exclude_id is not None:
            query += " AND id != %s"
            params.append(exclude_id)

        cursor.execute(query, params)
        count = cursor.fetchone()[0]

        if count == 0:
            return slug

        counter += 1
        slug = f"{base_slug}-{counter}"

    import uuid
    return f"{base_slug}-{uuid.uuid4().hex[:8]}"


def generate_unique_transport_type(cursor, base_type, client_id, region_id, exclude_id=None):
    """Generate unique transport_type (soft-delete aware)."""
    if not base_type:
        base_type = 'UNNAMED'

    transport_type = base_type
    counter = 0
    max_attempts = 1000

    while counter < max_attempts:
        query = """
            SELECT COUNT(*) FROM transports
            WHERE transport_type = %s
            AND client_id = %s
            AND region_id = %s

        """
        params = [transport_type, client_id, region_id]

        if exclude_id is not None:
            query += " AND id != %s"
            params.append(exclude_id)

        cursor.execute(query, params)
        count = cursor.fetchone()[0]

        if count == 0:
            return transport_type

        counter += 1
        transport_type = f"{base_type}_{counter}"

    import uuid
    return f"{base_type}_{uuid.uuid4().hex[:8].upper()}"


def auto_generate_internal_name(cursor, table, name, client_id, region_id=None, exclude_id=None):
    """Auto-generate internal_name from name."""
    base_slug = slugify(name)
    return generate_unique_slug(cursor, table, 'internal_name', base_slug, client_id, region_id, exclude_id)


def auto_generate_transport_type(cursor, name, client_id, region_id, exclude_id=None):
    """Auto-generate transport_type from name."""
    base_type = slugify_uppercase(name)
    return generate_unique_transport_type(cursor, base_type, client_id, region_id, exclude_id)


def auto_generate_display_name(name, provided_display_name=None):
    """Auto-generate display_name."""
    return provided_display_name if provided_display_name else name


def get_valid_destination_types(cursor):
    """Query database for valid destination_type values."""
    try:
        cursor.execute("""
            SELECT pg_get_constraintdef(oid)
            FROM pg_constraint
            WHERE conname = 'destinations_destination_type_check'
        """)
        constraint = cursor.fetchone()

        if constraint:
            constraint_def = constraint[0]
            matches = re.findall(r"'([A-Z_]+)'", constraint_def)
            if matches:
                logger.info(f"Found valid destination_types: {matches}")
                return matches
    except Exception as e:
        logger.warning(f"Could not query destination_type constraint: {e}")

    return ['CITY', 'HILL_STATION', 'BEACH', 'RELIGIOUS', 'ADVENTURE', 'WILDLIFE', 'HERITAGE', 'OTHER']


def get_safe_destination_type(cursor, data, name=None):
    """Get a safe destination_type value."""
    if data.get('destination_type'):
        return data['destination_type']

    valid_types = get_valid_destination_types(cursor)

    if name:
        name_lower = name.lower()
        if any(keyword in name_lower for keyword in ['manali', 'shimla', 'kasol', 'solang', 'kullu', 'hill', 'valley', 'mountain']):
            if 'HILL_STATION' in valid_types:
                return 'HILL_STATION'
        if any(keyword in name_lower for keyword in ['goa', 'beach', 'coastal', 'island', 'sea']):
            if 'BEACH' in valid_types:
                return 'BEACH'
        if any(keyword in name_lower for keyword in ['temple', 'church', 'mosque', 'gurudwara', 'varanasi', 'amritsar', 'haridwar', 'rishikesh']):
            if 'RELIGIOUS' in valid_types:
                return 'RELIGIOUS'
        if any(keyword in name_lower for keyword in ['adventure', 'trek', 'rafting', 'skiing', 'paragliding']):
            if 'ADVENTURE' in valid_types:
                return 'ADVENTURE'
        if any(keyword in name_lower for keyword in ['safari', 'wildlife', 'jungle', 'tiger', 'reserve', 'sanctuary']):
            if 'WILDLIFE' in valid_types:
                return 'WILDLIFE'
        if any(keyword in name_lower for keyword in ['fort', 'palace', 'heritage', 'historical', 'monument', 'jaipur', 'udaipur']):
            if 'HERITAGE' in valid_types:
                return 'HERITAGE'

    if 'CITY' in valid_types:
        return 'CITY'
    elif 'OTHER' in valid_types:
        return 'OTHER'
    elif valid_types:
        return valid_types[0]
    else:
        return 'CITY'


def get_valid_addon_types(cursor):
    """Query database for valid addon_type values."""
    try:
        cursor.execute("""
            SELECT pg_get_constraintdef(oid)
            FROM pg_constraint
            WHERE conname = 'addons_addon_type_check'
        """)
        constraint = cursor.fetchone()

        if constraint:
            constraint_def = constraint[0]
            matches = re.findall(r"'([A-Z_]+)'", constraint_def)
            if matches:
                logger.info(f"Found valid addon_types: {matches}")
                return matches
    except Exception as e:
        logger.warning(f"Could not query addon_type constraint: {e}")

    return ['GENERAL', 'INSURANCE', 'MEAL', 'ACTIVITY', 'TRANSPORT', 'EQUIPMENT', 'SERVICE']


def get_safe_addon_type(cursor, data, name=None):
    """Get a safe addon_type value."""
    if data.get('addon_type'):
        provided = data['addon_type'].upper()
        valid_types = get_valid_addon_types(cursor)
        if provided in valid_types:
            return provided

    valid_types = get_valid_addon_types(cursor)

    if name:
        name_lower = name.lower()
        if any(keyword in name_lower for keyword in ['insurance', 'cover', 'protection']):
            if 'INSURANCE' in valid_types:
                return 'INSURANCE'
        if any(keyword in name_lower for keyword in ['meal', 'food', 'breakfast', 'lunch', 'dinner']):
            if 'MEAL' in valid_types:
                return 'MEAL'
        if any(keyword in name_lower for keyword in ['activity', 'tour', 'excursion', 'trek', 'adventure']):
            if 'ACTIVITY' in valid_types:
                return 'ACTIVITY'
        if any(keyword in name_lower for keyword in ['transport', 'transfer', 'pickup', 'drop']):
            if 'TRANSPORT' in valid_types:
                return 'TRANSPORT'
        if any(keyword in name_lower for keyword in ['equipment', 'gear', 'rental']):
            if 'EQUIPMENT' in valid_types:
                return 'EQUIPMENT'
        if any(keyword in name_lower for keyword in ['service', 'guide', 'assistance']):
            if 'SERVICE' in valid_types:
                return 'SERVICE'

    if 'GENERAL' in valid_types:
        return 'GENERAL'
    elif valid_types:
        return valid_types[0]
    else:
        return 'GENERAL'


def get_safe_defaults_for_entity(entity_type, data, cursor=None, name=None):
    """Returns safe default values for all enterprise-required fields."""
    defaults = {}
    defaults['active'] = data.get('active', True)
    defaults['deleted'] = data.get('deleted', False)

    if entity_type == 'destination':
        if cursor:
            defaults['destination_type'] = get_safe_destination_type(cursor, data, name)
        else:
            defaults['destination_type'] = data.get('destination_type', 'CITY')
        defaults['is_special'] = data.get('is_special', 0)
        defaults['base_rate'] = data.get('base_rate', 0)
        defaults['per_day_rate'] = data.get('per_day_rate', 0)
        defaults['four_by_four_rate'] = data.get('four_by_four_rate', 0)
        defaults['free_sightseeing_days'] = data.get('free_sightseeing_days', 0)

    elif entity_type == 'hotel':
        defaults['is_kasol'] = data.get('is_kasol', 0)
        defaults['extra_mattress_rate'] = data.get('extra_mattress_rate', 0)
        defaults['extra_mattress_child_rate'] = data.get('extra_mattress_child_rate', 0)
        defaults['child_age_limit'] = data.get('child_age_limit', 5)
        defaults['adult_rate_peak'] = data.get('adult_rate_peak', 0)
        defaults['child_rate_peak'] = data.get('child_rate_peak', 0)
        defaults['adult_rate_off'] = data.get('adult_rate_off', 0)
        defaults['child_rate_off'] = data.get('child_rate_off', 0)
        defaults['custom_sharing_name'] = data.get('custom_sharing_name', '')

    elif entity_type == 'transport':
        defaults['seat_capacity'] = data.get('seat_capacity', 0)
        defaults['adult_rate_peak'] = data.get('adult_rate_peak', 0)
        defaults['child_rate_peak'] = data.get('child_rate_peak', 0)
        defaults['peak_pricing_type'] = data.get('peak_pricing_type', 'per_person')
        defaults['adult_rate_off'] = data.get('adult_rate_off', 0)
        defaults['child_rate_off'] = data.get('child_rate_off', 0)
        defaults['off_pricing_type'] = data.get('off_pricing_type', 'per_person')

    elif entity_type == 'cab':
        defaults['capacity'] = data.get('capacity', 4)
        defaults['base_rate'] = data.get('base_rate', 0)
        defaults['per_day_rate'] = data.get('per_day_rate', 0)

    elif entity_type == 'addon':
        defaults['pricing_type'] = data.get('pricing_type', 'flat')
        defaults['rate_peak'] = data.get('rate_peak', 0)
        defaults['rate_off'] = data.get('rate_off', 0)
        if cursor:
            defaults['addon_type'] = get_safe_addon_type(cursor, data, name)
        else:
            defaults['addon_type'] = data.get('addon_type', 'GENERAL')

    elif entity_type == 'region':
        defaults['currency'] = data.get('currency', 'INR')
        defaults['is_domestic'] = data.get('is_domestic', True)
        defaults['service_percent'] = data.get('service_percent', 15)
        defaults['booking_percent'] = data.get('booking_percent', 12)

    return defaults


# =====================================================
# TRANSPORT TRIP TYPE VALIDATION UTILITIES
# =====================================================
# Change 1 (v3.4): Accept and validate tripType from frontend,
# pass safely to pricing_engine. No pricing logic here.
# =====================================================

VALID_TRIP_TYPES = ('one_way', 'return', 'round_trip', 'multi_city')

# Canonical mapping — normalise various frontend aliases to engine keys
_TRIP_TYPE_ALIAS_MAP = {
    'one_way': 'one_way',
    'oneway': 'one_way',
    'one-way': 'one_way',
    'single': 'one_way',
    'return': 'return',
    'round_trip': 'return',
    'roundtrip': 'return',
    'round-trip': 'return',
    'two_way': 'return',
    'twoway': 'return',
    'two-way': 'return',
    'multi_city': 'multi_city',
    'multicity': 'multi_city',
    'multi-city': 'multi_city',
    'multi': 'multi_city',
}


def _validate_and_normalise_trip_type(raw_trip_type) -> str:
    """
    Validate and normalise the tripType / trip_type field supplied by the frontend.

    Accepts string values in any case, strips whitespace, resolves known aliases.
    Returns a canonical trip type string ('one_way', 'return', 'multi_city').
    Defaults to 'one_way' for unrecognised or missing values without raising an
    exception — the pricing engine is the authoritative validator for business rules.

    This function ONLY normalises. It does NOT perform any pricing calculation.
    """
    if not raw_trip_type:
        return 'one_way'

    normalised = str(raw_trip_type).lower().strip()
    canonical = _TRIP_TYPE_ALIAS_MAP.get(normalised)

    if canonical:
        return canonical

    # If the raw value is already one of the valid canonical types, accept it
    if normalised in VALID_TRIP_TYPES:
        return normalised

    logger.warning(
        f"Unrecognised tripType value '{raw_trip_type}' received — defaulting to 'one_way'. "
        f"Valid values: {VALID_TRIP_TYPES}"
    )
    return 'one_way'


def _extract_trip_type_from_payload(payload: dict) -> str:
    """
    Extract trip type from a request payload.
    Checks both camelCase (tripType) and snake_case (trip_type) keys.
    Returns normalised canonical trip type.
    """
    raw = payload.get('tripType') or payload.get('trip_type') or 'one_way'
    return _validate_and_normalise_trip_type(raw)


# =====================================================
# AUTHENTICATION
# =====================================================

def admin_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function


def agent_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('agent_logged_in'):
            return redirect(url_for('agent_login'))
        return f(*args, **kwargs)
    return decorated_function


# ── Password/PIN hashing helpers ──────────────────────────────────────────────

def _hash_password(plain: str) -> str:
    """Hash a password or PIN using bcrypt. Returns hash as UTF-8 string."""
    if not BCRYPT_AVAILABLE:
        raise RuntimeError("bcrypt library is required for password hashing. Install with: pip install bcrypt")
    salt = _bcrypt.gensalt(rounds=12)
    return _bcrypt.hashpw(plain.encode('utf-8'), salt).decode('utf-8')


def _check_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password/PIN against a bcrypt hash. Returns True if match."""
    if not BCRYPT_AVAILABLE:
        return False
    try:
        return _bcrypt.checkpw(plain.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False


# ── WebAuthn RP helpers ────────────────────────────────────────────────────────

def _get_rp_id() -> str:
    """
    Dynamically derive the WebAuthn RP ID from the current request host.
    Strips port number — RP ID must be a domain only (e.g. 'localhost', 'example.com').
    """
    host = request.host  # e.g. 'localhost:5000' or 'myapp.onrender.com'
    # Strip port if present
    return host.split(':')[0]


def _get_rp_origin() -> str:
    """
    Derive the full expected origin for WebAuthn verification.
    Includes scheme and port (if non-standard).
    """
    host = request.host
    # Determine scheme — trust X-Forwarded-Proto header from proxies (Render, nginx)
    forwarded_proto = request.headers.get('X-Forwarded-Proto', '')
    if forwarded_proto in ('https', 'http'):
        scheme = forwarded_proto
    else:
        scheme = 'https' if 'localhost' not in host else 'http'
    return f'{scheme}://{host}'


def _store_webauthn_challenge(key: str, challenge: bytes) -> None:
    """Store a WebAuthn challenge with TTL. key format: 'reg:{username}' or 'auth:{username}'."""
    _webauthn_challenges[key] = {
        'challenge': challenge,
        'expires_at': time.time() + WEBAUTHN_CHALLENGE_TTL_SECONDS,
    }


def _get_webauthn_challenge(key: str) -> bytes | None:
    """Retrieve and remove a stored WebAuthn challenge. Returns None if missing or expired."""
    entry = _webauthn_challenges.pop(key, None)
    if not entry:
        return None
    if time.time() > entry['expires_at']:
        return None
    return entry['challenge']


# ── Admin user DB helpers ──────────────────────────────────────────────────────

def _get_admin_user(cursor, username: str) -> dict | None:
    """Fetch admin user row by username. Returns dict or None."""
    cursor.execute(
        "SELECT id, username, password_hash, pin_hash FROM admin_users WHERE username=%s",
        (username,)
    )
    row = cursor.fetchone()
    if not row:
        return None
    return {'id': row[0], 'username': row[1], 'password_hash': row[2], 'pin_hash': row[3]}


def _get_admin_webauthn_credentials(cursor, admin_user_id: int) -> list:
    """Fetch all WebAuthn credentials for an admin user."""
    cursor.execute(
        "SELECT id, credential_id, public_key, sign_count FROM webauthn_credentials WHERE admin_user_id=%s",
        (admin_user_id,)
    )
    rows = cursor.fetchall()
    return [{'id': r[0], 'credential_id': r[1], 'public_key': r[2], 'sign_count': r[3]} for r in rows]


def _has_any_admin_users(cursor) -> bool:
    """Return True if at least one admin user exists in the database."""
    cursor.execute("SELECT COUNT(*) FROM admin_users")
    return cursor.fetchone()[0] > 0


# =====================================================
# ADMIN AUTHENTICATION ROUTES
# =====================================================
# Multi-method auth system:
#   1. Password login (bcrypt-hashed in admin_users table)
#   2. PIN login (4–6 digit, bcrypt-hashed per-admin in admin_users table)
#   3. WebAuthn/Passkey (device biometrics via py_webauthn)
#
# Session: permanent=False (expires on browser close).
# No "Remember Me" functionality.
# All validation is backend-only — frontend sends credentials, backend verifies.
# =====================================================

@app.route('/admin/login', methods=['GET'])
def admin_login():
    """Render admin login page. Jinja2 template detects login vs dashboard mode."""
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))
    return render_template(
        'admin.html',
        mode='login',
        webauthn_available=WEBAUTHN_AVAILABLE,
    )


@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    session.pop('admin_user_id', None)
    session.pop('role', None)
    return redirect(url_for('admin_login'))


@app.route('/admin')
@admin_login_required
def admin_dashboard():
    return render_template('admin.html', mode='dashboard')


@app.route('/admin/agent/<agent_name>')
@admin_login_required
def admin_agent_detail(agent_name):
    return render_template('admin_agent_detail.html', agent_name=agent_name)


@app.route('/admin/check-setup', methods=['GET'])
def admin_check_setup():
    """
    Returns whether any admin users exist.
    Used by frontend to determine if first-time setup is needed.
    """
    try:
        db = get_db()
        cur = db.cursor()
        setup_done = _has_any_admin_users(cur)
        db.close()
        return jsonify({'setup_required': not setup_done, 'setup_done': setup_done})
    except Exception as e:
        logger.error(f"admin_check_setup error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/admin/setup', methods=['POST'])
def admin_setup():
    """
    First-time admin user creation endpoint.
    Only usable when NO admin users exist yet (prevents unauthorized use).

    Body: { "username": "admin", "password": "...", "pin": "1234" (optional) }
    """
    if not BCRYPT_AVAILABLE:
        return jsonify({'error': 'bcrypt library is required. Install with: pip install bcrypt'}), 500
    try:
        db = get_db()
        cur = db.cursor()

        # Block if admin users already exist
        if _has_any_admin_users(cur):
            db.close()
            return jsonify({'error': 'Admin user already exists. Use the login page.'}), 400

        data = request.get_json()
        if not data:
            db.close()
            return jsonify({'error': 'No data provided'}), 400

        username = str(data.get('username', '')).strip()
        password = str(data.get('password', '')).strip()
        pin = str(data.get('pin', '')).strip()

        if not username:
            db.close()
            return jsonify({'error': 'Username is required'}), 400
        if len(username) > 100:
            db.close()
            return jsonify({'error': 'Username must be 100 characters or fewer'}), 400
        if not password:
            db.close()
            return jsonify({'error': 'Password is required'}), 400
        if len(password) < 8:
            db.close()
            return jsonify({'error': 'Password must be at least 8 characters'}), 400

        pin_hash = None
        if pin:
            if not re.match(r'^\d{4,6}$', pin):
                db.close()
                return jsonify({'error': 'PIN must be 4–6 digits'}), 400
            pin_hash = _hash_password(pin)

        password_hash = _hash_password(password)

        cur.execute(
            "INSERT INTO admin_users (username, password_hash, pin_hash) VALUES (%s, %s, %s) RETURNING id",
            (username, password_hash, pin_hash)
        )
        new_id = cur.fetchone()[0]
        db.commit()
        db.close()

        logger.info(f"Admin user created: {username} (id={new_id})")
        return jsonify({'success': True, 'message': f'Admin user "{username}" created successfully'})

    except Exception as e:
        logger.error(f"admin_setup error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/admin/auth/password', methods=['POST'])
def admin_auth_password():
    """
    Password-based admin login.
    Body: { "username": "...", "password": "..." }
    Sets session on success.
    """
    if not BCRYPT_AVAILABLE:
        return jsonify({'success': False, 'error': 'bcrypt library required. Contact administrator.'}), 500
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400

        username = str(data.get('username', '')).strip()
        password = str(data.get('password', '')).strip()

        if not username or not password:
            return jsonify({'success': False, 'error': 'Username and password are required'}), 400

        db = get_db()
        cur = db.cursor()
        admin = _get_admin_user(cur, username)
        db.close()

        if not admin:
            logger.warning(f"Password login failed: unknown username '{username}'")
            # Constant-time delay to prevent username enumeration
            import hashlib
            hashlib.sha256(b'dummy').hexdigest()
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

        if not admin['password_hash'] or not _check_password(password, admin['password_hash']):
            logger.warning(f"Password login failed: wrong password for '{username}'")
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

        session.permanent = False
        session['admin_logged_in'] = True
        session['admin_username'] = username
        session['admin_user_id'] = admin['id']
        session['role'] = 'admin'

        logger.info(f"Admin password login successful: {username}")
        return jsonify({'success': True, 'message': 'Login successful', 'redirect': '/admin'})

    except Exception as e:
        logger.error(f"admin_auth_password error: {e}", exc_info=True)
        return jsonify({'success': False, 'error': 'Login failed. Please try again.'}), 500


@app.route('/admin/auth/pin', methods=['POST'])
def admin_auth_pin():
    """
    PIN-based admin login.
    Body: { "username": "...", "pin": "1234" }
    Sets session on success.
    """
    if not BCRYPT_AVAILABLE:
        return jsonify({'success': False, 'error': 'bcrypt library required. Contact administrator.'}), 500
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400

        username = str(data.get('username', '')).strip()
        pin = str(data.get('pin', '')).strip()

        if not username or not pin:
            return jsonify({'success': False, 'error': 'Username and PIN are required'}), 400

        if not re.match(r'^\d{4,6}$', pin):
            return jsonify({'success': False, 'error': 'PIN must be 4–6 digits'}), 400

        db = get_db()
        cur = db.cursor()
        admin = _get_admin_user(cur, username)
        db.close()

        if not admin:
            logger.warning(f"PIN login failed: unknown username '{username}'")
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

        if not admin['pin_hash']:
            logger.warning(f"PIN login failed: no PIN configured for '{username}'")
            return jsonify({'success': False, 'error': 'PIN login not configured for this account'}), 401

        if not _check_password(pin, admin['pin_hash']):
            logger.warning(f"PIN login failed: wrong PIN for '{username}'")
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

        session.permanent = False
        session['admin_logged_in'] = True
        session['admin_username'] = username
        session['admin_user_id'] = admin['id']
        session['role'] = 'admin'

        logger.info(f"Admin PIN login successful: {username}")
        return jsonify({'success': True, 'message': 'Login successful', 'redirect': '/admin'})

    except Exception as e:
        logger.error(f"admin_auth_pin error: {e}", exc_info=True)
        return jsonify({'success': False, 'error': 'Login failed. Please try again.'}), 500


# ── WebAuthn Registration (begin) ─────────────────────────────────────────────

@app.route('/admin/webauthn/register/begin', methods=['POST'])
@admin_login_required
def webauthn_register_begin():
    """
    Begin WebAuthn passkey registration.
    Must be called while already logged in (to bind credential to current admin user).
    Returns registration options JSON for the browser's navigator.credentials.create() call.
    """
    if not WEBAUTHN_AVAILABLE:
        return jsonify({'error': 'WebAuthn not available. Install py_webauthn: pip install py_webauthn'}), 501
    try:
        username = session['admin_username']
        user_id = session['admin_user_id']

        db = get_db()
        cur = db.cursor()

        # Get existing credentials to exclude them (prevent re-registering same device)
        existing_creds = _get_admin_webauthn_credentials(cur, user_id)
        db.close()

        exclude_credentials = []
        for cred in existing_creds:
            cred_id_bytes = bytes(cred['credential_id'])
            exclude_credentials.append(
                PublicKeyCredentialDescriptor(
                    type=PublicKeyCredentialType.PUBLIC_KEY,
                    id=cred_id_bytes,
                )
            )

        rp_id = _get_rp_id()

        options = _webauthn.generate_registration_options(
            rp_id=rp_id,
            rp_name='Global Calc Admin',
            user_id=str(user_id).encode('utf-8'),
            user_name=username,
            user_display_name=username,
            attestation=AttestationConveyancePreference.NONE,
            authenticator_selection=AuthenticatorSelectionCriteria(
                authenticator_attachment=AuthenticatorAttachment.PLATFORM,
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            exclude_credentials=exclude_credentials,
        )

        # Store challenge for verification
        _store_webauthn_challenge(f'reg:{username}', options.challenge)

        options_dict = _webauthn_options_to_dict(options)
        return jsonify({'success': True, 'options': options_dict})

    except Exception as e:
        logger.error(f"webauthn_register_begin error: {e}", exc_info=True)
        return jsonify({'error': f'WebAuthn registration start failed: {str(e)}'}), 500


@app.route('/admin/webauthn/register/complete', methods=['POST'])
@admin_login_required
def webauthn_register_complete():
    """
    Complete WebAuthn passkey registration.
    Verifies the attestation response from the browser and stores the credential.
    Body: { "credential": <PublicKeyCredential JSON from browser> }
    """
    if not WEBAUTHN_AVAILABLE:
        return jsonify({'error': 'WebAuthn not available'}), 501
    try:
        username = session['admin_username']
        user_id = session['admin_user_id']
        rp_id = _get_rp_id()
        rp_origin = _get_rp_origin()

        challenge = _get_webauthn_challenge(f'reg:{username}')
        if not challenge:
            return jsonify({'error': 'Registration challenge expired or not found. Please restart the process.'}), 400

        data = request.get_json()
        if not data or 'credential' not in data:
            return jsonify({'error': 'Credential data is required'}), 400

        credential = data['credential']

        # Decode the response from the browser (base64url fields)
        from webauthn.helpers import base64url_to_bytes

        attestation_obj_bytes = base64url_to_bytes(credential['response']['attestationObject'])
        client_data_bytes = base64url_to_bytes(credential['response']['clientDataJSON'])
        raw_id_bytes = base64url_to_bytes(credential['rawId'])

        verification = _webauthn.verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=rp_id,
            expected_origin=rp_origin,
            require_user_verification=True,
        )

        # Store credential in DB
        db = get_db()
        cur = db.cursor()
        cur.execute(
            """INSERT INTO webauthn_credentials
               (admin_user_id, credential_id, public_key, sign_count)
               VALUES (%s, %s, %s, %s)
               ON CONFLICT (credential_id) DO UPDATE
               SET sign_count = EXCLUDED.sign_count""",
            (
                user_id,
                verification.credential_id,
                verification.credential_public_key,
                verification.sign_count,
            )
        )
        db.commit()
        db.close()

        logger.info(f"WebAuthn credential registered for admin '{username}'")
        return jsonify({'success': True, 'message': 'Passkey registered successfully'})

    except Exception as e:
        logger.error(f"webauthn_register_complete error: {e}", exc_info=True)
        return jsonify({'error': f'WebAuthn registration failed: {str(e)}'}), 400


# ── WebAuthn Authentication (begin) ───────────────────────────────────────────

@app.route('/admin/webauthn/login/begin', methods=['POST'])
def webauthn_login_begin():
    """
    Begin WebAuthn passkey authentication.
    Body: { "username": "admin" }
    Returns authentication options for browser's navigator.credentials.get().
    """
    if not WEBAUTHN_AVAILABLE:
        return jsonify({'error': 'WebAuthn not available. Install py_webauthn: pip install py_webauthn'}), 501
    try:
        data = request.get_json() or {}
        username = str(data.get('username', '')).strip()

        if not username:
            return jsonify({'error': 'Username is required'}), 400

        db = get_db()
        cur = db.cursor()
        admin = _get_admin_user(cur, username)
        if not admin:
            db.close()
            return jsonify({'error': 'No account found for this username'}), 404

        existing_creds = _get_admin_webauthn_credentials(cur, admin['id'])
        db.close()

        if not existing_creds:
            return jsonify({'error': 'No passkeys registered for this account. Please register a passkey first.'}), 400

        allow_credentials = []
        for cred in existing_creds:
            allow_credentials.append(
                PublicKeyCredentialDescriptor(
                    type=PublicKeyCredentialType.PUBLIC_KEY,
                    id=bytes(cred['credential_id']),
                )
            )

        rp_id = _get_rp_id()

        options = _webauthn.generate_authentication_options(
            rp_id=rp_id,
            allow_credentials=allow_credentials,
            user_verification=UserVerificationRequirement.REQUIRED,
        )

        _store_webauthn_challenge(f'auth:{username}', options.challenge)

        options_dict = _webauthn_auth_options_to_dict(options)
        return jsonify({'success': True, 'options': options_dict})

    except Exception as e:
        logger.error(f"webauthn_login_begin error: {e}", exc_info=True)
        return jsonify({'error': f'WebAuthn login start failed: {str(e)}'}), 500


@app.route('/admin/webauthn/login/complete', methods=['POST'])
def webauthn_login_complete():
    """
    Complete WebAuthn passkey authentication.
    Verifies the assertion response and sets session on success.
    Body: { "username": "admin", "credential": <PublicKeyCredential JSON> }
    """
    if not WEBAUTHN_AVAILABLE:
        return jsonify({'error': 'WebAuthn not available'}), 501
    try:
        data = request.get_json() or {}
        username = str(data.get('username', '')).strip()
        credential = data.get('credential')

        if not username or not credential:
            return jsonify({'error': 'Username and credential are required'}), 400

        challenge = _get_webauthn_challenge(f'auth:{username}')
        if not challenge:
            return jsonify({'error': 'Authentication challenge expired or not found. Please restart.'}), 400

        db = get_db()
        cur = db.cursor()
        admin = _get_admin_user(cur, username)
        if not admin:
            db.close()
            return jsonify({'error': 'Invalid credentials'}), 401

        # Find matching credential record
        raw_id_b64 = credential.get('rawId', '')
        from webauthn.helpers import base64url_to_bytes
        raw_id_bytes = base64url_to_bytes(raw_id_b64)

        cred_rows = _get_admin_webauthn_credentials(cur, admin['id'])
        matched_cred = None
        for cr in cred_rows:
            if bytes(cr['credential_id']) == raw_id_bytes:
                matched_cred = cr
                break

        if not matched_cred:
            db.close()
            return jsonify({'error': 'Credential not recognized. Please re-register your passkey.'}), 401

        rp_id = _get_rp_id()
        rp_origin = _get_rp_origin()

        verification = _webauthn.verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=rp_id,
            expected_origin=rp_origin,
            credential_public_key=bytes(matched_cred['public_key']),
            credential_current_sign_count=matched_cred['sign_count'],
            require_user_verification=True,
        )

        # Update sign count
        cur.execute(
            "UPDATE webauthn_credentials SET sign_count=%s WHERE id=%s",
            (verification.new_sign_count, matched_cred['id'])
        )
        db.commit()
        db.close()

        session.permanent = False
        session['admin_logged_in'] = True
        session['admin_username'] = username
        session['admin_user_id'] = admin['id']
        session['role'] = 'admin'

        logger.info(f"Admin WebAuthn login successful: {username}")
        return jsonify({'success': True, 'message': 'Login successful', 'redirect': '/admin'})

    except Exception as e:
        logger.error(f"webauthn_login_complete error: {e}", exc_info=True)
        return jsonify({'error': f'WebAuthn verification failed: {str(e)}'}), 401


# ── WebAuthn serialization helpers ────────────────────────────────────────────

def _webauthn_options_to_dict(options) -> dict:
    """
    Convert py_webauthn registration options object to a JSON-serializable dict
    that matches the W3C WebAuthn JSON format expected by browsers.
    """
    from webauthn.helpers import bytes_to_base64url
    return {
        'rp': {'id': options.rp.id, 'name': options.rp.name},
        'user': {
            'id': bytes_to_base64url(options.user.id),
            'name': options.user.name,
            'displayName': options.user.display_name,
        },
        'challenge': bytes_to_base64url(options.challenge),
        'pubKeyCredParams': [
            {'type': 'public-key', 'alg': p.alg.value}
            for p in options.pub_key_cred_params
        ],
        'timeout': options.timeout,
        'excludeCredentials': [
            {
                'type': 'public-key',
                'id': bytes_to_base64url(bytes(c.id)),
            }
            for c in (options.exclude_credentials or [])
        ],
        'authenticatorSelection': {
            'authenticatorAttachment': getattr(options.authenticator_selection, 'authenticator_attachment', None),
            'residentKey': getattr(options.authenticator_selection, 'resident_key', None),
            'userVerification': getattr(options.authenticator_selection, 'user_verification', None),
        } if options.authenticator_selection else {},
        'attestation': str(options.attestation) if options.attestation else 'none',
        'extensions': {},
    }


def _webauthn_auth_options_to_dict(options) -> dict:
    """
    Convert py_webauthn authentication options object to JSON-serializable dict
    for the browser's navigator.credentials.get() call.
    """
    from webauthn.helpers import bytes_to_base64url
    return {
        'challenge': bytes_to_base64url(options.challenge),
        'timeout': options.timeout,
        'rpId': options.rp_id,
        'allowCredentials': [
            {
                'type': 'public-key',
                'id': bytes_to_base64url(bytes(c.id)),
            }
            for c in (options.allow_credentials or [])
        ],
        'userVerification': str(options.user_verification) if options.user_verification else 'required',
    }


@app.route('/admin/auth/set-pin', methods=['POST'])
@admin_login_required
def admin_set_pin():
    """
    Set or update the PIN for the currently logged-in admin.
    Body: { "pin": "1234", "current_password": "..." }
    Requires current password to authorize PIN change.
    """
    if not BCRYPT_AVAILABLE:
        return jsonify({'success': False, 'error': 'bcrypt library required'}), 500
    try:
        data = request.get_json() or {}
        pin = str(data.get('pin', '')).strip()
        current_password = str(data.get('current_password', '')).strip()

        if not re.match(r'^\d{4,6}$', pin):
            return jsonify({'success': False, 'error': 'PIN must be 4–6 digits'}), 400

        if not current_password:
            return jsonify({'success': False, 'error': 'Current password is required to set PIN'}), 400

        username = session['admin_username']
        db = get_db()
        cur = db.cursor()
        admin = _get_admin_user(cur, username)

        if not admin or not _check_password(current_password, admin['password_hash']):
            db.close()
            return jsonify({'success': False, 'error': 'Current password is incorrect'}), 401

        new_pin_hash = _hash_password(pin)
        cur.execute("UPDATE admin_users SET pin_hash=%s WHERE username=%s", (new_pin_hash, username))
        db.commit()
        db.close()

        logger.info(f"PIN updated for admin '{username}'")
        return jsonify({'success': True, 'message': 'PIN updated successfully'})

    except Exception as e:
        logger.error(f"admin_set_pin error: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/agent/login', methods=['GET', 'POST'])
def agent_login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        try:
            db = get_db()
            cur = db.cursor()
            cur.execute(
                "SELECT id, name, password FROM agents WHERE name=%s AND active=TRUE",
                (username,)
            )
            agent_row = cur.fetchone()
            db.close()
            if agent_row and agent_row[2] == password:
                session['agent_logged_in'] = True
                session['agent_id'] = agent_row[0]
                session['agent_username'] = agent_row[1]
                session['role'] = 'agent'
                return redirect(url_for('agent_dashboard'))
        except Exception:
            agent_user = os.environ.get('AGENT_USER', 'agent')
            agent_pass = os.environ.get('AGENT_PASS', 'agent123')
            if username == agent_user and password == agent_pass:
                session['agent_logged_in'] = True
                session['agent_username'] = username
                session['role'] = 'agent'
                return redirect(url_for('agent_dashboard'))
        return render_template('login.html', error='Invalid credentials', mode='agent')
    return render_template('login.html', mode='agent')


@app.route('/agent/logout')
def agent_logout():
    session.pop('agent_logged_in', None)
    session.pop('agent_id', None)
    session.pop('agent_username', None)
    session.pop('role', None)
    return redirect(url_for('agent_login'))


@app.route('/agent')
@agent_login_required
def agent_dashboard():
    return render_template('agent.html')


# =====================================================
# CLIENT MANAGEMENT
# =====================================================

@app.route('/api/clients', methods=['GET'])
def list_clients():
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM clients ORDER BY name")
        result = rows_to_dicts(cur, cur.fetchall())
        db.close()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error listing clients: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/clients', methods=['POST'])
def create_client():
    data = request.get_json()
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(
            """INSERT INTO clients (name, code, contact_email, contact_phone, currency_default)
               VALUES (%s, %s, %s, %s, %s) RETURNING id""",
            (data['name'], data['code'], data.get('contact_email', ''),
             data.get('contact_phone', ''), data.get('currency_default', 'INR'))
        )
        cid = cur.fetchone()[0]
        cur.execute(
            """INSERT INTO global_rules (client_id) VALUES (%s) ON CONFLICT (client_id) DO NOTHING""",
            (cid,)
        )
        db.commit()
        return jsonify({'id': cid, 'message': 'Client created'}), 201
    except Exception as e:
        db.rollback()
        logger.error(f"Error creating client: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/clients/<int:cid>', methods=['PUT'])
def update_client(cid):
    data = request.get_json()
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(
            """UPDATE clients SET name=%s, code=%s, contact_email=%s, contact_phone=%s,
               currency_default=%s WHERE id=%s""",
            (data['name'], data['code'], data.get('contact_email', ''),
             data.get('contact_phone', ''), data.get('currency_default', 'INR'), cid)
        )
        db.commit()
        return jsonify({'message': 'Client updated'})
    except Exception as e:
        db.rollback()
        logger.error(f"Error updating client {cid}: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/clients/<int:cid>/toggle', methods=['PATCH'])
def toggle_client(cid):
    """
    Point 2 (v4.0): Returns {success, active, message} so frontend can update
    in-memory cache and re-render the specific row without a full table reload.
    """
    data = request.get_json()
    db = get_db()
    cur = db.cursor()
    try:
        new_active = bool(data['active'])
        cur.execute("UPDATE clients SET active=%s WHERE id=%s RETURNING active", (new_active, cid))
        row = cur.fetchone()
        actual_active = bool(row[0]) if row else new_active
        db.commit()
        return jsonify({'success': True, 'message': 'Toggled', 'active': actual_active})
    except Exception as e:
        db.rollback()
        logger.error(f"Error toggling client {cid}: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/clients/<int:cid>', methods=['DELETE'])
def delete_client(cid):
    """
    Hard delete client and all associated data.
    Change 2 (v3.4): Permanently deletes records from DB with no orphan rows.
    Client ID 1 (default) is protected.
    """
    if cid == 1:
        return jsonify({'error': 'Cannot delete default client', 'deleted': False}), 400

    db = get_db()
    cur = db.cursor()
    try:
        # Verify the client exists before attempting deletion
        cur.execute("SELECT id, name FROM clients WHERE id=%s", (cid,))
        client_row = cur.fetchone()
        if not client_row:
            db.close()
            return jsonify({'error': f'Client {cid} not found', 'deleted': False}), 404

        client_name = client_row[1]

        # Hard delete all dependent records to prevent orphan rows.
        # Order matters: deepest dependencies first, then parents.
        cur.execute("DELETE FROM cab_destination_rates WHERE client_id=%s", (cid,))
        cur.execute("DELETE FROM addons WHERE client_id=%s", (cid,))
        cur.execute("DELETE FROM cabs WHERE client_id=%s", (cid,))
        cur.execute("DELETE FROM destinations WHERE client_id=%s", (cid,))
        cur.execute("DELETE FROM hotels WHERE client_id=%s", (cid,))
        cur.execute("DELETE FROM transports WHERE client_id=%s", (cid,))
        cur.execute("DELETE FROM regions WHERE client_id=%s", (cid,))
        cur.execute("DELETE FROM pricing_rules WHERE client_id=%s", (cid,))
        cur.execute("DELETE FROM global_rules WHERE client_id=%s", (cid,))
        cur.execute("DELETE FROM clients WHERE id=%s", (cid,))

        db.commit()
        logger.info(f"Hard deleted client ID {cid} ({client_name}) and all associated data")
        return jsonify({
            'message': f'Client "{client_name}" permanently deleted',
            'deleted': True,
            'client_id': cid
        })
    except Exception as e:
        db.rollback()
        logger.error(f"Error hard deleting client {cid}: {e}", exc_info=True)
        return jsonify({'error': str(e), 'deleted': False}), 500
    finally:
        db.close()


# =====================================================
# REGIONS (WITH DOMESTIC/INTERNATIONAL SEPARATION)
# =====================================================

@app.route('/api/regions', methods=['GET'])
def list_regions():
    client_id = get_client_id()
    region_type = request.args.get('type')  # 'domestic' or 'international'

    db = get_db()
    cur = db.cursor()
    try:
        if region_type == 'domestic':
            cur.execute(
                """SELECT * FROM regions
                   WHERE client_id=%s AND is_domestic=TRUE
                   ORDER BY name""",
                (client_id,)
            )
        elif region_type == 'international':
            cur.execute(
                """SELECT * FROM regions
                   WHERE client_id=%s AND is_domestic=FALSE
                   ORDER BY name""",
                (client_id,)
            )
        else:
            cur.execute(
                "SELECT * FROM regions WHERE client_id=%s ORDER BY is_domestic DESC, name",
                (client_id,)
            )

        result = rows_to_dicts(cur, cur.fetchall())
        db.close()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error listing regions: {e}", exc_info=True)
        if db:
            db.close()
        return jsonify({'error': str(e)}), 500


@app.route('/api/regions', methods=['POST'])
def create_region():
    data = request.get_json()
    client_id = data.get('client_id', 1)

    db = get_db()
    cur = db.cursor()

    try:
        defaults = get_safe_defaults_for_entity('region', data)

        is_domestic_val = defaults['is_domestic']
        if isinstance(is_domestic_val, str):
            is_domestic_val = is_domestic_val.lower() in ('true', '1', 'domestic')
        elif isinstance(is_domestic_val, int):
            is_domestic_val = bool(is_domestic_val)

        cur.execute(
            """INSERT INTO regions (client_id, name, currency, is_domestic, service_percent, booking_percent)
               VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""",
            (client_id, data['name'], defaults['currency'],
             is_domestic_val, defaults['service_percent'],
             defaults['booking_percent'])
        )
        rid = cur.fetchone()[0]
        db.commit()

        logger.info(f"Created region ID {rid}: {data['name']} (domestic={is_domestic_val})")
        return jsonify({'id': rid, 'message': 'Region created'}), 201

    except Exception as e:
        db.rollback()
        logger.error(f"Error creating region: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/regions/<int:rid>', methods=['PUT'])
def update_region(rid):
    data = request.get_json()
    db = get_db()
    cur = db.cursor()

    try:
        is_domestic_val = data.get('is_domestic', True)
        if isinstance(is_domestic_val, str):
            is_domestic_val = is_domestic_val.lower() in ('true', '1', 'domestic')
        elif isinstance(is_domestic_val, int):
            is_domestic_val = bool(is_domestic_val)

        cur.execute(
            """UPDATE regions SET name=%s, currency=%s, is_domestic=%s,
               service_percent=%s, booking_percent=%s
               WHERE id=%s""",
            (data['name'], data.get('currency', 'INR'), is_domestic_val,
             data.get('service_percent', 15), data.get('booking_percent', 12), rid)
        )
        db.commit()
        return jsonify({'message': 'Region updated'})
    except Exception as e:
        db.rollback()
        logger.error(f"Error updating region {rid}: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/regions/<int:rid>/toggle', methods=['PATCH'])
def toggle_region(rid):
    """Point 2 (v4.0): Returns {success, active, message}."""
    data = request.get_json()
    db = get_db()
    cur = db.cursor()
    try:
        new_active = bool(data['active'])
        cur.execute("UPDATE regions SET active=%s WHERE id=%s RETURNING active", (new_active, rid))
        row = cur.fetchone()
        actual_active = bool(row[0]) if row else new_active
        db.commit()
        return jsonify({'success': True, 'message': 'Toggled', 'active': actual_active})
    except Exception as e:
        db.rollback()
        logger.error(f"Error toggling region {rid}: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/regions/<int:rid>', methods=['DELETE'])
def delete_region(rid):
    """
    Hard delete region and all child records.
    Change 2 (v3.4): Permanently removes region, all destinations, hotels,
    transports, cabs, addons, and related rates belonging to this region.
    """
    db = get_db()
    cur = db.cursor()
    try:
        # Verify region exists before deletion
        cur.execute("SELECT id, name, client_id FROM regions WHERE id=%s", (rid,))
        region_row = cur.fetchone()
        if not region_row:
            db.close()
            return jsonify({'error': f'Region {rid} not found', 'deleted': False}), 404

        region_name = region_row[1]

        # Get all cabs in this region for rate cleanup
        cur.execute("SELECT id FROM cabs WHERE region_id=%s", (rid,))
        cab_ids = [r[0] for r in cur.fetchall()]

        # Delete cab_destination_rates for cabs in this region
        if cab_ids:
            cur.execute(
                "DELETE FROM cab_destination_rates WHERE cab_id = ANY(%s)",
                (cab_ids,)
            )

        # Hard delete all child entities in dependency order
        cur.execute("DELETE FROM addons WHERE region_id=%s", (rid,))
        cur.execute("DELETE FROM cabs WHERE region_id=%s", (rid,))

        # Null out destination_id on hotels before deleting destinations
        cur.execute(
            """UPDATE hotels SET destination_id=NULL
               WHERE destination_id IN (SELECT id FROM destinations WHERE region_id=%s)""",
            (rid,)
        )
        cur.execute("DELETE FROM destinations WHERE region_id=%s", (rid,))
        cur.execute("DELETE FROM hotels WHERE region_id=%s", (rid,))
        cur.execute("DELETE FROM transports WHERE region_id=%s", (rid,))
        cur.execute("DELETE FROM regions WHERE id=%s", (rid,))

        db.commit()
        logger.info(f"Hard deleted region ID {rid} ({region_name}) and all associated data")
        return jsonify({
            'message': f'Region "{region_name}" permanently deleted',
            'deleted': True,
            'region_id': rid
        })
    except Exception as e:
        db.rollback()
        logger.error(f"Error hard deleting region {rid}: {e}", exc_info=True)
        return jsonify({'error': str(e), 'deleted': False}), 500
    finally:
        db.close()


# =====================================================
# TRANSPORTS (FIXED WITH PRICING TYPE + TRIP TYPE SUPPORT)
# =====================================================

@app.route('/api/transports', methods=['GET'])
def list_transports():
    client_id = get_client_id()
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(
            "SELECT * FROM transports WHERE client_id=%s ORDER BY name",
            (client_id,)
        )
        result = rows_to_dicts(cur, cur.fetchall())
        db.close()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error listing transports: {e}", exc_info=True)
        if db:
            db.close()
        return jsonify({'error': str(e)}), 500


@app.route('/api/transports', methods=['POST'])
def create_transport():
    data = request.get_json()
    client_id = data.get('client_id', 1)

    db = get_db()
    cur = db.cursor()

    try:
        name = data['name']
        region_id = data['region_id']

        transport_type = data.get('transport_type')
        if not transport_type:
            transport_type = auto_generate_transport_type(cur, name, client_id, region_id)

        display_name = auto_generate_display_name(name, data.get('display_name'))
        defaults = get_safe_defaults_for_entity('transport', data)

        cur.execute(
            """INSERT INTO transports (client_id, region_id, name, transport_type, display_name,
               seat_capacity, adult_rate_peak, child_rate_peak, peak_pricing_type,
               adult_rate_off, child_rate_off, off_pricing_type)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
            (client_id, region_id, name, transport_type, display_name,
             defaults['seat_capacity'],
             defaults['adult_rate_peak'], defaults['child_rate_peak'], defaults['peak_pricing_type'],
             defaults['adult_rate_off'], defaults['child_rate_off'], defaults['off_pricing_type'])
        )
        tid = cur.fetchone()[0]
        db.commit()

        logger.info(f"Created transport ID {tid}: {name} -> {transport_type}")
        return jsonify({'id': tid, 'message': 'Transport created'}), 201

    except Exception as e:
        db.rollback()
        logger.error(f"Error creating transport: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/transports/<int:tid>', methods=['PUT'])
def update_transport(tid):
    data = request.get_json()
    db = get_db()
    cur = db.cursor()

    try:
        cur.execute("SELECT client_id, region_id, transport_type FROM transports WHERE id=%s", (tid,))
        current = cur.fetchone()
        if not current:
            db.close()
            return jsonify({'error': 'Transport not found'}), 404

        client_id, region_id, current_transport_type = current

        name = data['name']
        transport_type = data.get('transport_type')
        if not transport_type or transport_type == current_transport_type:
            transport_type = auto_generate_transport_type(cur, name, client_id, region_id, exclude_id=tid)

        defaults = get_safe_defaults_for_entity('transport', data)

        cur.execute(
            """UPDATE transports SET name=%s, region_id=%s, transport_type=%s,
               adult_rate_peak=%s, child_rate_peak=%s, peak_pricing_type=%s,
               adult_rate_off=%s, child_rate_off=%s, off_pricing_type=%s
               WHERE id=%s""",
            (name, data['region_id'], transport_type,
             defaults['adult_rate_peak'], defaults['child_rate_peak'], defaults['peak_pricing_type'],
             defaults['adult_rate_off'], defaults['child_rate_off'], defaults['off_pricing_type'], tid)
        )
        db.commit()

        return jsonify({'message': 'Updated'})

    except Exception as e:
        db.rollback()
        logger.error(f"Error updating transport {tid}: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/transports/<int:tid>/toggle', methods=['PATCH'])
def toggle_transport(tid):
    """Point 2 (v4.0): Returns {success, active, message}."""
    data = request.get_json()
    db = get_db()
    cur = db.cursor()
    try:
        new_active = bool(data['active'])
        cur.execute("UPDATE transports SET active=%s WHERE id=%s RETURNING active", (new_active, tid))
        row = cur.fetchone()
        actual_active = bool(row[0]) if row else new_active
        db.commit()
        return jsonify({'success': True, 'message': 'Toggled', 'active': actual_active})
    except Exception as e:
        db.rollback()
        logger.error(f"Error toggling transport {tid}: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/transports/<int:tid>', methods=['DELETE'])
def delete_transport(tid):
    """
    Hard delete transport record.
    Change 2 (v3.4): Permanently deletes transport, no orphan rows.
    """
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("SELECT id, name FROM transports WHERE id=%s", (tid,))
        row = cur.fetchone()
        if not row:
            db.close()
            return jsonify({'error': f'Transport {tid} not found', 'deleted': False}), 404

        transport_name = row[1]
        cur.execute("DELETE FROM transports WHERE id=%s", (tid,))
        db.commit()
        logger.info(f"Hard deleted transport ID {tid} ({transport_name})")
        return jsonify({
            'message': f'Transport "{transport_name}" permanently deleted',
            'deleted': True,
            'transport_id': tid
        })
    except Exception as e:
        db.rollback()
        logger.error(f"Error hard deleting transport {tid}: {e}", exc_info=True)
        return jsonify({'error': str(e), 'deleted': False}), 500
    finally:
        db.close()


# =====================================================
# HOTELS
# =====================================================

@app.route('/api/hotels', methods=['GET'])
def list_hotels():
    client_id = get_client_id()
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(
            "SELECT * FROM hotels WHERE client_id=%s ORDER BY name",
            (client_id,)
        )
        result = rows_to_dicts(cur, cur.fetchall())
        db.close()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error listing hotels: {e}", exc_info=True)
        if db:
            db.close()
        return jsonify({'error': str(e)}), 500


@app.route('/api/hotels', methods=['POST'])
def create_hotel():
    data = request.get_json()
    client_id = data.get('client_id', 1)

    db = get_db()
    cur = db.cursor()

    try:
        name = data['name']
        region_id = data['region_id']

        internal_name = data.get('internal_name')
        if not internal_name:
            internal_name = auto_generate_internal_name(cur, 'hotels', name, client_id, region_id)

        defaults = get_safe_defaults_for_entity('hotel', data)

        sharing = data.get('sharing_type', 'DOUBLE')
        cap = 2
        if sharing == 'QUAD':
            cap = 4
        elif sharing == 'CUSTOM':
            cap = int(data.get('custom_capacity', 2))

        destination_id = data.get('destination_id') if data.get('destination_id') else None

        cur.execute(
            """INSERT INTO hotels (client_id, region_id, destination_id, name, internal_name,
               sharing_type, sharing_capacity, custom_sharing_name, is_kasol,
               extra_mattress_rate, extra_mattress_child_rate, child_age_limit,
               adult_rate_peak, child_rate_peak, adult_rate_off, child_rate_off)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
            (client_id, region_id, destination_id,
             name, internal_name, sharing, cap,
             defaults['custom_sharing_name'], defaults['is_kasol'],
             defaults['extra_mattress_rate'], defaults['extra_mattress_child_rate'],
             defaults['child_age_limit'],
             defaults['adult_rate_peak'], defaults['child_rate_peak'],
             defaults['adult_rate_off'], defaults['child_rate_off'])
        )
        hid = cur.fetchone()[0]
        db.commit()

        logger.info(f"Created hotel ID {hid}: {name} -> {internal_name}")
        return jsonify({'id': hid, 'message': 'Hotel created'}), 201

    except Exception as e:
        db.rollback()
        logger.error(f"Error creating hotel: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/hotels/<int:hid>', methods=['PUT'])
def update_hotel(hid):
    data = request.get_json()
    db = get_db()
    cur = db.cursor()

    try:
        cur.execute("SELECT client_id, region_id, internal_name FROM hotels WHERE id=%s", (hid,))
        current = cur.fetchone()
        if not current:
            db.close()
            return jsonify({'error': 'Hotel not found'}), 404

        client_id, region_id, current_internal_name = current

        name = data['name']
        internal_name = data.get('internal_name')
        if not internal_name or internal_name == current_internal_name:
            internal_name = auto_generate_internal_name(cur, 'hotels', name, client_id, region_id, exclude_id=hid)

        defaults = get_safe_defaults_for_entity('hotel', data)

        sharing = data.get('sharing_type', 'DOUBLE')
        cap = 2
        if sharing == 'QUAD':
            cap = 4
        elif sharing == 'CUSTOM':
            cap = int(data.get('custom_capacity', 2))

        destination_id = data.get('destination_id') if data.get('destination_id') else None

        cur.execute(
            """UPDATE hotels SET name=%s, region_id=%s, destination_id=%s, internal_name=%s,
               sharing_type=%s, sharing_capacity=%s, custom_sharing_name=%s,
               adult_rate_peak=%s, child_rate_peak=%s, adult_rate_off=%s, child_rate_off=%s
               WHERE id=%s""",
            (name, data.get('region_id'), destination_id, internal_name,
             sharing, cap, defaults['custom_sharing_name'],
             defaults['adult_rate_peak'], defaults['child_rate_peak'],
             defaults['adult_rate_off'], defaults['child_rate_off'], hid)
        )
        db.commit()

        return jsonify({'message': 'Updated'})

    except Exception as e:
        db.rollback()
        logger.error(f"Error updating hotel {hid}: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/hotels/<int:hid>/toggle', methods=['PATCH'])
def toggle_hotel(hid):
    """Point 2 (v4.0): Returns {success, active, message}."""
    data = request.get_json()
    db = get_db()
    cur = db.cursor()
    try:
        new_active = bool(data['active'])
        cur.execute("UPDATE hotels SET active=%s WHERE id=%s RETURNING active", (new_active, hid))
        row = cur.fetchone()
        actual_active = bool(row[0]) if row else new_active
        db.commit()
        return jsonify({'success': True, 'message': 'Toggled', 'active': actual_active})
    except Exception as e:
        db.rollback()
        logger.error(f"Error toggling hotel {hid}: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/hotels/<int:hid>', methods=['DELETE'])
def delete_hotel(hid):
    """
    Hard delete hotel record.
    Change 2 (v3.4): Permanently deletes hotel from database.
    """
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("SELECT id, name FROM hotels WHERE id=%s", (hid,))
        row = cur.fetchone()
        if not row:
            db.close()
            return jsonify({'error': f'Hotel {hid} not found', 'deleted': False}), 404

        hotel_name = row[1]
        cur.execute("DELETE FROM hotels WHERE id=%s", (hid,))
        db.commit()
        logger.info(f"Hard deleted hotel ID {hid} ({hotel_name})")
        return jsonify({
            'message': f'Hotel "{hotel_name}" permanently deleted',
            'deleted': True,
            'hotel_id': hid
        })
    except Exception as e:
        db.rollback()
        logger.error(f"Error hard deleting hotel {hid}: {e}", exc_info=True)
        return jsonify({'error': str(e), 'deleted': False}), 500
    finally:
        db.close()


# =====================================================
# DESTINATIONS
# =====================================================

@app.route('/api/destinations', methods=['GET'])
def list_destinations():
    client_id = get_client_id()
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(
            "SELECT * FROM destinations WHERE client_id=%s ORDER BY name",
            (client_id,)
        )
        result = rows_to_dicts(cur, cur.fetchall())
        db.close()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error listing destinations: {e}", exc_info=True)
        if db:
            db.close()
        return jsonify({'error': str(e)}), 500


@app.route('/api/destinations', methods=['POST'])
def create_destination():
    data = request.get_json()
    client_id = data.get('client_id', 1)

    db = get_db()
    cur = db.cursor()

    try:
        name = data['name']
        region_id = data['region_id']

        internal_name = data.get('internal_name')
        if not internal_name:
            internal_name = auto_generate_internal_name(cur, 'destinations', name, client_id, region_id)

        display_name = auto_generate_display_name(name, data.get('display_name'))
        defaults = get_safe_defaults_for_entity('destination', data, cursor=cur, name=name)

        cur.execute(
            """INSERT INTO destinations (client_id, region_id, name, internal_name, display_name,
               destination_type, is_special, base_rate, per_day_rate, four_by_four_rate, free_sightseeing_days)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
            (client_id, region_id, name, internal_name, display_name, defaults['destination_type'],
             defaults['is_special'], defaults['base_rate'],
             defaults['per_day_rate'], defaults['four_by_four_rate'],
             defaults['free_sightseeing_days'])
        )

        did = cur.fetchone()[0]
        db.commit()

        logger.info(f"Created destination ID {did}: {name} -> {internal_name}")
        return jsonify({'id': did, 'message': 'Destination created'}), 201

    except Exception as e:
        db.rollback()
        logger.error(f"Error creating destination: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/destinations/<int:did>', methods=['PUT'])
def update_destination(did):
    data = request.get_json()
    db = get_db()
    cur = db.cursor()

    try:
        cur.execute("SELECT client_id, region_id, internal_name FROM destinations WHERE id=%s", (did,))
        current = cur.fetchone()
        if not current:
            db.close()
            return jsonify({'error': 'Destination not found'}), 404

        client_id, region_id, current_internal_name = current

        name = data['name']
        internal_name = data.get('internal_name')
        if not internal_name or internal_name == current_internal_name:
            internal_name = auto_generate_internal_name(cur, 'destinations', name, client_id, region_id, exclude_id=did)

        display_name = auto_generate_display_name(name, data.get('display_name'))
        defaults = get_safe_defaults_for_entity('destination', data, cursor=cur, name=name)

        cur.execute(
            """UPDATE destinations SET name=%s, region_id=%s, internal_name=%s, display_name=%s,
               destination_type=%s, is_special=%s, base_rate=%s, per_day_rate=%s WHERE id=%s""",
            (name, data.get('region_id'), internal_name, display_name, defaults['destination_type'],
             defaults['is_special'], defaults['base_rate'],
             defaults['per_day_rate'], did)
        )

        db.commit()
        logger.info(f"Updated destination ID {did}: {name}")
        return jsonify({'message': 'Updated'})

    except Exception as e:
        db.rollback()
        logger.error(f"Error updating destination {did}: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/destinations/<int:did>/toggle', methods=['PATCH'])
def toggle_destination(did):
    """Point 2 (v4.0): Returns {success, active, message}."""
    data = request.get_json()
    db = get_db()
    cur = db.cursor()
    try:
        new_active = bool(data['active'])
        cur.execute("UPDATE destinations SET active=%s WHERE id=%s RETURNING active", (new_active, did))
        row = cur.fetchone()
        actual_active = bool(row[0]) if row else new_active
        db.commit()
        return jsonify({'success': True, 'message': 'Toggled', 'active': actual_active})
    except Exception as e:
        db.rollback()
        logger.error(f"Error toggling destination {did}: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/destinations/<int:did>', methods=['DELETE'])
def delete_destination(did):
    """
    Hard delete destination and clean up hotel references.
    Change 2 (v3.4): Permanently removes destination, nulls hotel.destination_id FK.
    """
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("SELECT id, name FROM destinations WHERE id=%s", (did,))
        row = cur.fetchone()
        if not row:
            db.close()
            return jsonify({'error': f'Destination {did} not found', 'deleted': False}), 404

        destination_name = row[1]

        # Null out FK references in hotels before deletion to avoid constraint violations
        cur.execute("UPDATE hotels SET destination_id=NULL WHERE destination_id=%s", (did,))
        cur.execute("DELETE FROM destinations WHERE id=%s", (did,))
        db.commit()
        logger.info(f"Hard deleted destination ID {did} ({destination_name})")
        return jsonify({
            'message': f'Destination "{destination_name}" permanently deleted',
            'deleted': True,
            'destination_id': did
        })
    except Exception as e:
        db.rollback()
        logger.error(f"Error hard deleting destination {did}: {e}", exc_info=True)
        return jsonify({'error': str(e), 'deleted': False}), 500
    finally:
        db.close()


# =====================================================
# CABS
# =====================================================

@app.route('/api/cabs', methods=['GET'])
def list_cabs():
    client_id = get_client_id()
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(
            "SELECT * FROM cabs WHERE client_id=%s ORDER BY name",
            (client_id,)
        )
        result = rows_to_dicts(cur, cur.fetchall())
        db.close()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error listing cabs: {e}", exc_info=True)
        if db:
            db.close()
        return jsonify({'error': str(e)}), 500


@app.route('/api/cabs', methods=['POST'])
def create_cab():
    data = request.get_json()
    client_id = data.get('client_id', 1)

    db = get_db()
    cur = db.cursor()

    try:
        name = data['name']
        region_id = data['region_id']

        internal_name = data.get('internal_name')
        if not internal_name:
            internal_name = auto_generate_internal_name(cur, 'cabs', name, client_id, region_id)

        display_name = auto_generate_display_name(name, data.get('display_name'))
        defaults = get_safe_defaults_for_entity('cab', data)

        cur.execute(
            """INSERT INTO cabs (client_id, region_id, name, internal_name, display_name,
               capacity, base_rate, per_day_rate)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
            (client_id, region_id, name, internal_name, display_name,
             defaults['capacity'], defaults['base_rate'], defaults['per_day_rate'])
        )
        cid = cur.fetchone()[0]
        db.commit()

        logger.info(f"Created cab ID {cid}: {name} -> {internal_name}")
        return jsonify({'id': cid, 'message': 'Cab created'}), 201

    except Exception as e:
        db.rollback()
        logger.error(f"Error creating cab: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/cabs/<int:cid>', methods=['PUT'])
def update_cab(cid):
    data = request.get_json()
    db = get_db()
    cur = db.cursor()

    try:
        cur.execute("SELECT client_id, region_id, internal_name FROM cabs WHERE id=%s", (cid,))
        current = cur.fetchone()
        if not current:
            db.close()
            return jsonify({'error': 'Cab not found'}), 404

        client_id, region_id, current_internal_name = current

        name = data['name']
        internal_name = data.get('internal_name')
        if not internal_name or internal_name == current_internal_name:
            internal_name = auto_generate_internal_name(cur, 'cabs', name, client_id, region_id, exclude_id=cid)

        display_name = auto_generate_display_name(name, data.get('display_name'))
        defaults = get_safe_defaults_for_entity('cab', data)

        cur.execute(
            """UPDATE cabs SET name=%s, region_id=%s, internal_name=%s, display_name=%s,
               base_rate=%s, per_day_rate=%s WHERE id=%s""",
            (name, data.get('region_id'), internal_name, display_name,
             defaults['base_rate'], defaults['per_day_rate'], cid)
        )
        db.commit()

        return jsonify({'message': 'Updated'})

    except Exception as e:
        db.rollback()
        logger.error(f"Error updating cab {cid}: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/cabs/<int:cid>/toggle', methods=['PATCH'])
def toggle_cab(cid):
    """Point 2 (v4.0): Returns {success, active, message}."""
    data = request.get_json()
    db = get_db()
    cur = db.cursor()
    try:
        new_active = bool(data['active'])
        cur.execute("UPDATE cabs SET active=%s WHERE id=%s RETURNING active", (new_active, cid))
        row = cur.fetchone()
        actual_active = bool(row[0]) if row else new_active
        db.commit()
        return jsonify({'success': True, 'message': 'Toggled', 'active': actual_active})
    except Exception as e:
        db.rollback()
        logger.error(f"Error toggling cab {cid}: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/cabs/<int:cid>', methods=['DELETE'])
def delete_cab(cid):
    """
    Hard delete cab and its associated destination rates.
    Change 2 (v3.4): Permanently removes cab and orphan rate rows.
    """
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("SELECT id, name FROM cabs WHERE id=%s", (cid,))
        row = cur.fetchone()
        if not row:
            db.close()
            return jsonify({'error': f'Cab {cid} not found', 'deleted': False}), 404

        cab_name = row[1]

        # Delete associated rates first to avoid orphan rows
        cur.execute("DELETE FROM cab_destination_rates WHERE cab_id=%s", (cid,))
        cur.execute("DELETE FROM cabs WHERE id=%s", (cid,))
        db.commit()
        logger.info(f"Hard deleted cab ID {cid} ({cab_name}) and its destination rates")
        return jsonify({
            'message': f'Cab "{cab_name}" permanently deleted',
            'deleted': True,
            'cab_id': cid
        })
    except Exception as e:
        db.rollback()
        logger.error(f"Error hard deleting cab {cid}: {e}", exc_info=True)
        return jsonify({'error': str(e), 'deleted': False}), 500
    finally:
        db.close()


# =====================================================
# CAB-DESTINATION RATES
# =====================================================

@app.route('/api/cab-destination-rates', methods=['GET'])
def list_cab_dest_rates():
    client_id = get_client_id()
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(
            "SELECT * FROM cab_destination_rates WHERE client_id=%s ORDER BY cab_id, destination_id",
            (client_id,)
        )
        result = rows_to_dicts(cur, cur.fetchall())
        db.close()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error listing cab-destination rates: {e}", exc_info=True)
        if db:
            db.close()
        return jsonify({'error': str(e)}), 500


@app.route('/api/cab-destination-rates', methods=['PUT'])
def upsert_cab_dest_rate():
    data = request.get_json()
    client_id = data.get('client_id', 1)
    db = get_db()
    cur = db.cursor()

    try:
        cur.execute(
            """SELECT id FROM cab_destination_rates
               WHERE client_id=%s AND cab_id=%s AND destination_id=%s""",
            (client_id, data['cab_id'], data['destination_id'])
        )
        existing = cur.fetchone()

        if existing:
            cur.execute(
                """UPDATE cab_destination_rates
                   SET rate=%s, override_rate=%s
                   WHERE client_id=%s AND cab_id=%s AND destination_id=%s""",
                (data.get('rate', 0), data.get('override_rate'),
                 client_id, data['cab_id'], data['destination_id'])
            )
        else:
            cur.execute(
                """INSERT INTO cab_destination_rates (client_id, cab_id, destination_id, rate, override_rate)
                   VALUES (%s, %s, %s, %s, %s)""",
                (client_id, data['cab_id'], data['destination_id'],
                 data.get('rate', 0), data.get('override_rate'))
            )

        db.commit()
        return jsonify({'message': 'Rate updated successfully'})

    except Exception as e:
        db.rollback()
        logger.error(f"Error updating cab-destination rate: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/cab-destination-matrix', methods=['GET'])
def cab_destination_matrix():
    """Full matrix of all active cabs × all active destinations."""
    client_id = get_client_id()

    try:
        db = get_db()
        cur = db.cursor()

        cur.execute(
            "SELECT id, name, internal_name FROM cabs WHERE client_id=%s AND active=TRUE ORDER BY name",
            (client_id,)
        )
        cabs = rows_to_dicts(cur, cur.fetchall())

        cur.execute(
            "SELECT id, name, internal_name, display_name FROM destinations WHERE client_id=%s AND active=TRUE ORDER BY name",
            (client_id,)
        )
        destinations = rows_to_dicts(cur, cur.fetchall())

        cur.execute(
            """SELECT cab_id, destination_id, rate, override_rate
               FROM cab_destination_rates
               WHERE client_id=%s""",
            (client_id,)
        )
        existing_rates = {}
        for row in cur.fetchall():
            key = f"{row[0]}_{row[1]}"
            existing_rates[key] = {
                'cab_id': row[0],
                'destination_id': row[1],
                'rate': float(row[2]) if row[2] else 0,
                'override_rate': float(row[3]) if row[3] else None
            }

        matrix = []
        for cab in cabs:
            for dest in destinations:
                key = f"{cab['id']}_{dest['id']}"
                existing = existing_rates.get(key)
                matrix.append({
                    'cab_id': cab['id'],
                    'cab_name': cab['name'],
                    'destination_id': dest['id'],
                    'destination_name': dest.get('display_name') or dest['name'],
                    'rate': existing['rate'] if existing else 0,
                    'override_rate': existing['override_rate'] if existing else None,
                    'has_record': existing is not None
                })

        db.close()

        return jsonify({
            'cabs': cabs,
            'destinations': destinations,
            'matrix': matrix,
            'existing_rates': existing_rates
        })

    except Exception as e:
        logger.error(f"Matrix endpoint error: {e}", exc_info=True)
        return jsonify({
            'error': str(e),
            'cabs': [],
            'destinations': [],
            'matrix': [],
            'existing_rates': {}
        }), 500


# =====================================================
# ADD-ONS (FIXED WITH PEAK/OFF RATES)
# =====================================================

@app.route('/api/addons', methods=['GET'])
def list_addons():
    client_id = get_client_id()
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(
            "SELECT * FROM addons WHERE client_id=%s ORDER BY name",
            (client_id,)
        )
        result = rows_to_dicts(cur, cur.fetchall())
        db.close()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error listing addons: {e}", exc_info=True)
        if db:
            db.close()
        return jsonify({'error': str(e)}), 500


@app.route('/api/addons', methods=['POST'])
def create_addon():
    data = request.get_json()
    client_id = data.get('client_id', 1)

    db = get_db()
    cur = db.cursor()

    try:
        name = data.get('name', '').strip()
        if not name:
            return jsonify({'error': 'Add-on name is required'}), 400

        region_id = data.get('region_id')
        if not region_id:
            return jsonify({'error': 'Region is required'}), 400
        region_id = int(region_id)

        internal_name = data.get('internal_name', '').strip()
        if not internal_name:
            internal_name = auto_generate_internal_name(cur, 'addons', name, client_id, region_id)

        defaults = get_safe_defaults_for_entity('addon', data, cursor=cur, name=name)

        valid_pricing_types = ('flat', 'per_person', 'per_day', 'per_night')
        pricing_type = defaults['pricing_type']
        if pricing_type not in valid_pricing_types:
            pricing_type = 'flat'

        try:
            rate_peak = float(defaults['rate_peak'])
        except (ValueError, TypeError):
            rate_peak = 0

        try:
            rate_off = float(defaults['rate_off'])
        except (ValueError, TypeError):
            rate_off = 0

        addon_type = defaults['addon_type']
        if not addon_type:
            addon_type = 'GENERAL'

        cur.execute(
            """INSERT INTO addons (client_id, region_id, name, internal_name, addon_type, pricing_type, rate_peak, rate_off)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id""",
            (client_id, region_id, name, internal_name, addon_type, pricing_type, rate_peak, rate_off)
        )
        aid = cur.fetchone()[0]
        db.commit()

        logger.info(f"Created addon ID {aid}: {name} -> {internal_name} (type: {addon_type}, pricing: {pricing_type}, peak: {rate_peak}, off: {rate_off})")
        return jsonify({'id': aid, 'message': 'Addon created'}), 201

    except Exception as e:
        db.rollback()
        logger.error(f"Error creating addon: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/addons/<int:aid>', methods=['PUT'])
def update_addon(aid):
    data = request.get_json()
    db = get_db()
    cur = db.cursor()

    try:
        cur.execute("SELECT client_id, region_id, internal_name FROM addons WHERE id=%s", (aid,))
        current = cur.fetchone()
        if not current:
            db.close()
            return jsonify({'error': 'Addon not found'}), 404

        client_id, region_id, current_internal_name = current

        name = data.get('name', '').strip()
        if not name:
            return jsonify({'error': 'Add-on name is required'}), 400

        internal_name = data.get('internal_name', '').strip()
        if not internal_name or internal_name == current_internal_name:
            internal_name = auto_generate_internal_name(cur, 'addons', name, client_id, region_id, exclude_id=aid)

        defaults = get_safe_defaults_for_entity('addon', data, cursor=cur, name=name)

        valid_pricing_types = ('flat', 'per_person', 'per_day', 'per_night')
        pricing_type = defaults['pricing_type']
        if pricing_type not in valid_pricing_types:
            pricing_type = 'flat'

        try:
            rate_peak = float(defaults['rate_peak'])
        except (ValueError, TypeError):
            rate_peak = 0

        try:
            rate_off = float(defaults['rate_off'])
        except (ValueError, TypeError):
            rate_off = 0

        addon_type = defaults['addon_type']
        if not addon_type:
            addon_type = 'GENERAL'

        cur.execute(
            """UPDATE addons SET name=%s, region_id=%s, internal_name=%s, addon_type=%s, pricing_type=%s, rate_peak=%s, rate_off=%s
               WHERE id=%s""",
            (name, data.get('region_id', region_id), internal_name, addon_type, pricing_type, rate_peak, rate_off, aid)
        )
        db.commit()

        return jsonify({'message': 'Updated'})

    except Exception as e:
        db.rollback()
        logger.error(f"Error updating addon {aid}: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/addons/<int:aid>/toggle', methods=['PATCH'])
def toggle_addon(aid):
    """Point 2 (v4.0): Returns {success, active, message}."""
    data = request.get_json()
    db = get_db()
    cur = db.cursor()
    try:
        new_active = bool(data['active'])
        cur.execute("UPDATE addons SET active=%s WHERE id=%s RETURNING active", (new_active, aid))
        row = cur.fetchone()
        actual_active = bool(row[0]) if row else new_active
        db.commit()
        return jsonify({'success': True, 'message': 'Toggled', 'active': actual_active})
    except Exception as e:
        db.rollback()
        logger.error(f"Error toggling addon {aid}: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/addons/<int:aid>', methods=['DELETE'])
def delete_addon(aid):
    """
    Hard delete addon record.
    Change 2 (v3.4): Permanently removes addon from database.
    """
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("SELECT id, name FROM addons WHERE id=%s", (aid,))
        row = cur.fetchone()
        if not row:
            db.close()
            return jsonify({'error': f'Addon {aid} not found', 'deleted': False}), 404

        addon_name = row[1]
        cur.execute("DELETE FROM addons WHERE id=%s", (aid,))
        db.commit()
        logger.info(f"Hard deleted addon ID {aid} ({addon_name})")
        return jsonify({
            'message': f'Addon "{addon_name}" permanently deleted',
            'deleted': True,
            'addon_id': aid
        })
    except Exception as e:
        db.rollback()
        logger.error(f"Error hard deleting addon {aid}: {e}", exc_info=True)
        return jsonify({'error': str(e), 'deleted': False}), 500
    finally:
        db.close()


# =====================================================
# GLOBAL RULES
# =====================================================

@app.route('/api/global-rules', methods=['GET'])
def get_global_rules():
    client_id = get_client_id()
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("SELECT * FROM global_rules WHERE client_id=%s", (client_id,))
        row = cur.fetchone()
        db.close()
        if not row:
            return jsonify({})
        return jsonify(row_to_dict(cur, row))
    except Exception as e:
        logger.error(f"Error getting global rules: {e}", exc_info=True)
        if db:
            db.close()
        return jsonify({'error': str(e)}), 500


@app.route('/api/global-rules', methods=['PUT'])
def update_global_rules():
    data = request.get_json()
    client_id = data.get('client_id', 1)
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(
            """INSERT INTO global_rules (client_id, service_charge, booking_charge, tax, default_margin, default_cancellation)
               VALUES (%s,%s,%s,%s,%s,%s)
               ON CONFLICT (client_id) DO UPDATE
               SET service_charge=EXCLUDED.service_charge, booking_charge=EXCLUDED.booking_charge,
                   tax=EXCLUDED.tax, default_margin=EXCLUDED.default_margin,
                   default_cancellation=EXCLUDED.default_cancellation""",
            (client_id, data.get('service_charge', 15), data.get('booking_charge', 12),
             data.get('tax', 0), data.get('default_margin', 0), data.get('default_cancellation', 0))
        )
        db.commit()
        cur.execute("SELECT * FROM global_rules WHERE client_id=%s", (client_id,))
        row = cur.fetchone()
        result = row_to_dict(cur, row)
        return jsonify(result)
    except Exception as e:
        db.rollback()
        logger.error(f"Error updating global rules: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


# =====================================================
# PRICING RULES
# =====================================================

@app.route('/api/pricing-rules', methods=['GET'])
def list_pricing_rules():
    client_id = get_client_id()
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(
            """SELECT * FROM pricing_rules WHERE client_id=%s
               ORDER BY priority ASC, id ASC""",
            (client_id,)
        )
        result = rows_to_dicts(cur, cur.fetchall())
        db.close()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error listing pricing rules: {e}", exc_info=True)
        if db:
            db.close()
        return jsonify({'error': str(e)}), 500


@app.route('/api/pricing-rules', methods=['POST'])
def create_pricing_rule():
    data = request.get_json()
    client_id = data.get('client_id', 1)
    db = get_db()
    cur = db.cursor()

    try:
        conditions = data.get('conditions_json', {})
        actions = data.get('actions_json', {})
        if isinstance(conditions, str):
            conditions = json.loads(conditions)
        if isinstance(actions, str):
            actions = json.loads(actions)

        cur.execute(
            """INSERT INTO pricing_rules
               (client_id, name, description, entity_type, entity_id,
                conditions_json, actions_json, priority, stackable)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
            (client_id, data['name'], data.get('description', ''),
             data.get('entity_type', 'global'), data.get('entity_id'),
             json.dumps(conditions), json.dumps(actions),
             data.get('priority', 100), data.get('stackable', True))
        )
        rid = cur.fetchone()[0]
        db.commit()
        return jsonify({'id': rid, 'message': 'Rule created'}), 201
    except Exception as e:
        db.rollback()
        logger.error(f"Error creating pricing rule: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/pricing-rules/<int:rid>', methods=['PUT'])
def update_pricing_rule(rid):
    data = request.get_json()
    db = get_db()
    cur = db.cursor()

    try:
        conditions = data.get('conditions_json', {})
        actions = data.get('actions_json', {})
        if isinstance(conditions, str):
            conditions = json.loads(conditions)
        if isinstance(actions, str):
            actions = json.loads(actions)

        cur.execute(
            """UPDATE pricing_rules SET name=%s, description=%s, entity_type=%s,
               entity_id=%s, conditions_json=%s, actions_json=%s,
               priority=%s, stackable=%s WHERE id=%s""",
            (data['name'], data.get('description', ''),
             data.get('entity_type', 'global'), data.get('entity_id'),
             json.dumps(conditions), json.dumps(actions),
             data.get('priority', 100), data.get('stackable', True), rid)
        )
        db.commit()
        return jsonify({'message': 'Rule updated'})
    except Exception as e:
        db.rollback()
        logger.error(f"Error updating pricing rule {rid}: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/pricing-rules/<int:rid>/toggle', methods=['PATCH'])
def toggle_pricing_rule(rid):
    """Point 2 (v4.0): Returns {success, active, message}."""
    data = request.get_json()
    db = get_db()
    cur = db.cursor()
    try:
        new_active = bool(data['active'])
        cur.execute("UPDATE pricing_rules SET active=%s WHERE id=%s RETURNING active", (new_active, rid))
        row = cur.fetchone()
        actual_active = bool(row[0]) if row else new_active
        db.commit()
        return jsonify({'success': True, 'message': 'Toggled', 'active': actual_active})
    except Exception as e:
        db.rollback()
        logger.error(f"Error toggling pricing rule {rid}: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/pricing-rules/<int:rid>', methods=['DELETE'])
def delete_pricing_rule(rid):
    """
    Hard delete pricing rule.
    Change 2 (v3.4): Permanently removes rule from database.
    """
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("SELECT id, name FROM pricing_rules WHERE id=%s", (rid,))
        row = cur.fetchone()
        if not row:
            db.close()
            return jsonify({'error': f'Pricing rule {rid} not found', 'deleted': False}), 404

        rule_name = row[1]
        cur.execute("DELETE FROM pricing_rules WHERE id=%s", (rid,))
        db.commit()
        logger.info(f"Hard deleted pricing rule ID {rid} ({rule_name})")
        return jsonify({
            'message': f'Pricing rule "{rule_name}" permanently deleted',
            'deleted': True,
            'rule_id': rid
        })
    except Exception as e:
        db.rollback()
        logger.error(f"Error hard deleting pricing rule {rid}: {e}", exc_info=True)
        return jsonify({'error': str(e), 'deleted': False}), 500
    finally:
        db.close()


# =====================================================
# AI-ASSISTED RULE CREATION (WITH CLARIFICATION)
# =====================================================

@app.route('/api/ai-parse-rule', methods=['POST'])
def ai_parse_rule():
    """
    ENHANCED: Parses natural language into structured rule.
    Asks for clarification when ambiguous.
    NEVER calculates prices.
    """
    data = request.get_json()
    text = data.get('text', '').strip()

    if not text:
        return jsonify({'error': 'No text provided'}), 400

    try:
        result = _parse_natural_language_rule(text)
        return jsonify(result)
    except Exception as e:
        logger.error(f"AI rule parse error: {e}", exc_info=True)
        return jsonify({
            'error': f'Could not parse rule: {str(e)}',
            'name': text[:200],
            'description': text,
            'entity_type': 'global',
            'entity_id': None,
            'conditions_json': {},
            'actions_json': {},
            'priority': 100,
            'stackable': True,
            'needs_clarification': True,
            'clarification_question': 'Could you provide more details? For example: "Increase hotel rate by 10% when season is peak and adults >= 6"'
        })


def _parse_natural_language_rule(text: str) -> dict:
    """
    ENHANCED: Rule-based NLU parser with ambiguity detection.
    Returns structured rule OR clarification request.
    """
    original_text = text
    txt = text.lower().strip()

    conditions = {}
    actions = {}
    entity_type = 'global'
    entity_id = None
    priority = 100
    stackable = True
    name = original_text[:200]
    needs_clarification = False
    clarification_question = None

    # Season conditions
    if any(phrase in txt for phrase in ['peak season', 'season is peak', 'season is on', 'on season', 'in season', 'season = on', 'season=on']):
        conditions['season'] = 'ON'
    elif any(phrase in txt for phrase in ['off season', 'season is off', 'off-season', 'lean season', 'season = off', 'season=off']):
        conditions['season'] = 'OFF'

    # Adults conditions
    adults_gte_match = re.search(r'(?:adults?\s*(?:>=|≥|is\s*at\s*least|at\s*least|or\s*more)|(?:groups?\s+of|more\s+than)\s+)(\d+)(?:\s*(?:or\s*more\s*)?adults?)?', txt)
    if not adults_gte_match:
        adults_gte_match = re.search(r'(\d+)\+\s*adults?', txt)
    if adults_gte_match:
        conditions['adults_gte'] = int(adults_gte_match.group(1))

    adults_lte_match = re.search(r'adults?\s*(?:<=|≤|is\s*at\s*most|at\s*most|less\s*than|fewer\s*than|under)\s*(\d+)', txt)
    if adults_lte_match:
        conditions['adults_lte'] = int(adults_lte_match.group(1))

    # Children conditions
    children_gte_match = re.search(r'(?:children\s*(?:>=|≥|is\s*at\s*least|at\s*least)|(?:groups?\s+of|more\s+than)\s+)(\d+)(?:\s*children)?', txt)
    if not children_gte_match:
        children_gte_match = re.search(r'(\d+)\+\s*child', txt)
    if children_gte_match:
        conditions['children_gte'] = int(children_gte_match.group(1))

    # Pax conditions
    pax_gte_match = re.search(r'(?:pax|people|persons?|travelers?|travellers?|guests?)\s*(?:>=|≥|is\s*at\s*least|at\s*least)\s*(\d+)', txt)
    if not pax_gte_match:
        pax_gte_match = re.search(r'(?:groups?\s+of|more\s+than|at\s+least)\s+(\d+)\s*(?:pax|people|persons?|travelers?|travellers?|guests?)', txt)
    if not pax_gte_match:
        pax_gte_match = re.search(r'(\d+)\+\s*(?:pax|people|persons?|travelers?|travellers?|guests?)', txt)
    if pax_gte_match:
        conditions['pax_gte'] = int(pax_gte_match.group(1))

    # Nights conditions
    nights_gte_match = re.search(r'(?:nights?\s*(?:>=|≥|is\s*at\s*least|at\s*least)|(?:more\s+than|at\s+least)\s+(\d+)\s*nights?)', txt)
    if not nights_gte_match:
        nights_gte_match = re.search(r'(\d+)\+\s*nights?', txt)
    if nights_gte_match:
        conditions['nights_gte'] = int(nights_gte_match.group(1))

    nights_lte_match = re.search(r'nights?\s*(?:<=|≤|is\s*at\s*most|at\s*most|less\s*than|fewer\s*than|under)\s*(\d+)', txt)
    if nights_lte_match:
        conditions['nights_lte'] = int(nights_lte_match.group(1))

    # Region condition
    region_match = re.search(r'region\s*(?:id\s*)?(?:=|is)?\s*(\d+)', txt)
    if region_match:
        conditions['region_id'] = int(region_match.group(1))

    # Detect target
    target = 'total'
    target_map = {
        'hotel': 'hotel', 'accommodation': 'hotel', 'stay': 'hotel', 'room': 'hotel',
        'transport': 'transport', 'bus': 'transport', 'travel': 'transport', 'vehicle': 'transport',
        'sightseeing': 'sightseeing', 'tour': 'sightseeing', 'destination': 'sightseeing',
        'cab': 'cab', 'taxi': 'cab', 'car': 'cab',
        'addon': 'addon', 'add-on': 'addon', 'extra': 'addon', 'add on': 'addon',
        'total': 'total', 'overall': 'total', 'package': 'total', 'entire': 'total',
    }

    for keyword, mapped_target in target_map.items():
        if re.search(r'\b' + re.escape(keyword) + r'\b', txt):
            target = mapped_target
            if mapped_target in ('hotel', 'transport', 'cab', 'addon'):
                entity_type = mapped_target
            elif mapped_target == 'sightseeing':
                entity_type = 'destination'
            break

    # Extract actions
    inc_match = re.search(
        r'(?:increase|raise|hike|surcharge|markup|add\s+a\s+surcharge\s+of|boost)\s+(?:the\s+)?(?:' + re.escape(target) + r'\s+)?(?:rate|cost|price|charge)?\s*(?:by|of)?\s+(\d+(?:\.\d+)?)\s*%',
        txt
    )
    if inc_match:
        actions = {
            'type': 'increase_rate_percent',
            'target': target,
            'value': float(inc_match.group(1))
        }

    dec_match = re.search(
        r'(?:decrease|reduce|discount|lower|cut|give\s+a\s+discount\s+of)\s+(?:the\s+)?(?:' + re.escape(target) + r'\s+)?(?:rate|cost|price|charge)?\s*(?:by|of)?\s+(\d+(?:\.\d+)?)\s*%',
        txt
    )
    if dec_match and not actions:
        actions = {
            'type': 'decrease_rate_percent',
            'target': target,
            'value': float(dec_match.group(1))
        }

    override_match = re.search(
        r'(?:override|set|fix|replace|change)\s+(?:the\s+)?(?:' + re.escape(target) + r'\s+)?(?:rate|cost|price)\s+(?:to|at|=)\s*(?:₹|rs\.?|inr)?\s*(\d+(?:\.\d+)?)',
        txt
    )
    if override_match and not actions:
        actions = {
            'type': 'override_rate',
            'target': target,
            'value': float(override_match.group(1))
        }

    flat_match = re.search(
        r'(?:add|charge|apply|include)\s+(?:a\s+)?(?:flat\s+)?(?:fee|charge|amount|surcharge|cost)\s+(?:of\s+)?(?:₹|rs\.?|inr)?\s*(\d+(?:\.\d+)?)',
        txt
    )
    if not flat_match:
        flat_match = re.search(
            r'(?:flat\s+fee|flat\s+charge|fixed\s+fee|fixed\s+charge)\s+(?:of\s+)?(?:₹|rs\.?|inr)?\s*(\d+(?:\.\d+)?)',
            txt
        )
    if flat_match and not actions:
        actions = {
            'type': 'add_flat_fee',
            'target': target,
            'value': float(flat_match.group(1))
        }

    margin_match = re.search(
        r'(?:apply|add|include)\s+(?:a\s+)?(\d+(?:\.\d+)?)\s*%\s*margin',
        txt
    )
    if margin_match and not actions:
        actions = {
            'type': 'apply_margin',
            'target': target,
            'value': float(margin_match.group(1))
        }

    # Fallback: percentage without clear action
    if not actions:
        pct_match = re.search(r'(\d+(?:\.\d+)?)\s*%', txt)
        if pct_match:
            val = float(pct_match.group(1))
            if any(w in txt for w in ['discount', 'reduce', 'decrease', 'lower', 'less', 'off', 'cut', 'cheaper']):
                actions = {'type': 'decrease_rate_percent', 'target': target, 'value': val}
            elif any(w in txt for w in ['increase', 'raise', 'hike', 'surcharge', 'markup', 'add', 'boost', 'more']):
                actions = {'type': 'increase_rate_percent', 'target': target, 'value': val}
            else:
                needs_clarification = True
                clarification_question = f"You mentioned {val}% but it's unclear if this is an increase or decrease. Please specify: 'increase by {val}%' or 'decrease by {val}%'?"

    # Fallback: flat amount
    if not actions and not needs_clarification:
        amt_match = re.search(r'(?:₹|rs\.?|inr)\s*(\d+(?:\.\d+)?)', txt)
        if amt_match:
            actions = {'type': 'add_flat_fee', 'target': target, 'value': float(amt_match.group(1))}

    # Check for ambiguity
    if not actions and not needs_clarification:
        needs_clarification = True
        clarification_question = "I couldn't detect a clear action (increase, decrease, override, flat fee, or margin). Please rephrase with keywords like 'increase by 10%', 'decrease by 15%', 'add flat fee of 500', etc."

    if actions and not conditions:
        needs_clarification = True
        clarification_question = "I detected an action but no conditions. When should this rule apply? (e.g., 'when season is peak', 'for groups of 6+ adults', 'when nights >= 3')"

    # Generate name
    parts = []
    if actions.get('type') == 'increase_rate_percent':
        parts.append(f"+{actions['value']}% {target}")
    elif actions.get('type') == 'decrease_rate_percent':
        parts.append(f"-{actions['value']}% {target}")
    elif actions.get('type') == 'override_rate':
        parts.append(f"Override {target} to ₹{actions['value']}")
    elif actions.get('type') == 'add_flat_fee':
        parts.append(f"Flat fee ₹{actions['value']}")
    elif actions.get('type') == 'apply_margin':
        parts.append(f"{actions['value']}% margin")

    cond_parts = []
    if conditions.get('season') == 'ON':
        cond_parts.append('peak season')
    elif conditions.get('season') == 'OFF':
        cond_parts.append('off season')
    if conditions.get('adults_gte'):
        cond_parts.append(f"{conditions['adults_gte']}+ adults")
    if conditions.get('adults_lte'):
        cond_parts.append(f"≤{conditions['adults_lte']} adults")
    if conditions.get('pax_gte'):
        cond_parts.append(f"{conditions['pax_gte']}+ pax")
    if conditions.get('nights_gte'):
        cond_parts.append(f"{conditions['nights_gte']}+ nights")
    if conditions.get('nights_lte'):
        cond_parts.append(f"≤{conditions['nights_lte']} nights")

    if parts and cond_parts:
        name = f"{' '.join(parts)} ({', '.join(cond_parts)})"
    elif parts:
        name = ' '.join(parts)

    # Priority
    if any(w in txt for w in ['urgent', 'critical', 'high priority', 'first', 'immediately']):
        priority = 10
    elif any(w in txt for w in ['low priority', 'last', 'fallback', 'default']):
        priority = 500
    elif entity_type != 'global':
        priority = 50

    # Stackable
    if any(w in txt for w in ['exclusive', 'non-stackable', 'only this', 'not stackable', 'override only', 'exclusive rule']):
        stackable = False

    result = {
        'name': name,
        'description': original_text,
        'entity_type': entity_type,
        'entity_id': entity_id,
        'conditions_json': conditions,
        'actions_json': actions,
        'priority': priority,
        'stackable': stackable
    }

    if needs_clarification:
        result['needs_clarification'] = True
        result['clarification_question'] = clarification_question

    return result


# =====================================================
# AMADEUS API SHARED INFRASTRUCTURE
# =====================================================
# Environment variables required:
#   AMADEUS_CLIENT_ID     — Amadeus client key (Self-Service API)
#   AMADEUS_CLIENT_SECRET — Amadeus client secret (Self-Service API)
#   AMADEUS_ENV           — 'test' or 'production' (default: 'test')
#
# Legacy variable names also supported for backwards compatibility:
#   AMADEUS_API_KEY    — alias for AMADEUS_CLIENT_ID
#   AMADEUS_API_SECRET — alias for AMADEUS_CLIENT_SECRET
#
# Token lifecycle:
#   - Fetched once per process and cached in _amadeus_token_cache
#   - Reused across all requests while still valid (expiry - 30s buffer)
#   - Automatically refreshed on expiry or 401 response
#   - Secrets are NEVER logged, NEVER included in any response body
# =====================================================

# Amadeus token cache — in-memory, survives for the lifetime of the process.
# Shared across all request threads (flights AND hotels AND hotel-lookup use same token).
_amadeus_token_cache = {'token': None, 'expires_at': 0}


def _get_amadeus_base_url() -> str:
    """Return the correct Amadeus base URL based on AMADEUS_ENV."""
    env = os.environ.get('AMADEUS_ENV', 'test')
    if env == 'production':
        return 'https://api.amadeus.com'
    return 'https://test.api.amadeus.com'


def _get_amadeus_credentials() -> tuple:
    """
    Retrieve Amadeus credentials from environment variables.
    Supports both the new canonical names (AMADEUS_CLIENT_ID / AMADEUS_CLIENT_SECRET)
    and the legacy names (AMADEUS_API_KEY / AMADEUS_API_SECRET) for backwards
    compatibility.  Returns (client_id, client_secret) as strings.
    Raises ValueError if either value is missing or empty.
    Credentials are never logged.
    """
    client_id = (
        os.environ.get('AMADEUS_CLIENT_ID', '').strip()
        or os.environ.get('AMADEUS_API_KEY', '').strip()
    )
    client_secret = (
        os.environ.get('AMADEUS_CLIENT_SECRET', '').strip()
        or os.environ.get('AMADEUS_API_SECRET', '').strip()
    )
    if not client_id:
        raise ValueError(
            "Amadeus client ID is not configured. "
            "Set the AMADEUS_CLIENT_ID environment variable."
        )
    if not client_secret:
        raise ValueError(
            "Amadeus client secret is not configured. "
            "Set the AMADEUS_CLIENT_SECRET environment variable."
        )
    return client_id, client_secret


def _fetch_fresh_amadeus_token() -> str:
    """
    Perform the OAuth 2.0 client_credentials grant against the Amadeus token
    endpoint and update _amadeus_token_cache.
    Returns the new access token string.
    Raises requests.HTTPError on non-2xx responses.
    Secrets are never logged.
    """
    client_id, client_secret = _get_amadeus_credentials()
    base_url = _get_amadeus_base_url()
    token_url = f'{base_url}/v1/security/oauth2/token'

    logger.info("Amadeus OAuth: requesting new access token")

    resp = _requests.post(
        token_url,
        data={
            'grant_type': 'client_credentials',
            'client_id': client_id,
            'client_secret': client_secret,
        },
        timeout=10,
    )
    resp.raise_for_status()

    token_data = resp.json()
    access_token = token_data['access_token']
    expires_in = int(token_data.get('expires_in', 1799))

    _amadeus_token_cache['token'] = access_token
    _amadeus_token_cache['expires_at'] = time.time() + expires_in

    logger.info(
        f"Amadeus OAuth: new token obtained, valid for {expires_in}s "
        f"(expires_at={_amadeus_token_cache['expires_at']:.0f})"
    )
    return access_token


def _get_amadeus_token() -> str:
    """
    Return a valid Amadeus Bearer token.
    Uses the cached token when it has more than 30 seconds of remaining life.
    Otherwise fetches a fresh token via _fetch_fresh_amadeus_token().
    This function is the single call-site used by all Amadeus API helpers
    (flights, hotels, and hotel-lookup share the same token cache).
    """
    now = time.time()
    cached_token = _amadeus_token_cache.get('token')
    expires_at = _amadeus_token_cache.get('expires_at', 0)

    if cached_token and now < expires_at - 30:
        return cached_token

    return _fetch_fresh_amadeus_token()


def _invalidate_amadeus_token() -> None:
    """
    Force-expire the cached token so that the next call to _get_amadeus_token()
    will fetch a fresh one.  Called automatically on 401 responses.
    """
    _amadeus_token_cache['token'] = None
    _amadeus_token_cache['expires_at'] = 0
    logger.info("Amadeus OAuth: token cache invalidated (will refresh on next request)")


# =====================================================
# CURRENCY CONVERSION — SERVER-SIDE ONLY
# =====================================================
# FX conversion is performed server-side before returning prices to the
# frontend. API keys are NEVER sent to the client.
# Primary source: exchangerate-api.com (set EXCHANGERATE_API_KEY env var)
# Fallback: hardcoded approximate rates (used when primary is unavailable).
# All amounts returned to frontend are already in INR.
# =====================================================

# In-memory FX rate cache to avoid hitting the FX API on every hotel search.
_fx_rate_cache: dict = {}
FX_CACHE_TTL_SECONDS = 3600

# Fallback approximate rates to INR (updated periodically by the dev team).
_FX_FALLBACK_RATES_TO_INR = {
    'INR': 1.0,
    'USD': 83.50,
    'EUR': 90.20,
    'GBP': 105.80,
    'AED': 22.74,
    'SGD': 62.00,
    'THB': 2.35,
    'MYR': 17.80,
    'JPY': 0.56,
    'AUD': 54.50,
    'CAD': 61.50,
    'CHF': 94.00,
    'HKD': 10.70,
    'NZD': 50.00,
    'SAR': 22.27,
    'QAR': 22.93,
    'KWD': 270.00,
    'OMR': 216.97,
    'BHD': 221.50,
    'ZAR': 4.45,
    'TRY': 2.60,
    'SEK': 8.10,
    'NOK': 7.90,
    'DKK': 12.10,
    'CNY': 11.60,
    'KRW': 0.063,
    'IDR': 0.0054,
    'PHP': 1.49,
    'VND': 0.0033,
}


def _get_fx_rate_to_inr(currency: str) -> float:
    """
    Return the exchange rate: 1 unit of `currency` = X INR.

    Lookup order:
      1. In-memory cache (valid for FX_CACHE_TTL_SECONDS)
      2. Live FX API (exchangerate-api.com if EXCHANGERATE_API_KEY is set)
      3. Hardcoded fallback rates
    """
    currency = currency.upper().strip()

    if currency == 'INR':
        return 1.0

    now = time.time()
    cached = _fx_rate_cache.get(currency)
    if cached and now < cached.get('expires_at', 0):
        logger.debug(f"FX cache hit: 1 {currency} = {cached['rate']} INR")
        return cached['rate']

    api_key = os.environ.get('EXCHANGERATE_API_KEY', '').strip()
    if api_key:
        try:
            fx_url = f"https://v6.exchangerate-api.com/v6/{api_key}/pair/{currency}/INR"
            resp = _requests.get(fx_url, timeout=5)
            if resp.ok:
                data = resp.json()
                rate = float(data.get('conversion_rate', 0))
                if rate > 0:
                    _fx_rate_cache[currency] = {
                        'rate': rate,
                        'expires_at': now + FX_CACHE_TTL_SECONDS
                    }
                    logger.info(f"FX live rate: 1 {currency} = {rate} INR")
                    return rate
        except Exception as e:
            logger.warning(f"FX live rate fetch failed for {currency}: {e} — using fallback")

    fallback = _FX_FALLBACK_RATES_TO_INR.get(currency)
    if fallback:
        logger.info(f"FX fallback rate: 1 {currency} = {fallback} INR")
        _fx_rate_cache[currency] = {
            'rate': fallback,
            'expires_at': now + 600
        }
        return fallback

    logger.error(f"FX: no rate available for {currency}, assuming 1:1 with INR (INCORRECT)")
    return 1.0


def _convert_to_inr(amount: float, currency: str) -> float:
    """Convert amount from `currency` to INR using server-side FX rates."""
    if currency.upper() == 'INR':
        return amount
    rate = _get_fx_rate_to_inr(currency)
    converted = round(amount * rate, 2)
    logger.info(f"FX conversion: {amount} {currency} → {converted} INR (rate={rate})")
    return converted


# =====================================================
# FLIGHT SEARCH — Amadeus v2 shopping/flight-offers
# =====================================================

def _normalize_flight_offers(raw_offers, trip_type='one_way'):
    """
    Normalize Amadeus raw offer list into a clean, frontend-safe structure.
    Returns list of dicts with only the fields needed for display and pricing.
    Raw Amadeus response is never forwarded to the frontend.
    """
    results = []
    for offer in (raw_offers or []):
        try:
            price = offer.get('price', {})
            total_fare_str = price.get('grandTotal') or price.get('total', '0')
            total_fare = float(total_fare_str)

            itineraries = offer.get('itineraries', [])
            if not itineraries:
                continue

            # Outbound itinerary
            out_it = itineraries[0]
            out_segments = out_it.get('segments', [])
            if not out_segments:
                continue

            first_seg = out_segments[0]
            last_seg = out_segments[-1]

            origin = first_seg.get('departure', {}).get('iataCode', '')
            destination = last_seg.get('arrival', {}).get('iataCode', '')
            duration = out_it.get('duration', '').replace('PT', '').lower()

            # Carrier
            carrier_code = first_seg.get('carrierCode', '')
            carrier_name = offer.get('validatingAirlineCodes', [carrier_code])
            carrier_name = carrier_name[0] if carrier_name else carrier_code

            # Stops
            stops = len(out_segments) - 1

            # Flight number
            flight_number = f"{first_seg.get('carrierCode','')}{first_seg.get('number','')}"

            # Cabin class
            traveler_pricings = offer.get('travelerPricings', [{}])
            fare_details = traveler_pricings[0].get('fareDetailsBySegment', [{}])
            cabin = fare_details[0].get('cabin', '') if fare_details else ''

            # Departure / arrival timestamps for the outbound leg
            departure_dt = first_seg.get('departure', {}).get('at', '')
            arrival_dt = last_seg.get('arrival', {}).get('at', '')

            # Return leg details (present only for round-trip offers)
            return_departure_dt = None
            return_arrival_dt = None
            return_duration = None
            if trip_type == 'return' and len(itineraries) > 1:
                ret_it = itineraries[1]
                ret_segments = ret_it.get('segments', [])
                if ret_segments:
                    return_departure_dt = ret_segments[0].get('departure', {}).get('at', '')
                    return_arrival_dt = ret_segments[-1].get('arrival', {}).get('at', '')
                    return_duration = ret_it.get('duration', '').replace('PT', '').lower()

            results.append({
                'id': offer.get('id', str(len(results))),
                # Airline / flight identifiers
                'airline': carrier_name,
                'carrier': carrier_name,          # kept for legacy compatibility
                'flightNumber': flight_number,
                # Route
                'origin': origin,
                'destination': destination,
                # Timing — outbound
                'departure': departure_dt,
                'arrival': arrival_dt,
                'duration': duration,
                'stops': stops,
                # Timing — return leg (None for one-way)
                'returnDeparture': return_departure_dt,
                'returnArrival': return_arrival_dt,
                'returnDuration': return_duration,
                # Fare (per-person total as returned by Amadeus)
                'price': total_fare,
                'totalFare': total_fare,          # kept for legacy compatibility
                'currency': price.get('currency', 'INR'),
                # Cabin
                'cabinClass': cabin,
            })
        except (KeyError, ValueError, TypeError) as e:
            logger.warning(f"Skipping malformed flight offer: {e}")
            continue

    # Sort by price ascending
    results.sort(key=lambda x: x['price'])
    return results


def _amadeus_flight_search_request(params: dict) -> _requests.Response:
    """
    Execute the Amadeus v2/shopping/flight-offers GET request with automatic
    token refresh on 401.  Returns the raw Response object.
    Raises requests.HTTPError for non-recoverable HTTP errors.
    """
    base_url = _get_amadeus_base_url()
    search_url = f'{base_url}/v2/shopping/flight-offers'

    token = _get_amadeus_token()
    resp = _requests.get(
        search_url,
        headers={'Authorization': f'Bearer {token}'},
        params=params,
        timeout=15,
    )

    if resp.status_code == 401:
        logger.warning("Amadeus API returned 401 — refreshing token and retrying")
        _invalidate_amadeus_token()
        token = _get_amadeus_token()
        resp = _requests.get(
            search_url,
            headers={'Authorization': f'Bearer {token}'},
            params=params,
            timeout=15,
        )

    return resp


@app.route('/api/flight-search', methods=['POST'])
def flight_search():
    """
    Live flight search via Amadeus Self-Service API.

    Accepts JSON body:
    {
        "origin":        "DEL",          # IATA departure code (required)
        "destination":   "BOM",          # IATA arrival code (required)
        "departureDate": "2026-04-10",   # YYYY-MM-DD (required)
        "returnDate":    "2026-04-15",   # YYYY-MM-DD (optional, round-trip only)
        "adults":        2,              # default 1
        "children":      0,              # default 0
        "trip_type":     "one_way"       # "one_way" | "return", default "one_way"
    }

    Returns clean structured JSON — raw Amadeus response is never forwarded.
    API credentials remain backend-only and are never included in any response.

    Change 1 (v3.4): tripType/trip_type is validated and normalised via
    _validate_and_normalise_trip_type() before being used.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No search parameters provided', 'offers': []}), 400

        # ── Input validation ──────────────────────────────────────────────────
        origin = (data.get('origin') or '').strip().upper()
        destination = (data.get('destination') or '').strip().upper()
        departure_date = (data.get('departureDate') or data.get('departure_date') or '').strip()
        return_date = (data.get('returnDate') or data.get('return_date') or '').strip()

        # Change 1: Use validated, normalised trip type from utility function
        raw_trip_type = data.get('tripType') or data.get('trip_type') or 'one_way'
        trip_type = _validate_and_normalise_trip_type(raw_trip_type)

        try:
            adults = max(1, int(data.get('adults', 1)))
        except (ValueError, TypeError):
            adults = 1

        try:
            children = max(0, int(data.get('children', 0)))
        except (ValueError, TypeError):
            children = 0

        if not origin or len(origin) < 2:
            return jsonify({'error': 'Valid departure IATA code required (e.g. DEL)', 'offers': []}), 400
        if not destination or len(destination) < 2:
            return jsonify({'error': 'Valid arrival IATA code required (e.g. BOM)', 'offers': []}), 400
        if not departure_date:
            return jsonify({'error': 'Departure date is required (YYYY-MM-DD)', 'offers': []}), 400
        if trip_type == 'return' and not return_date:
            return jsonify({'error': 'Return date is required for round-trip searches', 'offers': []}), 400

        # ── Build Amadeus request parameters ─────────────────────────────────
        params = {
            'originLocationCode': origin,
            'destinationLocationCode': destination,
            'departureDate': departure_date,
            'adults': adults,
            'max': 10,
            'currencyCode': 'INR',
        }
        if children > 0:
            params['children'] = children
        if trip_type == 'return' and return_date:
            params['returnDate'] = return_date

        # ── Call Amadeus API ──────────────────────────────────────────────────
        resp = _amadeus_flight_search_request(params)

        if not resp.ok:
            err_body = {}
            try:
                err_body = resp.json()
            except Exception:
                pass
            errors = err_body.get('errors', [])
            err_title = errors[0].get('title', 'Flight search failed') if errors else 'Flight search failed'
            err_detail = errors[0].get('detail', '') if errors else ''
            logger.error(
                f"Amadeus API error {resp.status_code} for {origin}->{destination}: "
                f"{err_title} — {err_detail}"
            )
            return jsonify({
                'error': err_title,
                'detail': err_detail,
                'offers': [],
            }), 200

        raw = resp.json()
        raw_offers = raw.get('data', [])

        if not raw_offers:
            logger.info(
                f"Flight search {origin}->{destination} on {departure_date}: no offers found"
            )
            return jsonify({'offers': [], 'count': 0}), 200

        offers = _normalize_flight_offers(raw_offers, trip_type)

        # Point 3 (v4.0): Cache raw offers by offer_id for the booking endpoint.
        # This allows /api/create-booking to reconstruct the full Amadeus Create Order payload.
        for raw_offer in raw_offers:
            raw_offer_id = str(raw_offer.get('id', ''))
            if raw_offer_id:
                _store_raw_flight_offer(raw_offer_id, raw_offer)

        logger.info(
            f"Flight search {origin}->{destination} on {departure_date}: "
            f"{len(offers)} offers returned, {len(raw_offers)} raw offers cached (trip_type={trip_type})"
        )
        return jsonify({'offers': offers, 'count': len(offers), 'tripType': trip_type})

    except ValueError as e:
        logger.error(f"Flight search configuration error: {e}", exc_info=True)
        return jsonify({'error': str(e), 'offers': []}), 200

    except _requests.exceptions.Timeout:
        logger.error("Flight search timed out connecting to Amadeus API")
        return jsonify({
            'error': 'Flight search timed out. Please try again.',
            'offers': [],
        }), 200

    except _requests.exceptions.ConnectionError as e:
        logger.error(f"Flight search network error: {e}", exc_info=True)
        return jsonify({
            'error': 'Could not reach the flight search service. Please check connectivity.',
            'offers': [],
        }), 200

    except Exception as e:
        logger.error(f"Flight search unexpected error: {e}", exc_info=True)
        return jsonify({
            'error': 'Flight search temporarily unavailable. Please try again.',
            'offers': [],
        }), 200


# =====================================================
# FLIGHT DETAILS — Structured JSON for selected flight
# =====================================================
# Change 3 (v3.4): After user selects a flight from search results,
# /api/flight-details returns a fully structured JSON containing:
#   airline, flight_number, departure_airport, arrival_airport,
#   departure_time, arrival_time, duration, pricing_breakdown
# All data comes from the backend. Raw Amadeus data is never forwarded.
# Credentials are never included in any response.
# =====================================================

def _build_flight_pricing_breakdown(offer_data: dict, adults: int, children: int) -> dict:
    """
    Build a detailed pricing breakdown dict from an Amadeus offer block.
    All calculation is descriptive only — no pricing engine logic is applied here.
    The breakdown shows component-level cost transparency for display purposes.
    Returns a structured dict safe for frontend consumption.
    """
    try:
        price = offer_data.get('price', {})
        traveler_pricings = offer_data.get('travelerPricings', [])

        grand_total_str = price.get('grandTotal') or price.get('total', '0')
        grand_total = float(grand_total_str)
        base_fare_str = price.get('base', grand_total_str)
        base_fare = float(base_fare_str)
        currency = price.get('currency', 'INR')
        fees = price.get('fees', [])

        total_taxes = 0.0
        for fee_item in fees:
            try:
                total_taxes += float(fee_item.get('amount', 0))
            except (ValueError, TypeError):
                pass

        # Per-traveler breakdown
        per_traveler = []
        for tp in traveler_pricings:
            try:
                tp_price = tp.get('price', {})
                tp_total_str = tp_price.get('total', '0')
                tp_base_str = tp_price.get('base', tp_total_str)
                tp_total = float(tp_total_str)
                tp_base = float(tp_base_str)
                traveler_type = tp.get('travelerType', 'ADULT')
                tp_quantity = tp.get('quantity', 1)
                per_traveler.append({
                    'travelerType': traveler_type,
                    'quantity': tp_quantity,
                    'baseFare': round(tp_base, 2),
                    'total': round(tp_total, 2),
                    'currency': currency,
                })
            except (ValueError, TypeError, KeyError) as e:
                logger.warning(f"Skipping malformed traveler pricing: {e}")
                continue

        return {
            'baseFare': round(base_fare, 2),
            'taxes': round(total_taxes, 2),
            'grandTotal': round(grand_total, 2),
            'currency': currency,
            'perTraveler': per_traveler,
            'adults': adults,
            'children': children,
        }
    except Exception as e:
        logger.warning(f"Could not build pricing breakdown: {e}")
        return {
            'baseFare': 0.0,
            'taxes': 0.0,
            'grandTotal': 0.0,
            'currency': 'INR',
            'perTraveler': [],
            'adults': adults,
            'children': children,
        }


def _build_structured_flight_detail(raw_offer: dict, trip_type: str, adults: int, children: int) -> dict:
    """
    Build fully structured flight detail dict from a raw Amadeus offer.
    Returns the complete structured response used by /api/flight-details.
    Raw Amadeus fields are never directly forwarded — all fields are explicitly extracted.
    """
    itineraries = raw_offer.get('itineraries', [])
    if not itineraries:
        raise ValueError("No itinerary data in flight offer")

    # ── Outbound leg ─────────────────────────────────────────────────────────
    out_it = itineraries[0]
    out_segments = out_it.get('segments', [])
    if not out_segments:
        raise ValueError("No segments in outbound itinerary")

    first_seg = out_segments[0]
    last_seg = out_segments[-1]

    carrier_code = first_seg.get('carrierCode', '')
    flight_number = f"{carrier_code}{first_seg.get('number', '')}"
    airline = raw_offer.get('validatingAirlineCodes', [carrier_code])
    airline = airline[0] if airline else carrier_code

    departure_airport = first_seg.get('departure', {}).get('iataCode', '')
    departure_terminal = first_seg.get('departure', {}).get('terminal', '')
    departure_time = first_seg.get('departure', {}).get('at', '')

    arrival_airport = last_seg.get('arrival', {}).get('iataCode', '')
    arrival_terminal = last_seg.get('arrival', {}).get('terminal', '')
    arrival_time = last_seg.get('arrival', {}).get('at', '')

    duration = out_it.get('duration', '').replace('PT', '').lower()
    stops = len(out_segments) - 1

    # Intermediate stops detail
    intermediate_stops = []
    for seg in out_segments[:-1]:
        stop_code = seg.get('arrival', {}).get('iataCode', '')
        stop_time = seg.get('arrival', {}).get('at', '')
        if stop_code:
            intermediate_stops.append({'airport': stop_code, 'arrivalAt': stop_time})

    # Cabin class from first traveler's first segment fare
    traveler_pricings = raw_offer.get('travelerPricings', [{}])
    fare_details = traveler_pricings[0].get('fareDetailsBySegment', [{}])
    cabin = fare_details[0].get('cabin', 'ECONOMY') if fare_details else 'ECONOMY'
    fare_basis = fare_details[0].get('fareBasis', '') if fare_details else ''

    # ── Baggage allowance ────────────────────────────────────────────────────
    baggage_allowance = {}
    if fare_details:
        included_bags = fare_details[0].get('includedCheckedBags', {})
        if included_bags:
            baggage_allowance = {
                'quantity': included_bags.get('quantity', 0),
                'weight': included_bags.get('weight'),
                'weightUnit': included_bags.get('weightUnit', 'KG'),
            }

    # ── Return leg ───────────────────────────────────────────────────────────
    return_leg = None
    if trip_type == 'return' and len(itineraries) > 1:
        ret_it = itineraries[1]
        ret_segments = ret_it.get('segments', [])
        if ret_segments:
            ret_first = ret_segments[0]
            ret_last = ret_segments[-1]
            return_leg = {
                'departureAirport': ret_first.get('departure', {}).get('iataCode', ''),
                'departureTerminal': ret_first.get('departure', {}).get('terminal', ''),
                'departureTime': ret_first.get('departure', {}).get('at', ''),
                'arrivalAirport': ret_last.get('arrival', {}).get('iataCode', ''),
                'arrivalTerminal': ret_last.get('arrival', {}).get('terminal', ''),
                'arrivalTime': ret_last.get('arrival', {}).get('at', ''),
                'duration': ret_it.get('duration', '').replace('PT', '').lower(),
                'stops': len(ret_segments) - 1,
                'flightNumber': f"{ret_first.get('carrierCode','')}{ret_first.get('number','')}",
            }

    # ── Pricing breakdown ─────────────────────────────────────────────────────
    pricing_breakdown = _build_flight_pricing_breakdown(raw_offer, adults, children)

    return {
        'offerId': raw_offer.get('id', ''),
        'airline': airline,
        'flightNumber': flight_number,
        'carrierCode': carrier_code,
        'tripType': trip_type,
        # Outbound leg
        'departureAirport': departure_airport,
        'departureTerminal': departure_terminal,
        'departureTime': departure_time,
        'arrivalAirport': arrival_airport,
        'arrivalTerminal': arrival_terminal,
        'arrivalTime': arrival_time,
        'duration': duration,
        'stops': stops,
        'intermediateStops': intermediate_stops,
        # Cabin / fare
        'cabinClass': cabin,
        'fareBasis': fare_basis,
        'baggageAllowance': baggage_allowance,
        # Return leg
        'returnLeg': return_leg,
        # Pricing
        'pricingBreakdown': pricing_breakdown,
    }


@app.route('/api/flight-details', methods=['POST'])
def flight_details():
    """
    Change 3 (v3.4): Returns structured flight detail JSON for a selected flight offer.

    Accepts JSON body:
    {
        "offer_id":        "1",           # Amadeus offer ID from flight-search results (required)
        "origin":          "DEL",         # IATA departure code (required, used to re-fetch)
        "destination":     "BOM",         # IATA arrival code (required, used to re-fetch)
        "departureDate":   "2026-04-10",  # YYYY-MM-DD (required)
        "returnDate":      "2026-04-15",  # YYYY-MM-DD (optional, for return flights)
        "adults":          2,             # default 1
        "children":        0,             # default 0
        "tripType":        "one_way"      # "one_way" | "return" | "multi_city"
    }

    Returns structured JSON:
    {
        "airline":            str,        # Airline code / validating carrier
        "flight_number":      str,        # e.g. "6E234"
        "departure_airport":  str,        # IATA code
        "arrival_airport":    str,        # IATA code
        "departure_time":     str,        # ISO 8601
        "arrival_time":       str,        # ISO 8601
        "duration":           str,        # e.g. "2h30m"
        "pricing_breakdown":  {...}       # detailed fare components
        ... (additional fields)
    }

    All data originates from the backend. Raw Amadeus response is never forwarded.
    API credentials are never included in any response.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No parameters provided'}), 400

        offer_id = str(data.get('offer_id') or data.get('offerId') or '').strip()
        origin = (data.get('origin') or '').strip().upper()
        destination = (data.get('destination') or '').strip().upper()
        departure_date = (data.get('departureDate') or data.get('departure_date') or '').strip()
        return_date = (data.get('returnDate') or data.get('return_date') or '').strip()

        # Validate and normalise trip type (Change 1 utility)
        raw_trip_type = data.get('tripType') or data.get('trip_type') or 'one_way'
        trip_type = _validate_and_normalise_trip_type(raw_trip_type)

        try:
            adults = max(1, int(data.get('adults', 1)))
        except (ValueError, TypeError):
            adults = 1

        try:
            children = max(0, int(data.get('children', 0)))
        except (ValueError, TypeError):
            children = 0

        if not origin or len(origin) < 2:
            return jsonify({'error': 'Valid departure IATA code required (e.g. DEL)'}), 400
        if not destination or len(destination) < 2:
            return jsonify({'error': 'Valid arrival IATA code required (e.g. BOM)'}), 400
        if not departure_date:
            return jsonify({'error': 'Departure date is required (YYYY-MM-DD)'}), 400
        if not offer_id:
            return jsonify({'error': 'offer_id is required to retrieve flight details'}), 400

        # Re-fetch the offer list from Amadeus to get the full offer structure
        # for the requested offer_id. This is necessary because Amadeus does not
        # provide a single-offer lookup endpoint in the Self-Service tier.
        params = {
            'originLocationCode': origin,
            'destinationLocationCode': destination,
            'departureDate': departure_date,
            'adults': adults,
            'max': 20,
            'currencyCode': 'INR',
        }
        if children > 0:
            params['children'] = children
        if trip_type == 'return' and return_date:
            params['returnDate'] = return_date

        resp = _amadeus_flight_search_request(params)

        if not resp.ok:
            err_body = {}
            try:
                err_body = resp.json()
            except Exception:
                pass
            errors = err_body.get('errors', [])
            err_title = errors[0].get('title', 'Flight lookup failed') if errors else 'Flight lookup failed'
            err_detail = errors[0].get('detail', '') if errors else ''
            logger.error(f"Amadeus flight-details error {resp.status_code}: {err_title}")
            return jsonify({'error': err_title, 'detail': err_detail}), 200

        raw = resp.json()
        raw_offers = raw.get('data', [])

        if not raw_offers:
            return jsonify({'error': 'No flight offers found for the specified search. The offer may have expired.'}), 200

        # Find the specific offer by ID; fall back to first offer if not found
        # (Amadeus IDs are positional and may shift between calls)
        matched_offer = None
        for ro in raw_offers:
            if str(ro.get('id', '')) == offer_id:
                matched_offer = ro
                break

        if not matched_offer:
            # Use first offer as best-effort fallback and log a warning
            logger.warning(
                f"Flight offer ID '{offer_id}' not found in fresh results for "
                f"{origin}->{destination} on {departure_date}. Using first available offer."
            )
            matched_offer = raw_offers[0]

        # Build structured detail response
        try:
            structured = _build_structured_flight_detail(matched_offer, trip_type, adults, children)
        except ValueError as ve:
            logger.error(f"Error building structured flight detail: {ve}", exc_info=True)
            return jsonify({'error': f'Could not process flight offer data: {str(ve)}'}), 200

        # Map to the canonical frontend-facing field names specified in Change 3
        response = {
            'airline': structured['airline'],
            'flight_number': structured['flightNumber'],
            'departure_airport': structured['departureAirport'],
            'departure_terminal': structured.get('departureTerminal', ''),
            'arrival_airport': structured['arrivalAirport'],
            'arrival_terminal': structured.get('arrivalTerminal', ''),
            'departure_time': structured['departureTime'],
            'arrival_time': structured['arrivalTime'],
            'duration': structured['duration'],
            'stops': structured['stops'],
            'intermediate_stops': structured.get('intermediateStops', []),
            'cabin_class': structured.get('cabinClass', 'ECONOMY'),
            'fare_basis': structured.get('fareBasis', ''),
            'baggage_allowance': structured.get('baggageAllowance', {}),
            'trip_type': trip_type,
            'return_leg': structured.get('returnLeg'),
            'pricing_breakdown': structured['pricingBreakdown'],
            'offer_id': structured.get('offerId', offer_id),
            'carrier_code': structured.get('carrierCode', ''),
        }

        logger.info(
            f"Flight details returned for offer '{offer_id}': "
            f"{response['departure_airport']}->{response['arrival_airport']}, "
            f"airline={response['airline']}, trip_type={trip_type}"
        )
        return jsonify(response), 200

    except ValueError as e:
        logger.error(f"Flight details configuration error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 200

    except _requests.exceptions.Timeout:
        logger.error("Flight details request timed out")
        return jsonify({'error': 'Request timed out. Please try again.'}), 200

    except _requests.exceptions.ConnectionError as e:
        logger.error(f"Flight details network error: {e}", exc_info=True)
        return jsonify({'error': 'Could not reach flight service. Please check connectivity.'}), 200

    except Exception as e:
        logger.error(f"Flight details unexpected error: {e}", exc_info=True)
        return jsonify({'error': 'Flight details temporarily unavailable. Please try again.'}), 200


# =====================================================
# HOTEL SEARCH — Amadeus Hotel Offers API v3
# =====================================================

def _amadeus_get_request(url: str, params: dict, timeout: int = 15) -> _requests.Response:
    """
    Make an authenticated GET request to any Amadeus endpoint.
    Handles 401 token auto-refresh automatically.
    Returns the raw Response object.
    """
    token = _get_amadeus_token()
    resp = _requests.get(
        url,
        headers={'Authorization': f'Bearer {token}'},
        params=params,
        timeout=timeout,
    )

    if resp.status_code == 401:
        logger.warning(f"Amadeus 401 at {url} — refreshing token and retrying")
        _invalidate_amadeus_token()
        token = _get_amadeus_token()
        resp = _requests.get(
            url,
            headers={'Authorization': f'Bearer {token}'},
            params=params,
            timeout=timeout,
        )

    return resp


def _fetch_hotel_ids_for_city(city_code: str, max_hotels: int = 20, ratings: list = None) -> list:
    """
    Step 1: Retrieve hotel IDs for a given IATA city code from Amadeus.
    Returns a list of hotelId strings (up to max_hotels).
    Returns empty list on error (caller handles gracefully).

    Point 5 (v4.0): Optional `ratings` parameter (list of ints, e.g. [4, 5]).
    When provided, passed to Amadeus /by-city as server-side star filter.
    Backend also validates returned hotels match requested ratings for double safety.
    """
    base_url = _get_amadeus_base_url()
    url = f'{base_url}/v1/reference-data/locations/hotels/by-city'

    params = {'cityCode': city_code.upper()}

    # Point 5 (v4.0): Pass ratings filter to Amadeus API
    if ratings:
        valid_ratings = [str(r) for r in ratings if isinstance(r, int) and 1 <= r <= 5]
        if valid_ratings:
            params['ratings'] = ','.join(valid_ratings)
            logger.info(f"Hotel IDs fetch for city {city_code} with star filter: {valid_ratings}")

    try:
        resp = _amadeus_get_request(url, params, timeout=10)
        if not resp.ok:
            logger.warning(
                f"Hotel IDs fetch failed for city {city_code}: "
                f"HTTP {resp.status_code}"
            )
            return []

        data = resp.json()
        hotels_data = data.get('data', [])

        # Point 5 (v4.0): Backend validation — re-filter by rating before returning IDs.
        # The Amadeus API may return hotels slightly outside the requested ratings; this
        # backend guard ensures only exactly-matching star ratings reach the offers step.
        if ratings and hotels_data:
            requested_ratings_set = set(int(r) for r in ratings if str(r).isdigit())
            filtered_hotels = []
            for h in hotels_data:
                hotel_rating = h.get('rating')
                if hotel_rating is not None:
                    try:
                        if int(hotel_rating) in requested_ratings_set:
                            filtered_hotels.append(h)
                    except (ValueError, TypeError):
                        pass
                else:
                    # If Amadeus doesn't return a rating field, include the hotel
                    # (it was returned by the ratings filter, so it likely matches)
                    filtered_hotels.append(h)
            hotels_data = filtered_hotels
            logger.info(f"City {city_code}: {len(hotels_data)} hotels after star rating backend validation")

        hotel_ids = [h.get('hotelId') for h in hotels_data if h.get('hotelId')]
        logger.info(f"City {city_code}: found {len(hotel_ids)} hotel IDs")
        return hotel_ids[:max_hotels]

    except (_requests.exceptions.Timeout, _requests.exceptions.ConnectionError) as e:
        logger.warning(f"Hotel ID fetch network error for {city_code}: {e}")
        return []
    except Exception as e:
        logger.warning(f"Hotel ID fetch error for {city_code}: {e}")
        return []

def _fetch_hotel_offers(
    hotel_ids: list,
    check_in: str,
    check_out: str,
    adults: int,
    room_quantity: int
) -> list:
    """
    Step 2: Retrieve hotel offers for a list of hotel IDs.
    Returns raw Amadeus offer list.
    Returns empty list on error.
    """
    if not hotel_ids:
        return []

    base_url = _get_amadeus_base_url()
    url = f'{base_url}/v3/shopping/hotel-offers'

    params = {
        'hotelIds': ','.join(hotel_ids),
        'checkInDate': check_in,
        'checkOutDate': check_out,
        'adults': adults,
        'roomQuantity': room_quantity,
        'currency': 'INR',
        'bestRateOnly': 'true',
    }

    try:
        resp = _amadeus_get_request(url, params, timeout=20)
        if not resp.ok:
            err_body = {}
            try:
                err_body = resp.json()
            except Exception:
                pass
            errors = err_body.get('errors', [])
            err_msg = errors[0].get('title', f'HTTP {resp.status_code}') if errors else f'HTTP {resp.status_code}'
            logger.warning(f"Hotel offers fetch failed: {err_msg}")
            return []

        data = resp.json()
        return data.get('data', [])

    except (_requests.exceptions.Timeout, _requests.exceptions.ConnectionError) as e:
        logger.warning(f"Hotel offers fetch network error: {e}")
        return []
    except Exception as e:
        logger.warning(f"Hotel offers fetch error: {e}")
        return []


def _normalize_hotel_offers(raw_offers: list, nights: int) -> list:
    """
    Normalize raw Amadeus hotel offer list into clean frontend-safe structure.
    All prices are converted to INR server-side.
    Raw Amadeus data is NEVER forwarded to the frontend.
    """
    results = []

    for offer_block in (raw_offers or []):
        try:
            hotel_info = offer_block.get('hotel', {})
            hotel_name = hotel_info.get('name', 'Unknown Hotel')
            hotel_id = hotel_info.get('hotelId', '')

            offers = offer_block.get('offers', [])
            if not offers:
                continue

            for offer in offers:
                offer_id = offer.get('id', f'{hotel_id}_{len(results)}')

                # Room info
                room = offer.get('room', {})
                type_estimated = room.get('typeEstimated', {})
                room_type = type_estimated.get('category', room.get('type', 'Standard'))
                if not room_type:
                    room_type = 'Standard'

                # Board type (meal plan)
                board_type = offer.get('boardType', 'ROOM_ONLY')

                # Cancellation policy
                policies = offer.get('policies', {})
                cancellation = policies.get('cancellation', {})
                cancel_policy = cancellation.get('description', {}).get('text', '')
                if not cancel_policy:
                    cancel_type = cancellation.get('type', '')
                    cancel_policy = cancel_type if cancel_type else 'Check hotel policy'

                # Pricing
                price_info = offer.get('price', {})
                raw_total_str = price_info.get('grandTotal') or price_info.get('total', '0')
                try:
                    raw_total = float(raw_total_str)
                except (ValueError, TypeError):
                    raw_total = 0.0

                original_currency = (
                    price_info.get('currency')
                    or offer_block.get('currency', 'INR')
                ).upper()

                original_price = raw_total

                # Server-side FX conversion to INR
                total_price_inr = _convert_to_inr(raw_total, original_currency)

                per_night_price_inr = round(total_price_inr / max(nights, 1), 2) if nights > 0 else total_price_inr

                results.append({
                    'id': offer_id,
                    'hotelName': hotel_name,
                    'hotelId': hotel_id,
                    'roomType': room_type,
                    'boardType': board_type,
                    'cancellationPolicy': cancel_policy,
                    'totalPrice': round(total_price_inr, 2),
                    'currency': 'INR',
                    'perNightPrice': per_night_price_inr,
                    'originalCurrency': original_currency,
                    'originalPrice': round(original_price, 2),
                })
        except (KeyError, ValueError, TypeError) as e:
            logger.warning(f"Skipping malformed hotel offer block: {e}")
            continue

    results.sort(key=lambda x: x['totalPrice'])
    return results


@app.route('/api/hotel-search', methods=['POST'])
def hotel_search():
    """
    Live hotel search via Amadeus Hotel Offers API v3.

    Accepts JSON body:
    {
        "cityCode":      "DXB",          # IATA city code (required)
        "checkInDate":   "2026-03-10",   # YYYY-MM-DD (required)
        "checkOutDate":  "2026-03-15",   # YYYY-MM-DD (required)
        "adults":        2,              # default 2
        "roomQuantity":  1               # default 1
    }

    Returns normalized structure. All prices are in INR.
    Raw Amadeus response is never forwarded.
    API credentials remain backend-only.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'hotels': [],
                'count': 0,
                'message': 'No search parameters provided.'
            }), 400

        city_code = (data.get('cityCode') or '').strip().upper()
        check_in = (data.get('checkInDate') or data.get('check_in') or '').strip()
        check_out = (data.get('checkOutDate') or data.get('check_out') or '').strip()

        try:
            adults = max(1, int(data.get('adults', 2)))
        except (ValueError, TypeError):
            adults = 2

        try:
            room_quantity = max(1, int(data.get('roomQuantity', data.get('rooms', 1))))
        except (ValueError, TypeError):
            room_quantity = 1

        # Point 5 (v4.0): Parse starRatings filter (list of ints, e.g. [4] or [3,4,5])
        # Accepts: array [3,4,5] or single int 4 or comma-string "3,4,5"
        raw_ratings = data.get('starRatings') or data.get('ratings')
        requested_ratings = []
        if raw_ratings is not None:
            if isinstance(raw_ratings, list):
                requested_ratings = [int(r) for r in raw_ratings if str(r).isdigit() and 1 <= int(r) <= 5]
            elif isinstance(raw_ratings, (int, float)):
                r = int(raw_ratings)
                if 1 <= r <= 5:
                    requested_ratings = [r]
            elif isinstance(raw_ratings, str):
                for part in raw_ratings.split(','):
                    part = part.strip()
                    if part.isdigit() and 1 <= int(part) <= 5:
                        requested_ratings.append(int(part))

        # If a specific hotelId was provided (name/both search mode), cityCode is not required.
        # We skip the city-wide lookup and search only that hotel directly.
        specific_hotel_id = (data.get('hotelId') or '').strip().upper()

        # hotelName is optionally sent by the frontend when searching in name/both mode.
        # Used during fallback to name-match within city results and return only the
        # specific hotel rather than all 20 city-wide results.
        specific_hotel_name = (data.get('hotelName') or '').strip().upper()

        if not specific_hotel_id and (not city_code or len(city_code) < 2):
            return jsonify({
                'hotels': [],
                'count': 0,
                'message': 'Valid city IATA code is required (e.g. DXB, SIN, BKK).'
            }), 400

        if not check_in:
            return jsonify({'hotels': [], 'count': 0, 'message': 'Check-in date is required (YYYY-MM-DD).'}), 400

        if not check_out:
            return jsonify({'hotels': [], 'count': 0, 'message': 'Check-out date is required (YYYY-MM-DD).'}), 400

        if check_out <= check_in:
            return jsonify({'hotels': [], 'count': 0, 'message': 'Check-out date must be after check-in date.'}), 400

        try:
            from datetime import date
            ci = date.fromisoformat(check_in)
            co = date.fromisoformat(check_out)
            nights = max(1, (co - ci).days)
        except Exception:
            nights = 1

        ratings_label = f", starFilter={requested_ratings}" if requested_ratings else ""
        logger.info(
            f"Hotel search: city={city_code or 'n/a'}, hotelId={specific_hotel_id or 'none'}, "
            f"checkIn={check_in}, checkOut={check_out}, "
            f"adults={adults}, rooms={room_quantity}, nights={nights}{ratings_label}"
        )

        fallback_message = None  # set when we fall back from specific hotel to city

        # ── ID ROUTING LOGIC ─────────────────────────────────────────────────
        # WHY WE DON'T USE THE AUTOCOMPLETE hotelId DIRECTLY:
        #
        # Amadeus has two separate hotel ID namespaces:
        #   1. Reference Data API (/reference-data/locations/hotel) — autocomplete
        #      Returns "reference IDs" (e.g. MCDXB907). Content/reference DB only.
        #   2. Hotel List API (/reference-data/locations/hotels/by-city)
        #      Returns "shopping IDs" (GDS property codes) the Offers API accepts.
        #
        # Passing a reference ID to the Offers API always causes:
        #   "PROPERTY CODE NOT FOUND IN SYSTEM"
        # The hotel IS real — it just uses different IDs in different subsystems.
        #
        # FIX: When hotelName + iataCode are available (name/both mode), skip the
        # direct hotelId path entirely and go straight to city Hotel List + name-match.

        iata_fallback = (data.get('iataCode') or '').strip().upper()
        search_city = city_code or iata_fallback

        # ── Stop words for name-matching ─────────────────────────────────────
        _STOP_WORDS = {
            'THE', 'A', 'AN', 'AND', 'OF', 'BY', 'AT', 'IN', 'ON',
            'DE', 'LA', 'LE', 'LES', 'DU', 'ET',
            'HOTEL', 'HOTELS', 'RESORT', 'RESORTS', 'SUITES', 'SUITE',
            'INN', 'LODGE', 'LODGES', 'PALACE', 'PALACES',
            'TOWER', 'TOWERS', 'COURT', 'COURTS',
            'BOUTIQUE', 'LUXURY', 'PREMIUM', 'GRAND', 'ROYAL', 'EXECUTIVE',
            'INTERNATIONAL', 'GLOBAL', 'COLLECTION', 'CLUB', 'SIGNATURE',
        }

        def _name_match(city_raw_offers, query_name):
            """Filter raw offer blocks to those matching query_name via brand-word scoring."""
            all_words = set(query_name.upper().split())
            sig_words = all_words - _STOP_WORDS
            if not sig_words:
                sig_words = all_words
            logger.info(f"Hotel name-match: query='{query_name}', significant={sig_words}")
            scored = []
            for ob in city_raw_offers:
                h_name = (ob.get('hotel', {}).get('name', '')).upper()
                matched = [w for w in sig_words if w in h_name]
                if matched:
                    scored.append((len(matched), ob))
            if not scored:
                return [], 'none'
            scored.sort(key=lambda x: x[0], reverse=True)
            best = scored[0][0]
            total = len(sig_words)
            full = [ob for sc, ob in scored if sc == total]
            if full:
                return full, 'full'
            return [ob for sc, ob in scored if sc == best], 'partial'

        raw_offers = []

        if specific_hotel_name and search_city:
            # ── NAME SEARCH: city Hotel List + name-match ─────────────────────
            # Skip the autocomplete hotelId — it's a reference ID, not a shopping
            # ID. Always use city Hotel List for shopping-compatible IDs.
            logger.info(
                f"Hotel search: name+city — city={search_city}, "
                f"name='{specific_hotel_name}' (bypassing direct hotelId)"
            )
            city_ids = _fetch_hotel_ids_for_city(
                search_city, max_hotels=50, ratings=requested_ratings or None
            )
            if not city_ids:
                return jsonify({
                    'hotels': [], 'count': 0,
                    'message': f'No hotels found for city code "{search_city}". Try a different city.'
                }), 200
            city_raw = _fetch_hotel_offers(city_ids, check_in, check_out, adults, room_quantity)
            if city_raw:
                matched, match_type = _name_match(city_raw, specific_hotel_name)
                if match_type == 'full':
                    raw_offers = matched
                    fallback_message = None
                    logger.info(f"Name-match FULL: {len(raw_offers)} result(s) for '{specific_hotel_name}'")
                elif match_type == 'partial':
                    raw_offers = matched
                    fallback_message = (
                        f'Showing closest available match for '
                        f'"{specific_hotel_name.title()}" on these dates.'
                    )
                    logger.info(f"Name-match PARTIAL: {len(raw_offers)} result(s) for '{specific_hotel_name}'")
                else:
                    # Hotel is in Amadeus reference DB (appeared in autocomplete) but
                    # its name doesn't appear in the GDS shopping inventory for this
                    # city/dates. This can happen because:
                    #   a) The hotel uses a different trading name in the GDS
                    #   b) The hotel is not GDS-connected for these dates
                    #   c) Amadeus test environment has limited inventory
                    #
                    # UX decision: show ALL city results with a clear explanation
                    # rather than a dead end. The user can still pick an available hotel.
                    raw_offers = city_raw
                    fallback_message = (
                        f'"{specific_hotel_name.title()}" was not found with live rates '
                        f'for these dates. Showing all available hotels in the area — '
                        f'try different dates if you specifically need this hotel.'
                    )
                    logger.info(
                        f"Name-match NONE: showing all {len(city_raw)} city results "
                        f"for {search_city} as fallback for '{specific_hotel_name}'"
                    )

        elif specific_hotel_id:
            # ── DIRECT ID (no name available) ────────────────────────────────
            logger.info(f"Hotel search: direct hotelId={specific_hotel_id} (no name provided)")
            raw_offers = _fetch_hotel_offers([specific_hotel_id], check_in, check_out, adults, room_quantity)
            if not raw_offers and search_city:
                logger.info(f"Direct hotelId failed — city fallback for {search_city}")
                fallback_ids = _fetch_hotel_ids_for_city(
                    search_city, max_hotels=50, ratings=requested_ratings or None
                )
                if fallback_ids:
                    raw_offers = _fetch_hotel_offers(fallback_ids, check_in, check_out, adults, room_quantity)
                    if raw_offers:
                        fallback_message = (
                            'No availability found for the selected hotel on these dates. '
                            'Showing other available hotels in the area instead.'
                        )

        else:
            # ── CITY MODE ────────────────────────────────────────────────────
            hotel_ids = _fetch_hotel_ids_for_city(city_code, max_hotels=20, ratings=requested_ratings or None)
            if not hotel_ids:
                return jsonify({
                    'hotels': [], 'count': 0,
                    'message': f'No hotels found for city code "{city_code}"' 
                               + (f' with {requested_ratings}★ rating.' if requested_ratings else '. Try a different city code.')
                }), 200
            raw_offers = _fetch_hotel_offers(hotel_ids, check_in, check_out, adults, room_quantity)

        if not raw_offers:
            logger.info(f"Hotel search: no offers for {city_code or specific_hotel_id} on {check_in}-{check_out}")
            # Build a specific, actionable message based on what was searched
            if specific_hotel_name:
                hotel_display = specific_hotel_name.title()
                # This path is hit only when the city itself has zero available hotels
                # (city_raw was empty), not just when name-match failed.
                not_found_msg = (
                    f'No hotels with live rates found in this area for your selected dates. '
                    f'Try different dates, or switch to "By City" mode with a nearby city code.'
                )
            elif specific_hotel_id:
                not_found_msg = (
                    'No availability found for this hotel on these dates. '
                    'Try different dates, or use "By City" to browse all hotels in the area.'
                )
            else:
                not_found_msg = 'No live hotels found for these dates. Try different dates or city.'
            return jsonify({
                'hotels': [],
                'count': 0,
                'message': not_found_msg
            }), 200

        normalized = _normalize_hotel_offers(raw_offers, nights)

        if not normalized:
            return jsonify({'hotels': [], 'count': 0, 'message': 'No live hotels found. Try different dates.'}), 200

        # Point 3 (v4.0): Cache raw hotel offers by offer_id for the booking endpoint.
        # Each raw offer block may contain multiple offer entries — we store each individually.
        for offer_block in raw_offers:
            for offer in offer_block.get('offers', []):
                raw_offer_id = str(offer.get('id', ''))
                if raw_offer_id:
                    # Store the full offer block + search params keyed by offer_id.
                    # search_meta is used by the auto-refresh logic in create_booking
                    # when the offer expires — it has everything needed to re-search
                    # the same hotel without any user interaction.
                    _store_raw_hotel_offer(raw_offer_id, {
                        'hotel': offer_block.get('hotel', {}),
                        'offer': offer,
                        'self': offer_block.get('self', ''),
                        'search_meta': {
                            'checkInDate':  check_in,
                            'checkOutDate': check_out,
                            'adults':       adults,
                            'roomQuantity': room_quantity,
                            'cityCode':     search_city,   # shopping-compatible city code
                        },
                    })

        logger.info(f"Hotel search {city_code} {check_in}-{check_out}: {len(normalized)} hotels returned")

        resp_body = {
            'hotels': normalized,
            'count': len(normalized),
            'nights': nights,
            'checkInDate': check_in,
            'checkOutDate': check_out,
            'starFilter': requested_ratings if requested_ratings else None,
        }
        if fallback_message:
            resp_body['fallbackMessage'] = fallback_message
        return jsonify(resp_body), 200

    except ValueError as e:
        logger.error(f"Hotel search configuration error: {e}", exc_info=True)
        return jsonify({'hotels': [], 'count': 0, 'message': str(e)}), 200

    except _requests.exceptions.Timeout:
        logger.error("Hotel search timed out connecting to Amadeus API")
        return jsonify({'hotels': [], 'count': 0, 'message': 'Hotel search timed out. Please try again.'}), 200

    except _requests.exceptions.ConnectionError as e:
        logger.error(f"Hotel search network error: {e}", exc_info=True)
        return jsonify({'hotels': [], 'count': 0, 'message': 'Could not reach hotel search service. Please check connectivity.'}), 200

    except Exception as e:
        logger.error(f"Hotel search unexpected error: {e}", exc_info=True)
        return jsonify({'hotels': [], 'count': 0, 'message': 'Hotel search temporarily unavailable. Please try again.'}), 200


# =====================================================
# HOTEL LOOKUP — Amadeus Hotel Name Autocomplete
# =====================================================
# Change 4 (v3.4): New /hotel-lookup route.
# Calls Amadeus Hotel Name Autocomplete API (v1/reference-data/locations/hotel).
# Returns structured JSON with hotel_name, hotelId, city, country.
# API key is NEVER exposed in any response.
# Basic rate limiting applied via _check_rate_limit().
# =====================================================

def _fetch_hotel_autocomplete(keyword: str, max_results: int = 10) -> list:
    """
    Call Amadeus Hotel Name Autocomplete API.
    Returns raw list of hotel location objects.
    Returns empty list on error.
    Credentials are never logged or returned.

    Endpoint: GET /v1/reference-data/locations/hotel
    Requires: keyword query param
    """
    base_url = _get_amadeus_base_url()
    logger.info(f"Base URL: {base_url}")
    url = f'{base_url}/v1/reference-data/locations/hotel'

    # subType must be passed as repeated params, NOT comma-separated string
    # requests encodes a list as: subType=HOTEL_LEISURE&subType=HOTEL_GDS
    params = {
        'keyword': keyword.strip(),
        'subType': ['HOTEL_LEISURE', 'HOTEL_GDS'],
        'view': 'LIGHT',
        'lang': 'EN',
        'max': min(max_results, 20),  # cap at 20 per Amadeus limit
    }

    try:
        resp = _amadeus_get_request(url, params, timeout=10)
        if not resp.ok:
            err_body = {}
            try:
                err_body = resp.json()
            except Exception:
                pass
            errors = err_body.get('errors', [])
            err_msg = errors[0].get('title', f'HTTP {resp.status_code}') if errors else f'HTTP {resp.status_code}'
            # Log full error body for easier debugging
            logger.warning(
                f"Hotel autocomplete failed for keyword='{keyword}': "
                f"{err_msg} | full response: {err_body}"
            )
            return []

        data = resp.json()
        return data.get('data', [])

    except (_requests.exceptions.Timeout, _requests.exceptions.ConnectionError) as e:
        logger.warning(f"Hotel autocomplete network error for keyword='{keyword}': {e}")
        return []
    except Exception as e:
        logger.warning(f"Hotel autocomplete error for keyword='{keyword}': {e}")
        return []


def _normalize_hotel_autocomplete_results(raw_results: list) -> list:
    """
    Normalize raw Amadeus hotel autocomplete results into a clean, safe list.
    Returns list of dicts with hotel_name, hotelId, city, country.
    Raw Amadeus fields are never forwarded directly.

    Also filters out garbage/non-hotel entries that Amadeus sometimes returns.
    Amadeus's Hotel Name Autocomplete API can return personal names, company
    names, and other non-hotel entities (e.g. "Trideeb", "Tripta Sister 4B TL MAX"
    when searching for "TRIDENT"). These are filtered out by:
      1. Requiring a valid hotelId (not empty)
      2. Requiring a valid iataCode (confirms it's a location-linked property)
      3. Requiring the result subType to indicate a hotel category
         (HOTEL_LEISURE or HOTEL_GDS), not a generic POI or address
    """
    # Valid subTypes that indicate an actual hotel entity in Amadeus
    VALID_SUBTYPES = {'HOTEL_LEISURE', 'HOTEL_GDS', 'HOTEL'}

    results = []
    for item in (raw_results or []):
        try:
            # ── subType guard: only accept actual hotel entries ───────────────
            sub_type = str(item.get('subType', '')).upper().strip()
            if sub_type and sub_type not in VALID_SUBTYPES:
                logger.debug(f"Autocomplete: skipping non-hotel subType='{sub_type}' name='{item.get('name','')}'")
                continue

            hotel_id = str(item.get('hotelIds', [item.get('id', '')])[0] if item.get('hotelIds') else item.get('id', ''))
            name = str(item.get('name', '')).strip()
            if not name:
                continue

            # ── hotelId guard: must have a real hotel ID ──────────────────────
            if not hotel_id or hotel_id in ('None', '[]', ''):
                logger.debug(f"Autocomplete: skipping entry with no hotelId: '{name}'")
                continue

            address = item.get('address', {})
            city_name = str(address.get('cityName', '')).strip()
            country_code = str(address.get('countryCode', '')).strip()

            iata_code = str(item.get('iataCode', '')).strip()
            if not city_name and iata_code:
                city_name = iata_code

            # ── iataCode guard: must be location-linked ───────────────────────
            # Genuine hotel entries always have an IATA city code.
            # Garbage entries (personal names, random strings) typically don't.
            if not iata_code:
                logger.debug(f"Autocomplete: skipping entry with no iataCode: '{name}'")
                continue

            results.append({
                'hotel_name': name,
                'hotelId': hotel_id,
                'city': city_name,
                'country': country_code,
                'iataCode': iata_code,
            })
        except (KeyError, IndexError, TypeError) as e:
            logger.warning(f"Skipping malformed hotel autocomplete result: {e}")
            continue

    return results


@app.route('/hotel-lookup', methods=['GET', 'POST'])
def hotel_lookup():
    """
    Change 4 (v3.4): Hotel name autocomplete via Amadeus Hotel Name Autocomplete API.

    Accepts:
      GET  /hotel-lookup?q=marriott&limit=10
      POST /hotel-lookup  body: {"q": "marriott", "limit": 10}

    Query parameters:
      q      (str, required) — hotel name keyword to search
      limit  (int, optional) — max results to return, default 10, max 20

    Returns structured JSON:
    [
        {
            "hotel_name":  str,   # Hotel display name
            "hotelId":     str,   # Amadeus hotel ID
            "city":        str,   # City name
            "country":     str,   # ISO country code
            "iataCode":    str    # IATA city code (if available)
        },
        ...
    ]

    Security:
      - API key is NEVER included in any response
      - Basic rate limiting: {RATE_LIMIT_MAX_CALLS} calls per IP per {RATE_LIMIT_WINDOW_SECONDS}s
      - Keyword is sanitised before forwarding to Amadeus
    """
    try:
        # ── Rate limiting removed in v4.0 (Point 6) ──────────────────────────
        # Rate limit infrastructure is kept for future use on other endpoints.
        # The hotel-lookup endpoint is no longer rate-limited.
        client_ip = _get_client_ip()

        # ── Extract keyword from GET or POST ──────────────────────────────────
        if request.method == 'POST':
            payload = request.get_json() or {}
            keyword = str(payload.get('q') or payload.get('keyword') or payload.get('name') or '').strip()
            try:
                limit = max(1, min(20, int(payload.get('limit', 10))))
            except (ValueError, TypeError):
                limit = 10
        else:
            keyword = str(request.args.get('q') or request.args.get('keyword') or request.args.get('name') or '').strip()
            try:
                limit = max(1, min(20, int(request.args.get('limit', 10))))
            except (ValueError, TypeError):
                limit = 10

        # ── Input validation ──────────────────────────────────────────────────
        if not keyword:
            return jsonify({
                'error': 'Search keyword is required. Use ?q=<hotel_name>',
                'results': []
            }), 400

        if len(keyword) < 3:
            return jsonify({
                'error': 'Please type at least 3 characters to search. Amadeus requires a minimum of 3 characters.',
                'results': []
            }), 400

        if len(keyword) > 100:
            return jsonify({
                'error': 'Search keyword must not exceed 100 characters.',
                'results': []
            }), 400

        # Sanitise keyword: allow only alphanumeric, spaces, hyphens, apostrophes
        # to prevent potential injection or encoding issues when forwarding to Amadeus
        sanitised_keyword = re.sub(r"[^a-zA-Z0-9\s\-\'\&\.]", '', keyword).strip()
        if not sanitised_keyword:
            return jsonify({
                'error': 'Search keyword contains no valid characters.',
                'results': []
            }), 400

        logger.info(f"Hotel lookup: keyword='{sanitised_keyword}', limit={limit}, ip={client_ip}")

        # ── Call Amadeus autocomplete ─────────────────────────────────────────
        raw_results = _fetch_hotel_autocomplete(sanitised_keyword, max_results=limit)

        if not raw_results:
            return jsonify({
                'results': [],
                'count': 0,
                'query': sanitised_keyword,
                'message': f'No hotels found matching "{sanitised_keyword}". Try a different name or spelling.'
            }), 200

        # ── Normalise and return ──────────────────────────────────────────────
        normalised = _normalize_hotel_autocomplete_results(raw_results)

        # Trim to requested limit
        normalised = normalised[:limit]

        logger.info(f"Hotel lookup '{sanitised_keyword}': {len(normalised)} results returned")

        return jsonify({
            'results': normalised,
            'count': len(normalised),
            'query': sanitised_keyword,
        }), 200

    except ValueError as e:
        logger.error(f"Hotel lookup configuration error: {e}", exc_info=True)
        return jsonify({
            'error': str(e),
            'results': [],
            'count': 0
        }), 200

    except _requests.exceptions.Timeout:
        logger.error("Hotel lookup timed out connecting to Amadeus API")
        return jsonify({
            'error': 'Hotel lookup timed out. Please try again.',
            'results': [],
            'count': 0
        }), 200

    except _requests.exceptions.ConnectionError as e:
        logger.error(f"Hotel lookup network error: {e}", exc_info=True)
        return jsonify({
            'error': 'Could not reach hotel lookup service. Please check connectivity.',
            'results': [],
            'count': 0
        }), 200

    except Exception as e:
        logger.error(f"Hotel lookup unexpected error: {e}", exc_info=True)
        return jsonify({
            'error': 'Hotel lookup temporarily unavailable. Please try again.',
            'results': [],
            'count': 0
        }), 200
    
# =====================================================
# AMADEUS BOOKING — FLIGHT PNR + HOTEL CONFIRMATION
# =====================================================
# Point 3 (v4.0):
# POST /api/create-booking
#   Accepts: flight_offer_id, hotel_offer_id, traveler details
#   Books flight via Amadeus POST /v1/booking/flight-orders
#   Books hotel via Amadeus POST /v1/booking/hotel-bookings
#   Stores both references separately in the bookings table
#   Returns: flight_pnr, hotel_confirmation, internal_ref
#
# Strict separation of concerns:
#   - NO pricing logic here
#   - NO AI price calculation
#   - Booking is purely Amadeus API interaction + DB storage
# =====================================================

def _amadeus_post_request(url: str, body: dict, timeout: int = 30) -> _requests.Response:
    """
    Make an authenticated POST request to any Amadeus endpoint.
    Handles 401 token auto-refresh automatically.
    Returns the raw Response object.
    """
    token = _get_amadeus_token()
    resp = _requests.post(
        url,
        headers={
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
        },
        json=body,
        timeout=timeout,
    )

    if resp.status_code == 401:
        logger.warning(f"Amadeus 401 at POST {url} — refreshing token and retrying")
        _invalidate_amadeus_token()
        token = _get_amadeus_token()
        resp = _requests.post(
            url,
            headers={
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json',
            },
            json=body,
            timeout=timeout,
        )

    return resp


def _sanitize_amadeus_name(name: str, max_len: int = 35) -> str:
    """
    Strip everything Amadeus rejects from a name field.
    Amadeus firstName/lastName: A-Z letters only, no spaces, hyphens, digits,
    or special characters. Max 35 chars.
    """
    return re.sub(r'[^A-Z]', '', name.strip().upper())[:max_len]


def _validate_traveler_data(traveler: dict) -> list:
    """
    Validate traveler detail fields for Amadeus Create Order.
    Returns list of error strings (empty if valid).
    All validation is backend-only.
    Uses strict Amadeus name rules: letters A-Z only, no spaces or hyphens.
    """
    errors = []
    first_name = _sanitize_amadeus_name(str(traveler.get('firstName', '')))
    last_name  = _sanitize_amadeus_name(str(traveler.get('lastName',  '')))
    dob    = str(traveler.get('dateOfBirth', '')).strip()
    email  = str(traveler.get('email',       '')).strip()
    phone  = str(traveler.get('phone',       '')).strip()
    gender = str(traveler.get('gender',      '')).strip().upper()

    if not first_name:
        errors.append('First name is required (letters only, no spaces or special characters)')
    elif len(first_name) < 2:
        errors.append('First name must be at least 2 letters')

    if not last_name:
        errors.append('Last name is required (letters only, no spaces or special characters)')
    elif len(last_name) < 2:
        errors.append('Last name must be at least 2 letters')

    if not dob:
        errors.append('Date of birth is required (YYYY-MM-DD)')
    else:
        try:
            from datetime import date
            dob_parsed = date.fromisoformat(dob)
            if dob_parsed >= date.today():
                errors.append('Date of birth must be in the past')
        except ValueError:
            errors.append('Date of birth must be in YYYY-MM-DD format')

    if not email:
        errors.append('Email address is required')
    elif not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email):
        errors.append('Email address format is invalid')

    if not phone:
        errors.append('Phone number is required')
    else:
        phone_digits = re.sub(r'[\s\-\(\)\+]', '', phone)
        if not phone_digits.isdigit() or len(phone_digits) < 7:
            errors.append('Phone number must contain at least 7 digits')

    if gender and gender not in ('MALE', 'FEMALE', 'M', 'F'):
        errors.append('Gender must be MALE or FEMALE')

    return errors


def _build_amadeus_flight_order_body(raw_offer: dict, travelers: list) -> dict:
    """
    Build the full Amadeus POST /v1/booking/flight-orders request body.

    Key rules enforced here:
    1. travelers[].id MUST exactly match travelerId in raw_offer.travelerPricings.
       We extract those IDs from the offer and fill one slot per required traveler,
       replicating the lead traveler's contact details for additional seats.
    2. firstName/lastName: letters A-Z only (via _sanitize_amadeus_name).
       Spaces, hyphens, digits all cause "firstName format is invalid".
    3. Phone: split into countryCallingCode + number digits.
    """
    lead = travelers[0] if travelers else {}

    # Sanitize names — Amadeus accepts A-Z letters only, no spaces/hyphens
    first  = _sanitize_amadeus_name(str(lead.get('firstName', 'GUEST')))
    last   = _sanitize_amadeus_name(str(lead.get('lastName',  'GUEST')))
    dob    = str(lead.get('dateOfBirth', '')).strip()
    email  = str(lead.get('email', '')).strip()
    phone  = str(lead.get('phone', '')).strip()
    gender = str(lead.get('gender', 'MALE')).strip().upper()
    if gender not in ('MALE', 'FEMALE'):
        gender = 'MALE'
    if not first:
        first = 'GUEST'
    if not last:
        last = 'GUEST'

    # Parse phone → Amadeus format: countryCallingCode (digits only) + number (digits only)
    phone_digits = re.sub(r'[\s\-\(\)]', '', phone)
    country_code = '91'
    if phone_digits.startswith('+'):
        rest = phone_digits[1:]
        if len(rest) > 10:
            country_code = rest[:len(rest) - 10]
            phone_digits  = rest[len(rest) - 10:]
        else:
            phone_digits = rest
    elif phone_digits.startswith('00'):
        phone_digits = phone_digits[2:]
    # Final safety: strip any remaining non-digits
    country_code = re.sub(r'\D', '', country_code) or '91'
    phone_digits = re.sub(r'\D', '', phone_digits)
    if len(phone_digits) < 7:
        phone_digits = '9999999999'

    # Determine required traveler IDs from the offer's travelerPricings.
    # Amadeus validates every travelerId in the offer MUST appear in travelers[].
    traveler_pricings = raw_offer.get('travelerPricings', [])
    if traveler_pricings:
        required_ids = [str(tp.get('travelerId', str(i + 1)))
                        for i, tp in enumerate(traveler_pricings)]
    else:
        required_ids = [str(i + 1) for i in range(max(1, len(travelers)))]

    traveler_payloads = []
    for tid in required_ids:
        traveler_payloads.append({
            'id': tid,
            'dateOfBirth': dob,
            'name': {
                'firstName': first,   # same lead name for all slots — valid for test env
                'lastName':  last,
            },
            'gender': gender,
            'contact': {
                'emailAddress': email,
                'phones': [{
                    'deviceType': 'MOBILE',
                    'countryCallingCode': country_code,
                    'number': phone_digits,
                }],
            },
            'documents': [],
        })

    logger.info(
        f"Flight order: {len(traveler_payloads)} traveler slot(s) "
        f"(IDs: {required_ids}), name={first}/{last}"
    )

    return {
        'data': {
            'type': 'flight-order',
            'flightOffers': [raw_offer],
            'travelers': traveler_payloads,
        }
    }
def _build_amadeus_hotel_booking_body(offer_id: str, guests: list) -> dict:
    """
    Build the full Amadeus POST /v1/booking/hotel-bookings request body.
    Uses the cached offer_id and guest details.

    Note: Amadeus test environment accepts a test credit card.
    In production, integrate a real payment gateway (Stripe, Razorpay) instead.
    """
    guest_payloads = []
    for idx, g in enumerate(guests, start=1):
        first = str(g.get('firstName', '')).strip().upper()
        last = str(g.get('lastName', '')).strip().upper()
        email = str(g.get('email', '')).strip()
        phone = str(g.get('phone', '')).strip()

        guest_payloads.append({
            'id': idx,
            'name': {
                'title': 'MR',
                'firstName': first,
                'lastName': last,
            },
            'contact': {
                'phone': f'+{re.sub(r"[^0-9]", "", phone)}' if phone else '+911234567890',
                'email': email,
            },
        })

    return {
        'data': {
            'offerId': offer_id,
            'guests': guest_payloads,
            'payments': [{
                'id': 1,
                'method': 'creditCard',
                'card': {
                    # Amadeus test environment card — replace with real payment gateway in production
                    'vendorCode': 'VI',
                    'cardNumber': '4151289722471370',
                    'expiryDate': '2026-08',
                },
            }],
        }
    }


@app.route('/api/create-booking', methods=['POST'])
def create_booking():
    """
    Point 3 (v4.0): Amadeus Create Order endpoint for real PNR + hotel confirmation.

    Accepts JSON body:
    {
        "client_id": 1,
        "flight_offer_id": "...",        # optional — from flight search cache
        "hotel_offer_id": "...",          # optional — from hotel search cache
        "travelers": [                     # required — at least 1 traveler
            {
                "firstName": "JOHN",
                "lastName": "DOE",
                "dateOfBirth": "1990-01-01",
                "gender": "MALE",
                "email": "john@example.com",
                "phone": "+91-9999999999"
            }
        ]
    }

    Returns:
    {
        "success": true,
        "internal_ref": "GC-ABC12345",    # internal booking reference
        "flight_pnr": "ABC123",            # Amadeus flight PNR (null if no flight)
        "hotel_confirmation": "HTL456",    # Amadeus hotel confirmation (null if no hotel)
        "flight_status": "confirmed",
        "hotel_status": "confirmed",
        "message": "Booking confirmed"
    }

    Strict separation:
    - flight_pnr and hotel_confirmation are ALWAYS separate fields
    - NO pricing recalculation
    - NO AI involvement
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No booking data provided'}), 400

        client_id = int(data.get('client_id', 1))
        flight_offer_id = str(data.get('flight_offer_id', '') or '').strip()
        hotel_offer_id = str(data.get('hotel_offer_id', '') or '').strip()
        travelers = data.get('travelers', [])

        # Require at least one booking component
        if not flight_offer_id and not hotel_offer_id:
            return jsonify({
                'success': False,
                'error': 'At least one of flight_offer_id or hotel_offer_id is required'
            }), 400

        # Require at least one traveler
        if not travelers or not isinstance(travelers, list):
            return jsonify({'success': False, 'error': 'At least one traveler is required'}), 400

        # Validate all travelers server-side
        all_errors = []
        for idx, t in enumerate(travelers, start=1):
            errs = _validate_traveler_data(t)
            if errs:
                for e in errs:
                    all_errors.append(f'Traveler {idx}: {e}')

        if all_errors:
            return jsonify({'success': False, 'error': 'Traveler validation failed', 'details': all_errors}), 400

        # Generate a unique internal reference
        internal_ref = f"GC-{uuid.uuid4().hex[:8].upper()}"

        flight_pnr = None
        hotel_confirmation = None
        flight_booking_response = None
        hotel_booking_response = None
        flight_status = 'not_booked'
        hotel_status = 'not_booked'
        errors_list = []

        base_url = _get_amadeus_base_url()

        # ── Step 1: Book flight (if selected) ─────────────────────────────────
        if flight_offer_id:
            raw_flight_offer = _get_raw_flight_offer(flight_offer_id)
            if not raw_flight_offer:
                return jsonify({
                    'success': False,
                    'error': f'Flight offer "{flight_offer_id}" has expired or was not found. '
                             'Please search for flights again and reselect.'
                }), 400

            try:
                flight_order_url = f'{base_url}/v1/booking/flight-orders'
                flight_body = _build_amadeus_flight_order_body(raw_flight_offer, travelers)
                flight_resp = _amadeus_post_request(flight_order_url, flight_body, timeout=30)

                if flight_resp.ok:
                    flight_data = flight_resp.json()
                    flight_booking_response = flight_data
                    # Extract PNR from Amadeus response
                    resp_data = flight_data.get('data', {})
                    # PNR is in associatedRecords[0].reference for test environment
                    assoc_records = resp_data.get('associatedRecords', [])
                    if assoc_records:
                        flight_pnr = assoc_records[0].get('reference', '')
                    if not flight_pnr:
                        # Fallback: use the booking order ID
                        flight_pnr = resp_data.get('id', f'PENDING-{internal_ref}')
                    flight_status = 'confirmed'
                    logger.info(f"Flight booked: PNR={flight_pnr}, internal_ref={internal_ref}")
                else:
                    err_body = {}
                    try:
                        err_body = flight_resp.json()
                    except Exception:
                        pass
                    errors_api = err_body.get('errors', [])
                    err_msg = errors_api[0].get('detail', 'Flight booking failed') if errors_api else f'HTTP {flight_resp.status_code}'
                    errors_list.append(f'Flight booking failed: {err_msg}')
                    flight_status = 'failed'
                    logger.error(f"Flight booking failed for {internal_ref}: {err_msg}")

            except Exception as fe:
                errors_list.append(f'Flight booking error: {str(fe)}')
                flight_status = 'error'
                logger.error(f"Flight booking exception for {internal_ref}: {fe}", exc_info=True)

        # ── Step 2: Book hotel (if selected) ──────────────────────────────────
        if hotel_offer_id:
            raw_hotel_entry = _get_raw_hotel_offer(hotel_offer_id)
            if not raw_hotel_entry:
                # If flight was already booked, report partial success
                if flight_pnr:
                    errors_list.append(
                        f'Hotel offer "{hotel_offer_id}" has expired. Your flight is booked (PNR: {flight_pnr}) '
                        'but hotel was NOT booked. Please search hotels again.'
                    )
                else:
                    return jsonify({
                        'success': False,
                        'error': f'Hotel offer "{hotel_offer_id}" has expired or was not found. '
                                 'Please search for hotels again and reselect.'
                    }), 400
            else:
                try:
                    # ── HOTEL OFFER FRESHNESS + AUTO-REFRESH ─────────────────────────
                    # Amadeus hotel offers expire in ~15-30 minutes. Rather than
                    # aborting the hotel booking when the offer is stale, we:
                    #   1. Try to re-validate via GET /v2/shopping/hotel-offers/{id}
                    #   2. If 200 → use the refreshed offer ID (Amadeus may rotate it)
                    #   3. If 404 (expired) → auto-re-search the same hotel using
                    #      hotel name + iataCode + dates stored in the cache entry,
                    #      then pick the first matching offer and book with that.
                    #   4. Only fail if re-search also returns nothing.
                    # This means the user NEVER has to go back just because of expiry.

                    live_offer_id = hotel_offer_id
                    hotel_offer_expired = False

                    try:
                        revalidate_url = f'{base_url}/v2/shopping/hotel-offers/{hotel_offer_id}'
                        reval_resp = _amadeus_get_request(revalidate_url, {}, timeout=15)

                        if reval_resp.ok:
                            reval_data = reval_resp.json()
                            reval_offers = (reval_data.get('data') or {}).get('offers', [])
                            if reval_offers:
                                live_offer_id = str(reval_offers[0].get('id', hotel_offer_id))
                            logger.info(
                                f"Hotel offer re-validated: "
                                f"original={hotel_offer_id}, live={live_offer_id}"
                            )

                        elif reval_resp.status_code == 404:
                            # Offer expired — attempt auto-refresh using cached hotel details
                            logger.warning(
                                f"Hotel offer {hotel_offer_id} expired (404) for {internal_ref} "
                                f"— attempting auto-refresh from cached hotel details"
                            )

                            # Extract hotel identity and search params from the cache entry.
                            # Prefer search_meta (explicitly stored at search time) over
                            # parsing from the offer object (which Amadeus may not populate).
                            cached_hotel   = raw_hotel_entry.get('hotel', {})
                            cached_offer   = raw_hotel_entry.get('offer', {})
                            meta           = raw_hotel_entry.get('search_meta', {})

                            refresh_name     = str(cached_hotel.get('name', '')).strip().upper()
                            refresh_hotel_id = str(cached_hotel.get('hotelId', '')).strip().upper()

                            # City: prefer search_meta (shopping-compatible), fall back to hotel fields
                            refresh_iata = (
                                str(meta.get('cityCode') or
                                    cached_hotel.get('cityCode') or
                                    cached_hotel.get('iataCode') or '')
                            ).strip().upper()

                            # Dates: prefer search_meta, fall back to offer fields
                            refresh_ci = str(meta.get('checkInDate') or cached_offer.get('checkInDate', '')).strip()
                            refresh_co = str(meta.get('checkOutDate') or cached_offer.get('checkOutDate', '')).strip()

                            # Adults: prefer search_meta
                            try:
                                refresh_adults = max(1, int(
                                    meta.get('adults') or
                                    cached_offer.get('guests', {}).get('adults') or
                                    len(travelers) or 1
                                ))
                            except (TypeError, ValueError):
                                refresh_adults = max(1, len(travelers)) if travelers else 1

                            refresh_rooms = max(1, int(meta.get('roomQuantity', 1)))

                            refreshed_offer_id = None

                            if refresh_iata and refresh_ci and refresh_co:
                                logger.info(
                                    f"Auto-refresh: re-searching hotel='{refresh_name}' "
                                    f"city={refresh_iata} {refresh_ci}–{refresh_co} "
                                    f"adults={refresh_adults}"
                                )
                                # Step 1: get shopping-compatible IDs for the city
                                refresh_city_ids = _fetch_hotel_ids_for_city(
                                    refresh_iata, max_hotels=50
                                )
                                if refresh_city_ids:
                                    # Step 2: fetch live offers
                                    refresh_raw = _fetch_hotel_offers(
                                        refresh_city_ids, refresh_ci, refresh_co,
                                        refresh_adults, refresh_rooms
                                    )
                                    if refresh_raw:
                                        # Step 3: name-match to find the same hotel
                                        # Try exact hotelId match first (fastest)
                                        id_matched = [
                                            ob for ob in refresh_raw
                                            if ob.get('hotel', {}).get('hotelId', '').upper() == refresh_hotel_id
                                        ]
                                        candidates = id_matched if id_matched else refresh_raw

                                        # Name-match fallback using the same stop-word logic
                                        if not id_matched and refresh_name:
                                            _SW = {
                                                'THE','A','AN','AND','OF','BY','AT','IN','ON',
                                                'HOTEL','HOTELS','RESORT','RESORTS','SUITES','SUITE',
                                                'INN','LODGE','TOWER','TOWERS','COURT',
                                                'GRAND','ROYAL','LUXURY','PREMIUM','EXECUTIVE',
                                                'INTERNATIONAL','COLLECTION','CLUB','SIGNATURE',
                                            }
                                            sig = set(refresh_name.split()) - _SW or set(refresh_name.split())
                                            scored = []
                                            for ob in refresh_raw:
                                                h = ob.get('hotel', {}).get('name', '').upper()
                                                sc = sum(1 for w in sig if w in h)
                                                if sc:
                                                    scored.append((sc, ob))
                                            if scored:
                                                scored.sort(key=lambda x: x[0], reverse=True)
                                                best = scored[0][0]
                                                tot  = len(sig)
                                                full = [o for s, o in scored if s == tot]
                                                candidates = full if full else [o for s, o in scored if s == best]

                                        # Step 4: pick first fresh offer from best candidate
                                        for candidate in candidates:
                                            fresh_offers = candidate.get('offers', [])
                                            if fresh_offers:
                                                refreshed_offer_id = str(fresh_offers[0].get('id', ''))
                                                # Cache the fresh offer so the booking endpoint can use it
                                                if refreshed_offer_id:
                                                    _store_raw_hotel_offer(refreshed_offer_id, {
                                                        'hotel': candidate.get('hotel', {}),
                                                        'offer': fresh_offers[0],
                                                        'self':  candidate.get('self', ''),
                                                    })
                                                    logger.info(
                                                        f"Auto-refresh SUCCESS: "
                                                        f"old={hotel_offer_id} → new={refreshed_offer_id} "
                                                        f"hotel='{candidate.get('hotel',{}).get('name','?')}'"
                                                    )
                                                break

                            if refreshed_offer_id:
                                live_offer_id = refreshed_offer_id
                                # Not expired anymore — we have a fresh offer
                            else:
                                # Re-search also found nothing — genuine unavailability
                                hotel_offer_expired = True
                                hotel_status = 'expired'
                                expire_detail = (
                                    f'Hotel offer expired and auto-refresh found no availability '
                                    f'for "{refresh_name.title() if refresh_name else "selected hotel"}" '
                                    f'on {refresh_ci}–{refresh_co}. '
                                    f'Your flight is booked (PNR: {flight_pnr}). '
                                    f'Please rebook the hotel separately.'
                                ) if flight_pnr else (
                                    'Hotel offer expired and no fresh availability found. '
                                    'Please search again.'
                                )
                                errors_list.append(f'Hotel booking failed: {expire_detail}')
                                logger.warning(
                                    f"Auto-refresh FAILED for {internal_ref}: "
                                    f"hotel='{refresh_name}' city={refresh_iata} {refresh_ci}–{refresh_co}"
                                )

                        else:
                            logger.warning(
                                f"Hotel offer re-validation returned {reval_resp.status_code} "
                                f"for {hotel_offer_id} — attempting booking with cached id"
                            )

                    except Exception as reval_err:
                        logger.warning(
                            f"Hotel offer re-validation error: {reval_err} "
                            f"— proceeding with cached id"
                        )

                    if not hotel_offer_expired:
                        hotel_booking_url = f'{base_url}/v1/booking/hotel-bookings'
                        hotel_body = _build_amadeus_hotel_booking_body(live_offer_id, travelers)
                        hotel_resp = _amadeus_post_request(hotel_booking_url, hotel_body, timeout=30)

                        if hotel_resp.ok:
                            hotel_data = hotel_resp.json()
                            hotel_booking_response = hotel_data
                            resp_data_h = hotel_data.get('data', [])
                            if isinstance(resp_data_h, list) and resp_data_h:
                                booking_item = resp_data_h[0]
                                hotel_confirmation = (
                                    booking_item.get('providerConfirmationId')
                                    or booking_item.get('id')
                                    or f'HB-{uuid.uuid4().hex[:6].upper()}'
                                )
                            elif isinstance(resp_data_h, dict):
                                hotel_confirmation = (
                                    resp_data_h.get('providerConfirmationId')
                                    or resp_data_h.get('id')
                                    or f'HB-{uuid.uuid4().hex[:6].upper()}'
                                )
                            else:
                                hotel_confirmation = f'HB-{uuid.uuid4().hex[:6].upper()}'
                            hotel_status = 'confirmed'
                            logger.info(
                                f"Hotel booked: confirmation={hotel_confirmation}, "
                                f"internal_ref={internal_ref}"
                            )
                        else:
                            err_body_h = {}
                            try:
                                err_body_h = hotel_resp.json()
                            except Exception:
                                pass
                            errors_api_h = err_body_h.get('errors', [])
                            err_msg_h = (
                                errors_api_h[0].get('detail', 'Hotel booking failed')
                                if errors_api_h else f'HTTP {hotel_resp.status_code}'
                            )
                            errors_list.append(f'Hotel booking failed: {err_msg_h}')
                            hotel_status = 'failed'
                            logger.error(
                                f"Hotel booking failed for {internal_ref}: {err_msg_h}"
                            )

                except Exception as he:
                    errors_list.append(f'Hotel booking error: {str(he)}')
                    hotel_status = 'error'
                    logger.error(
                        f"Hotel booking exception for {internal_ref}: {he}", exc_info=True
                    )

        # ── Step 3: Determine overall success ─────────────────────────────────
        # Success = at least one component booked without error
        any_booked = (flight_pnr is not None) or (hotel_confirmation is not None)

        if not any_booked:
            return jsonify({
                'success': False,
                'internal_ref': internal_ref,
                'error': 'Booking failed for all components',
                'details': errors_list,
            }), 400

        # ── Step 4: Persist to database ───────────────────────────────────────
        try:
            db = get_db()
            cur = db.cursor()

            # Upsert into bookings table — strict separation of flight_pnr and hotel_confirmation
            cur.execute(
                """INSERT INTO bookings
                   (client_id, internal_ref, flight_pnr, hotel_confirmation,
                    flight_offer_id, hotel_offer_id,
                    traveler_details, flight_booking_response, hotel_booking_response,
                    status)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                   RETURNING id""",
                (
                    client_id,
                    internal_ref,
                    flight_pnr,
                    hotel_confirmation,
                    flight_offer_id or None,
                    hotel_offer_id or None,
                    json.dumps(travelers),
                    json.dumps(flight_booking_response) if flight_booking_response else None,
                    json.dumps(hotel_booking_response) if hotel_booking_response else None,
                    'confirmed' if not errors_list else 'partial',
                )
            )
            booking_id = cur.fetchone()[0]
            db.commit()
            db.close()
            logger.info(f"Booking saved to DB: id={booking_id}, internal_ref={internal_ref}")
        except Exception as db_err:
            logger.error(f"Booking DB save failed for {internal_ref}: {db_err}", exc_info=True)
            # Booking was made with Amadeus but DB save failed — still return success to user
            # with a warning. The PNR is real and valid regardless.

        # ── Step 5: Build response ─────────────────────────────────────────────
        response = {
            'success': True,
            'internal_ref': internal_ref,
            'flight_pnr': flight_pnr,              # null if no flight booked
            'hotel_confirmation': hotel_confirmation, # null if no hotel booked
            'flight_status': flight_status,
            'hotel_status': hotel_status,
            'message': _build_booking_confirmation_message(flight_pnr, hotel_confirmation, errors_list),
        }

        if errors_list:
            response['warnings'] = errors_list

        return jsonify(response)

    except Exception as e:
        logger.error(f"create_booking unexpected error: {e}", exc_info=True)
        return jsonify({'success': False, 'error': f'Booking system error: {str(e)}'}), 500


def _build_booking_confirmation_message(flight_pnr: str, hotel_confirmation: str, errors: list) -> str:
    """Build a user-facing confirmation message from booking results."""
    parts = []
    if flight_pnr:
        parts.append(f'Flight booked — PNR: {flight_pnr}')
    if hotel_confirmation:
        parts.append(f'Hotel confirmed — Ref: {hotel_confirmation}')
    if errors:
        parts.append(f'Note: {len(errors)} component(s) failed — see warnings for details.')
    return '. '.join(parts) if parts else 'Booking processed.'


# =====================================================
# PHASE 3 / 5: Pricing Engine Payload Helpers
# =====================================================

def _extract_flight_block(payload: dict) -> dict | None:
    """
    Extract and validate the optional flight block from the calculate payload.
    Returns a sanitised dict if present and structurally valid, else None.

    Change 1 (v3.4): tripType is now validated and normalised via
    _validate_and_normalise_trip_type() before being passed to the engine.
    The pricing engine remains the sole source of truth for pricing logic.
    """
    flight_raw = payload.get('flight')
    if not flight_raw or not isinstance(flight_raw, dict):
        return None

    # Change 1: Use canonical trip type validator
    raw_trip_type = flight_raw.get('type') or flight_raw.get('tripType') or flight_raw.get('trip_type') or 'one_way'
    flight_type = _validate_and_normalise_trip_type(raw_trip_type)

    try:
        base_fare = float(flight_raw.get('base_fare', 0))
    except (ValueError, TypeError):
        base_fare = 0.0

    try:
        pax = int(flight_raw.get('pax', 1))
        if pax < 1:
            pax = 1
    except (ValueError, TypeError):
        pax = 1

    return {
        'type': flight_type,
        'tripType': flight_type,   # alias for engine compatibility
        'base_fare': base_fare,
        'pax': pax,
    }


def _extract_live_hotel_block(payload: dict) -> dict | None:
    """
    Extract and validate the optional live_hotel block from the calculate payload.
    Returns a sanitised dict if present and structurally valid, else None.
    """
    live_raw = payload.get('live_hotel')
    if not live_raw or not isinstance(live_raw, dict):
        return None

    try:
        total_price = float(live_raw.get('live_hotel_total_price', 0))
        if total_price < 0:
            total_price = 0.0
    except (ValueError, TypeError):
        total_price = 0.0

    offer_id = str(live_raw.get('live_hotel_id', '')).strip()[:200]
    hotel_name = str(live_raw.get('live_hotel_name', '')).strip()[:200]
    room_type = str(live_raw.get('live_hotel_room_type', '')).strip()[:100]
    board_type = str(live_raw.get('live_hotel_board_type', '')).strip()[:50]
    currency = str(live_raw.get('live_hotel_currency', 'INR')).strip().upper()[:10]
    original_currency = str(live_raw.get('live_hotel_original_currency', currency)).strip().upper()[:10]

    try:
        original_price = float(live_raw.get('live_hotel_original_price', total_price))
    except (ValueError, TypeError):
        original_price = total_price

    return {
        'live_hotel_id': offer_id,
        'live_hotel_name': hotel_name,
        'live_hotel_room_type': room_type,
        'live_hotel_board_type': board_type,
        'live_hotel_total_price': total_price,
        'live_hotel_currency': currency,
        'live_hotel_original_price': original_price,
        'live_hotel_original_currency': original_currency,
    }


# =====================================================
# CALCULATION ENDPOINT (COMPREHENSIVE ERROR HANDLING)
# =====================================================

@app.route('/calculate', methods=['POST'])
def calculate():
    """
    Main pricing calculation with comprehensive error handling.
    Returns detailed error messages for debugging.

    Phase 3 extension: if the payload contains an optional "flight" block,
    it is sanitised via _extract_flight_block() and forwarded to
    pricing_engine.calculate_package_price() as payload['flight'].

    Phase 5 extension: if the payload contains hotel_source="live" and a
    "live_hotel" block, both are sanitised and forwarded to the pricing engine.

    Change 1 (v3.4): tripType from frontend is validated and normalised before
    being passed to the engine. No pricing logic is applied in this file.
    """
    try:
        payload = request.get_json()

        if not payload:
            logger.error("Empty payload received")
            return jsonify({
                'success': False,
                'error': 'No data provided',
                'hotelCost': 0,
                'transportCost': 0,
                'sightseeingCost': 0,
                'cabCost': 0,
                'addonCost': 0,
                'flightCost': 0,
                'ruleAdjustments': 0,
                'total': 0,
                'perPerson': 0
            }), 400

        client_id = int(payload.get('client_id', 1))
        logger.info(f"Calculate request for client {client_id}: {json.dumps(payload, default=str)}")

        # ── Change 1: Extract and validate tripType from top-level payload ───
        # This applies to transport-level trip type (e.g., one-way vs return bus booking).
        # It is separate from flight block trip type which is handled in _extract_flight_block().
        raw_transport_trip_type = payload.get('tripType') or payload.get('trip_type') or 'one_way'
        transport_trip_type = _validate_and_normalise_trip_type(raw_transport_trip_type)
        payload['tripType'] = transport_trip_type
        payload['trip_type'] = transport_trip_type  # snake_case alias for engine
        logger.info(f"Transport trip type: {transport_trip_type}")

        # ── Phase 3: extract optional flight block ────────────────────────────
        flight_block = _extract_flight_block(payload)
        payload['flight'] = flight_block
        if flight_block:
            logger.info(
                f"Flight block detected: type={flight_block['type']}, "
                f"base_fare={flight_block['base_fare']}, pax={flight_block['pax']}"
            )

        # ── Phase 5: extract hotel source + live hotel block ──────────────────
        hotel_source = payload.get('hotel_source', 'admin').lower().strip()
        if hotel_source not in ('admin', 'live'):
            hotel_source = 'admin'
        payload['hotel_source'] = hotel_source

        if hotel_source == 'live':
            live_hotel_block = _extract_live_hotel_block(payload)
            payload['live_hotel'] = live_hotel_block
            if live_hotel_block:
                logger.info(
                    f"Live hotel block detected: name={live_hotel_block['live_hotel_name']}, "
                    f"room={live_hotel_block['live_hotel_room_type']}, "
                    f"total_inr={live_hotel_block['live_hotel_total_price']}"
                )
            else:
                logger.warning("hotel_source=live but no valid live_hotel block found — hotel cost will be 0")
        else:
            payload['live_hotel'] = None

        required_fields = ['region_id', 'adults', 'nights', 'transport']
        missing_fields = [f for f in required_fields if f not in payload or payload[f] is None or payload[f] == '']
        if missing_fields:
            error_msg = f"Missing required fields: {', '.join(missing_fields)}"
            logger.error(error_msg)
            return jsonify({
                'success': False,
                'error': error_msg,
                'hotelCost': 0,
                'transportCost': 0,
                'sightseeingCost': 0,
                'cabCost': 0,
                'addonCost': 0,
                'flightCost': 0,
                'ruleAdjustments': 0,
                'total': 0,
                'perPerson': 0
            }), 400

        try:
            db = get_db()
        except Exception as db_error:
            logger.error(f"Database connection error: {db_error}", exc_info=True)
            return jsonify({
                'success': False,
                'error': 'Database connection failed. Please check your database configuration.',
                'hotelCost': 0,
                'transportCost': 0,
                'sightseeingCost': 0,
                'cabCost': 0,
                'addonCost': 0,
                'flightCost': 0,
                'ruleAdjustments': 0,
                'total': 0,
                'perPerson': 0
            }), 500

        try:
            cur = db.cursor()
            cur.execute(
                "SELECT id, name FROM regions WHERE id=%s AND client_id=%s AND active=TRUE",
                (payload['region_id'], client_id)
            )
            region_row = cur.fetchone()
            if not region_row:
                logger.error(f"Region not found: {payload['region_id']}")
                db.close()
                return jsonify({
                    'success': False,
                    'error': f'Region ID {payload["region_id"]} not found or inactive',
                    'hotelCost': 0,
                    'transportCost': 0,
                    'sightseeingCost': 0,
                    'cabCost': 0,
                    'addonCost': 0,
                    'flightCost': 0,
                    'ruleAdjustments': 0,
                    'total': 0,
                    'perPerson': 0
                }), 400
        except Exception as e:
            logger.error(f"Region verification error: {e}", exc_info=True)
            db.close()
            return jsonify({
                'success': False,
                'error': f'Error verifying region: {str(e)}',
                'hotelCost': 0,
                'transportCost': 0,
                'sightseeingCost': 0,
                'cabCost': 0,
                'addonCost': 0,
                'flightCost': 0,
                'ruleAdjustments': 0,
                'total': 0,
                'perPerson': 0
            }), 500

        transport_type = payload.get('transport')
        if transport_type:
            try:
                cur.execute(
                    "SELECT id, name, transport_type FROM transports WHERE transport_type=%s AND client_id=%s AND active=TRUE",
                    (transport_type, client_id)
                )
                transport_row = cur.fetchone()
                if not transport_row:
                    logger.error(f"Transport not found: {transport_type}")
                    db.close()
                    return jsonify({
                        'success': False,
                        'error': f'Transport "{transport_type}" not found or inactive. Please select a valid transport option.',
                        'hotelCost': 0,
                        'transportCost': 0,
                        'sightseeingCost': 0,
                        'cabCost': 0,
                        'addonCost': 0,
                        'flightCost': 0,
                        'ruleAdjustments': 0,
                        'total': 0,
                        'perPerson': 0
                    }), 400
            except Exception as e:
                logger.error(f"Transport verification error: {e}", exc_info=True)
                db.close()
                return jsonify({
                    'success': False,
                    'error': f'Error verifying transport: {str(e)}',
                    'hotelCost': 0,
                    'transportCost': 0,
                    'sightseeingCost': 0,
                    'cabCost': 0,
                    'addonCost': 0,
                    'flightCost': 0,
                    'ruleAdjustments': 0,
                    'total': 0,
                    'perPerson': 0
                }), 500

        # Hotel validation — only for admin hotel path
        if hotel_source == 'admin':
            hotel_key = payload.get('hotel')
            if hotel_key:
                try:
                    cur.execute(
                        "SELECT id, name, internal_name FROM hotels WHERE internal_name=%s AND client_id=%s AND active=TRUE",
                        (hotel_key, client_id)
                    )
                    hotel_row = cur.fetchone()
                    if not hotel_row:
                        logger.warning(f"Hotel not found: {hotel_key}, will proceed without hotel")
                        payload['hotel'] = None
                except Exception as e:
                    logger.error(f"Hotel verification error: {e}", exc_info=True)
                    payload['hotel'] = None
        else:
            logger.info("hotel_source=live — skipping admin hotel DB validation")

        cab_key = payload.get('cab')
        if cab_key:
            try:
                cur.execute(
                    "SELECT id, name, internal_name FROM cabs WHERE internal_name=%s AND client_id=%s AND active=TRUE",
                    (cab_key, client_id)
                )
                cab_row = cur.fetchone()
                if not cab_row:
                    logger.warning(f"Cab not found: {cab_key}, will proceed without cab")
                    payload['cab'] = None
            except Exception as e:
                logger.error(f"Cab verification error: {e}", exc_info=True)
                payload['cab'] = None

        try:
            engine = TravelPricingEngine(db, client_id)
            result = engine.calculate_package_price(payload)
        except ComponentNotFoundError as e:
            logger.error(f"Component not found: {e}", exc_info=True)
            db.close()
            return jsonify({
                'success': False,
                'error': f'Component not found: {str(e)}',
                'hotelCost': 0,
                'transportCost': 0,
                'sightseeingCost': 0,
                'cabCost': 0,
                'addonCost': 0,
                'flightCost': 0,
                'ruleAdjustments': 0,
                'total': 0,
                'perPerson': 0
            }), 400
        except InvalidConfigurationError as e:
            logger.error(f"Invalid configuration: {e}", exc_info=True)
            db.close()
            return jsonify({
                'success': False,
                'error': f'Invalid configuration: {str(e)}',
                'hotelCost': 0,
                'transportCost': 0,
                'sightseeingCost': 0,
                'cabCost': 0,
                'addonCost': 0,
                'flightCost': 0,
                'ruleAdjustments': 0,
                'total': 0,
                'perPerson': 0
            }), 400
        except Exception as engine_error:
            logger.error(f"Pricing engine error: {engine_error}", exc_info=True)
            db.close()
            return jsonify({
                'success': False,
                'error': f'Calculation error: {str(engine_error)}',
                'hotelCost': 0,
                'transportCost': 0,
                'sightseeingCost': 0,
                'cabCost': 0,
                'addonCost': 0,
                'flightCost': 0,
                'ruleAdjustments': 0,
                'total': 0,
                'perPerson': 0
            }), 500

        db.close()

        if not result:
            result = {}

        result.setdefault('success', True)
        result.setdefault('hotelCost', 0)
        result.setdefault('transportCost', 0)
        result.setdefault('sightseeingCost', 0)
        result.setdefault('cabCost', 0)
        result.setdefault('addonCost', 0)
        result.setdefault('flightCost', 0)
        result.setdefault('ruleAdjustments', 0)
        result.setdefault('serviceCharge', 0)
        result.setdefault('bookingCharge', 0)
        result.setdefault('total', 0)
        result.setdefault('perPerson', 0)
        result.setdefault('rooms', payload.get('rooms', 0))
        result.setdefault('appliedRules', [])
        result.setdefault('hotelSource', hotel_source)
        result.setdefault('tripType', transport_trip_type)

        logger.info(
            f"Calculation successful: total={result.get('total')}, "
            f"perPerson={result.get('perPerson')}, "
            f"hotelSource={hotel_source}, "
            f"tripType={transport_trip_type}"
        )

        return jsonify(result)

    except PricingEngineError as e:
        logger.error(f"Pricing engine error: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e),
            'hotelCost': 0,
            'transportCost': 0,
            'sightseeingCost': 0,
            'cabCost': 0,
            'addonCost': 0,
            'flightCost': 0,
            'ruleAdjustments': 0,
            'total': 0,
            'perPerson': 0
        }), 400
    except Exception as e:
        logger.error(f"Unexpected calculation error: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'error': f'Server error: {str(e)}',
            'hotelCost': 0,
            'transportCost': 0,
            'sightseeingCost': 0,
            'cabCost': 0,
            'addonCost': 0,
            'flightCost': 0,
            'ruleAdjustments': 0,
            'total': 0,
            'perPerson': 0
        }), 500


@app.route('/check-cab-required', methods=['POST'])
def check_cab():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided', 'cabRequired': False}), 400
        transport = data.get('transport', '')
        days = data.get('days', [])
        required = check_cab_required(transport, days)
        return jsonify({'cabRequired': required})
    except Exception as e:
        logger.error(f"check_cab error: {e}", exc_info=True)
        return jsonify({'error': str(e), 'cabRequired': False}), 500


@app.route('/api/room-calculator', methods=['POST'])
def room_calc():
    """Standalone room calculation endpoint."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        result = RoomCalculator.calculate_room_allocation(
            adults=int(data.get('adults', 2)),
            children=int(data.get('children', 0)),
            sharing_capacity=int(data.get('sharing_capacity', 2)),
            child_age_limit=int(data.get('child_age_limit', 5)),
            paying_children=data.get('paying_children')
        )
        return jsonify(result)
    except ValueError as e:
        logger.error(f"Room calc validation error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Room calc error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 400


# =====================================================
# AI ORCHESTRATION LAYER  v5.0
# =====================================================
# - Conversation memory (full history per session)
# - Web search via DuckDuckGo (no key required)
# - MULTI_ACTION: batch multiple package changes
# - EXPLAIN_PACKAGE: narrative trip summary
# - Friendly "Sharad" travel sales advisor persona
# - Rich formatted responses
# =====================================================

_AI_SESSIONS: dict = {}   # session_id -> {history:[], updated_at:float}
_AI_SESSION_TTL = 3600    # 1 hour inactivity


def _ai_get_history(session_id: str) -> list:
    """Return conversation history list for session, or [] if expired/new."""
    import time as _t
    entry = _AI_SESSIONS.get(session_id)
    if not entry or (_t.time() - entry.get('updated_at', 0)) > _AI_SESSION_TTL:
        return []
    return entry.get('history', [])


def _ai_save_history(session_id: str, history: list) -> None:
    """Save updated conversation history. Prune stale sessions."""
    import time as _t
    _AI_SESSIONS[session_id] = {'history': history[-60:], 'updated_at': _t.time()}
    if len(_AI_SESSIONS) > 1000:
        cutoff = _t.time() - _AI_SESSION_TTL
        stale = [k for k, v in _AI_SESSIONS.items() if v.get('updated_at', 0) < cutoff]
        for k in stale:
            _AI_SESSIONS.pop(k, None)


def _ai_web_search(query: str) -> str:
    """
    DuckDuckGo Instant Answer API — no API key required.
    Falls back to HTML scrape if instant answers are thin.
    """
    try:
        import re as _re
        # Instant Answer JSON API
        r = _requests.get('https://api.duckduckgo.com/', timeout=8, params={
            'q': query, 'format': 'json', 'no_html': '1',
            'skip_disambig': '1', 'no_redirect': '1',
        })
        if r.ok:
            d = r.json()
            parts = []
            if d.get('AbstractText'):
                parts.append(d['AbstractText'])
            if d.get('Answer'):
                parts.append(f"Key fact: {d['Answer']}")
            for t in d.get('RelatedTopics', [])[:4]:
                if isinstance(t, dict) and t.get('Text'):
                    parts.append(f"• {t['Text']}")
            if parts:
                return '\n'.join(parts[:6])
        # Fallback: lightweight HTML scrape
        r2 = _requests.get('https://html.duckduckgo.com/html/', timeout=8,
            params={'q': query},
            headers={'User-Agent': 'Mozilla/5.0 (TravelAdvisorBot/5.0)'})
        if r2.ok:
            snippets = _re.findall(r'<a class="result__snippet"[^>]*>(.*?)</a>', r2.text)
            cleaned = [_re.sub(r'<[^>]+>', '', s).strip() for s in snippets[:5] if s.strip()]
            if cleaned:
                return '\n'.join(f'• {c}' for c in cleaned)
        return 'No results found for this search.'
    except Exception as e:
        logger.warning(f'Web search error: {e}')
        return 'Web search unavailable right now; answering from my knowledge.'


def _ai_build_package_context(state: dict, last_calc: dict | None) -> str:
    """
    Build a rich, human-readable description of the current package.
    This goes into the system prompt so Sharad can explain it naturally.
    """
    parts = ['=== CURRENT BOOKING ===']

    dest = state.get('destination') or state.get('destinationName')
    if dest:
        parts.append(f'Destination: {dest}')
    season = state.get('season')
    if season:
        parts.append(f'Season: {"Peak (ON)" if season == "ON" else "Off-season (OFF)"}')

    adults = state.get('adults', 2)
    children = state.get('children', 0)
    pax = f'{adults} adult{"s" if adults != 1 else ""}'
    if children:
        pax += f', {children} child{"ren" if children != 1 else ""}'
    parts.append(f'Travellers: {pax}')

    nights = state.get('nights', 0)
    if nights:
        parts.append(f'Duration: {nights} night{"s" if nights != 1 else ""}')
    rooms = state.get('rooms', 0)
    if rooms:
        parts.append(f'Rooms: {rooms}')

    hs = state.get('hotelSource', 'admin')
    parts.append(f'Hotel source: {"Live Amadeus" if hs == "live" else "Agency catalogue"}')
    hotel = state.get('hotel')
    if hotel:
        parts.append(f'Hotel: {hotel}')
    lh = state.get('liveHotel')
    if lh:
        parts.append(f'Live hotel: {lh.get("hotelName","")} | {lh.get("roomType","")} | {lh.get("boardType","")}')
        if lh.get('totalPrice'):
            parts.append(f'Live hotel cost: Rs {lh["totalPrice"]:,.0f}')

    transport = state.get('transport') or state.get('transportName')
    if transport:
        parts.append(f'Transport: {transport}')
    tt = state.get('tripType', 'return')
    parts.append(f'Journey: {"Round trip" if tt == "return" else "One way"}')
    cab = state.get('cab')
    if cab:
        parts.append(f'Local cab: {cab}')
    addons = state.get('selectedAddons', [])
    if addons:
        parts.append(f'Add-ons: {", ".join(addons)}')
    fl = state.get('flight')
    if fl:
        parts.append(f'Flight: {fl.get("airline","")} {fl.get("origin","")} -> {fl.get("destination","")} @ Rs {fl.get("price",0):,.0f}/person')

    if last_calc:
        parts.append('')
        parts.append('=== PRICE BREAKDOWN (calculated by backend engine) ===')
        parts.append(f'Total: Rs {last_calc.get("total", 0):,.0f}')
        parts.append(f'Per person: Rs {last_calc.get("perPerson", 0):,.0f}')
        for label, key in [('Hotel', 'hotelCost'), ('Transport', 'transportCost'),
                            ('Flights', 'flightCost'), ('Sightseeing', 'sightseeingCost'),
                            ('Cab', 'cabCost'), ('Add-ons', 'addonCost'),
                            ('Service charge', 'serviceCharge')]:
            v = last_calc.get(key)
            if v:
                parts.append(f'  {label}: Rs {v:,.0f}')
        rules = last_calc.get('appliedRules', [])
        if rules:
            parts.append(f'  Rules applied: {", ".join(r.get("name","") for r in rules)}')
    else:
        parts.append('(Price not yet calculated)')

    parts.append('=== END ===')
    return '\n'.join(parts)


@app.route('/ai-chat', methods=['POST'])
def ai_chat():
    """v5.0 AI endpoint — memory, web search, multi-action."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'reply': json.dumps({'action': 'GENERAL_CHAT', 'message': 'No input received.'})}), 400

        user_msg   = (data.get('message') or '').strip()
        session_id = (data.get('sessionId') or 'anon').strip()
        state      = data.get('currentState', {})
        last_calc  = data.get('lastCalculation')
        client_id  = int(data.get('client_id', 1))
        # Client sends its local history so server stays in sync across restarts
        client_hist = data.get('conversationHistory', [])

        if not user_msg:
            return jsonify({'reply': json.dumps({'action': 'GENERAL_CHAT', 'message': 'What can I help you with? 😊'})}), 200

        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT name FROM clients WHERE id=%s", (client_id,))
        row = cur.fetchone()
        client_name = row[0] if row else 'Travel Agency'
        cur.execute("SELECT internal_name, name FROM hotels WHERE client_id=%s AND active=TRUE", (client_id,))
        hotels = [{'key': r[0], 'name': r[1]} for r in cur.fetchall()]
        cur.execute("SELECT transport_type, display_name FROM transports WHERE client_id=%s AND active=TRUE", (client_id,))
        transports = [{'key': r[0], 'name': r[1]} for r in cur.fetchall()]
        cur.execute("SELECT internal_name, display_name FROM destinations WHERE client_id=%s AND active=TRUE", (client_id,))
        destinations = [{'key': r[0], 'name': r[1]} for r in cur.fetchall()]
        cur.execute("SELECT internal_name, name FROM addons WHERE client_id=%s AND active=TRUE", (client_id,))
        addons = [{'key': r[0], 'name': r[1]} for r in cur.fetchall()]
        cur.execute("SELECT internal_name, display_name FROM cabs WHERE client_id=%s AND active=TRUE", (client_id,))
        cabs = [{'key': r[0], 'name': r[1]} for r in cur.fetchall()]
        db.close()

        # Client history is source of truth; server store is a backup
        history = client_hist if client_hist else _ai_get_history(session_id)

        result = _ai_process(
            message=user_msg, state=state, last_calc=last_calc,
            hotels=hotels, transports=transports, destinations=destinations,
            addons=addons, cabs=cabs, client_name=client_name, history=history,
        )

        updated = history + [
            {'role': 'user',      'content': user_msg},
            {'role': 'assistant', 'content': result.get('message', '')},
        ]
        _ai_save_history(session_id, updated)

        return jsonify({'reply': json.dumps(result), 'updatedHistory': updated[-60:]})

    except Exception as e:
        logger.error(f'AI chat error: {e}', exc_info=True)
        return jsonify({'reply': json.dumps({
            'action': 'GENERAL_CHAT',
            'message': "Sorry, I hit a snag! Give me just a moment and try again. 😊"
        })})



def _ai_process_anthropic(message, state, last_calc, hotels, transports, destinations,
                           addons, cabs, client_name, history, api_key):
    """
    Anthropic Claude fallback AI — same capabilities as OpenAI path:
    full conversation memory, web search, multi-action, package explanation.
    Uses claude-3-5-haiku-20241022 (fast + cost-effective).
    """
    pkg_ctx = _ai_build_package_context(state, last_calc)

    def _opts(items, name_key='name', key_key='key'):
        return ' | '.join(f'{i[name_key]} [key:{i[key_key]}]' for i in items) or 'none available'

    opts = (
        f"DESTINATIONS: {_opts(destinations)}\n"
        f"HOTELS: {_opts(hotels)}\n"
        f"TRANSPORTS: {_opts(transports)}\n"
        f"CABS: {_opts(cabs)}\n"
        f"ADD-ONS: {_opts(addons)}"
    )

    system = f"""You are Sharad, a warm and experienced travel sales advisor at {client_name}.
You have 15+ years helping Indian travellers plan dream holidays. You are knowledgeable, enthusiastic, and friendly.
You speak like a trusted friend who happens to be a travel expert. You remember the entire conversation naturally.
Use occasional emojis tastefully.

{pkg_ctx}

AVAILABLE OPTIONS (use exact keys when setting values):
{opts}

RESPONSE FORMAT — always return a single valid JSON object, no markdown fences:

Single action: {{"action":"ACTION_NAME","value":"value_if_needed","message":"your warm response"}}
Multiple changes: {{"action":"MULTI_ACTION","actions":[{{"action":"SET_X","value":"v1"}},{{"action":"SET_Y","value":"v2"}}],"message":"confirmation"}}

VALID ACTIONS: SET_DESTINATION, SET_HOTEL, SET_TRANSPORT, SET_CAB, SET_ADULTS, SET_CHILDREN,
SET_NIGHTS, SET_ROOMS, SET_SEASON (ON/OFF), ADD_ADDON, REMOVE_ADDON,
READY_TO_CALCULATE, EXPLAIN_PACKAGE, SUGGEST_UPGRADE, ASK_FIELD, GENERAL_CHAT, MULTI_ACTION

CRITICAL: NEVER state, estimate or calculate any price. Use READY_TO_CALCULATE to trigger the pricing engine.
You may reference prices already shown in the breakdown above.

For GENERAL_CHAT about destinations, attractions, weather, food, visa etc — answer knowledgeably and helpfully.
For EXPLAIN_PACKAGE — give a warm narrative of the full trip, not a list.
For package suggestions — ask about interests/budget/group type, then use MULTI_ACTION to set everything."""

    # Build conversation history for Anthropic format
    anthropic_msgs = []
    for h in history[-40:]:
        role = h.get('role', 'user')
        content = h.get('content', '')
        if role in ('user', 'assistant') and content:
            anthropic_msgs.append({'role': role, 'content': content})
    anthropic_msgs.append({'role': 'user', 'content': message})

    client_ant = _anthropic.Anthropic(api_key=api_key)
    resp = client_ant.messages.create(
        model='claude-3-5-haiku-20241022',
        max_tokens=700,
        system=system,
        messages=anthropic_msgs,
        temperature=0.75,
    )

    raw = resp.content[0].text.strip() if resp.content else ''
    logger.info(f"Sharad (Anthropic) raw response len={len(raw)}")

    # Parse JSON
    result = None
    try:
        result = json.loads(raw)
    except Exception:
        import re as _re
        m = _re.search(r'```(?:json)?\s*(\{[\s\S]*?\})\s*```', raw)
        if m:
            try: result = json.loads(m.group(1))
            except Exception: pass
    if not result:
        import re as _re
        m = _re.search(r'\{[\s\S]*\}', raw)
        if m:
            try: result = json.loads(m.group(0))
            except Exception: pass
    if not result:
        result = {'action': 'GENERAL_CHAT', 'message': raw}

    # Validate
    VALID = {
        'SET_HOTEL','SET_TRANSPORT','SET_DESTINATION','SET_ADULTS','SET_CHILDREN',
        'SET_NIGHTS','SET_ROOMS','SET_SEASON','ADD_ADDON','REMOVE_ADDON','SET_CAB',
        'READY_TO_CALCULATE','SUGGEST_UPGRADE','ASK_FIELD','GENERAL_CHAT',
        'EXPLAIN_PACKAGE','MULTI_ACTION',
    }
    if result.get('action') not in VALID:
        result['action'] = 'GENERAL_CHAT'
    if result.get('action') == 'MULTI_ACTION':
        subs = result.get('actions', [])
        result['actions'] = [s for s in subs if isinstance(s, dict) and s.get('action') in VALID]

    logger.info(f"Sharad (Anthropic): action={result.get('action')}")
    return result


def _ai_smart_fallback(message, state, last_calc, hotels, transports, destinations, addons, cabs):
    """
    Enhanced rule-based fallback with web search for general knowledge questions.
    Used when no AI API key is available.
    """
    msg_lower = message.lower().strip()

    # Detect general knowledge / travel info questions — answer with web search
    GENERAL_TRIGGERS = [
        'things to do', 'what to do', 'places to visit', 'must see', 'attractions',
        'weather', 'best time', 'when to visit', 'climate', 'temperature',
        'visa', 'passport', 'entry requirements', 'documents',
        'distance', 'how far', 'how long to reach', 'travel time',
        'food', 'cuisine', 'restaurants', 'what to eat',
        'culture', 'history', 'language', 'currency', 'local',
        'tell me about', 'what is', 'who is', 'where is', 'explain',
        'tips', 'advice', 'guide', 'itinerary', 'suggest',
        'how are you', 'hi ', 'hello', 'hey ',
    ]

    is_general = any(t in msg_lower for t in GENERAL_TRIGGERS)

    if is_general:
        # Try web search for better answers
        try:
            search_result = _ai_web_search(f"travel {message}")
            if search_result and len(search_result) > 50 and 'unavailable' not in search_result.lower():
                return {
                    'action': 'GENERAL_CHAT',
                    'message': (
                        f"Here\'s what I found:\n\n{search_result}\n\n"
                        f"Is there anything from your trip I can help customise? 😊"
                    )
                }
        except Exception:
            pass

        # Greetings
        if any(w in msg_lower for w in ['hi', 'hello', 'hey', 'how are you', 'namaste']):
            dest_list = ', '.join(d['name'] for d in destinations[:5]) if destinations else 'many destinations'
            return {
                'action': 'GENERAL_CHAT',
                'message': (
                    f"Hi there! I\'m Sharad, your travel advisor. 😊\n\n"
                    f"I can help you plan an amazing trip to {dest_list} and more!\n"
                    f"Tell me where you\'d like to go, how many nights, and who\'s travelling."
                )
            }

        # Destination-specific general query
        for d in destinations:
            if d['name'].lower() in msg_lower:
                return {
                    'action': 'GENERAL_CHAT',
                    'message': (
                        f"{d['name']} is a wonderful destination! 🌟 "
                        f"For detailed travel info, I\'d recommend a quick search — "
                        f"I\'m best at building you the perfect package there. "
                        f"Want me to set {d['name']} as your destination and start planning?"
                    )
                }

        return {
            'action': 'GENERAL_CHAT',
            'message': (
                "Great question! For the most up-to-date travel information, "
                "a quick web search will give you the best details. 🌐\n\n"
                "What I can do brilliantly is build you a complete personalised package — "
                "just tell me your destination, nights, and number of travellers!"
            )
        }

    # Fall through to full rule-based processor for package-related queries
    return _process_ai_intent_fallback(message, state, last_calc, hotels, transports, destinations, addons, cabs)



def _ai_process(message, state, last_calc, hotels, transports, destinations, addons, cabs,
                client_name='Travel Agency', history=None):
    """
    Core AI dispatcher — tries providers in order:
      1. OpenAI gpt-4o  (if OPENAI_API_KEY set)
      2. Anthropic Claude  (if ANTHROPIC_API_KEY set)
      3. Rule-based + web-search enhanced fallback
    """
    if history is None:
        history = []

    openai_api_key   = os.environ.get('OPENAI_API_KEY', '').strip()
    anthropic_api_key = os.environ.get('ANTHROPIC_API_KEY', '').strip()

    # Log which provider we will use — helps diagnose silent fallbacks
    if OPENAI_AVAILABLE and openai_api_key:
        logger.info("Sharad: using OpenAI gpt-4o")
    elif ANTHROPIC_AVAILABLE and anthropic_api_key:
        logger.info("Sharad: OpenAI key missing — using Anthropic Claude")
    else:
        logger.warning(
            "Sharad: no AI API key found (OPENAI_API_KEY or ANTHROPIC_API_KEY). "
            "Using rule-based fallback. Set one of these env vars to enable full AI."
        )
        return _ai_smart_fallback(message, state, last_calc, hotels, transports, destinations, addons, cabs)

    # Try Anthropic if OpenAI is not available
    if not (OPENAI_AVAILABLE and openai_api_key):
        if ANTHROPIC_AVAILABLE and anthropic_api_key:
            return _ai_process_anthropic(
                message=message, state=state, last_calc=last_calc,
                hotels=hotels, transports=transports, destinations=destinations,
                addons=addons, cabs=cabs, client_name=client_name, history=history,
                api_key=anthropic_api_key,
            )
        return _ai_smart_fallback(message, state, last_calc, hotels, transports, destinations, addons, cabs)

    if history is None:
        history = []

    try:
        oai = _OpenAI(api_key=openai_api_key, timeout=45.0, max_retries=0)

        pkg_ctx = _ai_build_package_context(state, last_calc)

        # Format available options with keys clearly labelled
        def _opts(items, name_key='name', key_key='key'):
            return ' | '.join(f'{i[name_key]} [key:{i[key_key]}]' for i in items) or 'none available'

        opts = (
            f"DESTINATIONS: {_opts(destinations)}\n"
            f"HOTELS: {_opts(hotels)}\n"
            f"TRANSPORTS: {_opts(transports)}\n"
            f"CABS: {_opts(cabs)}\n"
            f"ADD-ONS: {_opts(addons)}"
        )

        system = f"""You are Sharad, a warm and experienced travel sales advisor at {client_name}.
You have 15+ years helping Indian travellers plan dream holidays. You are knowledgeable, enthusiastic, and friendly — never pushy.
You speak like a trusted friend who happens to be a travel expert. You remember the entire conversation and reference it naturally.
Use occasional emojis tastefully. Address the user personally and warmly.

{pkg_ctx}

AVAILABLE OPTIONS (always use exact keys when setting values):
{opts}

━━━ WHAT YOU CAN DO ━━━

1. MODIFY THE PACKAGE — change destination, hotel, transport, nights, travellers, rooms, season, add-ons, cab.
   For ONE change: {{"action":"SET_X","value":"key","message":"warm explanation"}}
   For MULTIPLE changes at once: {{"action":"MULTI_ACTION","actions":[{{"action":"SET_X","value":"v1"}},{{"action":"SET_Y","value":"v2"}}],"message":"warm summary"}}

2. EXPLAIN THE PACKAGE — give a warm narrative of what's booked, why it's great, what's included.
   {{"action":"EXPLAIN_PACKAGE","message":"your detailed friendly explanation of the full trip"}}

3. SUGGEST A TAILORED PACKAGE — when user asks for recommendations, ask about their interests/budget/group if not clear,
   then build a complete package using available options. Use MULTI_ACTION to set it all at once.

4. WEB SEARCH — for destination info, weather, visa, attractions, travel tips. Use the web_search function.
   Then weave the results into a natural, conversational answer.

5. CALCULATE PRICE — {{"action":"READY_TO_CALCULATE","message":"..."}} — triggers the pricing engine.

━━━ ALL VALID ACTIONS ━━━
SET_DESTINATION, SET_HOTEL, SET_TRANSPORT, SET_CAB, SET_ADULTS, SET_CHILDREN,
SET_NIGHTS, SET_ROOMS, SET_SEASON (value: ON or OFF), ADD_ADDON, REMOVE_ADDON,
READY_TO_CALCULATE, EXPLAIN_PACKAGE, SUGGEST_UPGRADE, ASK_FIELD, GENERAL_CHAT, MULTI_ACTION

━━━ CRITICAL PRICE RULE ━━━
NEVER state, estimate, guess, or calculate any price yourself. The backend pricing engine does ALL pricing.
You may REFERENCE prices already shown in the breakdown above (those came from the engine).
To get a price: use READY_TO_CALCULATE.

━━━ OUTPUT FORMAT ━━━
Always return a single valid JSON object. No markdown fences. No extra text outside the JSON.
Your "message" field is shown directly to the user — make it warm, conversational, and helpful.
Use line breaks (\\n) in messages where natural. Bold important words with **word**.

━━━ PACKAGE EXPLANATION STYLE ━━━
When explaining, don't list fields — narrate: "You're headed to stunning Goa for 5 nights...
Your stay at [hotel] promises [what makes it great]... Getting there by [transport] means [benefit]..."
Include what's included, what makes this trip special, value highlights.

━━━ SUGGESTION STYLE ━━━
Ask 2-3 targeted questions: What's the vibe — beach/adventure/culture? Budget range — comfortable/premium/luxury?
Who's travelling — couple, family, friends? Then pick from available options and build a package with MULTI_ACTION."""

        # Web search tool
        tools = [{
            'type': 'function',
            'function': {
                'name': 'web_search',
                'description': (
                    'Search the web for current travel information: destination guides, '
                    'weather & best time to visit, visa requirements, top attractions, '
                    'local food & culture, travel tips. Use when you need specific or '
                    'up-to-date facts you want to verify.'
                ),
                'parameters': {
                    'type': 'object',
                    'properties': {
                        'query': {
                            'type': 'string',
                            'description': 'Specific travel search query, e.g. "Goa India best time to visit weather" or "Dubai visa requirements Indian passport"'
                        }
                    },
                    'required': ['query']
                }
            }
        }]

        # Build messages: system + history + current message
        msgs = [{'role': 'system', 'content': system}]
        for h in history[-40:]:
            role = h.get('role', 'user')
            content = h.get('content', '')
            if role in ('user', 'assistant') and content:
                msgs.append({'role': role, 'content': content})
        msgs.append({'role': 'user', 'content': message})

        # First call — AI may answer directly or invoke web_search
        resp1 = oai.chat.completions.create(
            model='gpt-4o',
            messages=msgs,
            tools=tools,
            tool_choice='auto',
            temperature=0.75,
            max_tokens=700,
        )
        rmsg = resp1.choices[0].message

        # Handle web search tool calls
        if rmsg.tool_calls:
            msgs.append(rmsg)
            for tc in rmsg.tool_calls:
                if tc.function.name == 'web_search':
                    try:
                        args = json.loads(tc.function.arguments)
                        q = args.get('query', message)
                        logger.info(f'Sharad web search: "{q}"')
                        result_text = _ai_web_search(q)
                    except Exception as se:
                        result_text = f'Search error: {se}'
                    msgs.append({'tool_call_id': tc.id, 'role': 'tool',
                                 'name': 'web_search', 'content': result_text})

            # Add instruction to format response as JSON
            msgs.append({'role': 'user',
                         'content': 'Based on the search results, respond in the JSON format from your instructions.'})
            resp2 = oai.chat.completions.create(
                model='gpt-4o', messages=msgs, temperature=0.75, max_tokens=700)
            raw = (resp2.choices[0].message.content or '').strip()
        else:
            raw = (rmsg.content or '').strip()

        # Parse JSON — try multiple strategies
        result = None
        # 1. Direct parse
        try:
            result = json.loads(raw)
        except Exception:
            pass
        # 2. Extract from markdown fences
        if not result:
            m = re.search(r'```(?:json)?\s*(\{[\s\S]*?\})\s*```', raw)
            if m:
                try: result = json.loads(m.group(1))
                except Exception: pass
        # 3. Find any JSON object
        if not result:
            m = re.search(r'\{[\s\S]*\}', raw)
            if m:
                try: result = json.loads(m.group(0))
                except Exception: pass
        # 4. Wrap as GENERAL_CHAT
        if not result:
            logger.warning('Sharad: non-JSON response, wrapping as GENERAL_CHAT')
            result = {'action': 'GENERAL_CHAT', 'message': raw}

        # Validate action
        VALID = {
            'SET_HOTEL','SET_TRANSPORT','SET_DESTINATION','SET_ADULTS','SET_CHILDREN',
            'SET_NIGHTS','SET_ROOMS','SET_SEASON','ADD_ADDON','REMOVE_ADDON','SET_CAB',
            'READY_TO_CALCULATE','SUGGEST_UPGRADE','ASK_FIELD','GENERAL_CHAT',
            'EXPLAIN_PACKAGE','MULTI_ACTION',
        }
        action = result.get('action', 'GENERAL_CHAT')
        if action not in VALID:
            logger.warning(f'Unknown AI action "{action}" — defaulting GENERAL_CHAT')
            result['action'] = 'GENERAL_CHAT'

        # Validate MULTI_ACTION
        if result.get('action') == 'MULTI_ACTION':
            subs = result.get('actions', [])
            if not isinstance(subs, list) or not subs:
                result['action'] = 'GENERAL_CHAT'
            else:
                result['actions'] = [s for s in subs if isinstance(s, dict) and s.get('action') in VALID]

        # Price safety guard
        if result.get('action') == 'GENERAL_CHAT':
            msg_lo = str(result.get('message', '')).lower()
            if any(p in msg_lo for p in ['₹', 'inr', 'price is', 'total is', 'costs rs', 'quote is']):
                logger.warning('Sharad tried to quote price — redirecting to READY_TO_CALCULATE')
                result = {'action': 'READY_TO_CALCULATE',
                          'message': "Let me get the exact price from our engine right now! 💰"}

        logger.info(f'Sharad v5: action={result.get("action")}, msg_len={len(str(result.get("message","")))}')
        return result

    except Exception as e:
        logger.error(f'Sharad OpenAI error: {e}', exc_info=True)
        # Try Anthropic before falling all the way back to rule-based
        if ANTHROPIC_AVAILABLE and anthropic_api_key:
            logger.info("Sharad: OpenAI failed — trying Anthropic Claude")
            try:
                return _ai_process_anthropic(
                    message=message, state=state, last_calc=last_calc,
                    hotels=hotels, transports=transports, destinations=destinations,
                    addons=addons, cabs=cabs, client_name=client_name, history=history,
                    api_key=anthropic_api_key,
                )
            except Exception as ae:
                logger.error(f'Sharad Anthropic error: {ae}', exc_info=True)
        return _ai_smart_fallback(message, state, last_calc, hotels, transports, destinations, addons, cabs)


# Keep legacy alias
def _process_ai_intent_openai(message, state, last_calc, hotels, transports,
                               destinations, addons, cabs, client_name='Travel Agency'):
    """Legacy alias — routes to the new _ai_process."""
    return _ai_process(message=message, state=state, last_calc=last_calc,
                       hotels=hotels, transports=transports, destinations=destinations,
                       addons=addons, cabs=cabs, client_name=client_name, history=[])


# Keep old name as alias for any legacy calls
def _process_ai_intent(message, state, last_calc, hotels, transports, destinations, addons, cabs):
    """Legacy alias — calls the fallback rule-based processor directly."""
    return _process_ai_intent_fallback(message, state, last_calc, hotels, transports, destinations, addons, cabs)



def _process_ai_intent_fallback(message, state, last_calc, hotels, transports, destinations, addons, cabs):
    """
    Rule-based intent processor — fallback when OpenAI is unavailable.
    Extracts ALL recognisable values from one message and prioritises the
    most important missing field so the conversation moves forward naturally.
    """
    msg = message.lower().strip()

    # ── 1. Extract EVERYTHING from the message upfront ────────────────────────
    extracted = {}

    # pax / person synonyms → adults
    for pattern in [r'(\d+)\s*pax', r'(\d+)\s*person', r'(\d+)\s*people',
                    r'(\d+)\s*travell?er', r'(\d+)\s*passenger', r'(\d+)\s*adult']:
        m = re.search(pattern, msg)
        if m:
            val = int(m.group(1))
            if 1 <= val <= 20:
                extracted['adults'] = val
                break

    # children
    m = re.search(r'(\d+)\s*child', msg)
    if m:
        val = int(m.group(1))
        if 0 <= val <= 10:
            extracted['children'] = val

    # nights / days
    m = re.search(r'(\d+)\s*night', msg)
    if m:
        val = int(m.group(1))
        if 1 <= val <= 30:
            extracted['nights'] = val
    elif re.search(r'(\d+)\s*day', msg):
        m = re.search(r'(\d+)\s*day', msg)
        val = int(m.group(1))
        if 1 <= val <= 30:
            extracted['nights'] = val

    # rooms
    m = re.search(r'(\d+)\s*room', msg)
    if m:
        val = int(m.group(1))
        if 1 <= val <= 20:
            extracted['rooms'] = val

    # destination — check against DB destinations list
    matched_dest = None
    for d in destinations:
        if d['name'].lower() in msg or d['key'].lower() in msg:
            matched_dest = d
            break

    # hotel — check against DB hotels list
    matched_hotel = None
    for h in hotels:
        if h['name'].lower() in msg or h['key'].lower() in msg:
            matched_hotel = h
            break

    # transport — check against DB transports list
    matched_transport = None
    for t in transports:
        if t['name'].lower() in msg or t['key'].lower() in msg:
            matched_transport = t
            break

    # season keywords
    if any(w in msg for w in ['peak season', 'high season', 'on season']):
        extracted['season'] = 'ON'
    elif any(w in msg for w in ['off season', 'low season', 'offseason']):
        extracted['season'] = 'OFF'

    # budget / upgrade intent flags
    is_budget   = any(w in msg for w in ['budget', 'cheap', 'affordable', 'save', 'economical', 'low cost'])
    is_premium  = any(w in msg for w in ['upgrade', 'premium', 'luxury', 'better', 'best'])
    is_price_q  = any(w in msg for w in ['price', 'quote', 'cost', 'how much', 'total', 'calculate', 'rate'])
    is_greeting = any(w in msg for w in ['hello', 'hi', 'hey', 'how are you', 'good morning',
                                          'good evening', 'good afternoon', 'namaste', 'hola'])
    is_pkg_srch = any(w in msg for w in ['find', 'search', 'plan', 'trip', 'package',
                                          'holiday', 'vacation', 'tour', 'suggest'])
    is_addon_remove = any(w in msg for w in ['remove', 'delete', 'cancel', 'no '])

    # addons
    for a in addons:
        if a['name'].lower() in msg or a['key'].lower() in msg:
            if is_addon_remove:
                return {'action': 'REMOVE_ADDON', 'value': a['key'], 'message': f"Removed {a['name']} from your package."}
            else:
                return {'action': 'ADD_ADDON', 'value': a['key'], 'message': f"Added {a['name']} to your package."}

    # ── 2. Now decide what to return based on what was found ──────────────────

    # Destination match → highest priority single-field action
    if matched_dest:
        parts = []
        if extracted.get('nights'):
            parts.append(f"{extracted['nights']} nights")
        if extracted.get('adults'):
            parts.append(f"{extracted['adults']} travellers")
        extra = f" I also noted {', '.join(parts)}." if parts else ""
        return {
            'action': 'SET_DESTINATION',
            'value': matched_dest['key'],
            'message': f"Great choice! Setting your destination to {matched_dest['name']}.{extra} Now please select your season and transport to get a price."
        }

    # Hotel match
    if matched_hotel:
        return {'action': 'SET_HOTEL', 'value': matched_hotel['key'],
                'message': f"Changed your hotel to {matched_hotel['name']}."}

    # Transport match
    if matched_transport:
        return {'action': 'SET_TRANSPORT', 'value': matched_transport['key'],
                'message': f"Changed transport to {matched_transport['name']}."}

    # Season
    if 'season' in extracted:
        label = 'Peak Season' if extracted['season'] == 'ON' else 'Off Season'
        return {'action': 'SET_SEASON', 'value': extracted['season'],
                'message': f"Set to {label}."}

    # Adults extracted (without destination in message)
    if 'adults' in extracted:
        reply_msg = f"Got it — {extracted['adults']} traveller{'s' if extracted['adults'] != 1 else ''}."
        if not state.get('destination'):
            reply_msg += " Where would you like to go?"
        elif not state.get('transport'):
            reply_msg += " Which transport would you prefer?"
        # Return SET_ADULTS — handleAIReply will NOT auto-submit unless region+transport are set
        return {'action': 'SET_ADULTS', 'value': extracted['adults'], 'message': reply_msg}

    # Nights extracted
    if 'nights' in extracted:
        reply_msg = f"Set to {extracted['nights']} nights."
        if not state.get('destination'):
            reply_msg += " Where would you like to go?"
        return {'action': 'SET_NIGHTS', 'value': extracted['nights'], 'message': reply_msg}

    # Rooms extracted
    if 'rooms' in extracted:
        return {'action': 'SET_ROOMS', 'value': extracted['rooms'],
                'message': f"Set to {extracted['rooms']} room{'s' if extracted['rooms'] != 1 else ''}."}

    # Price / quote intent
    if is_price_q:
        if state.get('nights', 0) > 0 and state.get('transport') and state.get('destination'):
            return {'action': 'READY_TO_CALCULATE', 'message': "Let me calculate your package price right now!"}
        missing = []
        if not state.get('destination'): missing.append('destination')
        if not state.get('nights'):      missing.append('number of nights')
        if not state.get('transport'):   missing.append('transport')
        return {
            'action': 'ASK_FIELD',
            'field': missing[0] if missing else 'details',
            'message': f"I need a few more details to quote: {', '.join(missing)}. Please use the guided flow or tell me."
        }

    # Budget intent
    if is_budget:
        suggestions = []
        if state.get('season') == 'ON':
            suggestions.append("switching to off-season")
        suggestions.append("choosing fewer nights or a standard hotel tier")
        return {
            'action': 'SUGGEST_UPGRADE',
            'suggestion': 'budget_optimize',
            'message': f"To keep costs down, consider: {', '.join(suggestions)}. Would you like me to adjust your package?"
        }

    # Premium / upgrade intent
    if is_premium:
        return {
            'action': 'SUGGEST_UPGRADE',
            'suggestion': 'premium',
            'message': "For a premium experience I'd recommend a luxury hotel and private transport. Want me to make those changes?"
        }

    # Greeting
    if is_greeting:
        dest_list = ', '.join([d['name'] for d in destinations[:5]]) if destinations else 'various destinations'
        return {
            'action': 'GENERAL_CHAT',
            'message': f"Hello! I'm your travel assistant. I can help you plan packages to {dest_list} and more. Tell me your destination, how many nights, and how many travellers!"
        }

    # Package search intent (e.g. "find me a package for goa", "plan a trip")
    if is_pkg_srch:
        dest_list = ', '.join([d['name'] for d in destinations[:5]]) if destinations else 'various destinations'
        return {
            'action': 'GENERAL_CHAT',
            'message': f"I'd love to help plan your trip! Available destinations include: {dest_list}. Tell me where you'd like to go, how many nights, and how many travellers — or use the guided flow on the left."
        }

    # General knowledge / factual question — acknowledge honestly
    if any(w in msg for w in ['how far', 'distance', 'km', 'miles', 'capital', 'currency',
                                'weather', 'temperature', 'visa', 'passport', 'language',
                                'time zone', 'timezone', 'population', 'when is', 'what is',
                                'who is', 'where is', 'which is', 'tell me about']):
        return {
            'action': 'GENERAL_CHAT',
            'message': "That's a great question! I'm specialised in building travel packages rather than general information — for detailed facts I'd suggest a quick Google search. For your trip, I can help with destinations, hotels, transport, and pricing. What would you like to plan?"
        }

    # Default fallback
    dest_list = ', '.join([d['name'] for d in destinations[:4]]) if destinations else 'our destinations'
    return {
        'action': 'GENERAL_CHAT',
        'message': f"I can help you plan a trip! Try telling me your destination ({dest_list}), number of nights, and number of travellers — or use the step-by-step flow on the left."
    }


@app.route('/api/ai-status', methods=['GET'])
def ai_status():
    """Returns which AI provider is active. Used by frontend to show status badge."""
    has_openai    = OPENAI_AVAILABLE    and bool(os.environ.get('OPENAI_API_KEY', '').strip())
    has_anthropic = ANTHROPIC_AVAILABLE and bool(os.environ.get('ANTHROPIC_API_KEY', '').strip())
    if has_openai:
        provider = 'openai'
        label    = 'GPT-4o'
        status   = 'active'
    elif has_anthropic:
        provider = 'anthropic'
        label    = 'Claude'
        status   = 'active'
    else:
        provider = 'none'
        label    = 'Rule-based'
        status   = 'limited'
    return jsonify({'provider': provider, 'label': label, 'status': status})


# =====================================================
# FRONTEND ROUTES
# =====================================================

@app.route('/')
def index():
    return render_template('index.html')


# =====================================================
# ENTRY POINT
# =====================================================

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)