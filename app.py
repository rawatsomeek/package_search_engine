"""
Travel Pricing Rule Engine — Enterprise Flask Backend
=====================================================
PRODUCTION VERSION 3.3 — AMADEUS LIVE HOTEL INTEGRATION EXTENSION

Fixed Issues (inherited from 3.1):
1. Transport pricing_type columns added (ISSUE 1)
2. Domestic/International region separation (ISSUE 2)
3. Add-on rate_peak/rate_off columns added (ISSUE 3)

New in 3.2 (ADDITIVE ONLY — no existing code altered):
- Phase 1: Amadeus OAuth token generation + in-memory cache with expiry tracking
- Phase 2: POST /api/flight-search route — calls Amadeus v2 shopping API, returns clean JSON
- Phase 3: Pricing engine compatibility — optional "flight" block passthrough to engine

New in 3.3 (ADDITIVE ONLY — no existing code altered):
- Phase 4: POST /api/hotel-search route — Amadeus Hotel Offers API v3 integration
  * In-memory OAuth token reuse (shared cache with flights)
  * 401 auto-refresh
  * Server-side FX conversion (non-INR → INR via exchangerate-api or fallback rates)
  * Normalized output: id, hotelName, roomType, boardType, totalPrice (INR),
    currency, perNightPrice, cancellationPolicy
  * Sorted by totalPrice ASC
  * Safe empty-results response — no server crash
- Phase 5: Pricing engine compatibility — optional "live_hotel" block + "hotel_source" passthrough
  * hotel_source="live" → uses Amadeus total price directly (no nights/pax multiplication)
  * hotel_source="admin" (default) → existing logic untouched
  * entity_type="hotel" rules skipped for live hotel path (handled in pricing_engine.py)
"""

from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_cors import CORS
from functools import wraps
import psycopg2
from psycopg2.extras import RealDictCursor
import json
import os
import logging
import re
import time
import requests as _requests
from decimal import Decimal

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

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')
CORS(app)

# =====================================================
# DATABASE
# =====================================================

DB_CONFIG = {
    'host': os.environ.get('DB_HOST', 'localhost'),
    'port': int(os.environ.get('DB_PORT', 5432)),
    'database': os.environ.get('DB_NAME', 'travel_pricing'),
    'user': os.environ.get('DB_USER', 'apoorvaranjan'),
    'password': os.environ.get('DB_PASS', ''),
}


def get_db():
    return psycopg2.connect(**DB_CONFIG)


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
                AND deleted = FALSE
            """
            params = [slug, client_id, region_id]
        else:
            query = f"""
                SELECT COUNT(*) FROM {table}
                WHERE {column} = %s
                AND client_id = %s
                AND deleted = FALSE
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
            AND deleted = FALSE
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


# =====================================================
# LEAD MANAGEMENT SYSTEM — FRONTEND ROUTES
# =====================================================

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        admin_user = os.environ.get('ADMIN_USER', 'admin')
        admin_pass = os.environ.get('ADMIN_PASS', 'admin123')
        if username == admin_user and password == admin_pass:
            session['admin_logged_in'] = True
            session['admin_username'] = username
            session['role'] = 'admin'
            return redirect(url_for('admin_dashboard'))
        return render_template('admin.html', error='Invalid credentials', mode='admin')
    return render_template('admin.html', mode='admin')


@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    session.pop('role', None)
    return redirect(url_for('admin_login'))


@app.route('/admin')
@admin_login_required
def admin_dashboard():
    return render_template('admin.html')


@app.route('/admin/agent/<agent_name>')
@admin_login_required
def admin_agent_detail(agent_name):
    return render_template('admin_agent_detail.html', agent_name=agent_name)


@app.route('/agent/login', methods=['GET', 'POST'])
def agent_login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        try:
            db = get_db()
            cur = db.cursor()
            cur.execute(
                "SELECT id, name, password FROM agents WHERE name=%s AND active=TRUE AND deleted=FALSE",
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
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM clients WHERE deleted = FALSE ORDER BY name")
    result = rows_to_dicts(cur, cur.fetchall())
    db.close()
    return jsonify(result)


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
    data = request.get_json()
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("UPDATE clients SET active=%s WHERE id=%s", (data['active'], cid))
        db.commit()
        return jsonify({'message': 'Client toggled'})
    except Exception as e:
        db.rollback()
        logger.error(f"Error toggling client {cid}: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/clients/<int:cid>', methods=['DELETE'])
def delete_client(cid):
    if cid == 1:
        return jsonify({'error': 'Cannot delete default client'}), 400
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("UPDATE clients SET deleted=TRUE, active=FALSE WHERE id=%s", (cid,))
        db.commit()
        return jsonify({'message': 'Client deleted'})
    except Exception as e:
        db.rollback()
        logger.error(f"Error deleting client {cid}: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
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
                   WHERE client_id=%s AND is_domestic=TRUE AND deleted=FALSE
                   ORDER BY name""",
                (client_id,)
            )
        elif region_type == 'international':
            cur.execute(
                """SELECT * FROM regions
                   WHERE client_id=%s AND is_domestic=FALSE AND deleted=FALSE
                   ORDER BY name""",
                (client_id,)
            )
        else:
            cur.execute(
                "SELECT * FROM regions WHERE client_id=%s AND deleted=FALSE ORDER BY is_domestic DESC, name",
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
    data = request.get_json()
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("UPDATE regions SET active=%s WHERE id=%s", (data['active'], rid))
        db.commit()
        return jsonify({'message': 'Toggled'})
    except Exception as e:
        db.rollback()
        logger.error(f"Error toggling region {rid}: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/regions/<int:rid>', methods=['DELETE'])
def delete_region(rid):
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("UPDATE regions SET deleted=TRUE, active=FALSE WHERE id=%s", (rid,))
        db.commit()
        return jsonify({'message': 'Deleted'})
    except Exception as e:
        db.rollback()
        logger.error(f"Error deleting region {rid}: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


# =====================================================
# TRANSPORTS (FIXED WITH PRICING TYPE SUPPORT)
# =====================================================

@app.route('/api/transports', methods=['GET'])
def list_transports():
    client_id = get_client_id()
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(
            "SELECT * FROM transports WHERE client_id=%s AND deleted=FALSE ORDER BY name",
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
    data = request.get_json()
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("UPDATE transports SET active=%s WHERE id=%s", (data['active'], tid))
        db.commit()
        return jsonify({'message': 'Toggled'})
    except Exception as e:
        db.rollback()
        logger.error(f"Error toggling transport {tid}: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/transports/<int:tid>', methods=['DELETE'])
def delete_transport(tid):
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("UPDATE transports SET deleted=TRUE, active=FALSE WHERE id=%s", (tid,))
        db.commit()
        return jsonify({'message': 'Deleted'})
    except Exception as e:
        db.rollback()
        logger.error(f"Error deleting transport {tid}: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
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
            "SELECT * FROM hotels WHERE client_id=%s AND deleted=FALSE ORDER BY name",
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
    data = request.get_json()
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("UPDATE hotels SET active=%s WHERE id=%s", (data['active'], hid))
        db.commit()
        return jsonify({'message': 'Toggled'})
    except Exception as e:
        db.rollback()
        logger.error(f"Error toggling hotel {hid}: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/hotels/<int:hid>', methods=['DELETE'])
def delete_hotel(hid):
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("UPDATE hotels SET deleted=TRUE, active=FALSE WHERE id=%s", (hid,))
        db.commit()
        return jsonify({'message': 'Deleted'})
    except Exception as e:
        db.rollback()
        logger.error(f"Error deleting hotel {hid}: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
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
            "SELECT * FROM destinations WHERE client_id=%s AND deleted=FALSE ORDER BY name",
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
    data = request.get_json()
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("UPDATE destinations SET active=%s WHERE id=%s", (data['active'], did))
        db.commit()
        return jsonify({'message': 'Toggled'})
    except Exception as e:
        db.rollback()
        logger.error(f"Error toggling destination {did}: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/destinations/<int:did>', methods=['DELETE'])
def delete_destination(did):
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("UPDATE hotels SET destination_id=NULL WHERE destination_id=%s", (did,))
        cur.execute("UPDATE destinations SET deleted=TRUE, active=FALSE WHERE id=%s", (did,))
        db.commit()
        return jsonify({'message': 'Deleted'})
    except Exception as e:
        db.rollback()
        logger.error(f"Error deleting destination {did}: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
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
            "SELECT * FROM cabs WHERE client_id=%s AND deleted=FALSE ORDER BY name",
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
    data = request.get_json()
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("UPDATE cabs SET active=%s WHERE id=%s", (data['active'], cid))
        db.commit()
        return jsonify({'message': 'Toggled'})
    except Exception as e:
        db.rollback()
        logger.error(f"Error toggling cab {cid}: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/cabs/<int:cid>', methods=['DELETE'])
def delete_cab(cid):
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("UPDATE cabs SET deleted=TRUE, active=FALSE WHERE id=%s", (cid,))
        db.commit()
        return jsonify({'message': 'Deleted'})
    except Exception as e:
        db.rollback()
        logger.error(f"Error deleting cab {cid}: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
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
            "SELECT id, name, internal_name FROM cabs WHERE client_id=%s AND active=TRUE AND deleted=FALSE ORDER BY name",
            (client_id,)
        )
        cabs = rows_to_dicts(cur, cur.fetchall())

        cur.execute(
            "SELECT id, name, internal_name, display_name FROM destinations WHERE client_id=%s AND active=TRUE AND deleted=FALSE ORDER BY name",
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
            "SELECT * FROM addons WHERE client_id=%s AND deleted=FALSE ORDER BY name",
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
    data = request.get_json()
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("UPDATE addons SET active=%s WHERE id=%s", (data['active'], aid))
        db.commit()
        return jsonify({'message': 'Toggled'})
    except Exception as e:
        db.rollback()
        logger.error(f"Error toggling addon {aid}: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/addons/<int:aid>', methods=['DELETE'])
def delete_addon(aid):
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("UPDATE addons SET deleted=TRUE, active=FALSE WHERE id=%s", (aid,))
        db.commit()
        return jsonify({'message': 'Deleted'})
    except Exception as e:
        db.rollback()
        logger.error(f"Error deleting addon {aid}: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
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
            """SELECT * FROM pricing_rules WHERE client_id=%s AND deleted=FALSE
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
    data = request.get_json()
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("UPDATE pricing_rules SET active=%s WHERE id=%s", (data['active'], rid))
        db.commit()
        return jsonify({'message': 'Toggled'})
    except Exception as e:
        db.rollback()
        logger.error(f"Error toggling pricing rule {rid}: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/pricing-rules/<int:rid>', methods=['DELETE'])
def delete_pricing_rule(rid):
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("UPDATE pricing_rules SET deleted=TRUE, active=FALSE WHERE id=%s", (rid,))
        db.commit()
        return jsonify({'message': 'Deleted'})
    except Exception as e:
        db.rollback()
        logger.error(f"Error deleting pricing rule {rid}: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
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
# Shared across all request threads (flights AND hotels use the same token).
# Token refresh is safe: worst case two threads both refresh simultaneously,
# which is harmless (last write wins).
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
    (both flights and hotels share the same token cache).
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
# Rates expire after FX_CACHE_TTL_SECONDS (1 hour by default).
_fx_rate_cache: dict = {}
FX_CACHE_TTL_SECONDS = 3600

# Fallback approximate rates to INR (updated periodically by the dev team).
# These are only used when the live FX API is unavailable.
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

    This function is NEVER called from the frontend. Credentials and raw
    rates are never included in API responses.
    """
    currency = currency.upper().strip()

    if currency == 'INR':
        return 1.0

    now = time.time()
    cached = _fx_rate_cache.get(currency)
    if cached and now < cached.get('expires_at', 0):
        logger.debug(f"FX cache hit: 1 {currency} = {cached['rate']} INR")
        return cached['rate']

    # Attempt live fetch
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

    # Fallback to hardcoded rates
    fallback = _FX_FALLBACK_RATES_TO_INR.get(currency)
    if fallback:
        logger.info(f"FX fallback rate: 1 {currency} = {fallback} INR")
        # Cache the fallback too, but for shorter time
        _fx_rate_cache[currency] = {
            'rate': fallback,
            'expires_at': now + 600  # 10 min cache for fallback
        }
        return fallback

    # Last resort: assume 1:1 (should not happen in production)
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
    token refresh on 401.  Returns the parsed JSON response body.
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
        # Token was rejected — invalidate cache and retry once with a fresh token
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
        trip_type = (data.get('trip_type') or 'one_way').strip().lower()

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

        # Surface Amadeus-level errors as user-friendly messages
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

        logger.info(
            f"Flight search {origin}->{destination} on {departure_date}: "
            f"{len(offers)} offers returned"
        )
        return jsonify({'offers': offers, 'count': len(offers)})

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
# HOTEL SEARCH — Amadeus Hotel Offers API v3
# =====================================================
# Phase 4 implementation.
# Uses the shared Amadeus OAuth token (same cache as flights).
# FX conversion is performed server-side using _convert_to_inr().
# Raw Amadeus responses are NEVER forwarded to the frontend.
# Credentials are NEVER included in any response body.
#
# Two-step Amadeus hotel flow:
#   Step 1: GET /v1/reference-data/locations/hotels/by-city
#             → Returns list of hotel IDs for city code
#   Step 2: GET /v3/shopping/hotel-offers
#             → Returns availability + pricing for those hotel IDs
#
# Input:
#   { cityCode, checkInDate, checkOutDate, adults, roomQuantity }
#
# Output (normalized, all prices in INR):
#   { hotels: [...], count: int, message?: str }
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


def _fetch_hotel_ids_for_city(city_code: str, max_hotels: int = 20) -> list:
    """
    Step 1: Retrieve hotel IDs for a given IATA city code from Amadeus.
    Returns a list of hotelId strings (up to max_hotels).
    Returns empty list on error (caller handles gracefully).
    """
    base_url = _get_amadeus_base_url()
    url = f'{base_url}/v1/reference-data/locations/hotels/by-city'

    try:
        resp = _amadeus_get_request(url, {'cityCode': city_code.upper()}, timeout=10)
        if not resp.ok:
            logger.warning(
                f"Hotel IDs fetch failed for city {city_code}: "
                f"HTTP {resp.status_code}"
            )
            return []

        data = resp.json()
        hotels_data = data.get('data', [])
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

    Returns list of dicts with:
      id, hotelName, roomType, boardType, cancellationPolicy,
      totalPrice (INR), currency, perNightPrice (INR, optional display only),
      originalCurrency, originalPrice
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

                # Cancellation policy — raw text from Amadeus for display only
                policies = offer.get('policies', {})
                cancellation = policies.get('cancellation', {})
                cancel_policy = cancellation.get('description', {}).get('text', '')
                if not cancel_policy:
                    cancel_type = cancellation.get('type', '')
                    cancel_policy = cancel_type if cancel_type else 'Check hotel policy'

                # Pricing
                price_info = offer.get('price', {})
                # Try grandTotal first, then total
                raw_total_str = price_info.get('grandTotal') or price_info.get('total', '0')
                try:
                    raw_total = float(raw_total_str)
                except (ValueError, TypeError):
                    raw_total = 0.0

                # Currency from offer, fall back to base if not set
                original_currency = (
                    price_info.get('currency')
                    or offer_block.get('currency', 'INR')
                ).upper()

                original_price = raw_total

                # Server-side FX conversion to INR
                total_price_inr = _convert_to_inr(raw_total, original_currency)

                # Per-night breakdown for display (not used in engine math)
                per_night_price_inr = round(total_price_inr / max(nights, 1), 2) if nights > 0 else total_price_inr

                results.append({
                    'id': offer_id,
                    'hotelName': hotel_name,
                    'hotelId': hotel_id,
                    'roomType': room_type,
                    'boardType': board_type,
                    'cancellationPolicy': cancel_policy,
                    # All pricing fields in INR
                    'totalPrice': round(total_price_inr, 2),
                    'currency': 'INR',
                    'perNightPrice': per_night_price_inr,
                    # Original currency info (for transparency in the summary only)
                    'originalCurrency': original_currency,
                    'originalPrice': round(original_price, 2),
                })
        except (KeyError, ValueError, TypeError) as e:
            logger.warning(f"Skipping malformed hotel offer block: {e}")
            continue

    # Sort by totalPrice ascending
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

    Implementation flow:
      1. Validate input
      2. Fetch hotel IDs for the city (Step 1 Amadeus call)
      3. Fetch hotel offers for those IDs (Step 2 Amadeus call)
      4. Normalize + convert currency server-side
      5. Return sorted list by totalPrice ASC
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'hotels': [],
                'count': 0,
                'message': 'No search parameters provided.'
            }), 400

        # ── Input validation ──────────────────────────────────────────────────
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

        if not city_code or len(city_code) < 2:
            return jsonify({
                'hotels': [],
                'count': 0,
                'message': 'Valid city IATA code is required (e.g. DXB, SIN, BKK).'
            }), 400

        if not check_in:
            return jsonify({
                'hotels': [],
                'count': 0,
                'message': 'Check-in date is required (YYYY-MM-DD).'
            }), 400

        if not check_out:
            return jsonify({
                'hotels': [],
                'count': 0,
                'message': 'Check-out date is required (YYYY-MM-DD).'
            }), 400

        if check_out <= check_in:
            return jsonify({
                'hotels': [],
                'count': 0,
                'message': 'Check-out date must be after check-in date.'
            }), 400

        # Calculate number of nights for per-night price display
        try:
            from datetime import date
            ci = date.fromisoformat(check_in)
            co = date.fromisoformat(check_out)
            nights = max(1, (co - ci).days)
        except Exception:
            nights = 1

        logger.info(
            f"Hotel search: city={city_code}, checkIn={check_in}, checkOut={check_out}, "
            f"adults={adults}, rooms={room_quantity}, nights={nights}"
        )

        # ── Step 1: Get hotel IDs for city ───────────────────────────────────
        hotel_ids = _fetch_hotel_ids_for_city(city_code, max_hotels=20)

        if not hotel_ids:
            logger.info(f"Hotel search: no hotel IDs found for city {city_code}")
            return jsonify({
                'hotels': [],
                'count': 0,
                'message': f'No hotels found for city code "{city_code}". Try a different city code.'
            }), 200

        # ── Step 2: Get offers for those hotel IDs ───────────────────────────
        raw_offers = _fetch_hotel_offers(hotel_ids, check_in, check_out, adults, room_quantity)

        if not raw_offers:
            logger.info(
                f"Hotel search: no offers for city {city_code} "
                f"on {check_in}-{check_out}"
            )
            return jsonify({
                'hotels': [],
                'count': 0,
                'message': 'No live hotels found for these dates. Try different dates or city.'
            }), 200

        # ── Step 3: Normalize + convert FX ───────────────────────────────────
        normalized = _normalize_hotel_offers(raw_offers, nights)

        if not normalized:
            return jsonify({
                'hotels': [],
                'count': 0,
                'message': 'No live hotels found. Try different dates.'
            }), 200

        logger.info(
            f"Hotel search {city_code} {check_in}-{check_out}: "
            f"{len(normalized)} hotels returned"
        )

        return jsonify({
            'hotels': normalized,
            'count': len(normalized),
            'nights': nights,
            'checkInDate': check_in,
            'checkOutDate': check_out,
        }), 200

    except ValueError as e:
        # Configuration errors (missing credentials)
        logger.error(f"Hotel search configuration error: {e}", exc_info=True)
        return jsonify({
            'hotels': [],
            'count': 0,
            'message': str(e)
        }), 200

    except _requests.exceptions.Timeout:
        logger.error("Hotel search timed out connecting to Amadeus API")
        return jsonify({
            'hotels': [],
            'count': 0,
            'message': 'Hotel search timed out. Please try again.'
        }), 200

    except _requests.exceptions.ConnectionError as e:
        logger.error(f"Hotel search network error: {e}", exc_info=True)
        return jsonify({
            'hotels': [],
            'count': 0,
            'message': 'Could not reach hotel search service. Please check connectivity.'
        }), 200

    except Exception as e:
        logger.error(f"Hotel search unexpected error: {e}", exc_info=True)
        return jsonify({
            'hotels': [],
            'count': 0,
            'message': 'Hotel search temporarily unavailable. Please try again.'
        }), 200


# =====================================================
# PHASE 3 / 5: Pricing Engine Payload Helpers
# =====================================================
# The /calculate route accepts optional "flight" and "live_hotel" blocks.
# These are sanitised server-side and forwarded to pricing_engine.py.
# No pricing arithmetic happens in this file.
# =====================================================

def _extract_flight_block(payload: dict) -> dict | None:
    """
    Extract and validate the optional flight block from the calculate payload.
    Returns a sanitised dict if present and structurally valid, else None.
    """
    flight_raw = payload.get('flight')
    if not flight_raw or not isinstance(flight_raw, dict):
        return None

    flight_type = str(flight_raw.get('type', 'one_way')).strip().lower()
    if flight_type not in ('one_way', 'return'):
        flight_type = 'one_way'

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
        'base_fare': base_fare,
        'pax': pax,
    }


def _extract_live_hotel_block(payload: dict) -> dict | None:
    """
    Extract and validate the optional live_hotel block from the calculate payload.
    Returns a sanitised dict if present and structurally valid, else None.

    Expected input structure (from frontend after hotel-search):
    {
        "live_hotel_id":             str,   # Amadeus offer ID
        "live_hotel_name":           str,   # hotel name
        "live_hotel_room_type":      str,   # room type
        "live_hotel_board_type":     str,   # board type
        "live_hotel_total_price":    float, # total stay price in INR (already converted)
        "live_hotel_currency":       str,   # "INR" (post-conversion)
        "live_hotel_original_price": float, # original price before FX (informational)
        "live_hotel_original_currency": str # original currency before FX (informational)
    }
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

    # Sanitise string fields
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
    The engine computes hotel cost from live_hotel_total_price directly
    (no night/pax multiplication). entity_type="hotel" pricing rules are
    skipped automatically by the rule engine in live hotel mode.
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
            # Ensure live_hotel is cleared in admin mode
            payload['live_hotel'] = None
        # ─────────────────────────────────────────────────────────────────────

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
                "SELECT id, name FROM regions WHERE id=%s AND client_id=%s AND active=TRUE AND deleted=FALSE",
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
                    "SELECT id, name, transport_type FROM transports WHERE transport_type=%s AND client_id=%s AND active=TRUE AND deleted=FALSE",
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
                        "SELECT id, name, internal_name FROM hotels WHERE internal_name=%s AND client_id=%s AND active=TRUE AND deleted=FALSE",
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
            # Live hotel mode — hotel key is not from DB, skip DB validation
            logger.info("hotel_source=live — skipping admin hotel DB validation")

        cab_key = payload.get('cab')
        if cab_key:
            try:
                cur.execute(
                    "SELECT id, name, internal_name FROM cabs WHERE internal_name=%s AND client_id=%s AND active=TRUE AND deleted=FALSE",
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

        logger.info(f"Calculation successful: total={result.get('total')}, perPerson={result.get('perPerson')}, hotelSource={hotel_source}")

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
    data = request.get_json()
    transport = data.get('transport', '')
    days = data.get('days', [])
    required = check_cab_required(transport, days)
    return jsonify({'cabRequired': required})


@app.route('/api/room-calculator', methods=['POST'])
def room_calc():
    """Standalone room calculation endpoint."""
    data = request.get_json()
    try:
        result = RoomCalculator.calculate_room_allocation(
            adults=int(data.get('adults', 2)),
            children=int(data.get('children', 0)),
            sharing_capacity=int(data.get('sharing_capacity', 2)),
            child_age_limit=int(data.get('child_age_limit', 5)),
            paying_children=data.get('paying_children')
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Room calc error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 400


# =====================================================
# AI ORCHESTRATION LAYER
# =====================================================

@app.route('/ai-chat', methods=['POST'])
def ai_chat():
    """
    AI orchestration endpoint.
    AI outputs JSON commands — NEVER prices.
    """
    try:
        data = request.get_json()
        user_message = data.get('message', '')
        session_id = data.get('sessionId', '')
        current_state = data.get('currentState', {})
        last_calc = data.get('lastCalculation')
        client_id = int(data.get('client_id', 1))

        db = get_db()
        cur = db.cursor()

        cur.execute("SELECT name FROM clients WHERE id=%s", (client_id,))
        client_row = cur.fetchone()
        client_name = client_row[0] if client_row else 'Travel Agency'

        cur.execute("SELECT internal_name, name FROM hotels WHERE client_id=%s AND active=TRUE AND deleted=FALSE", (client_id,))
        hotels = [{'key': r[0], 'name': r[1]} for r in cur.fetchall()]

        cur.execute("SELECT transport_type, display_name FROM transports WHERE client_id=%s AND active=TRUE AND deleted=FALSE", (client_id,))
        transports = [{'key': r[0], 'name': r[1]} for r in cur.fetchall()]

        cur.execute("SELECT internal_name, display_name FROM destinations WHERE client_id=%s AND active=TRUE AND deleted=FALSE", (client_id,))
        destinations = [{'key': r[0], 'name': r[1]} for r in cur.fetchall()]

        cur.execute("SELECT internal_name, name FROM addons WHERE client_id=%s AND active=TRUE AND deleted=FALSE", (client_id,))
        addons = [{'key': r[0], 'name': r[1]} for r in cur.fetchall()]

        cur.execute("SELECT internal_name, display_name FROM cabs WHERE client_id=%s AND active=TRUE AND deleted=FALSE", (client_id,))
        cabs = [{'key': r[0], 'name': r[1]} for r in cur.fetchall()]

        db.close()

        reply = _process_ai_intent(
            user_message, current_state, last_calc,
            hotels, transports, destinations, addons, cabs
        )

        return jsonify({'reply': json.dumps(reply)})

    except Exception as e:
        logger.error(f"AI chat error: {e}", exc_info=True)
        return jsonify({
            'reply': json.dumps({
                'action': 'GENERAL_CHAT',
                'message': 'Sorry, I encountered an error. Please try again.'
            })
        })


def _process_ai_intent(message, state, last_calc, hotels, transports, destinations, addons, cabs):
    """Rule-based intent processor."""
    msg = message.lower().strip()

    if any(w in msg for w in ['price', 'quote', 'cost', 'how much', 'total', 'calculate']):
        if state.get('nights', 0) > 0 and state.get('transport'):
            return {'action': 'READY_TO_CALCULATE', 'message': 'Let me get your price quote!'}
        else:
            missing = []
            if not state.get('destination'):
                missing.append('destination')
            if not state.get('nights'):
                missing.append('number of nights')
            if not state.get('transport'):
                missing.append('transport')
            return {
                'action': 'ASK_FIELD',
                'field': missing[0] if missing else 'details',
                'message': f"To get a quote, I still need: {', '.join(missing)}. Please complete the guided flow or tell me your preferences."
            }

    for h in hotels:
        if h['name'].lower() in msg or h['key'].lower() in msg:
            return {'action': 'SET_HOTEL', 'value': h['key'], 'message': f"Changed hotel to {h['name']}."}

    for t in transports:
        if t['name'].lower() in msg or t['key'].lower() in msg:
            return {'action': 'SET_TRANSPORT', 'value': t['key'], 'message': f"Changed transport to {t['name']}."}

    adult_match = re.search(r'(\d+)\s*adult', msg)
    if adult_match:
        val = int(adult_match.group(1))
        if 1 <= val <= 20:
            return {'action': 'SET_ADULTS', 'value': val, 'message': f"Set adults to {val}."}

    child_match = re.search(r'(\d+)\s*child', msg)
    if child_match:
        val = int(child_match.group(1))
        if 0 <= val <= 10:
            return {'action': 'SET_CHILDREN', 'value': val, 'message': f"Set children to {val}."}

    night_match = re.search(r'(\d+)\s*night', msg)
    if night_match:
        val = int(night_match.group(1))
        if 0 <= val <= 10:
            return {'action': 'SET_NIGHTS', 'value': val, 'message': f"Set nights to {val}."}

    room_match = re.search(r'(\d+)\s*room', msg)
    if room_match:
        val = int(room_match.group(1))
        if 1 <= val <= 20:
            return {'action': 'SET_ROOMS', 'value': val, 'message': f"Set rooms to {val}."}

    for a in addons:
        if a['name'].lower() in msg or a['key'].lower() in msg:
            if any(w in msg for w in ['remove', 'delete', 'cancel', 'no ']):
                return {'action': 'REMOVE_ADDON', 'value': a['key'], 'message': f"Removed {a['name']}."}
            else:
                return {'action': 'ADD_ADDON', 'value': a['key'], 'message': f"Added {a['name']}."}

    if any(w in msg for w in ['budget', 'cheap', 'affordable', 'save', 'less']):
        suggestions = []
        if state.get('season') == 'ON':
            suggestions.append("Switch to off-season for lower rates.")
        suggestions.append("Consider fewer nights or a different hotel tier.")
        return {
            'action': 'SUGGEST_UPGRADE',
            'suggestion': 'budget_optimize',
            'message': "Here are some ways to reduce cost: " + " ".join(suggestions)
        }

    if any(w in msg for w in ['upgrade', 'premium', 'luxury', 'better']):
        return {
            'action': 'SUGGEST_UPGRADE',
            'suggestion': 'premium',
            'message': "For a premium experience, consider upgrading your hotel or transport. Would you like me to suggest specific options?"
        }

    return {
        'action': 'GENERAL_CHAT',
        'message': "I can help you modify your package! Try asking me to change hotel, transport, number of nights, add extras, or get a price quote. You can also use the guided flow on the left."
    }


# =====================================================
# FRONTEND ROUTES
# =====================================================

@app.route('/')
def index():
    return render_template('index.html')


# =====================================================
# ENTRY POINT
# =====================================================

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)