"""
Travel Pricing Rule Engine — Enterprise Edition
================================================
Core calculation logic with:
  - Multi-client scoping
  - Dynamic rule engine
  - Occupancy-based room calculator
  - Transport pricing type support (per_person/per_vehicle)
  - Add-on peak/off rates
  - Flight component support (one_way / return)
  - Live hotel support (Amadeus Hotel Offers API)
  - All pricing calculations

This is the SINGLE SOURCE OF TRUTH for all price computation.
AI layers and frontends MUST call this engine — never compute prices themselves.

Hotel Source Behavior:
  - hotel_source == "admin" (default): existing per-person per-night logic, all hotel rules apply
  - hotel_source == "live": Amadeus total stay price used directly, entity_type="hotel" rules skipped
"""

from decimal import Decimal, ROUND_HALF_UP
from typing import Dict, List, Any, Optional, Tuple
import math
import json
import logging

logger = logging.getLogger(__name__)


# =====================================================
# EXCEPTIONS
# =====================================================

class PricingEngineError(Exception):
    """Base exception for pricing engine errors"""
    pass

class ComponentNotFoundError(PricingEngineError):
    pass

class RateMissingError(PricingEngineError):
    pass

class InvalidConfigurationError(PricingEngineError):
    pass

class RuleEngineError(PricingEngineError):
    pass


# =====================================================
# ROOM / OCCUPANCY CALCULATOR
# =====================================================

class RoomCalculator:
    """
    Intelligent room allocation engine.
    Supports: sharing types, extra mattress, child occupancy.
    """

    @staticmethod
    def calculate_room_allocation(
        adults: int,
        children: int,
        sharing_capacity: int = 2,
        child_age_limit: int = 5,
        paying_children: int = None
    ) -> Dict[str, Any]:
        """
        Calculate optimal room allocation.

        Args:
            adults: Number of adults
            children: Number of children
            sharing_capacity: Persons per room (2=double, 4=quad, etc.)
            child_age_limit: Children under this age share free
            paying_children: Children that count as occupants (if None, all children count)

        Returns:
            Dict with rooms, extra_mattresses, allocation details
        """
        if adults <= 0:
            raise InvalidConfigurationError("At least 1 adult required")

        if paying_children is None:
            paying_children = children

        total_occupants = adults + paying_children

        # Calculate base rooms needed
        rooms_needed = math.ceil(total_occupants / sharing_capacity)

        # Ensure at least 1 room
        rooms_needed = max(1, rooms_needed)

        # Calculate capacity and extra mattresses
        total_capacity = rooms_needed * sharing_capacity
        extra_persons = max(0, total_occupants - total_capacity)
        extra_mattresses = extra_persons  # 1 mattress per extra person

        # Free children (under age limit)
        free_children = children - paying_children

        return {
            'rooms': rooms_needed,
            'extra_mattresses': extra_mattresses,
            'total_occupants': total_occupants,
            'sharing_capacity': sharing_capacity,
            'free_children': free_children,
            'paying_children': paying_children,
            'allocation_detail': (
                f"{rooms_needed} room(s) × {sharing_capacity}-sharing"
                f"{f' + {extra_mattresses} extra mattress(es)' if extra_mattresses else ''}"
            )
        }


# =====================================================
# RULE ENGINE
# =====================================================

class RuleEngine:
    """
    Dynamic pricing rule processor.
    Fetches rules from DB, evaluates conditions, applies actions.
    Rules NEVER override the core calculation structure —
    they modify component costs before margin application.

    Live Hotel Mode:
      When hotel_source == "live", rules with entity_type == "hotel" are
      skipped entirely. Global rules and margin still apply.
    """

    def __init__(self, db_connection, client_id: int):
        self.db = db_connection
        self.client_id = client_id

    def fetch_active_rules(
        self,
        entity_type: str = None,
        entity_id: int = None
    ) -> List[Dict]:
        """Fetch active rules sorted by priority (lower = first)."""
        cursor = self.db.cursor()

        query = """
            SELECT id, name, entity_type, entity_id,
                   conditions_json, actions_json, priority, stackable
            FROM pricing_rules
            WHERE client_id = %s AND active = TRUE AND deleted = FALSE
        """
        params = [self.client_id]

        if entity_type:
            query += " AND (entity_type = %s OR entity_type = 'global')"
            params.append(entity_type)

        if entity_id:
            query += " AND (entity_id = %s OR entity_id IS NULL)"
            params.append(entity_id)

        query += " ORDER BY priority ASC, id ASC"

        cursor.execute(query, params)
        columns = [desc[0] for desc in cursor.description]
        rows = cursor.fetchall()

        rules = []
        for row in rows:
            rule = dict(zip(columns, row))
            # Parse JSON fields
            if isinstance(rule['conditions_json'], str):
                rule['conditions_json'] = json.loads(rule['conditions_json'])
            if isinstance(rule['actions_json'], str):
                rule['actions_json'] = json.loads(rule['actions_json'])
            rules.append(rule)

        return rules

    def evaluate_conditions(self, conditions: Dict, context: Dict) -> bool:
        """
        Evaluate rule conditions against current calculation context.

        Supported condition operators:
            key == value          → exact match
            key_gte: N            → context[key] >= N
            key_lte: N            → context[key] <= N
            key_in: [a, b, c]    → context[key] in list
        """
        if not conditions:
            return True  # No conditions = always applies

        for cond_key, cond_value in conditions.items():
            # Parse operator suffix
            if cond_key.endswith('_gte'):
                field = cond_key[:-4]
                ctx_val = context.get(field)
                if ctx_val is None or float(ctx_val) < float(cond_value):
                    return False

            elif cond_key.endswith('_lte'):
                field = cond_key[:-4]
                ctx_val = context.get(field)
                if ctx_val is None or float(ctx_val) > float(cond_value):
                    return False

            elif cond_key.endswith('_in'):
                field = cond_key[:-3]
                ctx_val = context.get(field)
                if ctx_val is None or ctx_val not in cond_value:
                    return False

            else:
                # Exact match
                ctx_val = context.get(cond_key)
                if ctx_val is None or str(ctx_val) != str(cond_value):
                    return False

        return True

    def apply_action(
        self, action: Dict, costs: Dict[str, Decimal]
    ) -> Dict[str, Decimal]:
        """
        Apply a rule action to the cost breakdown.

        Supported actions:
            increase_rate_percent  → increase target cost by %
            decrease_rate_percent  → decrease target cost by %
            override_rate          → replace target cost
            add_flat_fee           → add flat amount to 'rule_adjustments'
            apply_margin           → add % margin on base_total
        """
        action_type = action.get('type', '')
        target = action.get('target', 'total')  # hotel, transport, sightseeing, cab, addon, flight, total
        value = Decimal(str(action.get('value', 0)))

        cost_key_map = {
            'hotel': 'hotel_cost',
            'transport': 'transport_cost',
            'sightseeing': 'sightseeing_cost',
            'cab': 'cab_cost',
            'addon': 'addon_cost',
            'flight': 'flight_cost',
            'total': 'base_total'
        }

        key = cost_key_map.get(target, 'base_total')

        if action_type == 'increase_rate_percent':
            current = costs.get(key, Decimal('0'))
            adjustment = (current * value / 100).quantize(Decimal('0.01'), ROUND_HALF_UP)
            costs[key] = current + adjustment
            costs['rule_adjustments'] = costs.get('rule_adjustments', Decimal('0')) + adjustment

        elif action_type == 'decrease_rate_percent':
            current = costs.get(key, Decimal('0'))
            adjustment = (current * value / 100).quantize(Decimal('0.01'), ROUND_HALF_UP)
            costs[key] = current - adjustment
            costs['rule_adjustments'] = costs.get('rule_adjustments', Decimal('0')) - adjustment

        elif action_type == 'override_rate':
            old_val = costs.get(key, Decimal('0'))
            costs[key] = value
            costs['rule_adjustments'] = costs.get('rule_adjustments', Decimal('0')) + (value - old_val)

        elif action_type == 'add_flat_fee':
            costs['rule_adjustments'] = costs.get('rule_adjustments', Decimal('0')) + value

        elif action_type == 'apply_margin':
            base = costs.get('base_total', Decimal('0'))
            margin = (base * value / 100).quantize(Decimal('0.01'), ROUND_HALF_UP)
            costs['rule_adjustments'] = costs.get('rule_adjustments', Decimal('0')) + margin

        return costs

    def process_rules(
        self,
        context: Dict,
        costs: Dict[str, Decimal],
        hotel_source: str = 'admin'
    ) -> Tuple[Dict[str, Decimal], List[Dict]]:
        """
        Main entry: fetch rules, evaluate, apply.
        Returns updated costs and list of applied rules.

        When hotel_source == 'live':
          Rules where entity_type == 'hotel' are skipped entirely.
          This ensures Amadeus total prices are not further adjusted by
          admin hotel-specific pricing rules.
        """
        rules = self.fetch_active_rules()
        applied_rules = []
        already_applied_non_stackable = set()

        for rule in rules:
            entity_type = rule['entity_type']

            # --- LIVE HOTEL RULE GATE ---
            # When using Amadeus live hotel pricing, skip hotel-specific rules.
            # Global rules, margin rules, transport rules, etc. still apply.
            if hotel_source == 'live' and entity_type == 'hotel':
                logger.info(
                    f"Rule skipped (live hotel mode): [{rule['id']}] {rule['name']} "
                    f"(entity_type=hotel rules do not apply to live hotel pricing)"
                )
                continue

            # Skip non-stackable duplicates
            if not rule['stackable']:
                ns_key = f"{entity_type}:{rule.get('entity_id', 'all')}"
                if ns_key in already_applied_non_stackable:
                    continue

            # Evaluate conditions
            if self.evaluate_conditions(rule['conditions_json'], context):
                costs = self.apply_action(rule['actions_json'], costs)
                applied_rules.append({
                    'rule_id': rule['id'],
                    'name': rule['name'],
                    'action': rule['actions_json']
                })

                if not rule['stackable']:
                    ns_key = f"{entity_type}:{rule.get('entity_id', 'all')}"
                    already_applied_non_stackable.add(ns_key)

                logger.info(f"Rule applied: [{rule['id']}] {rule['name']}")

        return costs, applied_rules


# =====================================================
# FLIGHT COST CALCULATOR
# =====================================================

class FlightCostCalculator:
    """
    Calculates flight cost component from a selected flight offer.
    Flight data comes from the Amadeus API search (handled by the route layer).
    The engine only receives the resolved base_fare and pax count.
    This is the SINGLE SOURCE OF TRUTH for flight cost computation.
    """

    @staticmethod
    def calculate(flight_payload: Optional[Dict], adults: int, children: int) -> Decimal:
        """
        Calculate total flight cost.

        Args:
            flight_payload: Dict containing:
                - type: 'one_way' | 'return' | 'none'
                - base_fare: numeric (per-person total fare from Amadeus)
                - pax: int (optional override; defaults to adults + children)
            adults: number of adult travelers
            children: number of child travelers

        Returns:
            Decimal total flight cost
        """
        if not flight_payload:
            return Decimal('0')

        flight_type = flight_payload.get('type', 'none')
        if flight_type == 'none' or not flight_type:
            return Decimal('0')

        base_fare = flight_payload.get('base_fare', 0)
        if not base_fare:
            return Decimal('0')

        base_fare = Decimal(str(base_fare))

        # Use explicit pax if provided, else sum adults + children
        pax = flight_payload.get('pax')
        if pax is not None:
            pax = int(pax)
        else:
            pax = adults + children

        if pax <= 0:
            return Decimal('0')

        total = (base_fare * pax).quantize(Decimal('0.01'), ROUND_HALF_UP)
        logger.info(f"Flight cost: {flight_type}, base_fare={base_fare}, pax={pax}, total={total}")
        return total


# =====================================================
# LIVE HOTEL COST CALCULATOR
# =====================================================

class LiveHotelCostCalculator:
    """
    Calculates hotel cost when hotel_source == 'live'.

    The Amadeus Hotel Offers API returns a totalPrice that already
    represents the COMPLETE STAY cost (all nights, all rooms, all pax).

    CRITICAL RULES:
      - DO NOT multiply by nights
      - DO NOT multiply by pax
      - DO NOT multiply by rooms
      - The totalPrice IS the hotel cost, already converted to INR
      - This is the SINGLE SOURCE OF TRUTH for live hotel cost computation
    """

    @staticmethod
    def calculate(live_hotel_payload: Optional[Dict]) -> Decimal:
        """
        Calculate live hotel cost from Amadeus offer payload.

        Args:
            live_hotel_payload: Dict containing:
                - live_hotel_total_price: numeric total stay price in INR
                  (currency conversion has already been applied server-side)
                - live_hotel_id: str (offer ID for reference, not used in math)
                - live_hotel_currency: str (original currency, informational only)
                - live_hotel_original_price: numeric (original price before FX, informational)

        Returns:
            Decimal total hotel cost in INR
        """
        if not live_hotel_payload:
            return Decimal('0')

        total_price_inr = live_hotel_payload.get('live_hotel_total_price', 0)
        if not total_price_inr:
            return Decimal('0')

        try:
            total = Decimal(str(total_price_inr)).quantize(Decimal('0.01'), ROUND_HALF_UP)
        except Exception as e:
            logger.error(f"LiveHotelCostCalculator: could not parse live_hotel_total_price: {e}")
            return Decimal('0')

        logger.info(
            f"Live hotel cost: total_price_inr={total} "
            f"(original_currency={live_hotel_payload.get('live_hotel_currency','INR')}, "
            f"original_price={live_hotel_payload.get('live_hotel_original_price', total_price_inr)})"
        )
        return total


# =====================================================
# MAIN PRICING ENGINE
# =====================================================

class TravelPricingEngine:
    """
    Core pricing engine — enterprise edition.
    All calculations are client-scoped.
    Rule engine applies dynamic adjustments.
    Room calculator handles occupancy.
    Transport pricing type support (per_person/per_vehicle).
    Add-on peak/off rates.
    Flight component support (one_way/return via Amadeus).
    Live hotel support (Amadeus Hotel Offers API total price).

    Hotel Source Modes:
      hotel_source = "admin" (default):
        - Uses internal DB hotel records
        - Per-person per-night pricing
        - hotel entity_type rules apply
      hotel_source = "live":
        - Uses Amadeus live_hotel_total_price (already full stay in INR)
        - Does NOT multiply by nights/pax/rooms
        - hotel entity_type rules are SKIPPED
        - Global rules and margin still apply
    """

    def __init__(self, db_connection, client_id: int = 1):
        self.db = db_connection
        self.client_id = client_id
        self.rule_engine = RuleEngine(db_connection, client_id)
        self.room_calculator = RoomCalculator()

    # -------------------------------------------------
    # MAIN ENTRY POINT
    # -------------------------------------------------

    def calculate_package_price(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main pricing calculation.
        Returns structured breakdown with rule adjustments.

        Supports two hotel source modes controlled by payload['hotel_source']:
          "admin" (default) — existing DB hotel pricing logic
          "live"            — Amadeus total stay price passthrough
        """
        self._validate_inputs(payload)

        region_id = payload['region_id']
        adults = int(payload.get('adults', payload.get('pax', 2)))
        children = int(payload.get('children', 0))
        pax = adults + children
        season = payload.get('season', 'ON')
        nights = int(payload.get('nights', 0))
        manual_rooms = payload.get('rooms')
        hotel_key = payload.get('hotel', '')
        transport_key = payload.get('transport', '')
        cab_key = payload.get('cab', '')
        days_list = payload.get('days', [])
        per_night_hotels = payload.get('perNightHotels', {})
        kasol_sharing = payload.get('kasolSharing', '')
        per_night_kasol = payload.get('perNightKasolSharing', {})
        addon_keys = payload.get('addons', [])

        # Hotel source flag — controls which hotel pricing path to use
        hotel_source = payload.get('hotel_source', 'admin').lower().strip()
        if hotel_source not in ('admin', 'live'):
            hotel_source = 'admin'

        # Live hotel payload — only present when hotel_source == 'live'
        live_hotel_payload = payload.get('live_hotel') if hotel_source == 'live' else None

        # Flight payload — optional, injected when user selects a live flight
        flight_payload = payload.get('flight', None)

        # Fetch region
        region = self._get_region(region_id)

        # Fetch global rules for this client
        global_rules = self._get_global_rules()

        # Determine service/booking percentages
        service_pct = Decimal(str(global_rules.get('service_charge', region['service_percent'])))
        booking_pct = Decimal(str(global_rules.get('booking_charge', region['booking_percent'])))

        # Resolve hotel (admin path only)
        hotel = None
        if hotel_source == 'admin' and hotel_key:
            hotel = self._resolve_hotel(hotel_key)

        # Auto-calculate rooms if not manually set
        if manual_rooms and int(manual_rooms) > 0:
            rooms = int(manual_rooms)
            room_allocation = None
        else:
            sharing_cap = hotel['sharing_capacity'] if hotel else 2
            room_alloc = self.room_calculator.calculate_room_allocation(
                adults, children, sharing_cap
            )
            rooms = room_alloc['rooms']
            room_allocation = room_alloc

        # Calculate component costs
        # HOTEL COST — branched by hotel_source
        if hotel_source == 'live':
            # Live hotel: Amadeus total price, no further multiplication
            hotel_cost = LiveHotelCostCalculator.calculate(live_hotel_payload)
            logger.info(f"Hotel path: LIVE — hotel_cost={hotel_cost}")
        else:
            # Admin hotel: existing per-person per-night logic
            hotel_cost = self._calculate_hotel_cost(
                hotel_key, nights, rooms, adults, children, season,
                per_night_hotels, kasol_sharing, per_night_kasol
            )
            logger.info(f"Hotel path: ADMIN — hotel_cost={hotel_cost}")

        transport_cost = self._calculate_transport_cost(
            transport_key, adults, children, season
        )
        sightseeing_cost = self._calculate_sightseeing_cost(
            days_list, adults, children, season, cab_key
        )
        cab_cost = self._calculate_cab_cost(
            cab_key, days_list
        )
        addon_cost = self._calculate_addon_cost(
            addon_keys, adults, children, nights, season
        )

        # Flight cost — calculated by FlightCostCalculator (single source of truth)
        flight_cost = FlightCostCalculator.calculate(flight_payload, adults, children)

        # Build costs dict for rule engine
        costs = {
            'hotel_cost': hotel_cost,
            'transport_cost': transport_cost,
            'sightseeing_cost': sightseeing_cost,
            'cab_cost': cab_cost,
            'addon_cost': addon_cost,
            'flight_cost': flight_cost,
            'rule_adjustments': Decimal('0'),
        }

        # Build rule context
        rule_context = {
            'region_id': region_id,
            'season': season,
            'adults': adults,
            'children': children,
            'pax': pax,
            'nights': nights,
            'rooms': rooms,
            'hotel': hotel_key,
            'transport': transport_key,
            'cab': cab_key,
            'sightseeing_days': len([d for d in days_list if d != 'N/A']),
            'has_flight': flight_cost > 0,
            'hotel_source': hotel_source,
        }

        # Apply pricing rules — hotel_source passed so hotel-entity rules can
        # be skipped in live hotel mode
        costs, applied_rules = self.rule_engine.process_rules(
            rule_context, costs, hotel_source=hotel_source
        )

        # Compute totals
        base_total = (
            costs['hotel_cost'] +
            costs['transport_cost'] +
            costs['sightseeing_cost'] +
            costs['cab_cost'] +
            costs['addon_cost'] +
            costs['flight_cost'] +
            costs['rule_adjustments']
        )

        service_charge = (base_total * service_pct / 100).quantize(
            Decimal('0.01'), ROUND_HALF_UP
        )
        after_service = base_total + service_charge

        booking_charge = (after_service * booking_pct / 100).quantize(
            Decimal('0.01'), ROUND_HALF_UP
        )

        final_total = after_service + booking_charge
        per_person = (final_total / pax).quantize(
            Decimal('0.01'), ROUND_HALF_UP
        ) if pax > 0 else Decimal('0')

        result = {
            'success': True,
            'hotelCost': float(costs['hotel_cost']),
            'transportCost': float(costs['transport_cost']),
            'sightseeingCost': float(costs['sightseeing_cost']),
            'cabCost': float(costs['cab_cost']),
            'addonCost': float(costs['addon_cost']),
            'flightCost': float(costs['flight_cost']),
            'ruleAdjustments': float(costs['rule_adjustments']),
            'appliedRules': applied_rules,
            'baseTotal': float(base_total),
            'serviceCharge': float(service_charge),
            'bookingCharge': float(booking_charge),
            'total': float(final_total),
            'perPerson': float(per_person),
            'rooms': rooms,
            'roomAllocation': room_allocation,
            'pax': pax,
            'adults': adults,
            'children': children,
            'hotelSource': hotel_source,
        }

        # If live hotel, include metadata for display
        if hotel_source == 'live' and live_hotel_payload:
            result['liveHotelMeta'] = {
                'hotelName': live_hotel_payload.get('live_hotel_name', ''),
                'roomType': live_hotel_payload.get('live_hotel_room_type', ''),
                'boardType': live_hotel_payload.get('live_hotel_board_type', ''),
                'totalPriceINR': float(hotel_cost),
                'originalCurrency': live_hotel_payload.get('live_hotel_currency', 'INR'),
                'originalPrice': live_hotel_payload.get('live_hotel_original_price', float(hotel_cost)),
                'offerId': live_hotel_payload.get('live_hotel_id', ''),
            }

        return result

    # -------------------------------------------------
    # VALIDATION
    # -------------------------------------------------

    def _validate_inputs(self, payload: Dict[str, Any]) -> None:
        if 'region_id' not in payload:
            raise InvalidConfigurationError("Missing required field: region_id")

        adults = int(payload.get('adults', payload.get('pax', 0)))
        children = int(payload.get('children', 0))
        if adults + children <= 0:
            raise InvalidConfigurationError("At least 1 traveler required")

    # -------------------------------------------------
    # REGION / GLOBAL
    # -------------------------------------------------

    def _get_region(self, region_id: int) -> Dict[str, Any]:
        cursor = self.db.cursor()
        cursor.execute(
            """SELECT id, name, currency, service_percent, booking_percent, is_domestic
               FROM regions
               WHERE id = %s AND client_id = %s AND active = TRUE AND deleted = FALSE""",
            (region_id, self.client_id)
        )
        row = cursor.fetchone()
        if not row:
            raise ComponentNotFoundError(f"Region {region_id} not found for client {self.client_id}")

        return {
            'id': row[0], 'name': row[1], 'currency': row[2],
            'service_percent': Decimal(str(row[3])),
            'booking_percent': Decimal(str(row[4])),
            'is_domestic': row[5]
        }

    def _get_global_rules(self) -> Dict[str, Any]:
        cursor = self.db.cursor()
        cursor.execute(
            "SELECT service_charge, booking_charge, tax, default_margin FROM global_rules WHERE client_id = %s",
            (self.client_id,)
        )
        row = cursor.fetchone()
        if not row:
            return {}
        return {
            'service_charge': float(row[0]),
            'booking_charge': float(row[1]),
            'tax': float(row[2]),
            'default_margin': float(row[3])
        }

    # -------------------------------------------------
    # RESOLVE HOTEL BY INTERNAL_NAME
    # -------------------------------------------------

    def _resolve_hotel(self, internal_name: str) -> Optional[Dict]:
        if not internal_name or internal_name == 'NONE':
            return None
        cursor = self.db.cursor()
        cursor.execute(
            """SELECT id, name, internal_name, sharing_type, sharing_capacity,
                      is_kasol, extra_mattress_rate, extra_mattress_child_rate,
                      child_age_limit,
                      adult_rate_peak, child_rate_peak, adult_rate_off, child_rate_off
               FROM hotels
               WHERE internal_name = %s AND client_id = %s AND active = TRUE AND deleted = FALSE""",
            (internal_name, self.client_id)
        )
        row = cursor.fetchone()
        if not row:
            return None
        return {
            'id': row[0], 'name': row[1], 'internal_name': row[2],
            'sharing_type': row[3], 'sharing_capacity': row[4],
            'is_kasol': row[5], 'extra_mattress_rate': Decimal(str(row[6])),
            'extra_mattress_child_rate': Decimal(str(row[7])),
            'child_age_limit': row[8],
            'adult_rate_peak': Decimal(str(row[9])),
            'child_rate_peak': Decimal(str(row[10])),
            'adult_rate_off': Decimal(str(row[11])),
            'child_rate_off': Decimal(str(row[12])),
        }

    # -------------------------------------------------
    # HOTEL COST (ADMIN PATH ONLY)
    # -------------------------------------------------

    def _calculate_hotel_cost(
        self, hotel_key, nights, rooms, adults, children, season,
        per_night_hotels, kasol_sharing, per_night_kasol
    ) -> Decimal:
        if nights <= 0 or not hotel_key:
            return Decimal('0')

        total = Decimal('0')

        for night_idx in range(nights):
            idx_str = str(night_idx)
            night_hotel_key = per_night_hotels.get(idx_str, hotel_key)
            hotel = self._resolve_hotel(night_hotel_key)

            if not hotel:
                continue

            if season == 'ON':
                adult_rate = hotel['adult_rate_peak']
                child_rate = hotel['child_rate_peak']
            else:
                adult_rate = hotel['adult_rate_off']
                child_rate = hotel['child_rate_off']

            night_cost = (adult_rate * adults) + (child_rate * children)

            # Kasol sharing multiplier
            night_kasol = per_night_kasol.get(idx_str, kasol_sharing)
            if hotel['is_kasol'] and night_kasol == 'QUAD':
                night_cost = night_cost * Decimal('0.75')  # Quad discount

            total += night_cost

        return total.quantize(Decimal('0.01'), ROUND_HALF_UP)

    # -------------------------------------------------
    # TRANSPORT COST (WITH PRICING TYPE SUPPORT)
    # -------------------------------------------------

    def _calculate_transport_cost(
        self, transport_key, adults, children, season
    ) -> Decimal:
        if not transport_key or transport_key == 'NONE':
            return Decimal('0')

        cursor = self.db.cursor()
        cursor.execute(
            """SELECT adult_rate_peak, child_rate_peak, peak_pricing_type,
                      adult_rate_off, child_rate_off, off_pricing_type
               FROM transports
               WHERE transport_type = %s AND client_id = %s AND active = TRUE AND deleted = FALSE""",
            (transport_key, self.client_id)
        )
        row = cursor.fetchone()
        if not row:
            return Decimal('0')

        if season == 'ON':
            adult_rate = Decimal(str(row[0]))
            child_rate = Decimal(str(row[1]))
            pricing_type = row[2]
        else:
            adult_rate = Decimal(str(row[3]))
            child_rate = Decimal(str(row[4]))
            pricing_type = row[5]

        # Calculate based on pricing type
        if pricing_type == 'per_vehicle':
            # Use adult_rate as full vehicle cost, ignore child_rate and pax
            total = adult_rate
        else:
            # Default: per_person
            total = (adult_rate * adults) + (child_rate * children)

        return total.quantize(Decimal('0.01'), ROUND_HALF_UP)

    # -------------------------------------------------
    # SIGHTSEEING COST
    # -------------------------------------------------

    def _calculate_sightseeing_cost(
        self, days_list, adults, children, season, cab_key
    ) -> Decimal:
        if not days_list:
            return Decimal('0')

        total = Decimal('0')
        pax = adults + children

        for dest_key in days_list:
            if not dest_key or dest_key == 'N/A':
                continue

            cursor = self.db.cursor()
            cursor.execute(
                """SELECT base_rate, per_day_rate, is_special, four_by_four_rate
                   FROM destinations
                   WHERE internal_name = %s AND client_id = %s AND active = TRUE AND deleted = FALSE""",
                (dest_key, self.client_id)
            )
            row = cursor.fetchone()
            if not row:
                continue

            base_rate = Decimal(str(row[0]))
            per_day_rate = Decimal(str(row[1]))
            is_special = row[2]
            four_by_four_rate = Decimal(str(row[3]))

            if is_special and four_by_four_rate > 0:
                vehicles = math.ceil(pax / 6)
                total += four_by_four_rate * vehicles
            elif is_special:
                total += base_rate + per_day_rate
            else:
                total += per_day_rate

        return total.quantize(Decimal('0.01'), ROUND_HALF_UP)

    # -------------------------------------------------
    # CAB COST
    # -------------------------------------------------

    def _calculate_cab_cost(self, cab_key, days_list) -> Decimal:
        if not cab_key or cab_key == 'NONE' or not days_list:
            return Decimal('0')

        active_days = [d for d in days_list if d and d != 'N/A']
        if not active_days:
            return Decimal('0')

        cursor = self.db.cursor()
        cursor.execute(
            """SELECT base_rate, per_day_rate
               FROM cabs
               WHERE internal_name = %s AND client_id = %s AND active = TRUE AND deleted = FALSE""",
            (cab_key, self.client_id)
        )
        row = cursor.fetchone()
        if not row:
            return Decimal('0')

        base_rate = Decimal(str(row[0]))
        per_day_rate = Decimal(str(row[1]))

        total = Decimal('0')

        for dest_key in active_days:
            # Check for cab-destination override rate
            cursor2 = self.db.cursor()
            cursor2.execute(
                """SELECT cdr.override_rate, cdr.rate
                   FROM cab_destination_rates cdr
                   JOIN cabs c ON cdr.cab_id = c.id
                   JOIN destinations d ON cdr.destination_id = d.id
                   WHERE c.internal_name = %s AND d.internal_name = %s
                   AND cdr.client_id = %s""",
                (cab_key, dest_key, self.client_id)
            )
            rate_row = cursor2.fetchone()
            if rate_row:
                override = rate_row[0]
                base = rate_row[1]
                day_cost = Decimal(str(override)) if override else Decimal(str(base))
            else:
                day_cost = per_day_rate

            total += day_cost

        return total.quantize(Decimal('0.01'), ROUND_HALF_UP)

    # -------------------------------------------------
    # ADDON COST (WITH PEAK/OFF RATES)
    # -------------------------------------------------

    def _calculate_addon_cost(
        self, addon_keys, adults, children, nights, season
    ) -> Decimal:
        if not addon_keys:
            return Decimal('0')

        total = Decimal('0')
        pax = adults + children

        for addon_key in addon_keys:
            cursor = self.db.cursor()
            cursor.execute(
                """SELECT pricing_type, rate_peak, rate_off
                   FROM addons
                   WHERE internal_name = %s AND client_id = %s AND active = TRUE AND deleted = FALSE""",
                (addon_key, self.client_id)
            )
            row = cursor.fetchone()
            if not row:
                continue

            pricing_type = row[0]
            rate_peak = Decimal(str(row[1]))
            rate_off = Decimal(str(row[2]))

            # Select rate based on season
            rate = rate_peak if season == 'ON' else rate_off

            # Apply pricing type
            if pricing_type == 'flat':
                total += rate
            elif pricing_type == 'per_person':
                total += rate * pax
            elif pricing_type in ('per_day', 'per_night'):
                total += rate * max(nights, 1)

        return total.quantize(Decimal('0.01'), ROUND_HALF_UP)


# =====================================================
# CHECK CAB REQUIRED HELPER
# =====================================================

def check_cab_required(transport_key: str, days_list: List[str]) -> bool:
    """Determine if cab is needed based on transport type and itinerary."""
    if not transport_key or transport_key == 'NONE':
        return False

    no_cab_transports = {'SELF_DRIVE', 'OWN_CAR', 'RENTAL'}
    if transport_key.upper() in no_cab_transports:
        return False

    active_days = [d for d in (days_list or []) if d and d != 'N/A']
    return len(active_days) > 0