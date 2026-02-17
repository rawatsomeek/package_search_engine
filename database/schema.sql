-- =====================================================
-- TRAVEL PRICING RULE ENGINE - ENTERPRISE SCHEMA
-- Version 3.1 — PRODUCTION FIX + MIGRATION SUPPORT
-- =====================================================

-- =====================================================
-- CORE: CLIENTS TABLE
-- =====================================================
CREATE TABLE IF NOT EXISTS clients (
    id SERIAL PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    code VARCHAR(30) NOT NULL,
    contact_email VARCHAR(200),
    contact_phone VARCHAR(30),
    currency_default VARCHAR(10) NOT NULL DEFAULT 'INR',
    active BOOLEAN NOT NULL DEFAULT TRUE,
    deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(name, deleted) WHERE deleted = FALSE,
    UNIQUE(code, deleted) WHERE deleted = FALSE
);

INSERT INTO clients (id, name, code, currency_default) VALUES
    (1, 'AKS Hospitality', 'aks-hospitality', 'INR')
ON CONFLICT (id) DO NOTHING;

-- =====================================================
-- REGIONS
-- =====================================================
CREATE TABLE IF NOT EXISTS regions (
    id SERIAL PRIMARY KEY,
    client_id INTEGER NOT NULL DEFAULT 1 REFERENCES clients(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    currency VARCHAR(10) NOT NULL DEFAULT 'INR',
    is_domestic BOOLEAN NOT NULL DEFAULT TRUE,
    service_percent DECIMAL(5,2) NOT NULL DEFAULT 15.00,
    booking_percent DECIMAL(5,2) NOT NULL DEFAULT 12.00,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS regions_client_name_active_unique 
ON regions(client_id, name) WHERE deleted = FALSE;

INSERT INTO regions (id, client_id, name, currency, is_domestic, service_percent, booking_percent) VALUES
    (1, 1, 'GOA', 'INR', TRUE, 15.00, 12.00),
    (2, 1, 'Himachal', 'INR', TRUE, 15.00, 12.00),
    (3, 1, 'Rajasthan', 'INR', TRUE, 15.00, 12.00)
ON CONFLICT DO NOTHING;

-- =====================================================
-- TRANSPORTS (WITH PRICING TYPES)
-- =====================================================
CREATE TABLE IF NOT EXISTS transports (
    id SERIAL PRIMARY KEY,
    client_id INTEGER NOT NULL DEFAULT 1 REFERENCES clients(id) ON DELETE CASCADE,
    region_id INTEGER NOT NULL REFERENCES regions(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    transport_type VARCHAR(60) NOT NULL,
    display_name VARCHAR(120) NOT NULL,
    seat_capacity INTEGER NOT NULL DEFAULT 0,
    adult_rate_peak DECIMAL(12,2) NOT NULL DEFAULT 0,
    child_rate_peak DECIMAL(12,2) NOT NULL DEFAULT 0,
    peak_pricing_type VARCHAR(20) NOT NULL DEFAULT 'per_person',
    adult_rate_off DECIMAL(12,2) NOT NULL DEFAULT 0,
    child_rate_off DECIMAL(12,2) NOT NULL DEFAULT 0,
    off_pricing_type VARCHAR(20) NOT NULL DEFAULT 'per_person',
    upgrade_to_id INTEGER REFERENCES transports(id) ON DELETE SET NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CHECK (peak_pricing_type IN ('per_person', 'per_vehicle')),
    CHECK (off_pricing_type IN ('per_person', 'per_vehicle'))
);

CREATE UNIQUE INDEX IF NOT EXISTS transports_client_region_type_active_unique 
ON transports(client_id, region_id, transport_type) WHERE deleted = FALSE;

-- MIGRATION: Add pricing_type columns if they don't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='transports' AND column_name='peak_pricing_type') THEN
        ALTER TABLE transports ADD COLUMN peak_pricing_type VARCHAR(20) NOT NULL DEFAULT 'per_person';
        ALTER TABLE transports ADD CONSTRAINT transports_peak_pricing_type_check CHECK (peak_pricing_type IN ('per_person', 'per_vehicle'));
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='transports' AND column_name='off_pricing_type') THEN
        ALTER TABLE transports ADD COLUMN off_pricing_type VARCHAR(20) NOT NULL DEFAULT 'per_person';
        ALTER TABLE transports ADD CONSTRAINT transports_off_pricing_type_check CHECK (off_pricing_type IN ('per_person', 'per_vehicle'));
    END IF;
END $$;

-- =====================================================
-- DESTINATIONS
-- =====================================================
CREATE TABLE IF NOT EXISTS destinations (
    id SERIAL PRIMARY KEY,
    client_id INTEGER NOT NULL DEFAULT 1 REFERENCES clients(id) ON DELETE CASCADE,
    region_id INTEGER NOT NULL REFERENCES regions(id) ON DELETE CASCADE,
    name VARCHAR(150) NOT NULL,
    internal_name VARCHAR(80) NOT NULL,
    display_name VARCHAR(150) NOT NULL,
    destination_type VARCHAR(30) DEFAULT 'CITY'
        CHECK (destination_type IN ('CITY', 'HILL_STATION', 'BEACH', 'RELIGIOUS', 'ADVENTURE', 'WILDLIFE', 'HERITAGE', 'OTHER')),
    is_special SMALLINT NOT NULL DEFAULT 0,
    base_rate DECIMAL(12,2) NOT NULL DEFAULT 0,
    per_day_rate DECIMAL(12,2) NOT NULL DEFAULT 0,
    four_by_four_rate DECIMAL(12,2) NOT NULL DEFAULT 0,
    free_sightseeing_days INTEGER NOT NULL DEFAULT 0,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS destinations_client_region_internal_active_unique 
ON destinations(client_id, region_id, internal_name) WHERE deleted = FALSE;

INSERT INTO destinations (client_id, region_id, name, internal_name, display_name, destination_type, is_special, base_rate, per_day_rate) VALUES
    (1, 1, 'Calangute Beach', 'calaungate', 'Calangute Beach', 'BEACH', 0, 0, 500.00),
    (1, 1, 'Baga Beach', 'baga-beach', 'Baga Beach', 'BEACH', 0, 0, 600.00),
    (1, 1, 'Old Goa', 'old-goa', 'Old Goa Churches', 'HERITAGE', 0, 0, 400.00),
    (1, 2, 'Manali', 'manali', 'Manali', 'HILL_STATION', 0, 0, 800.00),
    (1, 2, 'Solang Valley', 'solang-valley', 'Solang Valley', 'ADVENTURE', 1, 1200.00, 1500.00),
    (1, 3, 'Jaipur City', 'jaipur', 'Jaipur', 'HERITAGE', 0, 0, 700.00)
ON CONFLICT DO NOTHING;

-- =====================================================
-- HOTELS
-- =====================================================
CREATE TABLE IF NOT EXISTS hotels (
    id SERIAL PRIMARY KEY,
    client_id INTEGER NOT NULL DEFAULT 1 REFERENCES clients(id) ON DELETE CASCADE,
    region_id INTEGER NOT NULL REFERENCES regions(id) ON DELETE CASCADE,
    destination_id INTEGER REFERENCES destinations(id) ON DELETE SET NULL,
    name VARCHAR(150) NOT NULL,
    internal_name VARCHAR(80) NOT NULL,
    sharing_type VARCHAR(20) NOT NULL DEFAULT 'DOUBLE',
    sharing_capacity INTEGER NOT NULL DEFAULT 2,
    custom_sharing_name VARCHAR(60),
    is_kasol SMALLINT NOT NULL DEFAULT 0,
    extra_mattress_rate DECIMAL(12,2) NOT NULL DEFAULT 0,
    extra_mattress_child_rate DECIMAL(12,2) NOT NULL DEFAULT 0,
    child_age_limit INTEGER NOT NULL DEFAULT 5,
    adult_rate_peak DECIMAL(12,2) NOT NULL DEFAULT 0,
    child_rate_peak DECIMAL(12,2) NOT NULL DEFAULT 0,
    adult_rate_off DECIMAL(12,2) NOT NULL DEFAULT 0,
    child_rate_off DECIMAL(12,2) NOT NULL DEFAULT 0,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS hotels_client_region_internal_active_unique 
ON hotels(client_id, region_id, internal_name) WHERE deleted = FALSE;

INSERT INTO hotels (client_id, region_id, name, internal_name, sharing_type, sharing_capacity, adult_rate_peak, child_rate_peak, adult_rate_off, child_rate_off) VALUES
    (1, 1, 'Hotel Goa', 'hotel-goa', 'DOUBLE', 2, 2500.00, 1000.00, 2000.00, 800.00),
    (1, 1, 'Goa Beach Resort', 'goa-beach-resort', 'DOUBLE', 2, 3500.00, 1500.00, 3000.00, 1200.00),
    (1, 2, 'Manali Heights', 'manali-heights', 'DOUBLE', 2, 3000.00, 1200.00, 2500.00, 1000.00),
    (1, 3, 'Jaipur Palace Hotel', 'jaipur-palace', 'QUAD', 4, 4000.00, 1500.00, 3500.00, 1200.00)
ON CONFLICT DO NOTHING;

-- =====================================================
-- CABS
-- =====================================================
CREATE TABLE IF NOT EXISTS cabs (
    id SERIAL PRIMARY KEY,
    client_id INTEGER NOT NULL DEFAULT 1 REFERENCES clients(id) ON DELETE CASCADE,
    region_id INTEGER NOT NULL REFERENCES regions(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    internal_name VARCHAR(80) NOT NULL,
    display_name VARCHAR(120) NOT NULL,
    capacity INTEGER NOT NULL DEFAULT 4,
    base_rate DECIMAL(12,2) NOT NULL DEFAULT 0,
    per_day_rate DECIMAL(12,2) NOT NULL DEFAULT 0,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS cabs_client_region_internal_active_unique 
ON cabs(client_id, region_id, internal_name) WHERE deleted = FALSE;

INSERT INTO cabs (client_id, region_id, name, internal_name, display_name, capacity, base_rate, per_day_rate) VALUES
    (1, 1, 'Alto', 'alto', 'Maruti Alto', 4, 500.00, 800.00),
    (1, 1, 'Swift Dzire', 'swift-dzire', 'Swift Dzire', 4, 700.00, 1000.00),
    (1, 2, 'Innova', 'innova', 'Toyota Innova', 7, 1200.00, 1800.00),
    (1, 3, 'Tempo Traveller', 'tempo-traveller', 'Tempo Traveller', 12, 2000.00, 3000.00)
ON CONFLICT DO NOTHING;

-- =====================================================
-- CAB ↔ DESTINATION RATE MATRIX
-- =====================================================
CREATE TABLE IF NOT EXISTS cab_destination_rates (
    id SERIAL PRIMARY KEY,
    client_id INTEGER NOT NULL DEFAULT 1 REFERENCES clients(id) ON DELETE CASCADE,
    cab_id INTEGER NOT NULL REFERENCES cabs(id) ON DELETE CASCADE,
    destination_id INTEGER NOT NULL REFERENCES destinations(id) ON DELETE CASCADE,
    rate DECIMAL(12,2) NOT NULL DEFAULT 0,
    override_rate DECIMAL(12,2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS cab_dest_rates_client_cab_dest_active_unique 
ON cab_destination_rates(client_id, cab_id, destination_id);

INSERT INTO cab_destination_rates (client_id, cab_id, destination_id, rate, override_rate) 
SELECT 1, c.id, d.id, 800.00, NULL
FROM cabs c, destinations d
WHERE c.internal_name = 'alto' AND d.internal_name = 'calaungate'
ON CONFLICT DO NOTHING;

-- =====================================================
-- ADD-ONS (WITH PEAK/OFF RATES)
-- =====================================================
CREATE TABLE IF NOT EXISTS addons (
    id SERIAL PRIMARY KEY,
    client_id INTEGER NOT NULL DEFAULT 1 REFERENCES clients(id) ON DELETE CASCADE,
    region_id INTEGER NOT NULL REFERENCES regions(id) ON DELETE CASCADE,
    name VARCHAR(150) NOT NULL,
    internal_name VARCHAR(80) NOT NULL,
    addon_type VARCHAR(30) NOT NULL DEFAULT 'GENERAL'
        CHECK (addon_type IN ('GENERAL', 'INSURANCE', 'MEAL', 'ACTIVITY', 'TRANSPORT', 'EQUIPMENT', 'SERVICE')),
    pricing_type VARCHAR(20) NOT NULL DEFAULT 'flat'
        CHECK (pricing_type IN ('flat', 'per_person', 'per_day', 'per_night')),
    rate_peak DECIMAL(12,2) NOT NULL DEFAULT 0,
    rate_off DECIMAL(12,2) NOT NULL DEFAULT 0,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS addons_client_region_internal_active_unique 
ON addons(client_id, region_id, internal_name) WHERE deleted = FALSE;

-- MIGRATION: Add rate_peak and rate_off columns if they don't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='addons' AND column_name='rate_peak') THEN
        ALTER TABLE addons ADD COLUMN rate_peak DECIMAL(12,2) NOT NULL DEFAULT 0;
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='addons' AND column_name='rate_off') THEN
        ALTER TABLE addons ADD COLUMN rate_off DECIMAL(12,2) NOT NULL DEFAULT 0;
    END IF;
END $$;

INSERT INTO addons (client_id, region_id, name, internal_name, addon_type, pricing_type, rate_peak, rate_off) VALUES
    (1, 1, 'Travel Insurance', 'travel-insurance', 'INSURANCE', 'per_person', 500.00, 400.00),
    (1, 1, 'Water Sports', 'water-sports', 'ACTIVITY', 'per_person', 1500.00, 1200.00),
    (1, 2, 'Adventure Sports Package', 'adventure-sports', 'ACTIVITY', 'per_person', 2000.00, 1600.00),
    (1, 3, 'Heritage Tour Guide', 'heritage-guide', 'SERVICE', 'flat', 1000.00, 800.00)
ON CONFLICT DO NOTHING;

-- =====================================================
-- PRICING RULES
-- =====================================================
CREATE TABLE IF NOT EXISTS pricing_rules (
    id SERIAL PRIMARY KEY,
    client_id INTEGER NOT NULL DEFAULT 1 REFERENCES clients(id) ON DELETE CASCADE,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    entity_type VARCHAR(30) NOT NULL DEFAULT 'global'
        CHECK (entity_type IN ('global', 'hotel', 'transport', 'cab', 'destination', 'addon')),
    entity_id INTEGER,
    conditions_json JSONB NOT NULL DEFAULT '{}',
    actions_json JSONB NOT NULL DEFAULT '{}',
    priority INTEGER NOT NULL DEFAULT 100,
    stackable BOOLEAN NOT NULL DEFAULT TRUE,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO pricing_rules (client_id, name, description, entity_type, conditions_json, actions_json, priority, stackable) VALUES
    (1, 'Peak Season Surcharge', 'Add 10% to hotel cost during peak season', 'global', 
     '{"season": "ON"}', 
     '{"type": "increase_rate_percent", "target": "hotel", "value": 10}', 
     100, TRUE),
    (1, 'Group Discount', 'Reduce total by 5% for groups of 6 or more', 'global', 
     '{"pax_gte": 6}', 
     '{"type": "decrease_rate_percent", "target": "total", "value": 5}', 
     200, TRUE)
ON CONFLICT DO NOTHING;

-- =====================================================
-- GLOBAL RULES
-- =====================================================
CREATE TABLE IF NOT EXISTS global_rules (
    id SERIAL PRIMARY KEY,
    client_id INTEGER NOT NULL DEFAULT 1 REFERENCES clients(id) ON DELETE CASCADE,
    service_charge DECIMAL(5,2) NOT NULL DEFAULT 15.00,
    booking_charge DECIMAL(5,2) NOT NULL DEFAULT 12.00,
    tax DECIMAL(5,2) NOT NULL DEFAULT 0.00,
    default_margin DECIMAL(5,2) NOT NULL DEFAULT 0.00,
    default_cancellation DECIMAL(5,2) NOT NULL DEFAULT 0.00,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(client_id)
);

INSERT INTO global_rules (client_id, service_charge, booking_charge, tax, default_margin, default_cancellation)
VALUES (1, 15.00, 12.00, 0.00, 0.00, 0.00)
ON CONFLICT (client_id) DO NOTHING;

-- =====================================================
-- AI CHAT SESSIONS
-- =====================================================
CREATE TABLE IF NOT EXISTS ai_sessions (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(120) NOT NULL UNIQUE,
    client_id INTEGER NOT NULL DEFAULT 1 REFERENCES clients(id) ON DELETE CASCADE,
    state_json JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =====================================================
-- INDEXES
-- =====================================================
CREATE INDEX IF NOT EXISTS idx_regions_client ON regions(client_id);
CREATE INDEX IF NOT EXISTS idx_transports_client ON transports(client_id);
CREATE INDEX IF NOT EXISTS idx_transports_region ON transports(region_id);
CREATE INDEX IF NOT EXISTS idx_hotels_client ON hotels(client_id);
CREATE INDEX IF NOT EXISTS idx_hotels_region ON hotels(region_id);
CREATE INDEX IF NOT EXISTS idx_destinations_client ON destinations(client_id);
CREATE INDEX IF NOT EXISTS idx_destinations_region ON destinations(region_id);
CREATE INDEX IF NOT EXISTS idx_cabs_client ON cabs(client_id);
CREATE INDEX IF NOT EXISTS idx_cabs_region ON cabs(region_id);
CREATE INDEX IF NOT EXISTS idx_cab_dest_rates_client ON cab_destination_rates(client_id);
CREATE INDEX IF NOT EXISTS idx_addons_client ON addons(client_id);
CREATE INDEX IF NOT EXISTS idx_addons_region ON addons(region_id);
CREATE INDEX IF NOT EXISTS idx_pricing_rules_client ON pricing_rules(client_id);
CREATE INDEX IF NOT EXISTS idx_pricing_rules_entity ON pricing_rules(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_pricing_rules_priority ON pricing_rules(client_id, priority);
CREATE INDEX IF NOT EXISTS idx_ai_sessions_session ON ai_sessions(session_id);