#!/usr/bin/env python3
import psycopg2
import os
import sys

DB_CONFIG = {
    'host': os.environ.get('DB_HOST', 'localhost'),
    'port': int(os.environ.get('DB_PORT', 5432)),
    'database': os.environ.get('DB_NAME', 'travel_pricing'),
    'user': os.environ.get('DB_USER', 'apoorvaranjan'),
    'password': os.environ.get('DB_PASS', ''),
}

def check_column_exists(cursor, table_name, column_name):
    cursor.execute("SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = %s AND column_name = %s);", (table_name, column_name))
    return cursor.fetchone()[0]

def check_constraint_exists(cursor, constraint_name):
    cursor.execute("SELECT EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE constraint_name = %s);", (constraint_name,))
    return cursor.fetchone()[0]

def check_index_exists(cursor, index_name):
    cursor.execute("SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = %s);", (index_name,))
    return cursor.fetchone()[0]

def fix_unique_constraints(conn):
    cursor = conn.cursor()
    changes = []
    print("\n" + "="*70)
    print("FIXING UNIQUE CONSTRAINTS (Soft-Delete Compatible)")
    print("="*70)
    
    constraints_to_fix = [
        ('transports', 'transports_client_id_transport_type_key', 'transports_client_region_type_active_unique', 'client_id, region_id, transport_type'),
        ('hotels', 'hotels_client_id_internal_name_key', 'hotels_client_region_internal_active_unique', 'client_id, region_id, internal_name'),
        ('destinations', 'destinations_client_id_internal_name_key', 'destinations_client_region_internal_active_unique', 'client_id, region_id, internal_name'),
        ('cabs', 'cabs_client_id_internal_name_key', 'cabs_client_region_internal_active_unique', 'client_id, region_id, internal_name'),
        ('addons', 'addons_client_id_internal_name_key', 'addons_client_region_internal_active_unique', 'client_id, region_id, internal_name'),
        ('regions', 'regions_client_id_name_key', 'regions_client_name_active_unique', 'client_id, name'),
    ]
    
    for table, old_constraint, new_index, columns in constraints_to_fix:
        print(f"\n{table.upper()}")
        if check_constraint_exists(cursor, old_constraint):
            print(f"  ❌ Dropping old constraint: {old_constraint}")
            cursor.execute(f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {old_constraint};")
            changes.append(f"Dropped {old_constraint}")
            print(f"  ✅ Dropped")
        else:
            print(f"  ✅ No old constraint to drop")
        
        if not check_index_exists(cursor, new_index):
            print(f"  ❌ Creating partial unique index: {new_index}")
            cursor.execute(f"CREATE UNIQUE INDEX {new_index} ON {table} ({columns}) WHERE deleted = FALSE;")
            changes.append(f"Created {new_index}")
            print(f"  ✅ Created")
        else:
            print(f"  ✅ Index already exists")
    
    cursor.close()
    return changes

def fix_check_constraints(conn):
    cursor = conn.cursor()
    changes = []
    print("\n" + "="*70)
    print("FIXING CHECK CONSTRAINTS")
    print("="*70)
    
    # STEP 1: DROP ALL EXISTING CONSTRAINTS FIRST
    print("\nSTEP 1: Dropping all existing CHECK constraints...")
    constraints_to_drop = [
        'addons_addon_type_check',
        'destinations_destination_type_check',
        'hotels_sharing_type_check',
        'addons_pricing_type_check'
    ]
    
    for constraint in constraints_to_drop:
        if check_constraint_exists(cursor, constraint):
            table = constraint.split('_')[0]
            cursor.execute(f"ALTER TABLE {table} DROP CONSTRAINT {constraint};")
            print(f"  ✅ Dropped {constraint}")
            changes.append(f"Dropped {constraint}")
    
    # STEP 2: FIX DATA
    print("\nSTEP 2: Fixing invalid data...")
    
    # Fix addon_type
    print("\nADDONS - addon_type")
    cursor.execute("SELECT DISTINCT addon_type FROM addons WHERE addon_type IS NOT NULL;")
    existing_types = [row[0] for row in cursor.fetchall()]
    print(f"  Found existing addon_type values: {existing_types}")
    
    valid_addon_types = ['GENERAL', 'INSURANCE', 'MEAL', 'ACTIVITY', 'TRANSPORT', 'EQUIPMENT', 'SERVICE']
    
    # Update invalid or NULL addon_types
    cursor.execute("""
        UPDATE addons 
        SET addon_type = 'GENERAL' 
        WHERE addon_type IS NULL 
           OR addon_type NOT IN ('GENERAL', 'INSURANCE', 'MEAL', 'ACTIVITY', 'TRANSPORT', 'EQUIPMENT', 'SERVICE');
    """)
    updated = cursor.rowcount
    if updated > 0:
        changes.append(f"Fixed {updated} invalid addon_type value(s)")
        print(f"  ✅ Fixed {updated} row(s)")
    else:
        print(f"  ✅ All addon_type values are valid")
    
    # Fix destination_type
    print("\nDESTINATIONS - destination_type")
    cursor.execute("SELECT DISTINCT destination_type FROM destinations WHERE destination_type IS NOT NULL;")
    existing_dest_types = [row[0] for row in cursor.fetchall()]
    print(f"  Found existing destination_type values: {existing_dest_types}")
    
    cursor.execute("""
        UPDATE destinations 
        SET destination_type = 'CITY' 
        WHERE destination_type IS NULL 
           OR destination_type NOT IN ('CITY', 'HILL_STATION', 'BEACH', 'RELIGIOUS', 'ADVENTURE', 'WILDLIFE', 'HERITAGE', 'OTHER');
    """)
    updated = cursor.rowcount
    if updated > 0:
        changes.append(f"Fixed {updated} invalid destination_type value(s)")
        print(f"  ✅ Fixed {updated} row(s)")
    else:
        print(f"  ✅ All destination_type values are valid")
    
    # Fix hotel sharing_type
    print("\nHOTELS - sharing_type")
    cursor.execute("SELECT DISTINCT sharing_type FROM hotels WHERE sharing_type IS NOT NULL;")
    existing_sharing = [row[0] for row in cursor.fetchall()]
    print(f"  Found existing sharing_type values: {existing_sharing}")
    
    cursor.execute("""
        UPDATE hotels 
        SET sharing_type = 'DOUBLE' 
        WHERE sharing_type IS NULL 
           OR sharing_type NOT IN ('DOUBLE', 'QUAD', 'CUSTOM');
    """)
    updated = cursor.rowcount
    if updated > 0:
        changes.append(f"Fixed {updated} invalid sharing_type value(s)")
        print(f"  ✅ Fixed {updated} row(s)")
    else:
        print(f"  ✅ All sharing_type values are valid")
    
    # Fix addon pricing_type
    print("\nADDONS - pricing_type")
    cursor.execute("SELECT DISTINCT pricing_type FROM addons WHERE pricing_type IS NOT NULL;")
    existing_pricing = [row[0] for row in cursor.fetchall()]
    print(f"  Found existing pricing_type values: {existing_pricing}")
    
    cursor.execute("""
        UPDATE addons 
        SET pricing_type = 'flat' 
        WHERE pricing_type IS NULL 
           OR pricing_type NOT IN ('flat', 'per_person', 'per_day', 'per_night');
    """)
    updated = cursor.rowcount
    if updated > 0:
        changes.append(f"Fixed {updated} invalid pricing_type value(s)")
        print(f"  ✅ Fixed {updated} row(s)")
    else:
        print(f"  ✅ All pricing_type values are valid")
    
    # STEP 3: RECREATE CONSTRAINTS
    print("\nSTEP 3: Creating new CHECK constraints...")
    
    cursor.execute("""
        ALTER TABLE addons 
        ADD CONSTRAINT addons_addon_type_check 
        CHECK (addon_type IN ('GENERAL', 'INSURANCE', 'MEAL', 'ACTIVITY', 'TRANSPORT', 'EQUIPMENT', 'SERVICE'));
    """)
    changes.append("Created addons_addon_type_check")
    print("  ✅ addons_addon_type_check")
    
    cursor.execute("""
        ALTER TABLE destinations 
        ADD CONSTRAINT destinations_destination_type_check 
        CHECK (destination_type IN ('CITY', 'HILL_STATION', 'BEACH', 'RELIGIOUS', 'ADVENTURE', 'WILDLIFE', 'HERITAGE', 'OTHER'));
    """)
    changes.append("Created destinations_destination_type_check")
    print("  ✅ destinations_destination_type_check")
    
    cursor.execute("""
        ALTER TABLE hotels 
        ADD CONSTRAINT hotels_sharing_type_check 
        CHECK (sharing_type IN ('DOUBLE', 'QUAD', 'CUSTOM'));
    """)
    changes.append("Created hotels_sharing_type_check")
    print("  ✅ hotels_sharing_type_check")
    
    cursor.execute("""
        ALTER TABLE addons 
        ADD CONSTRAINT addons_pricing_type_check 
        CHECK (pricing_type IN ('flat', 'per_person', 'per_day', 'per_night'));
    """)
    changes.append("Created addons_pricing_type_check")
    print("  ✅ addons_pricing_type_check")
    
    cursor.close()
    return changes

def add_transport_columns(conn):
    cursor = conn.cursor()
    changes = []
    print("\n" + "="*70)
    print("TRANSPORT COLUMNS")
    print("="*70)
    
    if not check_column_exists(cursor, 'transports', 'peak_pricing_type'):
        print("\n❌ Adding peak_pricing_type column")
        cursor.execute("ALTER TABLE transports ADD COLUMN peak_pricing_type VARCHAR(20) NOT NULL DEFAULT 'per_person';")
        changes.append("Added transports.peak_pricing_type")
        print("✅ Added")
        if not check_constraint_exists(cursor, 'transports_peak_pricing_type_check'):
            cursor.execute("ALTER TABLE transports ADD CONSTRAINT transports_peak_pricing_type_check CHECK (peak_pricing_type IN ('per_person', 'per_vehicle'));")
            changes.append("Added transports_peak_pricing_type_check")
            print("✅ Constraint added")
    else:
        print("✅ peak_pricing_type exists")
    
    if not check_column_exists(cursor, 'transports', 'off_pricing_type'):
        print("\n❌ Adding off_pricing_type column")
        cursor.execute("ALTER TABLE transports ADD COLUMN off_pricing_type VARCHAR(20) NOT NULL DEFAULT 'per_person';")
        changes.append("Added transports.off_pricing_type")
        print("✅ Added")
        if not check_constraint_exists(cursor, 'transports_off_pricing_type_check'):
            cursor.execute("ALTER TABLE transports ADD CONSTRAINT transports_off_pricing_type_check CHECK (off_pricing_type IN ('per_person', 'per_vehicle'));")
            changes.append("Added transports_off_pricing_type_check")
            print("✅ Constraint added")
    else:
        print("✅ off_pricing_type exists")
    
    cursor.close()
    return changes

def migrate_addon_rates(conn):
    cursor = conn.cursor()
    changes = []
    print("\n" + "="*70)
    print("ADDON RATE MIGRATION")
    print("="*70)
    
    has_old_rate = check_column_exists(cursor, 'addons', 'rate')
    has_rate_peak = check_column_exists(cursor, 'addons', 'rate_peak')
    has_rate_off = check_column_exists(cursor, 'addons', 'rate_off')
    
    if has_old_rate:
        print("\n⚠️  Old 'rate' column found - migrating...")
        if not has_rate_peak:
            cursor.execute("ALTER TABLE addons ADD COLUMN rate_peak DECIMAL(12,2);")
            changes.append("Added addons.rate_peak")
        if not has_rate_off:
            cursor.execute("ALTER TABLE addons ADD COLUMN rate_off DECIMAL(12,2);")
            changes.append("Added addons.rate_off")
        cursor.execute("UPDATE addons SET rate_peak = COALESCE(rate_peak, rate, 0), rate_off = COALESCE(rate_off, rate, 0);")
        rows = cursor.rowcount
        if rows > 0:
            changes.append(f"Migrated {rows} addon rate(s)")
            print(f"  ✅ Migrated {rows} row(s)")
        cursor.execute("ALTER TABLE addons ALTER COLUMN rate_peak SET DEFAULT 0, ALTER COLUMN rate_peak SET NOT NULL;")
        cursor.execute("ALTER TABLE addons ALTER COLUMN rate_off SET DEFAULT 0, ALTER COLUMN rate_off SET NOT NULL;")
        changes.append("Set NOT NULL on rate_peak/rate_off")
        cursor.execute("ALTER TABLE addons DROP COLUMN rate;")
        changes.append("Dropped addons.rate")
        print("  ✅ Old column dropped")
    else:
        if not has_rate_peak:
            cursor.execute("ALTER TABLE addons ADD COLUMN rate_peak DECIMAL(12,2) NOT NULL DEFAULT 0;")
            changes.append("Added addons.rate_peak")
            print("✅ Added rate_peak")
        else:
            print("✅ rate_peak exists")
        if not has_rate_off:
            cursor.execute("ALTER TABLE addons ADD COLUMN rate_off DECIMAL(12,2) NOT NULL DEFAULT 0;")
            changes.append("Added addons.rate_off")
            print("✅ Added rate_off")
        else:
            print("✅ rate_off exists")
    
    cursor.close()
    return changes

def main():
    print("\n" + "="*70)
    print("COMPREHENSIVE TRAVEL PRICING SCHEMA MIGRATION")
    print("="*70)
    print(f"\nDatabase: {DB_CONFIG['database']}@{DB_CONFIG['host']}")
    
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        print("\n✅ Connected to database")
        
        all_changes = []
        all_changes.extend(fix_unique_constraints(conn))
        all_changes.extend(fix_check_constraints(conn))
        all_changes.extend(add_transport_columns(conn))
        all_changes.extend(migrate_addon_rates(conn))
        
        if all_changes:
            print("\n" + "="*70)
            print("COMMITTING CHANGES")
            print("="*70)
            conn.commit()
            print("✅ Committed")
            print("\nChanges Made:")
            for i, change in enumerate(all_changes, 1):
                print(f"  {i:2d}. {change}")
        else:
            print("\n✅ No changes needed - schema already up to date")
        
        print("\n" + "="*70)
        print("✅ MIGRATION COMPLETED SUCCESSFULLY")
        print("="*70)
        print("\n🎉 You can now create everything!")
        print("\nRestart Flask: python app.py")
        return 0
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == '__main__':
    sys.exit(main())
