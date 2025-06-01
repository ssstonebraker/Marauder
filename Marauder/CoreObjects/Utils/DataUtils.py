# Import custom libraries
from Marauder.DataObjects.CoreDB import DatabaseConnection, OnionServices, Tags, Links, Patterns, Scans, Findings

# Builds an empty database with the given name, fills it with sample data if requested
def build_database(database_name, sample_data=True):
    # Connect to SQLite database (or create it if it doesn't exist)
    print("Building the database...")
    db = DatabaseConnection(db_name=database_name)

    # Create Onion_Services table
    db.cursor.execute('''
    CREATE TABLE IF NOT EXISTS Onion_Services (
        service_id INTEGER PRIMARY KEY,
        onion_url TEXT UNIQUE NOT NULL,
        inbound_links INTEGER DEFAULT 0 NOT NULL,
        outbound_links INTEGER DEFAULT 0 NOT NULL,
        last_scanned TIMESTAMP,
        active BOOLEAN NOT NULL DEFAULT 1,
        note TEXT DEFAULT NULL,
        default_plugin TEXT NOT NULL DEFAULT 'SimpleOmniScanner'
    )
    ''')

    # Create Tags table
    db.cursor.execute('''
    CREATE TABLE IF NOT EXISTS Tags (
        tag_id INTEGER PRIMARY KEY,
        tag_text TEXT NOT NULL,
        onion_service INTEGER NOT NULL,
        FOREIGN KEY (onion_service) REFERENCES Onion_Services(service_id) 
    )
    ''')

    # Create Links table
    db.cursor.execute('''
    CREATE TABLE IF NOT EXISTS Links (
        origin INTEGER NOT NULL,
        destination INTEGER NOT NULL,
        FOREIGN KEY (origin) REFERENCES Onion_Services(service_id),
        FOREIGN KEY (destination) REFERENCES Onion_Services(service_id)
    )
    ''')

    # Create Pattern_Groups table
    db.cursor.execute('''
    CREATE TABLE IF NOT EXISTS Pattern_Groups (
        group_id INTEGER PRIMARY KEY,
        group_name TEXT NOT NULL,
        group_description TEXT,
        group_type TEXT NOT NULL,
        group_active BOOLEAN NOT NULL DEFAULT 1
    )
    ''')

    # Create Patterns table
    db.cursor.execute('''
    CREATE TABLE IF NOT EXISTS Patterns (
        pattern_id INTEGER PRIMARY KEY,
        group_id INTEGER NOT NULL,
        pattern_string TEXT NOT NULL,
        pattern_name TEXT,
        active BOOLEAN NOT NULL DEFAULT 1,
        FOREIGN KEY (group_id) REFERENCES Pattern_Groups(group_id)
    )
    ''')

    # Create Scans table
    db.cursor.execute('''
    CREATE TABLE IF NOT EXISTS Scans (
        scan_id INTEGER PRIMARY KEY,
        scan_type TEXT NOT NULL,
        scan_status TEXT NOT NULL,
        scan_start TIMESTAMP,
        scan_end TIMESTAMP,
        scan_notes TEXT
    )
    ''')

    # Create Service_Scan_History table
    db.cursor.execute('''
    CREATE TABLE IF NOT EXISTS Service_Scan_History (
        service_id INTEGER NOT NULL,
        scan_id INTEGER NOT NULL,
        content_hash TEXT,
        FOREIGN KEY (service_id) REFERENCES Onion_Services(service_id),
        FOREIGN KEY (scan_id) REFERENCES Scans(scan_id)
    )
    ''')

    # Create Findings table
    db.cursor.execute('''
    CREATE TABLE IF NOT EXISTS Findings (
        finding_id INTEGER PRIMARY KEY,
        pattern_id INTEGER NOT NULL,
        scan_id INTEGER NOT NULL,
        service_id INTEGER NOT NULL,
        total INTEGER DEFAULT 0 NOT NULL,
        FOREIGN KEY (pattern_id) REFERENCES Patterns(pattern_id),
        FOREIGN KEY (scan_id) REFERENCES Scans(scan_id),
        FOREIGN KEY (service_id) REFERENCES Onion_Services(service_id)
    )
    ''')

    # Commit changes and close the connection
    db.conn.commit()
    db.conn.close()


    # Generate sample data if needed
    if sample_data: generate_sample_data(database_name)

def generate_sample_data(database_name):
    # Initialize the database connection
    db = DatabaseConnection(db_name=database_name)

    # Initialize the table classes
    onion_services = OnionServices(db)
    tags = Tags(db)
    links = Links(db)
    patterns = Patterns(db)
    scans = Scans(db)
    findings = Findings(db)

    # Create sample data
    print("Creating sample data...")
    onion_services.create('http://exampleonion1.onion')
    onion_services.create('http://exampleonion2.onion')
    onion_services.create('http://exampleonion3.onion')
    onion_services.create('http://exampleonion4.onion')
    tags.create('Ransomware', 1)
    tags.create('Threat Actor', 1)
    tags.create('Marketplace', 2)
    tags.create('DO NOT VIEW', 3)
    patterns.create('pattern1')
    patterns.create('pattern2', active=False)
    patterns.create('pattern3')
    patterns.create('pattern4', active=False)
    links.create(1, 2)
    links.create(2, 3)
    links.create(3, 4)
    links.create(4, 1)
    scans.create("pattern")
    scans.update(1, scan_notes="Failed: No Connection")
    scans.create("pattern")
    findings.create(1, 2, 1, 10)
    findings.create(2, 2, 2, 20)
    findings.create(3, 2, 3, 30)
    findings.create(4, 2, 4, 40)

    # Close the database connection
    db.close()
