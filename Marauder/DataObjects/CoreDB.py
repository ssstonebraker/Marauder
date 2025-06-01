from datetime import datetime
import sqlite3

class DatabaseConnection:
    def __init__(self, db_name='example.db'):
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()

    def commit(self):
        self.conn.commit()

    def close(self):
        self.conn.close()

class OnionServices:
    def __init__(self, db_connection):
        self.db = db_connection

    def create(self, onion_url, inbound_links=0, outbound_links=0, last_scanned=None, active=True, note=None, default_plugin="SimpleOmniScanner"):
        self.db.cursor.execute('''
            INSERT INTO Onion_Services (onion_url, inbound_links, outbound_links, last_scanned, active, note, default_plugin)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (onion_url, inbound_links, outbound_links, last_scanned, active, note, default_plugin))
        self.db.commit()
        return self.db.cursor.lastrowid
    
    def service_exists(self, onion_url):
        self.db.cursor.execute('SELECT * FROM Onion_Services WHERE onion_url = ?', (onion_url,))
        return self.db.cursor.fetchone() is not None

    def get(self, service_id):
        self.db.cursor.execute('SELECT * FROM Onion_Services WHERE service_id = ?', (service_id,))
        return self.db.cursor.fetchone()
    
    def get_all(self):
        self.db.cursor.execute('SELECT * FROM Onion_Services')
        return self.db.cursor.fetchall()
    
    def get_active(self):
        self.db.cursor.execute('SELECT * FROM Onion_Services WHERE active = 1')
        return self.db.cursor.fetchall()
    
    def get_by_url(self, onion_url):
        self.db.cursor.execute('SELECT * FROM Onion_Services WHERE onion_url = ?', (onion_url,))
        return self.db.cursor.fetchone()

    def delete(self, service_id):
        self.db.cursor.execute('DELETE FROM Onion_Services WHERE service_id = ?', (service_id,))
        self.db.commit()

    def update(self, service_id, onion_url=None, inbound_links=None, outbound_links=None, last_scanned=None, active=None, note=None, default_plugin=None):
        # Update only the fields that are not None
        fields = {
            'onion_url': onion_url,
            'inbound_links': inbound_links,
            'outbound_links': outbound_links,
            'last_scanned': last_scanned,
            'active': active,
            'note': note,
            'default_plugin': default_plugin
        }
        updates = ', '.join(f"{k} = ?" for k, v in fields.items() if v is not None)
        values = [v for v in fields.values() if v is not None] + [service_id]
        self.db.cursor.execute(f'UPDATE Onion_Services SET {updates} WHERE service_id = ?', values)
        self.db.commit()

    def update_timestamp(self, service_id):
        current_time = datetime.now()
        self.db.cursor.execute('UPDATE Onion_Services SET last_scanned = ? WHERE service_id = ?', (current_time, service_id))
        self.db.commit()

class Tags:
    def __init__(self, db_connection):
        self.db = db_connection

    def create(self, tag_text, onion_service):
        self.db.cursor.execute('''
            INSERT INTO Tags (tag_text, onion_service)
            VALUES (?, ?)
        ''', (tag_text, onion_service))
        self.db.commit()
        return self.db.cursor.lastrowid


    def get_all(self):
        self.db.cursor.execute('SELECT * FROM Tags')
        return self.db.cursor.fetchall()

    def get_tags(self, onion_service_url):
        # Get service id of onion service
        self.db.cursor.execute('SELECT service_id FROM Onion_Services WHERE onion_url = ?', (onion_service_url,))
        service_id = self.db.cursor.fetchone()
        print(service_id)
        # Get all tags associated with the service id
        self.db.cursor.execute('SELECT * FROM Tags where onion_service = ?', (service_id))
        return self.db.cursor.fetchall()

    def delete(self, tag_id):
        self.db.cursor.execute('DELETE FROM Tags WHERE tag_id = ?', (tag_id))
        self.db.commit()

class Links:
    def __init__(self, db_connection):
        self.db = db_connection

    def create(self, origin, destination):
        self.db.cursor.execute('''
            INSERT INTO Links (origin, destination)
            VALUES (?, ?)
        ''', (origin, destination))
        self.db.commit()
        return self.db.cursor.lastrowid


    def get(self, origin, destination):
        self.db.cursor.execute('SELECT * FROM Links WHERE origin = ? AND destination = ?', (origin, destination))
        link = self.db.cursor.fetchone()
        if link:
            self.db.cursor.execute('SELECT onion_url FROM Onion_Services WHERE service_id = ?', (origin,))
            origin_url = self.db.cursor.fetchone()[0]
            self.db.cursor.execute('SELECT onion_url FROM Onion_Services WHERE service_id = ?', (destination,))
            destination_url = self.db.cursor.fetchone()[0]
            return link + (origin_url, destination_url)
        return None

    def delete(self, origin, destination):
        self.db.cursor.execute('DELETE FROM Links WHERE origin = ? AND destination = ?', (origin, destination))
        self.db.commit()

    def update(self, origin, destination, new_origin=None, new_destination=None):
        fields = {'origin': new_origin, 'destination': new_destination}
        updates = ', '.join(f"{k} = ?" for k, v in fields.items() if v is not None)
        values = [v for v in fields.values() if v is not None] + [origin, destination]
        self.db.cursor.execute(f'UPDATE Links SET {updates} WHERE origin = ? AND destination = ?', values)
        self.db.commit()

class Patterns:
    def __init__(self, db_connection):
        self.db = db_connection

    def create(self, pattern_string, pattern_name=None, active=True):
        self.db.cursor.execute('''
            INSERT INTO Patterns (pattern_string, pattern_name, active)
            VALUES (?, ?, ?)
        ''', (pattern_string, pattern_name, active))
        self.db.commit()
        return self.db.cursor.lastrowid


    def get(self, pattern_id):
        self.db.cursor.execute('SELECT * FROM Patterns WHERE pattern_id = ?', (pattern_id,))
        return self.db.cursor.fetchone()
    
    def get_all(self):
        self.db.cursor.execute('SELECT * FROM Patterns')
        return self.db.cursor.fetchall()

    def get_active(self):
        self.db.cursor.execute('''
            SELECT p.*
            FROM Patterns p
            INNER JOIN Pattern_Groups pg ON p.group_id = pg.group_id
            WHERE p.active = 1 AND pg.group_active = 1
        ''')
        return self.db.cursor.fetchall()

    def delete(self, pattern_id):
        self.db.cursor.execute('DELETE FROM Patterns WHERE pattern_id = ?', (pattern_id,))
        self.db.commit()

    def update(self, pattern_id, pattern_string=None, pattern_name=None, active=None):
        fields = {'pattern_string': pattern_string, 'pattern_name': pattern_name, 'active': active}
        updates = ', '.join(f"{k} = ?" for k, v in fields.items() if v is not None)
        values = [v for v in fields.values() if v is not None] + [pattern_id]
        self.db.cursor.execute(f'UPDATE Patterns SET {updates} WHERE pattern_id = ?', values)
        self.db.commit()

class Scans:
    def __init__(self, db_connection):
        self.db = db_connection

    def create(self, scan_type, scan_status="running", scan_start=datetime.now()):
        self.db.cursor.execute('''
            INSERT INTO Scans (scan_type, scan_status, scan_start)
            VALUES (?, ?, ?)
        ''', (scan_type, scan_status, scan_start))
        self.db.commit()
        return self.db.cursor.lastrowid


    def get(self, scan_id):
        self.db.cursor.execute('SELECT * FROM Scans WHERE scan_id = ?', (scan_id,))
        scan = self.db.cursor.fetchone()
        if scan:
            return scan
        return None

    def delete(self, scan_id):
        self.db.cursor.execute('DELETE FROM Scans WHERE scan_id = ?', (scan_id,))
        self.db.commit()

    def update(self, scan_id, scan_end=datetime.now(), scan_notes=None):
        fields = {'scan_end': scan_end, 'scan_notes': scan_notes}
        updates = ', '.join(f"{k} = ?" for k, v in fields.items() if v is not None)
        values = [v for v in fields.values() if v is not None] + [scan_id]
        self.db.cursor.execute(f'UPDATE Scans SET {updates} WHERE scan_id = ?', values)
        self.db.commit()

class Findings:
    def __init__(self, db_connection):
        self.db = db_connection

    def create(self, pattern_id, scan_id, service_id, total=0):
        self.db.cursor.execute('''
            INSERT INTO Findings (pattern_id, scan_id, service_id, total)
            VALUES (?, ?, ?, ?)
        ''', (pattern_id, scan_id, service_id, total))
        self.db.commit()
        return self.db.cursor.lastrowid


    def get(self, finding_id):
        self.db.cursor.execute('SELECT * FROM Findings WHERE finding_id = ?', (finding_id,))
        finding = self.db.cursor.fetchone()
        if finding:
            self.db.cursor.execute('SELECT pattern_string FROM Patterns WHERE pattern_id = ?', (finding[1],))
            pattern_string = self.db.cursor.fetchone()[0]
            self.db.cursor.execute('SELECT onion_url FROM Onion_Services WHERE service_id = ?', (finding[3],))
            onion_url = self.db.cursor.fetchone()[0]
            return finding + ("Scan ID: {}".format(finding[2]), pattern_string, onion_url)
        return None

    def delete(self, finding_id):
        self.db.cursor.execute('DELETE FROM Findings WHERE finding_id = ?', (finding_id,))
        self.db.commit()

    def update(self, finding_id, pattern_id=None, scan_id=None, service_id=None, total=None):
        fields = {'pattern_id': pattern_id, 'scan_id':scan_id, 'service_id': service_id, 'total': total}
        updates = ', '.join(f"{k} = ?" for k, v in fields.items() if v is not None)
        values = [v for v in fields.values() if v is not None] + [finding_id]
        self.db.cursor.execute(f'UPDATE Findings SET {updates} WHERE finding_id = ?', values)
        self.db.commit()

class ServiceScanHistory:
    def __init__(self, db_connection):
        self.db = db_connection

    def create(self, service_id, scan_id, content_hash):
        self.db.cursor.execute('''
            INSERT INTO Service_Scan_History (service_id, scan_id, content_hash)
            VALUES (?, ?, ?)
        ''', (service_id, scan_id, content_hash))
        self.db.commit()
        return self.db.cursor.lastrowid
    
    def get(self, service_id, scan_id):
        self.db.cursor.execute('SELECT * FROM Service_Scan_History WHERE service_id = ? AND scan_id = ?', (service_id, scan_id))
        return self.db.cursor.fetchone()
    
    def delete(self, service_id, scan_id):
        self.db.cursor.execute('DELETE FROM Service_Scan_History WHERE service_id = ? AND scan_id = ?', (service_id, scan_id))
        self.db.commit()

    def update(self, service_id, scan_id, content_hash):
        self.db.cursor.execute('UPDATE Service_Scan_History SET content_hash = ? WHERE service_id = ? AND scan_id = ?', (content_hash, service_id, scan_id))
        self.db.commit()

class PatternGroups:
    def __init__(self, db_connection):
        self.db = db_connection

    def create(self, group_name, group_description=None, group_type=None, group_active=True):
        self.db.cursor.execute('''
            INSERT INTO Pattern_Groups (group_name, group_description, group_type, group_active)
            VALUES (?, ?, ?, ?)
        ''', (group_name, group_description, group_type, group_active))
        self.db.commit()
        return self.db.cursor.lastrowid
    
    def get(self, group_id):
        self.db.cursor.execute('SELECT * FROM Pattern_Groups WHERE group_id = ?', (group_id,))
        return self.db.cursor.fetchone()
    
    def get_all(self):
        self.db.cursor.execute('SELECT * FROM Pattern_Groups')
        return self.db.cursor.fetchall()
    
    def delete(self, group_id):
        self.db.cursor.execute('DELETE FROM Pattern_Groups WHERE group_id = ?', (group_id,))
        self.db.commit()

    def update(self, group_id, group_name=None, group_description=None, group_type=None, group_active=None):
        fields = {'group_name': group_name, 'group_description': group_description, 'group_type': group_type, 'group_active': group_active}
        updates = ', '.join(f"{k} = ?" for k, v in fields.items() if v is not None)
        values = [v for v in fields.values() if v is not None] + [group_id]
        self.db.cursor.execute(f'UPDATE Pattern_Groups SET {updates} WHERE group_id = ?', values)
        self.db.commit()

    def get_active(self):
        self.db.cursor.execute('SELECT * FROM Pattern_Groups WHERE group_active = 1')
        return self.db.cursor.fetchall()
