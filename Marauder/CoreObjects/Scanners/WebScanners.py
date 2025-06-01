# Import custom libraries
from Marauder.DataObjects.CoreDB import DatabaseConnection, OnionServices, Links, Patterns, Findings, Scans, ServiceScanHistory
from Marauder.CoreObjects.Plugins.Tor import SimpleOnionPlugin
from Marauder.CoreObjects.OnionSession import OnionSession

# Import dependencies
import concurrent.futures
import time
from datetime import datetime, timedelta
import re

def get_base_onion_url(url):
    # Extracts the scheme and onion domain, discards any path/query
    match = re.match(r"(https?://[a-z2-7]{16,56}\.onion)", url)
    return match.group(1) if match else url

class Scanner:
    def __init__(self, socks_port=9051, database="sample.db"):
        # Build database utilities
        self.db_connection = DatabaseConnection(db_name=database)
        self.services = OnionServices(self.db_connection)
        self.links = Links(self.db_connection)
        self.patterns = Patterns(self.db_connection)
        self.findings = Findings(self.db_connection)
        self.scans = Scans(self.db_connection)
        self.service_scan_history = ServiceScanHistory(self.db_connection)

        # Set the database path for concurrent jobs
        self.db_path = database

        # Set the port number for the Tor connection
        self.socks_port = socks_port

        # Build Tor connection
        self.session = OnionSession(auto_start=True, port_number=socks_port)

    def scan_url(self, onion_url, scan_id=None):
        # Replce this with unqie scanner logic
        pass

    def run_scan(self):
        # Replace this with unqie scanner logic
        pass

class ConcurrentScanner(Scanner):
    def run_scan(self, max_workers=10, max_scan_age=86400, cache_content=False):
        # Create new scan in the database
        scan = self.scans.create(self.scan_type)
        # Get the scan ID
        scan_id = self.scans.get(scan)[0]
        # Get all known onion services from the database with the correct default_plugin
        onion_services = [
            service for service in self.services.get_active()
            if service[7] == self.__class__.__name__
        ]

        # Create a thread pool for concurrent scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {
                executor.submit(self.scan_url, service[1], scan_id=scan_id, cache_content=cache_content): service
                for service in onion_services
                if service[4] is None or datetime.strptime(service[4], "%Y-%m-%d %H:%M:%S.%f") < datetime.now() - timedelta(seconds=max_scan_age)
            }
            
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    data = future.result()
                    print(f"Scanned {url}: {data}")
                except Exception as exc:
                    print(f"{url} generated an exception: {exc}")

class LinearScanner(Scanner):
    def run_scan(self, max_scan_age=86400, cache_content=False):
        # Create new scan in the database
        scan = self.scans.create(self.scan_type)
        # Get the scan ID
        scan_id = self.scans.get(scan)[0]
        # Get all known onion services from the database with the correct default_plugin
        onion_services = [
            service for service in self.services.get_active()
            if service[7] == self.__class__.__name__
        ]

        for service in onion_services:
            if service[4] is None or datetime.strptime(service[4], "%Y-%m-%d %H:%M:%S.%f") < datetime.now() - timedelta(seconds=max_scan_age):
                self.scan_url(service[1], scan_id=scan_id, cache_content=cache_content)

    def scan_url(self, onion_url, scan_id=None, cache_content=False):
        # Retrieve the onion service from the database
        onion_service = self.services.get_by_url(onion_url)
        service_id = onion_service[0]
        # Replace the following line with a dynamic plugin once more than one plugin is available.
        onion_plugin = SimpleOnionPlugin(session=self.session)
        # Get the content of the onion URL
        content = onion_plugin.fetch_content(onion_url, cache_content=cache_content)
        if content[0]:
            # Add ServiceScanHistory
            self.service_scan_history.create(service_id, scan_id, content[2])
            # Parse the content for findings
            self.parse_content(content[1], service_id, scan_id)
            # Update the last scanned time in the database
            self.services.update_timestamp(service_id)
        else:
            self.services.update(service_id, active=False, note=content[1])
            self.services.update_timestamp(service_id)

class AsyncPatternScanner(ConcurrentScanner):
    def __init__(self, socks_port=9051, database="sample.db"):
        # Call the parent class's __init__ method
        super().__init__(socks_port=socks_port, database=database)
        # Set the scan type
        self.scan_type = "PatternScan"

    def scan_url(self, onion_url, scan_id=None, cache_content=False):
        # Build database utilities
        db_connection = DatabaseConnection(db_name=self.db_path)
        services = OnionServices(db_connection)
        links = Links(db_connection)
        patterns = Patterns(db_connection)
        findings = Findings(db_connection)
        scans = Scans(db_connection)
        service_scan_history = ServiceScanHistory(db_connection)

        # Retrieve the onion service from the database
        onion_service = services.get_by_url(onion_url)
        service_id = onion_service[0]
        # Replace the following line with a dynamic plugin once more than one plugin is available.
        onion_plugin = SimpleOnionPlugin(session=self.session)
        patterns = patterns.get_active()
        # Get the content of the onion URL
        content = onion_plugin.fetch_content(onion_url, cache_content=cache_content)
        if content:
            # Add ServiceScanHistory
            service_scan_history.create(service_id, scan_id, content[2])
            # Search for patterns in the content
            results = []
            for pattern in patterns:
                matches = re.findall(pattern[1], content)
                if matches:
                    results.append({
                        'pattern_id': pattern[0],
                        'matches': matches
                    })
            # Update the last scanned time in the database
            services.update_timestamp(service_id)
            # Store the results in the database
            for result in results:
                
                findings.create(result['pattern_id'], scan_id, service_id, len(result['matches']))
            print(results)

class SimplePatternScanner(LinearScanner):
    def __init__(self, socks_port=9051, database="sample.db"):
        # Call the parent class's __init__ method
        super().__init__(socks_port=socks_port, database=database)
        # Set the scan type
        self.scan_type = "PatternScan"

    def parse_content(self, content, service_id, scan_id):
        # Retrieve the patterns from the database
        patterns = self.patterns.get_active()
        results = []
        # Search for patterns in the content
        for pattern in patterns:
            matches = re.findall(pattern[2], content)
            if matches:
                results.append({
                    'pattern_id': pattern[0],
                    'matches': matches
                })
        # Store the results in the database
        for result in results:
            self.findings.create(result['pattern_id'], scan_id, service_id, len(result['matches']))
        print(results)

class SimpleDepthScanner(LinearScanner):
    def __init__(self, socks_port=9051, database="sample.db"):
        # Call the parent class's __init__ method
        super().__init__(socks_port=socks_port, database=database)
        # Set the scan type
        self.scan_type = "LinkScan"

    def parse_content(self, content, service_id, scan_id):
        # Search for links in the content
        results = set()
        # Use regex to find only valid v2/v3 onion addresses (no schema)
        links = re.findall(r"\b([a-z2-7]{16}|[a-z2-7]{56})\.onion\b", content)
        # Reconstruct the full .onion address from the match
        links = [f"http://{match}.onion" for match in links]
        for link in links:
            results.add(link)
        # Store the results in the database
        for result in results:
            new_service_id = None
            # Check if the service already exists in the database
            if not self.services.service_exists(result):
                # Create a new service in the database
                service = self.services.create(result)
                new_service_id = service
            else:
                # Get the existing service ID
                service = self.services.get_by_url(result)
                new_service_id = service[0]
            self.links.create(service_id, new_service_id)
        print(results)

class SimpleOmniScanner(LinearScanner):
    def __init__(self, socks_port=9051, database="sample.db"):
        # Call the parent class's __init__ method
        super().__init__(socks_port=socks_port, database=database)
        # Set the scan type
        self.scan_type = "OmniScan"

    def parse_content(self, content, service_id, scan_id, scan_types=None):
        # Build the needed scanners
        pattern_scanner = SimplePatternScanner(socks_port=self.socks_port, database=self.db_path)
        link_scanner = SimpleDepthScanner(socks_port=self.socks_port, database=self.db_path)
        # Search for links in the content
        pattern_scanner.parse_content(content, service_id, scan_id)
        link_scanner.parse_content(content, service_id, scan_id)

class PlayRansomwareScanner(LinearScanner):
    def __init__(self, socks_port=9051, database="sample.db"):
        super().__init__(socks_port=socks_port, database=database)
        self.scan_type = "PlayRansomwareOmniScan"

    def parse_content(self, content, service_id, scan_id, scan_types=None):
        # 1. Gather all ransomware claims and patterns (OmniScanner logic)
        pattern_scanner = SimplePatternScanner(socks_port=self.socks_port, database=self.db_path)
        pattern_scanner.parse_content(content, service_id, scan_id)

        # 2. Gather all onion links (OmniScanner logic)
        link_scanner = SimpleDepthScanner(socks_port=self.socks_port, database=self.db_path)
        link_scanner.parse_content(content, service_id, scan_id)

        # 3. Custom Play Ransomware internal link discovery

        base_url = get_base_onion_url(self.services.get(service_id)[1])

        # a. Find additional index.php pages via goto_page('N')
        goto_page_matches = re.findall(r"goto_page\('(\d+)'\)", content)
        for page_num in set(goto_page_matches):
            internal_url = f"{base_url}/index.php?page={page_num}"
            self._add_internal_link(service_id, internal_url, scan_id)

        # b. Find additional topic.php pages via viewtopic('ID')
        viewtopic_matches = re.findall(r"viewtopic\('([A-Za-z0-9]+)'\)", content)
        for topic_id in set(viewtopic_matches):
            internal_url = f"{base_url}/topic.php?id={topic_id}"
            self._add_internal_link(service_id, internal_url, scan_id)

    def _add_internal_link(self, service_id, url, scan_id):
        # Add the internal link to the OnionServices and Links tables if not present
        new_service_id = None
        if not self.services.service_exists(url):
            new_service_id = self.services.create(url)
        else:
            new_service_id = self.services.get_by_url(url)[0]
        self.links.create(service_id, new_service_id)
