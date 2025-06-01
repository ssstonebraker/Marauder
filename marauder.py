# Import Marauder modules
from Marauder.CoreObjects.Utils.DataUtils import build_database
from Marauder.CoreObjects.Seeds.Ransomware import seed as ransomware_seed
from Marauder.CoreObjects.Seeds.Forums import seed as forum_seed
from Marauder.DataObjects.CoreDB import DatabaseConnection, OnionServices, Tags, Links, Patterns, Scans, Findings
from Marauder.CoreObjects.Scanners.WebScanners import SimpleOmniScanner, PlayRansomwareScanner

# Import dependencies
import sys

# Parse arguments
if __name__ == "__main__":
    operation = sys.argv[1]
    match operation:
        case 'help':
            print("""I will put instructions here some day...""")
        case 'build_db':
            if len(sys.argv) == 3:
                build_database(sys.argv[2], sample_data=False)
            elif len(sys.argv) == 4:
                if sys.argv[3] == "-s" or sys.argv[3] == "--sample":
                    build_database(sys.argv[2], sample_data=True)
                elif sys.argv[3] == "-S" or sys.argv[3] == "--seed":
                    build_database(sys.argv[2], sample_data=False)
                    db_connection = DatabaseConnection(sys.argv[2])
                    ransomware_seed(db_connection, source='all')
            elif len(sys.argv) == 5:
                if sys.argv[3] == "-S" or sys.argv[3] == "--seed":
                    build_database(sys.argv[2], sample_data=False)
                    db_connection = DatabaseConnection(sys.argv[2])
                    if sys.argv[4] == "ransomwatch":
                        ransomware_seed(db_connection, source="ransomwatch")
                    elif sys.argv[4] == "deepdarkCTI":
                        ransomware_seed(db_connection, source="deepdarkCTI")
                    else:
                        print("Unknown seed source. Use 'all', 'ransomwatch', or 'deepdarkCTI'.")
            else:
                print("Incorrect number of arguments for this operation. Try this...\n  ./marauder.py build_db sample.db -s")
        case 'seed':
            if len(sys.argv) == 3:
                db_connection = DatabaseConnection(sys.argv[2])
                ransomware_seed(db_connection, source='all')
                forum_seed(db_connection, source='all')
            else:
                print("Incorrect number of arguments for this operation. Try this...\n  ./marauder.py seed sample.db")
        case 'run_scan':
            if len(sys.argv) <= 3:
                db_connection = sys.argv[2]
                if len(sys.argv) == 3:
                    print("Running SimpleOmniScanner...")
                    omni_scanner = SimpleOmniScanner(socks_port=9051, database=db_connection)
                    omni_scanner.run_scan(max_scan_age=30, cache_content=True)
                    play_scanner = PlayRansomwareScanner(socks_port=9051, database=db_connection)
                    play_scanner.run_scan(max_scan_age=30, cache_content=True)
                if len(sys.argv) == 4 and sys.argv[3] == "SimpleOmniScanner":
                    print("Running SimleOmniScanner...")
                    scanner = SimpleOmniScanner(socks_port=9051, database=db_connection)
                    scanner.run_scan(max_scan_age=30, cache_content=True)
                elif len(sys.argv) == 4 and sys.argv[3] == "PlayRansomwareScanner":
                    print("Running PlayRansomwareScanner...")
                    scanner = PlayRansomwareScanner(socks_port=9051, database=db_connection)
                    scanner.run_scan(max_scan_age=30, cache_content=True)
                


            else:
                print("Incorrect number of arguments for this operation. Try this...\n  ./marauder.py run_scan sample.db")
        case _:
            print("Unknown operation.")