import requests
import json
import re
from Marauder.DataObjects.CoreDB import DatabaseConnection, OnionServices, Tags

def seed(db_connection, source = 'all'):
    seed_links = set()
    services = OnionServices(db_connection)
    tags = Tags(db_connection)
    match source:
        case 'all':
            seed_links |= set(deepdarkCTI())
            seed_links |= set(ransomwatch())
        case 'deepdarkCTI':
            seed_links |= set(deepdarkCTI())
        case 'ransomwatch':
            seed_links |= set(ransomwatch())
        case _:
            print("Unknown seed...")
            return False
    
    # Insert the seed links into the database
    for link in seed_links:
        if not link.startswith(("http://", "https://")):
            link = "http://" + link  # Default to http if no scheme is provided
        # Check if the link already exists in the database
        existing_service = services.get_by_url(link)
        if not existing_service:
            # If it doesn't exist, create a new entry
            service = services.create(link)
            print(f"Inserted {link} into the database.")
            # Optionally, you can also add tags to the new entry
            tags.create("Ransomware", service)
        else:
            print(f"{link} already exists in the database.")

def deepdarkCTI():
    URL = "https://raw.githubusercontent.com/fastfire/deepdarkCTI/main/ransomware_gang.md"
    response = requests.get(URL)
    if response.status_code != 200:
        print("Failed to retrieve data.")
        return []

    lines = response.text.split("\n")
    onion_links = []

    for line in lines:
        if "ONLINE" in line:
            match = re.search(r"http[s]?://[a-zA-Z0-9.-]+\.onion", line)
            if match:
                onion_links.append(match.group())

    return onion_links


def ransomwatch():
    URL = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/groups.json"
    response = requests.get(URL)
    if response.status_code != 200:
        print("Failed to retrieve data.")
        return []

    data = response.json()
    fqdns = [location["fqdn"] for group in data for location in group.get("locations", []) if location.get("enabled") and location.get("fqdn").endswith(".onion")]

    return fqdns
