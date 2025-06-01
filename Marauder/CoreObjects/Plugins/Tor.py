import os
import hashlib
from Marauder.CoreObjects.OnionSession import OnionSession

class SimpleOnionPlugin:
    def __init__(self, auto_start=True, port_number=9051):
        self.__session = OnionSession(auto_start=auto_start, port_number=port_number)

    def __init__(self, session=None):
        self.__session = session

    def save_content(self, onion_url, content):
        """
        Save the fetched content to a local HTML file.
        The file path will be "./Tor/{onion service url}/{hash of content}.html".
        """
        # Create a hash of the content
        content_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()

        # Build the directory path based on the onion URL
        sanitized_url = onion_url.replace("http://", "").replace("https://", "").replace("/", "_").replace("?", "_")
        # Ensure the URL is valid for a directory name
        directory_path = os.path.join("cache", "Tor", sanitized_url)

        # Ensure the directory exists
        os.makedirs(directory_path, exist_ok=True)

        # Build the file path
        file_path = os.path.join(directory_path, f"{content_hash}.html")
        # Check if the file already exists
        if os.path.exists(file_path):
            print(f"File already exists: {file_path}")
            return
        else:
            # Save the content to the file
            with open(file_path, "w", encoding="utf-8") as file:
                file.write(content)
            print(f"Content saved to {file_path}")

    def fetch_content(self, onion_url, auto_close=False, timeout=600, cache_content=False):
        try:
            print(f"Fetching content from {onion_url}...")
            # Get page contents
            response = self.__session.session.get(onion_url, timeout=timeout, verify=False)
            # Check if the response is successful
            if response.status_code == 200:
                print("Content fetched successfully!")
                # Save the content to a local file
                if cache_content: self.save_content(onion_url, response.text)
                return (True, response.text, hashlib.sha256(response.text.encode('utf-8')).hexdigest())
            else:
                print(f"Failed with status code: {response.status_code}")
                return (False, "Status code: {}".format(response.status_code))
        except Exception as e:
            return (False, str(e))