import requests

class OnionSession:
    def __init__(self, auto_start=True, port_number=9051):
        self.session = None
        if auto_start:
            self.start_session(port_number)
    
    def start_session(self, port_number):
        self.session = requests.session()
        self.session.proxies = {
            "http":"socks5h://localhost:{}".format(port_number),
            "https":"socks5h://localhost:{}".format(port_number)
        }
    
    def close_session(self):
        self.session = None




        