# requester.py

import requests
from utils import print_msg

class Requester:
    def __init__(self, req_timeout=None, verify_ssl=True, proxies=None):
        self.req_timeout = req_timeout
        self.verify_ssl = verify_ssl
        self.proxies = proxies

    def send_request(self, method, url, headers, body=None, proxies=None):
        response = None

        if method == 'GET':
            response = requests.get(url, headers=headers, timeout=self.req_timeout, verify=self.verify_ssl, proxies=proxies)
        elif method == 'POST':
            response = requests.post(url, headers=headers, data=body, timeout=self.req_timeout, verify=self.verify_ssl, proxies=proxies)

        response_body = response.content
        return response, response_body
