# scanner.py

import urllib.parse
import random
import string
from requester import Requester
from utils import print_msg
from color_codes import *

class Scanner:
    def __init__(self, verbose=False, exit_early=False, specific_param="", scan_specific_param=False, proxies=None, ignore_ssl=False, timeout=5, param=None):
        self.verbose = verbose
        self.exit_early = exit_early
        self.specific_param = specific_param
        self.scan_specific_param = scan_specific_param
        self.original_response = None
        self.original_response_body = None
        self.proxies = proxies
        self.ignore_ssl = ignore_ssl
        self.timeout = timeout
        self.param = param
        self.requester = Requester(timeout, ignore_ssl, proxies)


    def current_dir_scan(self, method, url, headers, body, param, original_value, original_response_body, original_status, proxies=None):
        if not (param != self.specific_param and self.scan_specific_param):
            print("")
            print_msg("info", f"{bold}Testing parameter {cyan}{param}{reset} {bold}via current directory payloads{reset}")
            payloads_to_check = ["./x", "././x", "./././x", "././././././././././x"]
            responses = []
            
            for payload in payloads_to_check:
                modified_value = payload.replace("x", original_value)
                modified_params = {param: modified_value}
                
                if method == 'GET':
                    url_parts = urllib.parse.urlsplit(url)
                    query_params = urllib.parse.parse_qs(url_parts.query)
                    query_params[param] = modified_value
                    new_query_string = urllib.parse.urlencode(query_params, doseq=True)
                    new_query_string = urllib.parse.unquote(new_query_string)
                    new_url = urllib.parse.urlunsplit((url_parts.scheme, url_parts.netloc, url_parts.path, new_query_string, url_parts.fragment))
                    _, response_body = self.send_modified_request(method, new_url, headers, body, param, modified_value, original_response_body, original_status, proxies)
                elif method == 'POST':
                    post_params = urllib.parse.parse_qs(body)
                    post_params[param] = modified_value
                    new_body = urllib.parse.urlencode(post_params, doseq=True)
                    new_body = urllib.parse.unquote(new_body)
                    
                    _, response_body = self.send_modified_request(method, url, headers, new_body, param, modified_value, original_response_body, original_status, proxies)
                
                responses.append(response_body)

            if all(response == original_response_body for response in responses):
                print_msg("vuln", f"Potential server-side parameter pollution for parameter {bold}{red}{param}{reset} (no status or response change when appending ./ with different depths). This detection alone might not be an indication of vulnerability.")
                if self.exit_early:
                    print_msg("info", "Exiting the program...")
                    exit()
                    
            print("")

    def directory_node_scan(self, method, url, headers, body, original_response_body, original_status, proxies=None):
        responses = []
        
        if method == 'GET' and not body:  # No post_params or query_params
            print("")
            print_msg("info", f"{bold}API request detected. Launching the scan...{reset}")

            # Parse the URL to get the path
            url_parts = urllib.parse.urlsplit(url)
            path_segments = url_parts.path.split('/')[1:]  # Split the path and remove empty segment

            # Payloads for different scans
            current_dir_payloads = ["./x", "././x", "./././x", "././././././././././x"]
            traversal_depth_payloads = [f"/{'../' * depth}{segment}" for depth in range(1, 15) for segment in path_segments]
            payloads = ["%23", "%3f", "%26", "%2f", "%3d"]
            decoded_payloads = ["#", "?", "&", "/", "="]

            # Iterate through each segment in the path
            for i in range(len(path_segments)):
                original_segment = path_segments[i]

                # 1. Current Directory Scan
                print("")
                print_msg("info", f"{bold}Testing Current Directory Payloads on segment: {cyan}{original_segment}{reset}")
                for payload in current_dir_payloads:
                    modified_segment = payload.replace("x", original_segment)
                    modified_path_segments = path_segments[:i] + [modified_segment] + path_segments[i + 1:]
                    new_path = '/' + '/'.join(modified_path_segments)
                    new_url = urllib.parse.urlunsplit((url_parts.scheme, url_parts.netloc, new_path, url_parts.query, url_parts.fragment))

                    _, response_body = self.send_modified_request(method, new_url, headers, body, original_segment, modified_segment, original_response_body, original_status, proxies)
                    
                    responses.append(response_body)
                    
                if all(response == original_response_body for response in responses):              
                    print_msg("vuln", f"Potential server-side parameter pollution for segment {bold}{red}{original_segment}{reset} via current directory payload {bold}{red}{modified_segment}{reset}. (This detection alone might not be an indication of vulnerability)")
                    if self.exit_early:
                        print_msg("info", "Exiting the program...")
                        exit()

                # 2. Traversal Depth Scan
                print("")
                print_msg("info", f"{bold}Testing Traversal Depth Payloads on segment {cyan}{original_segment}{reset}")
                
                # No change on response for the same traversal back to its current API route. 
                payload = f"{original_segment}/{'../' * 1}{original_segment}"
                modified_path_segments = path_segments[:i] + [payload] + path_segments[i + 1:]
                new_path = '/' + '/'.join(modified_path_segments)
                new_url = urllib.parse.urlunsplit((url_parts.scheme, url_parts.netloc, new_path, url_parts.query, url_parts.fragment))
                _, response_body2 = self.send_modified_request(method, new_url, headers, body, original_segment, payload, original_response_body, original_status, proxies)
                if (len(response_body2) == len(original_response_body)):
                    # Increasing the traverse depth by 1 more should return to potential error 404.
                    payload = f"{original_segment}/{'../' * 2}{original_segment}"
                    modified_path_segments = path_segments[:i] + [payload] + path_segments[i + 1:]
                    new_path = '/' + '/'.join(modified_path_segments)
                    new_url = urllib.parse.urlunsplit((url_parts.scheme, url_parts.netloc, new_path, url_parts.query, url_parts.fragment))
                    _, response_body3 = self.send_modified_request(method, new_url, headers, body, original_segment, payload, original_response_body, original_status, proxies)
                    if (len(response_body3) != len(original_response_body)) and (len(response_body3) != len(response_body2)):
                        # Increase the depth even more, this should cause a bad request or another behaviour different from the two previous ones.
                        depth = i + 2
                        payload = f"{original_segment}/{'../' * depth}{original_segment}"
                        modified_path_segments = path_segments[:i] + [payload] + path_segments[i + 1:]
                        new_path = '/' + '/'.join(modified_path_segments)
                        new_url = urllib.parse.urlunsplit((url_parts.scheme, url_parts.netloc, new_path, url_parts.query, url_parts.fragment))
                        _, response_body4 = self.send_modified_request(method, new_url, headers, body, original_segment, payload, original_response_body, original_status, proxies)
                        if (len(response_body4) != len(original_response_body)) and (len(response_body4) != len(response_body3)) and (len(response_body4) != len(response_body2)) or i == 0:
                            print_msg("vuln", f"High confidence finding of server-side parameter pollution for segment {bold}{red}{original_segment}{reset} via traversal depth payload. Error occurred on in a depth greater than {i + 1}. Payload: {bold}{red}{payload}{reset}")
                            if self.exit_early:
                                print_msg("info", "Exiting the program...")
                                exit()
                        
                # 3. Existing Parameter Override Scan
                print("")
                print_msg("info", f"{bold}Testing Existing Parameter Override Payloads on segment {cyan}{original_segment}{reset}")
                for payload, decoded_payload in zip(payloads, decoded_payloads):
                    modified_value = original_segment + payload
                    modified_path_segments = path_segments[:i] + [modified_value] + path_segments[i + 1:]
                    new_path = '/' + '/'.join(modified_path_segments)
                    new_url = urllib.parse.urlunsplit((url_parts.scheme, url_parts.netloc, new_path, url_parts.query, url_parts.fragment))

                    _, response_body = self.send_modified_request(method, new_url, headers, body, original_segment, modified_value, original_response_body, original_status, proxies)
                    if str(original_segment + decoded_payload) in response_body.decode('utf-8', errors='replace'):
                        print_msg("vuln", f"High confidence finding of server-side parameter pollution on segment {bold}{red}{original_segment}{reset} with payload {bold}{red}{payload}{reset} found URL-decoded in response body")
                        if self.exit_early:
                            print_msg("info", "Exiting the program...")
                            exit()

            print("")

    def traversal_depth_scan(self, method, url, headers, body, param, original_value, original_response_body, original_status, proxies=None):
        print_msg("info", f"{bold}Testing Traversal Depth Payloads for parameter {cyan}{param}{reset}")
        responses = []
        for depth in range(1, 15):
            payload = f"{original_value}/{'../' * depth}{original_value}"
            modified_params = {param: payload}

            if method == 'GET':
                url_parts = urllib.parse.urlsplit(url)
                query_params = urllib.parse.parse_qs(url_parts.query)
                query_params[param] = payload
                new_query_string = urllib.parse.urlencode(query_params, doseq=True)
                new_query_string = urllib.parse.unquote(new_query_string)
                new_url = urllib.parse.urlunsplit((url_parts.scheme, url_parts.netloc, url_parts.path, new_query_string, url_parts.fragment))
                _, response_body = self.send_modified_request(method, new_url, headers, body, param, payload, original_response_body, original_status, proxies)
            elif method == 'POST':
                post_params = urllib.parse.parse_qs(body)
                post_params[param] = payload
                new_body = urllib.parse.urlencode(post_params, doseq=True)
                new_body = urllib.parse.unquote(new_body)
                _, response_body = self.send_modified_request(method, url, headers, new_body, param, payload, original_response_body, original_status, proxies)

            responses.append(response_body)

            # Check for response length change
            if len(response_body) != len(original_response_body):
                print_msg("vuln", f"Potential server-side parameter pollution for parameter {bold}{red}{param}{reset} via traversal depth payload: {bold}{red}{payload}{reset}")
                if self.exit_early:
                    print_msg("info", "Exiting the program...")
                    exit()

    def send_modified_request(self, method, url, headers, body, param_name, param_value, original_response_body, original_status, proxies=None):
        # Send the request using the existing send_request function
        response, response_body = self.requester.send_request(method, url, headers, body, proxies)

        # Get the status code and reason from the response
        status = response.status_code
        reason = response.reason

        if self.verbose:
            print_msg("info", f"Response Status: {cyan}{status}{reset} {reason}")

            # Uncomment to see the response body for debugging
            # try:
            #     print("")
            #     print(response_body.decode('utf-8'))
            #     print("")
            # except UnicodeDecodeError:
            #     print_msg("info", "Response body contains non-UTF-8 content")

            # Check for changes in response body length and content
            if (response_body != original_response_body) or (len(original_response_body) != len(response_body)):
                print_msg("debug", f"Different response detected for parameter {blue}{param_name}{reset} (was {len(original_response_body)} bytes, is {len(response_body)} bytes)")
            else:
                print_msg("debug", f"No difference found in response for parameter {cyan}{param_name}{reset}")

            # Check if the status code has changed
            if status != original_status:
                print_msg("debug", f"The status code has changed for parameter {blue}{param_name}{reset} (was {str(original_status)}, is {str(status)})")

        return status, response_body

    def parse_and_modify_http_request(self, raw_request, proxies=None):
        lines = raw_request.splitlines()
        request_line = lines[0]
        method, path, version = request_line.split()
        
        headers = {}
        body = ""
        in_headers = True
        for line in lines[1:]:
            if in_headers:
                if line == "":
                    in_headers = False
                else:
                    key, value = line.split(": ", 1)
                    headers[key] = value
            else:
                body += line

        host = headers.get("Host")
        url = f"https://{host}{path}"

        if self.verbose:
            print_msg("info", "Sending the original request...")
        
        original_response, original_response_body = self.requester.send_request(method, url, headers, body, proxies)
        original_status = original_response.status_code
        
        if self.verbose:
            print_msg("info", f"Original Response Status: {green}{original_status}{reset} {original_response.reason}")
            #If you want to see the request response for debugging purposes
            #try:
            #    print("")
            #    print(original_response_body.decode('utf-8'))
            #    print("")
            #except UnicodeDecodeError:
            #    print_msg("debug", "Original response body contains non-UTF-8 content")
            print_msg("info", f"Original Response Size: {green}{len(original_response_body)}{reset} bytes")

        url_parts = urllib.parse.urlsplit(url)
        query_params = urllib.parse.parse_qs(url_parts.query)
        post_params = urllib.parse.parse_qs(body)

        # Process path parameters (only applicable to API)
        if '?' not in path and method == "GET":
            self.directory_node_scan(method, url, headers, body, original_response_body, original_status, proxies)  # Handle the directory node scan for GET requests

        # Process query parameters
        for param in query_params:
            original_value = query_params[param][0]
            
            self.current_dir_scan(method, url, headers, body, param, original_value, original_response_body, original_status, proxies)
            self.traversal_depth_scan(method, url, headers, body, param, original_value, original_response_body, original_status, proxies)
            self.param_overriding_scan(method, url, headers, body, param, original_value, original_response_body, original_status, proxies)
            self.existing_param_override_scan(method, url, headers, body, param, original_value, original_response_body, original_status, proxies)

        # Process body parameters
        for param in post_params:
            original_value = post_params[param][0]
            
            self.current_dir_scan(method, url, headers, body, param, original_value, original_response_body, original_status, proxies)    
            self.traversal_depth_scan(method, url, headers, body, param, original_value, original_response_body, original_status, proxies)
            self.param_overriding_scan(method, url, headers, body, param, original_value, original_response_body, original_status, proxies)
            self.existing_param_override_scan(method, url, headers, body, param, original_value, original_response_body, original_status, proxies)

