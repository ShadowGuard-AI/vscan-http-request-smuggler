import argparse
import requests
import logging
from bs4 import BeautifulSoup
import sys
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description='Detects HTTP Request Smuggling vulnerabilities.')
    parser.add_argument('url', type=str, help='The URL to scan.')
    parser.add_argument('--method', type=str, default='GET', help='The HTTP method to use (default: GET).')
    parser.add_argument('--data', type=str, default=None, help='Data to send with the request (e.g., POST data).')
    parser.add_argument('--headers', type=str, default=None, help='Custom headers to include (JSON format).')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10).')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output.')
    return parser.parse_args()

def is_valid_url(url):
    """
    Validates that the provided URL is properly formatted.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def send_request(url, method='GET', data=None, headers=None, timeout=10, verbose=False):
    """
    Sends an HTTP request to the specified URL with the given parameters.
    Handles potential errors during the request process.
    """
    try:
        if headers:
            import json
            try:
                headers = json.loads(headers)
            except json.JSONDecodeError as e:
                logging.error(f"Invalid JSON format for headers: {e}")
                return None, None

        if verbose:
            logging.info(f"Sending {method} request to: {url}")
            if data:
                logging.info(f"Data: {data}")
            if headers:
                logging.info(f"Headers: {headers}")

        response = requests.request(method, url, data=data, headers=headers, timeout=timeout, allow_redirects=False)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        if verbose:
            logging.info(f"Received response with status code: {response.status_code}")
            logging.info(f"Response headers: {response.headers}")
            logging.info(f"Response content: {response.text}")

        return response.status_code, response.headers, response.text

    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed: {e}")
        return None, None, None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None, None, None

def detect_http_smuggling(url, method='GET', data=None, headers=None, timeout=10, verbose=False):
    """
    Detects HTTP request smuggling vulnerabilities.
    This is a simplified example and can be expanded with more sophisticated techniques.
    """
    # Test CL.TE - Content-Length, Transfer-Encoding
    cl_te_headers = {
        'Content-Length': '41',
        'Transfer-Encoding': 'chunked'
    }
    if headers:
        import json
        try:
            custom_headers = json.loads(headers)
            cl_te_headers.update(custom_headers) # Merge custom headers with existing ones
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON format for headers: {e}")
            return False

    cl_te_data = "0\r\n\r\nGET / HTTP/1.1\r\nX-Foo: bar\r\n\r\n"

    status_code, resp_headers, resp_text = send_request(url, method, data=cl_te_data, headers=cl_te_headers, timeout=timeout, verbose=verbose)

    if status_code and resp_text:
        if "X-Foo: bar" in resp_text:
            logging.warning("Potential CL.TE HTTP Request Smuggling Vulnerability Detected!")
            return True
        else:
            logging.info("CL.TE Test: No immediate vulnerability detected.")

    # Test TE.CL - Transfer-Encoding, Content-Length
    te_cl_headers = {
        'Transfer-Encoding': 'chunked',
        'Content-Length': '100'
    }

    if headers:
        import json
        try:
            custom_headers = json.loads(headers)
            te_cl_headers.update(custom_headers) # Merge custom headers with existing ones
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON format for headers: {e}")
            return False

    te_cl_data = "5c\r\nGET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\nX-Foo: bar\r\n\r\n0\r\n\r\n"
    status_code, resp_headers, resp_text = send_request(url, method, data=te_cl_data, headers=te_cl_headers, timeout=timeout, verbose=verbose)

    if status_code and resp_text:
        if "X-Foo: bar" in resp_text:
            logging.warning("Potential TE.CL HTTP Request Smuggling Vulnerability Detected!")
            return True
        else:
            logging.info("TE.CL Test: No immediate vulnerability detected.")


    # Test TE.TE - Transfer-Encoding, Transfer-Encoding
    te_te_headers = {
        'Transfer-Encoding': 'chunked, chunked'
    }

    if headers:
        import json
        try:
            custom_headers = json.loads(headers)
            te_te_headers.update(custom_headers)  # Merge custom headers with existing ones
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON format for headers: {e}")
            return False

    te_te_data = "0\r\n\r\nGET / HTTP/1.1\r\nX-Foo: bar\r\n\r\n"
    status_code, resp_headers, resp_text = send_request(url, method, data=te_te_data, headers=te_te_headers, timeout=timeout, verbose=verbose)

    if status_code and resp_text:
        if "X-Foo: bar" in resp_text:
            logging.warning("Potential TE.TE HTTP Request Smuggling Vulnerability Detected!")
            return True
        else:
            logging.info("TE.TE Test: No immediate vulnerability detected.")


    return False

def main():
    """
    Main function to execute the HTTP Request Smuggling detection.
    """
    args = setup_argparse()

    if not is_valid_url(args.url):
        logging.error("Invalid URL provided.")
        sys.exit(1)

    logging.info(f"Starting HTTP Request Smuggling scan on: {args.url}")

    try:
        if detect_http_smuggling(args.url, args.method, args.data, args.headers, args.timeout, args.verbose):
            logging.info("HTTP Request Smuggling scan completed. Vulnerabilities found.")
        else:
            logging.info("HTTP Request Smuggling scan completed. No immediate vulnerabilities found.")

    except Exception as e:
        logging.error(f"An error occurred during the scan: {e}")
        sys.exit(1)


if __name__ == "__main__":
    """
    Entry point of the script.
    """
    main()

# Usage Examples:
# python vscan-http-request-smuggler.py http://example.com
# python vscan-http-request-smuggler.py http://example.com --method POST --data "param1=value1&param2=value2"
# python vscan-http-request-smuggler.py http://example.com --headers '{"X-Custom-Header": "value"}'
# python vscan-http-request-smuggler.py http://example.com --timeout 5
# python vscan-http-request-smuggler.py http://example.com --verbose