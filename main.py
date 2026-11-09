import argparse
import json
import logging
import re
import socket
import ssl
import sys

import requests
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def setup_argparse():
    parser = argparse.ArgumentParser(description='Detects HTTP Request Smuggling vulnerabilities.')
    parser.add_argument('url', type=str, help='The URL to scan.')
    parser.add_argument('--method', type=str, default='GET', help='The HTTP method to use for the crafted requests (default: GET).')
    parser.add_argument('--data', type=str, default=None, help='Body to send with each crafted request instead of the default smuggling payload body.')
    parser.add_argument('--headers', type=str, default=None, help='Custom headers to include (JSON format).')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10).')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output (status codes and sizes only; header values and bodies are never logged).')
    return parser.parse_args()


def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def parse_headers(headers):
    """Accept a dict or a JSON string and return a dict, or None on bad input."""
    if headers is None:
        return {}
    if isinstance(headers, dict):
        return dict(headers)
    if isinstance(headers, str):
        try:
            parsed = json.loads(headers)
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON format for headers: {e}")
            return None
        if isinstance(parsed, dict):
            return parsed
        logging.error("Headers JSON must be an object.")
        return None
    logging.error("Headers must be a dict or a JSON string.")
    return None


def send_request(url, method='GET', data=None, headers=None, timeout=10, verbose=False):
    """Send one request with the requests library.

    Always returns a triple (status_code, headers, text); the values are
    None when the request did not complete. Error status responses are
    returned as data, not raised, because this tool exists to analyze
    server responses. Header values and body text are never logged.
    """
    parsed_headers = parse_headers(headers)
    if parsed_headers is None:
        return None, None, None
    try:
        if verbose:
            logging.info(f"Sending {method} request to: {url}")
            logging.info(f"Header names: {sorted(parsed_headers)}")
            logging.info(f"Body length: {len(data) if data else 0}")
        response = requests.request(method, url, data=data, headers=parsed_headers,
                                    timeout=timeout, allow_redirects=False)
        if verbose:
            logging.info(f"Received response with status code: {response.status_code}")
            logging.info(f"Response header names: {sorted(response.headers)}")
            logging.info(f"Response body length: {len(response.text)}")
        return response.status_code, response.headers, response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed: {e}")
        return None, None, None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None, None, None


MAX_HEADER_BYTES = 65536
MAX_BODY_BYTES = 1048576


class _Reader:
    """Buffered socket reader with hard size caps.

    A peer that floods bytes without framing can never grow the buffer
    past the caps: exceeding a cap raises ValueError and the response is
    reported as not completed.
    """

    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def _fill(self, cap):
        if len(self.buf) > cap:
            raise ValueError("response exceeds size cap")
        chunk = self.sock.recv(4096)
        if not chunk:
            raise EOFError("connection closed")
        self.buf += chunk
        if len(self.buf) > cap:
            raise ValueError("response exceeds size cap")

    def read_until(self, marker, cap):
        while marker not in self.buf:
            self._fill(cap)
        idx = self.buf.index(marker) + len(marker)
        out, self.buf = self.buf[:idx], self.buf[idx:]
        return out

    def read_exact(self, n, cap):
        if n > cap:
            raise ValueError("response exceeds size cap")
        while len(self.buf) < n:
            self._fill(cap)
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def read_line(self, cap):
        return self.read_until(b"\r\n", cap)


def _read_response(sock, timeout=10):
    """Read one HTTP response from a raw socket. Returns (status, body) or (None, None).

    Handles Content-Length and chunked Transfer-Encoding framing, with
    size caps on both the header block and the body. A response with
    neither framing header is treated as complete at the header block,
    because the connection is kept alive for the probe request that
    follows and there is no end of body signal to wait for.
    """
    sock.settimeout(timeout)
    reader = _Reader(sock)
    try:
        head_block = reader.read_until(b"\r\n\r\n", MAX_HEADER_BYTES)
        head = head_block[:-4]
        m = re.search(rb"HTTP/\d\.\d (\d{3})", head)
        status = int(m.group(1)) if m else None
        if status is None:
            return None, None
        te = re.search(rb"[Tt]ransfer-[Ee]ncoding: ([^\r\n]+)", head)
        cl = re.search(rb"[Cc]ontent-[Ll]ength: (\d+)", head)
        if te and "chunked" in te.group(1).decode("utf-8", "replace").lower():
            body = b""
            while True:
                size_line = reader.read_line(MAX_HEADER_BYTES).strip()
                try:
                    size = int(size_line.split(b";")[0], 16)
                except ValueError:
                    return None, None
                if size == 0:
                    # Consume any trailer lines up to the blank line.
                    while reader.read_line(MAX_HEADER_BYTES) != b"\r\n":
                        pass
                    break
                body += reader.read_exact(size, MAX_BODY_BYTES)
                if len(body) > MAX_BODY_BYTES:
                    return None, None
                reader.read_exact(2, MAX_HEADER_BYTES)  # trailing CRLF
        elif cl:
            need = int(cl.group(1))
            if need > MAX_BODY_BYTES:
                return None, None
            try:
                body = reader.read_exact(need, MAX_BODY_BYTES)
            except EOFError:
                body = reader.buf
        else:
            body = reader.buf
        return status, body.decode("utf-8", "replace")
    except (EOFError, ValueError, OSError):
        return None, None


def _raw_exchange(url, method, headers, body, timeout, probe_path, verbose=False):
    """Send one crafted raw request, then a normal probe request on the
    same connection. Returns (completed, probe_body). The probe body is
    where a desync becomes observable: if the server processed the
    smuggled request instead, the probe response answers that request.
    """
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    raw = None
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        if parsed.scheme == "https":
            ctx = ssl.create_default_context()
            raw = ctx.wrap_socket(raw, server_hostname=host)
        lines = [f"{method} {path} HTTP/1.1", f"Host: {parsed.netloc}", "Connection: keep-alive"]
        for k, v in headers.items():
            if k.lower() not in ("host", "connection"):
                lines.append(f"{k}: {v}")
        payload = ("\r\n".join(lines) + "\r\n\r\n" + body).encode("utf-8", "replace")
        raw.sendall(payload)
        status, _crafted_body = _read_response(raw, timeout)
        if verbose:
            logging.info(f"Crafted request status: {status}, response body length: {len(_crafted_body or '')}")
        if status is None:
            return False, ""
        probe = (f"GET {probe_path} HTTP/1.1\r\nHost: {parsed.netloc}\r\n"
                 f"Connection: close\r\n\r\n").encode()
        raw.sendall(probe)
        pstatus, pbody = _read_response(raw, timeout)
        if pstatus is None:
            return False, ""
        return True, pbody
    except Exception as e:
        logging.error(f"Raw request failed: {e}")
        return False, ""
    finally:
        if raw is not None:
            try:
                raw.close()
            except Exception:
                pass


def detect_http_smuggling(url, method='GET', data=None, headers=None, timeout=10, verbose=False):
    """Run the three framing tests.

    Each test sends a crafted request with raw socket framing (so the
    conflicting Content-Length and Transfer-Encoding headers reach the
    server as written) and then a normal probe request on the same
    connection. A test is positive only when the probe response is the
    response to the smuggled marker request embedded in the crafted
    body, which is an observable desync effect.

    Returns (vulnerable, completed_count).
    """
    custom = parse_headers(headers)
    if custom is None:
        return False, 0

    tests = [
        ("CL.TE", {'Content-Length': '41', 'Transfer-Encoding': 'chunked'},
         "0\r\n\r\nGET /__smuggled_clte HTTP/1.1\r\nX-Foo: bar\r\n\r\n"),
        ("TE.CL", {'Transfer-Encoding': 'chunked', 'Content-Length': '100'},
         "5c\r\nGET /__smuggled_tecl HTTP/1.1\r\nContent-Length: 10\r\nX-Foo: bar\r\n\r\n0\r\n\r\n"),
        ("TE.TE", {'Transfer-Encoding': 'chunked, chunked'},
         "0\r\n\r\nGET /__smuggled_tete HTTP/1.1\r\nX-Foo: bar\r\n\r\n"),
    ]
    # The test framing headers always win. A caller supplied Content-Length
    # or Transfer-Encoding (in any letter case) is dropped with a warning,
    # because letting it override would quietly disarm the header conflict
    # each test exists to create. Other custom headers are kept.
    framing = {"content-length", "transfer-encoding"}
    custom_clean = {}
    for k, v in custom.items():
        if k.lower() in framing:
            logging.warning(f"Ignoring custom {k} header: the test framing headers take precedence.")
        else:
            custom_clean[k] = v
    completed = 0
    vulnerable = False
    for name, test_headers, default_body in tests:
        merged = dict(custom_clean)
        merged.update(test_headers)
        body = data if data is not None else default_body
        marker = "/__smuggled_" + name.lower().replace(".", "")
        done, probe_body = _raw_exchange(url, method, merged, body, timeout, "/__probe_" + name.lower().replace(".", ""), verbose)
        if not done:
            logging.error(f"{name} Test: request did not complete.")
            continue
        completed += 1
        # A positive needs the probe body to carry the marker sentence for
        # the smuggled path (see README, How detection works). This is a
        # conservative signal: a desynced server that answers the smuggled
        # request with an ordinary error page is reported as no finding.
        if data is None and ("SMUGGLED_RESPONSE_FOR " + marker) in probe_body:
            logging.warning(f"Potential {name} HTTP Request Smuggling Vulnerability Detected: the follow-up probe was answered with the smuggled request response.")
            vulnerable = True
        else:
            logging.info(f"{name} Test: No immediate vulnerability detected.")
    return vulnerable, completed


def main():
    args = setup_argparse()

    if not is_valid_url(args.url):
        logging.error("Invalid URL provided.")
        sys.exit(1)

    logging.info(f"Starting HTTP Request Smuggling scan on: {args.url}")

    try:
        vulnerable, completed = detect_http_smuggling(
            args.url, args.method, args.data, args.headers, args.timeout, args.verbose)
    except Exception as e:
        logging.error(f"An error occurred during the scan: {e}")
        sys.exit(1)

    if completed == 0:
        logging.error("Scan failed: no test request completed, so no verdict can be given.")
        sys.exit(1)
    if vulnerable:
        logging.info("HTTP Request Smuggling scan completed. Vulnerabilities found.")
    else:
        logging.info("HTTP Request Smuggling scan completed. No immediate vulnerabilities found.")


if __name__ == "__main__":
    main()

# Usage Examples:
# python vscan-http-request-smuggler.py http://example.com
# python vscan-http-request-smuggler.py http://example.com --method POST --data "param1=value1&param2=value2"
# python vscan-http-request-smuggler.py http://example.com --headers '{"X-Custom-Header": "value"}'
# python vscan-http-request-smuggler.py http://example.com --timeout 5
# python vscan-http-request-smuggler.py http://example.com --verbose
