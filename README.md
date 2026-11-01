# vscan-http-request-smuggler
Detects HTTP Request Smuggling vulnerabilities by sending crafted requests and analyzing server responses. - Focused on Lightweight web application vulnerability scanning focused on identifying common misconfigurations and publicly known vulnerabilities

## Install
`git clone https://github.com/ShadowStrikeHQ/vscan-http-request-smuggler`

## Usage
`./vscan-http-request-smuggler [params]`

## Parameters
- `--method`: HTTP method used for the crafted requests (default: GET).
- `--data`: Body sent with each crafted request instead of the default smuggling payload body. When a body is supplied, the embedded marker request is not sent, so the follow-up probe check cannot produce a positive for that run.
- `--headers`: Custom headers to include (JSON format).
- `--timeout`: Request timeout in seconds (default: 10).
- `--verbose`: Enable verbose output. Verbose output shows status codes, header names, and sizes only; header values and response bodies are never logged.

## How detection works
Each of the three tests (CL.TE, TE.CL, TE.TE) sends one crafted request with raw socket framing so the conflicting length and encoding headers reach the server as written, then sends a normal probe request on the same connection. A test reports a vulnerability only when the probe is answered with the response to the smuggled marker request embedded in the crafted body, which is an observable desync effect. If no test request completes, the scan reports failure and exits non-zero instead of reporting a clean result.

## License
Copyright (c) ShadowStrikeHQ
