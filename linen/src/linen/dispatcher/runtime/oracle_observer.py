"""Trusted transport probe run in a separate disposable observer container.

No target code is imported, no redirects are followed, and no worker verdict
field is accepted. The dispatcher supplies a bounded operator-registered case.
"""

import http.client
import json
import sys
import time


def main() -> None:
    with open(sys.argv[1], encoding="utf-8") as stream:
        case = json.load(stream)
    request = case["request"]
    deadline = time.monotonic() + case["timeout_seconds"]
    response = None
    while time.monotonic() < deadline:
        connection = http.client.HTTPConnection("127.0.0.1", case["service_port"], timeout=min(2, max(0.1, deadline - time.monotonic())))
        try:
            connection.request(request["method"], request["path"], body=request.get("body"), headers=request.get("headers", {}))
            response = connection.getresponse()
            body = response.read(16385)
            print(json.dumps({"status_code": response.status, "body": body[:16384].decode("utf-8", "strict"),
                              "truncated": len(body) > 16384}), flush=True)
            return
        except (ConnectionRefusedError, ConnectionResetError):
            time.sleep(0.1)
        finally:
            connection.close()
    raise RuntimeError("registered target did not become reachable before the probe deadline")


if __name__ == "__main__":
    main()
