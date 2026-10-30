#!/usr/bin/env python3
"""Canary / redirector service for the Elastic Agent Builder repro.

Modes (CANARY_MODE env):
  serve    -> serves /x.zip and /y.zip from /data, /hook returns 200.
              Represents an internal-only service on the compose network.
  redirect -> 302-redirects to the canary: /jump.zip -> canary /y.zip
              (TEST 2's distinct plugin), every other path -> same path
              on the canary (CONTROL B's /hook). Represents a host that
              IS in xpack.actions.allowedHosts.

Every request is logged to stdout with a greppable prefix so the test
script can prove which container fetched what:
  CANARY-LOG     ... (serve mode)
  REDIRECTOR-LOG ... (redirect mode)
"""
import os
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODE = os.environ.get("CANARY_MODE", "serve")
PORT = 8080
CANARY_BASE = "http://canary:8080"
TAG = "CANARY-LOG" if MODE == "serve" else "REDIRECTOR-LOG"


def log(msg: str) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    print(f"{TAG} {ts} {msg}", flush=True)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # silence default logger; we log manually
        pass

    def _send(self, code: int, body: bytes, ctype: str = "text/plain", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _handle(self):
        log(f"{self.client_address[0]} {self.command} {self.path}")
        if MODE == "redirect":
            target = CANARY_BASE + ("/y.zip" if self.path == "/jump.zip" else self.path)
            log(f"302 -> {target}")
            self._send(302, b"", extra={"Location": target})
            return
        # serve mode
        if self.path in ("/x.zip", "/y.zip"):
            fpath = "/data" + self.path
            try:
                with open(fpath, "rb") as fh:
                    data = fh.read()
                self._send(200, data, "application/zip")
            except OSError as e:
                self._send(500, f"missing {fpath}: {e}".encode())
            return
        if self.path == "/hook":
            self._send(200, b"hook-ok")
            return
        self._send(404, b"not found")

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_HEAD = _handle


if __name__ == "__main__":
    log(f"starting mode={MODE} port={PORT}")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
