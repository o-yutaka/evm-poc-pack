#!/usr/bin/env python3
"""Canary / redirector service for the Elastic Agent Builder repro.

Modes (CANARY_MODE env):
  serve    -> serves /x.zip, /y.zip and /z.zip from /data, /hook returns 200,
              and POST /mcp is a minimal MCP (JSON-RPC) stub for run #4
              TEST 3. Represents an internal-only service on the compose
              network.
  redirect -> 302-redirects to the canary: /jump.zip -> canary /y.zip
              (TEST 2's distinct plugin), every other path -> same path
              on the canary (CONTROL B's /hook). Represents a host that
              IS in xpack.actions.allowedHosts.

Every request is logged to stdout with a greppable prefix so the test
script can prove which container fetched what:
  CANARY-LOG     ... (serve mode)
  REDIRECTOR-LOG ... (redirect mode)
"""
import json
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
        if self.path == "/mcp":
            if self.command == "POST":
                self._handle_mcp()
            else:
                # No standalone SSE stream offered (spec-sanctioned 405).
                self._send(405, b"method not allowed")
            return
        if self.path in ("/x.zip", "/y.zip", "/z.zip"):
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

    def _handle_mcp(self):
        # Minimal MCP-over-Streamable-HTTP stub (run #4, TEST 3). The
        # discriminator is the request's ARRIVAL (already logged by
        # _handle); the replies only need to be protocol-valid enough for
        # Kibana's MCP client to complete initialize + tools/list.
        # Stateless: no Mcp-Session-Id is issued.
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length > 0 else b""
        log(f"MCP request body: {raw[:400]!r}")
        try:
            msg = json.loads(raw.decode("utf-8", "replace")) if raw else {}
        except ValueError:
            msg = {}
        if isinstance(msg, list):  # JSON-RPC batch: answer first element only
            msg = msg[0] if msg else {}
        method = msg.get("method", "")
        mid = msg.get("id")
        params = msg.get("params") or {}

        def rpc(result):
            body = json.dumps({"jsonrpc": "2.0", "id": mid, "result": result}).encode()
            self._send(200, body, "application/json")

        if method == "initialize":
            rpc({
                "protocolVersion": params.get("protocolVersion", "2025-03-26"),
                "capabilities": {},
                "serverInfo": {"name": "canary-mcp-stub", "version": "0.0.1"},
            })
        elif method == "tools/list":
            rpc({"tools": [{
                "name": "canary_echo",
                "description": "Stub tool served by the repro canary; never invoked by the tests.",
                "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}},
            }]})
        elif method == "tools/call":
            rpc({"content": [{"type": "text", "text": "canary-echo"}], "isError": False})
        elif method == "ping":
            rpc({})
        elif mid is None:
            # JSON-RPC notification (e.g. notifications/initialized): 202, no body.
            self._send(202, b"")
        else:
            body = json.dumps({"jsonrpc": "2.0", "id": mid,
                               "error": {"code": -32601, "message": "method not found"}}).encode()
            self._send(200, body, "application/json")

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_HEAD = _handle


if __name__ == "__main__":
    log(f"starting mode={MODE} port={PORT}")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
