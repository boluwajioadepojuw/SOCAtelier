#!/usr/bin/env python3
"""Tiny lab collector: accepts GET/PUT/POST on 8099 and logs the real
connection tuples, acting as the lab's C2 stand-in."""
import http.server
import sys

class H(http.server.BaseHTTPRequestHandler):
    def _log(self):
        print(f"[collector] {self.client_address[0]}:{self.client_address[1]} -> "
              f"{self.server.server_address[0]}:{self.server.server_address[1]} "
              f"{self.command} {self.path}", flush=True)
    def do_GET(self):
        self._log()
        body = b"#!/bin/bash\necho lab-lynx setup marker\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_PUT(self):
        self._log()
        n = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(n)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"stored")
    def do_POST(self):
        self.do_PUT()
    def log_message(self, *a):
        pass

http.server.HTTPServer(("127.0.0.1", 8099), H).serve_forever()
