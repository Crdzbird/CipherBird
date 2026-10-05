#!/usr/bin/env python3
"""Serve a directory with permissive CORS headers so a browser test page on
another origin can fetch cipherbird.js and cipherbird.wasm."""
import sys
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer


class CorsHandler(SimpleHTTPRequestHandler):
    extensions_map = {**SimpleHTTPRequestHandler.extensions_map, '.wasm': 'application/wasm', '.js': 'text/javascript'}

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Cache-Control', 'no-store')
        super().end_headers()

    def log_message(self, format, *args):
        pass


if __name__ == '__main__':
    port = int(sys.argv[1])
    directory = sys.argv[2]
    ThreadingHTTPServer(('127.0.0.1', port), partial(CorsHandler, directory=directory)).serve_forever()
