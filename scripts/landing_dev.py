#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Live-reload dev server for docs/landing.html.

Usage:
    .venv/bin/python scripts/landing_dev.py
"""

from livereload import Server

server = Server()
server.watch("docs/landing.html")
server.serve(
    port=8099,
    root="docs/",
    open_url_delay=0.5,
    default_filename="landing.html",
)
