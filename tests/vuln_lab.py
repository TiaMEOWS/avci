"""Tiny vulnerable lab app for offline end-to-end AVCI validation.

Bugs planted (all findable via AVCI probes):
  v0.1: XSS /search?q= · redirect /go?url= · CORS /api/data · missing headers
  v0.2: .git/HEAD · /.env · IDOR /api/orders/<n> · /graphql introspection ·
        SSTI /render?tpl=
  v0.3: login enumeration + default creds (POST /login) ·
        negative quantity (POST /api/cart) · mass assignment
        (PATCH /api/account) · race/TOCTOU mixed-status (POST /api/coupon) ·
        cache deception (/api/profile + any suffix, Cache-Control public) ·
        cache poisoning (X-Forwarded-Host reflected) ·
        graphql depth + batch + field suggestions ·
        NoSQL error (?search= with ') · XXE (POST /xml) ·
        backup file /index.php.bak · sourcemap /app.js.map ·
        cookie without flags on /login page · debug stack on /oops ·
        HPP concat on /hpp · api versions /api/v1 /api/v2

Run: python tests/vuln_lab.py [port]
"""

from __future__ import annotations

import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

_ORDERS = {
    i: f'{{"id": {i}, "customer": "user{i}@shop.example", '
       f'"total": {39 + i}.90, "items": {i % 5 + 1}}}'
    for i in range(1330, 1350)
}
_coupon_lock = threading.Lock()
_coupon_claims = 0
# v0.5 identity fixture: register + session-bound /api/me (scoping works —
# the resource every cross-identity divergence check measures against)
_USERS: dict[str, str] = {}   # sid -> email
_sid_lock = threading.Lock()
_sid_seq = 0

_WINI = ("; for 16-bit app support\n[fonts]\n[extensions]\n"
         "fixedsys=FIXED.FON\n")


def _read_body(handler) -> bytes:
    n = int(handler.headers.get("Content-Length") or 0)
    return handler.rfile.read(n) if n else b""


class Lab(BaseHTTPRequestHandler):
    def log_message(self, *a) -> None:  # quiet
        pass

    def _send(self, status: int, body: str, headers: dict[str, str] | None = None):
        data = body.encode()
        self.send_response(status)
        for k, v in (headers or {"Content-Type": "text/html; charset=utf-8"}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # ------------------------------------------------------------------
    def do_OPTIONS(self) -> None:
        # PLANTED: PUT/DELETE/TRACE all "allowed"
        self._send(204, "", {"Allow": "GET, POST, PUT, DELETE, PATCH, TRACE",
                             "Content-Length": "0"})

    def do_TRACE(self) -> None:
        self._send(200, f"TRACE {self.path} HTTP/1.1",
                   {"Content-Type": "message/http"})

    # ------------------------------------------------------------------
    def do_POST(self) -> None:
        global _coupon_claims, _sid_seq
        parts = urlsplit(self.path)
        qs = {k: v[0] for k, v in parse_qs(parts.query,
                                           keep_blank_values=True).items()}
        body = _read_body(self).decode("utf-8", errors="replace")

        if parts.path == "/vault":
            # PLANTED: PHP-style loose hash comparison — any 0e<digits>
            # digest equals any other (magic-hash auth bypass)
            import hashlib
            form = {k: v[0] for k, v in parse_qs(body,
                                                 keep_blank_values=True).items()}
            p = form.get("password", "")
            h = hashlib.md5(p.encode()).hexdigest()
            target = "0e678703625362188185747119782643"
            def _is0e(s: str) -> bool:
                return s.startswith("0e") and s[2:].isdigit()
            if h == target or (_is0e(h) and _is0e(target)):
                self._send(200, "<html><body><h2>Welcome Admin</h2>"
                                "<h3>flag{lab-vault}</h3></body></html>")
            else:
                self._send(200, "<html><body><h3>Incorrect Vault Password: "
                                f"{h}</h3></body></html>")
            return

        if parts.path == "/feedback":
            # PLANTED: form-borne SSTI — comment rendered through a naive
            # template engine on the SAME response
            form = {k: v[0] for k, v in parse_qs(body,
                                                 keep_blank_values=True).items()}
            rendered = (form.get("comment", "")
                        .replace("{{7*7}}", "49")
                        .replace("{{7*'7'}}", "7777777")
                        .replace("${7*7}", "49")
                        .replace("<%= 7*7 %>", "49")
                        .replace("#{7*7}", "49")
                        .replace("{% widthratio 7 1 7 %}", "49")
                        .replace("{% debug %}", "django.conf SETTINGS dump"))
            self._send(200, "<html><body><h1>Thanks!</h1>"
                            f"<p>Your note: {rendered}</p></body></html>")
            return

        if parts.path == "/api/register":
            # v0.5 identity fixture: instant signup, sid cookie + bearer token
            m = re.search(r'"email"\s*:\s*"([^"]+)"', body)
            p = re.search(r'"password"\s*:\s*"([^"]+)"', body)
            if not (m and p):
                self._send(400, '{"error": "email and password required"}',
                           {"Content-Type": "application/json"})
                return
            with _sid_lock:
                _sid_seq += 1
                sid = f"tok{_sid_seq:04d}"
            _USERS[sid] = m.group(1)
            self._send(201, f'{{"user": "{m.group(1)}", "token": "{sid}"}}',
                       {"Content-Type": "application/json",
                        "Set-Cookie": f"sid={sid}; Path=/"})
            return

        if parts.path == "/graphql":
            q = body
            # PLANTED: introspection open
            if "__schema" in q:
                self._send(200, '{"data": {"__schema": {"types": '
                                '[{"name": "Query"}, {"name": "Mutation"}]}}}',
                           {"Content-Type": "application/json"})
                return
            # PLANTED: batch arrays executed (checked before depth — batch
            # bodies contain many braces)
            if q.strip().startswith("["):
                self._send(200, "[" + ",".join(
                    '{"data": {"__typename": "Query"}}' for _ in range(30)) + "]",
                           {"Content-Type": "application/json"})
                return
            # PLANTED: no depth limit — deep nesting executed
            if q.count("{") > 20:
                self._send(200, '{"data": {"a": {"a": {"a": "deep"}}}}',
                           {"Content-Type": "application/json"})
                return
            # PLANTED: field suggestions leak schema
            if "userr" in q:
                self._send(200, '{"errors": [{"message": "Cannot query field '
                                '\'userr\' on type \'Query\'. Did you mean '
                                '\'user\'?''"}]}',
                           {"Content-Type": "application/json"})
                return
            self._send(200, '{"data": {}}', {"Content-Type": "application/json"})
            return

        if parts.path == "/login":
            m = re.search(r'"username"\s*:\s*"([^"]+)"', body)
            user = m.group(1) if m else ""
            # PLANTED: default creds admin/admin
            if user == "admin" and '"password":"admin"' in body.replace(" ", ""):
                self._send(200, '{"token": "sess-admin-1", "user": "admin"}',
                           {"Content-Type": "application/json",
                            "Set-Cookie": "sid=adminsess1; Path=/"})
                return
            # PLANTED: enumeration — known user gets a different message
            if user == "admin":
                self._send(401, '{"error": "wrong password"}',
                           {"Content-Type": "application/json"})
            else:
                self._send(401, '{"error": "no such user"}',
                           {"Content-Type": "application/json"})
            return

        if parts.path == "/api/cart":
            # PLANTED: negative quantity accepted, negative total computed
            m = re.search(r'"quantity"\s*:\s*(-?\d+)', body)
            if m:
                qty = int(m.group(1))
                total = qty * 25.0
                self._send(200, f'{{"quantity": {qty}, "total": {total}}}',
                           {"Content-Type": "application/json"})
                return
            self._send(400, '{"error": "quantity required"}',
                       {"Content-Type": "application/json"})
            return

        if parts.path == "/api/coupon":
            # PLANTED: TOCTOU — first 3 concurrent claims succeed, rest 409
            with _coupon_lock:
                _coupon_claims += 1
                n = _coupon_claims
            if n <= 3:
                self._send(200, '{"coupon": "WELCOME10", "claim": %d}' % n,
                           {"Content-Type": "application/json"})
            else:
                self._send(409, '{"error": "already claimed"}',
                           {"Content-Type": "application/json"})
            return

        if parts.path == "/xml":
            # PLANTED: XXE — external entity resolved and echoed
            if "ENTITY" in body and "SYSTEM" in body:
                if "win.ini" in body:
                    self._send(200, "<r>" + _WINI + "</r>",
                               {"Content-Type": "application/xml"})
                else:
                    self._send(200, "<r>lab-host-01</r>",
                               {"Content-Type": "application/xml"})
                return
            self._send(400, "<error>bad xml</error>",
                       {"Content-Type": "application/xml"})
            return

        self._send(404, '{"error": "not found"}',
                   {"Content-Type": "application/json"})

    # ------------------------------------------------------------------
    def do_PATCH(self) -> None:
        parts = urlsplit(self.path)
        if parts.path == "/api/account":
            body = _read_body(self).decode("utf-8", errors="replace")
            # PLANTED: mass assignment — role field blindly persisted
            if '"role"' in body:
                m = re.search(r'"role"\s*:\s*"(\w+)"', body)
                self._send(200, f'{{"username": "victim", "role": '
                                f'"{m.group(1) if m else "user"}"}}',
                           {"Content-Type": "application/json"})
                return
            self._send(200, '{"username": "victim", "role": "user"}',
                       {"Content-Type": "application/json"})
            return
        self._send(404, '{"error": "not found"}',
                   {"Content-Type": "application/json"})

    # ------------------------------------------------------------------
    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        qs = {k: v[0] for k, v in parse_qs(parts.query,
                                           keep_blank_values=True).items()}

        if parts.path == "/search":
            q = qs.get("q", "")
            # PLANTED: verbatim reflection into HTML
            self._send(200, f"<html><body><h1>Results for {q}</h1>"
                            f"<p>3 items found</p></body></html>")

        elif parts.path == "/render":
            # PLANTED: naive template rendering
            tpl = qs.get("tpl", "")
            rendered = tpl.replace("{{7*7}}", "49").replace("${7*7}", "49")
            self._send(200, f"<html><body>rendered: {rendered}</body></html>")

        elif parts.path == "/go":
            target = qs.get("url", "/")
            # PLANTED: unconditional redirect
            self._send(302, "redirecting", {"Location": target})

        elif parts.path == "/hpp":
            # PLANTED: HPP — server joins duplicate params
            vals = parse_qs(parts.query, keep_blank_values=True).get("p", [])
            if len(vals) > 1:
                self._send(200, "<html>chosen: " + ",".join(vals) + "</html>")
            else:
                self._send(200, "<html>chosen: " + (vals[0] if vals else "") +
                            "</html>")

        elif parts.path == "/nosql":
            # PLANTED: mongo-style error on operator chars
            s = qs.get("search", "")
            if "'" in s or "$" in s:
                self._send(500, '{"error": "MongoError: query failed: '
                                'unknown top level operator"}',
                           {"Content-Type": "application/json"})
            else:
                self._send(200, '{"items": []}',
                           {"Content-Type": "application/json"})

        elif parts.path.startswith("/api/profile"):
            # PLANTED: cache deception — suffix variants serve private data
            # with public cache headers
            priv = ('{"username": "victim", "email": "victim@shop.example", '
                    '"token": "eyJhbGc.vict.im"}')
            self._send(200, priv, {"Content-Type": "application/json",
                                   "Cache-Control": "public, max-age=3600"})

        elif parts.path == "/api/me":
            # v0.5 identity fixture: session-scoped — A and B see different
            # data, anonymous gets 401 (the divergence oracle's reference)
            m = re.search(r"sid=([^\s;]+)", self.headers.get("Cookie") or "")
            tok = (self.headers.get("Authorization") or "").replace("Bearer ", "")
            sid = m.group(1) if m else (tok if tok in _USERS else "")
            if sid in _USERS:
                email = _USERS[sid]
                self._send(200, f'{{"email": "{email}", "plan": "free", '
                                f'"notes": {len(email) % 7}}}',
                           {"Content-Type": "application/json"})
            else:
                self._send(401, '{"error": "authentication required"}',
                           {"Content-Type": "application/json"})

        elif parts.path == "/api/data":
            origin = self.headers.get("Origin", "")
            # PLANTED: reflects arbitrary origin + credentials
            self._send(200, '{"users": ["a", "b"]}', {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
            })

        elif parts.path == "/poisonable":
            # PLANTED: unkeyed X-Forwarded-Host reflected into body
            fh = self.headers.get("X-Forwarded-Host", "")
            if fh:
                self._send(200, f'<html><script src="https://{fh}/static/'
                                f'app.js"></script></html>')
            else:
                self._send(200, "<html>ok</html>")

        elif parts.path == "/oops":
            # PLANTED: stack trace disclosure
            self._send(500, "<html><pre>Traceback (most recent call last):\n"
                            '  File "app.py", line 88, in handler\n'
                            "    return render(oops)\n"
                            "django.core.exceptions.**DEBUG = True**"
                            "</pre></html>")

        elif parts.path == "/vault":
            # form page carrying the magic-hash password field
            self._send(200, "<html><body><h1>Vault</h1>"
                            "<form action='/vault' method='POST'>"
                            "<input type='password' name='password'>"
                            "<button name='submit'>Access</button>"
                            "</form></body></html>")

        elif parts.path == "/feedback":
            # PLANTED: page carrying the SSTI form (battery entry point)
            self._send(200, "<html><body><h1>Feedback</h1>"
                            "<form action='/feedback' method='POST'>"
                            "<input name='name' value=''>"
                            "<textarea name='comment'></textarea>"
                            "<button name='submit'>Send</button>"
                            "</form></body></html>")

        elif parts.path == "/login":
            # cookie planted WITHOUT flags (HttpOnly/Secure/SameSite)
            self._send(200, "<html><body>login form</body></html>",
                       {"Set-Cookie": "guest=1; Path=/"})

        elif parts.path == "/api/v1" or parts.path == "/api/v2":
            # PLANTED: multiple live API versions
            v = parts.path.rsplit("/", 1)[-1]
            self._send(200, f'{{"version": "{v}", "endpoints": 12}}',
                       {"Content-Type": "application/json"})

        elif parts.path == "/index.php.bak":
            # PLANTED: backup config with credentials
            self._send(200, "<?php\n$db_password = 'hunter2-prod';\n"
                            "define('DB_USER', 'root');\n",
                       {"Content-Type": "text/plain"})

        elif parts.path == "/app.js.map":
            # PLANTED: source map with full sources
            self._send(200, '{"version": 3, "sources": ["src/app.ts", '
                            '"src/secret.ts"], "sourcesContent": '
                            '["const KEY = 42;", "const apiKey = \'k\';"]}',
                       {"Content-Type": "application/json"})

        elif parts.path.startswith("/api/orders/"):
            oid = parts.path.rsplit("/", 1)[-1]
            # PLANTED: no ownership check — any id returns another user's order
            if oid.isdigit() and int(oid) in _ORDERS:
                self._send(200, _ORDERS[int(oid)],
                           {"Content-Type": "application/json"})
            else:
                self._send(404, '{"error": "no such order"}',
                           {"Content-Type": "application/json"})

        elif parts.path == "/.git/HEAD":
            # PLANTED: readable git metadata
            self._send(200, "ref: refs/heads/main", {"Content-Type": "text/plain"})

        elif parts.path == "/.env":
            # PLANTED: config leak
            self._send(200, "DB_PASSWORD=s3cr3t-hunter\n"
                            "DATABASE_URL=postgres://app:pw@db.internal:5432/prod\n"
                            "STRIPE_KEY=sk_live_51abcdef\n",
                       {"Content-Type": "text/plain"})

        else:
            # PLANTED: no HSTS/CSP/XFO anywhere
            self._send(200, "<html><head><title>AVCI Lab</title></head>"
                            "<body><a href='/search?q=test'>search</a> "
                            "<a href='/api/data'>api</a> "
                            "<a href='/api/orders/1337'>order</a> "
                            "<a href='/render?tpl=hi'>render</a> "
                            "<a href='/graphql'>graphql</a> "
                            "<a href='/login'>login</a> "
                            "<a href='/api/profile'>profile</a> "
                            "<a href='/api/cart'>cart</a> "
                            "<a href='/nosql?search=x'>nosql</a> "
                            "<a href='/hpp?p=1'>hpp</a> "
                            "<a href='/oops'>oops</a> "
                            "<a href='/app.js.map'>map</a> "
                            "<a href='/api/register'>register</a> "
                            "<a href='/api/me'>me</a></body></html>")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8901
    print(f"AVCI vuln lab on 127.0.0.1:{port}", flush=True)
    HTTPServer(("127.0.0.1", port), Lab).serve_forever()
