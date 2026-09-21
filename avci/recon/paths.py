"""Sensitive-path discovery — built-in wordlist, signature-verified hits.

The ffuf/nuclei exposures lesson in pure stdlib: probe ~220 paths per live
host, verify by content signature (not just 200), report leads.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

import httpx

from ..scope.guard import ScopeGuard

log = logging.getLogger("avci.recon.paths")

PATHS: tuple[str, ...] = (
    # credentials / config
    ".env", ".env.local", ".env.production", ".env.backup", ".env.old",
    "config.php", "config.php.bak", "configuration.php", "configuration.yaml",
    "appsettings.json", "settings.py", "settings.json", "config.json",
    "config.yml", "config.yaml", "application.properties", "secrets.json",
    "credentials.json", "application.yml", "web.config", "wp-config.php",
    "wp-config.php.bak", "wp-config.txt", "db.php", "database.yml",
    # vcs / editor
    ".git/config", ".git/HEAD", ".git/index", ".git/logs/HEAD",
    ".svn/entries", ".hg/store", ".DS_Store", "Thumbs.db",
    # backups & dumps
    "backup.zip", "backup.tar.gz", "backup.sql", "backup.sql.gz",
    "db.sql", "db.dump", "dump.sql", "database.sql", "site.zip",
    "www.zip", "web.zip", "html.zip", "src.zip", "release.zip",
    "backup/", "backups/", "old/", "_old/", "archive/",
    # admin & panels
    "admin", "admin/", "admin/login", "administrator/", "adminer.php",
    "phpmyadmin/", "pma/", "manager/html", "cpanel/", "wp-admin/",
    "wp-login.php", "wp-json/", "xmlrpc.php", "wp-content/plugins/",
    "typo3/", "joomla/administrator", "drupal/user/login",
    "adminpanel", "adminpanel/", "adminpanel/profile", "admin-panel/",
    "panel/", "console/", "manage/", "backstage/", "dashboard/",
    # dev & docs
    "swagger", "swagger/", "swagger.json", "swagger-ui.html", "swagger/index.html",
    "api-docs", "api-docs/", "openapi.json", "api/swagger.json", "graphql",
    "graphql/", "api/graphql", "v1/graphql", "gql",
    "graphiql", "actuator", "actuator/health", "actuator/env", "actuator/heapdump",
    "trace", "health", "status", "info", "metrics", "debug", "console/",
    "server-status", "server-info", "phpinfo.php", "info.php", "test.php",
    # CI/CD & infra
    ".gitlab-ci.yml", "Jenkinsfile", "Dockerfile", "docker-compose.yml",
    "docker-compose.yaml", ".travis.yml", "package.json", "composer.json",
    "Gemfile", "requirements.txt", "Pipfile", "yarn.lock", "package-lock.json",
    ".circleci/config.yml", ".github/workflows/", "Makefile", "Procfile",
    # logs & temp
    "logs/", "log/", "error.log", "access.log", "debug.log", "app.log",
    "tmp/", "temp/", "cache/", ".cache/", "uploads/", "upload/",
    # keys & certs
    "id_rsa", "id_rsa.key", "private.key", "server.key", "server.crt",
    "certificate.pem", "keystore.jks", ".htpasswd", ".htaccess",
    "oauth-keys.json", "firebase-adminsdk.json", "service-account.json",
    # mail & misc
    "robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
    ".well-known/security.txt", "humans.txt", "readme.md", "README.md",
    "CHANGELOG.md", "todo.txt", "notes.txt", ".vscode/sftp.json",
    ".idea/workspace.xml", "azure-pipelines.yml", ".dockerignore",
    "webhook.php", "payment.php", "paypal.php", "cron.php", "shell.php",
)

# (regex-signature, what-it-means) — hit must match signature to count
SIGNATURES: tuple[tuple[str, str, str], ...] = (
    (r"DB_(PASSWORD|HOST|USER)|DATABASE_URL|MYSQL|POSTGRES_", ".env credentials", "high"),
    (r"ref:\s*refs/", ".git repository exposure", "high"),
    (r"define\s*\(\s*['\"]DB_(PASSWORD|USER|HOST)", "wp-config credentials", "high"),
    (r"BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY", "private key exposure", "critical"),
    (r"\"aws_access_key_id\"|AKIA[0-9A-Z]{16}", "cloud credentials", "critical"),
    (r"password\s*[:=]\s*['\"][^'\"]{4,}", "plaintext credential", "high"),
    (r"swagger|openapi|\"paths\"\s*:", "API specification exposed", "medium"),
    (r"__schema|Must provide query string|No query document|GraphiQL",
     "GraphQL endpoint exposed", "medium"),
    (r"<definitions[^>]+xmlns|soap:address|xmlns:soap=",
     "WSDL/SOAP service exposed", "medium"),
    (r"Stable tag:\s*[0-9.]+",
     "WordPress plugin readme exposed (name+version)", "info"),
    (r"wp-content/plugins|wp-includes|wp-json",
     "WordPress detected", "info"),
    (r"\"_links\"|\"_embedded\"", "HAL API root exposed", "low"),
    (r"phpinfo\(\)|PHP Version|phpinfo", "phpinfo disclosure", "medium"),
    (r"[Pp]ath:\s*/", "directory listing", "low"),
    (r"[Ee]rrorLog|[Dd]ocumentRoot", "config file readable", "medium"),
    (r"parent directory|directory listing for", "open directory listing", "low"),
)

HARD_HITS: dict[str, tuple[str, str, str]] = {
    # path → (title, severity, body marker) — status 200 alone never counts
    # (SPA catch-alls answer 200 to everything; the marker must match too)
    "actuator/heapdump": ("Spring heapdump exposure", "critical",
                          r"java\.lang|Instance\s+Count|Class Histogram|No\. of Instances"),
    "actuator/env": ("Spring actuator env disclosure", "high",
                     r"propertySources|systemProperties|activeProfiles"),
    "phpmyadmin/": ("phpMyAdmin exposed", "high", r"(?i)phpmyadmin"),
    "adminer.php": ("Adminer exposed", "high", r"(?i)adminer"),
    ".well-known/security.txt": ("security.txt (info)", "info", r"(?i)^\s*Contact:"),
    "robots.txt": ("robots.txt (info)", "info", r"(?im)^(user-agent|disallow|allow|sitemap):"),
    "graphql": ("GraphQL endpoint", "medium",
                r"(?i)graphiql|__schema|must provide query string|no query document|"
                r"\"query\"|\"mutation\""),
    "graphiql": ("GraphiQL IDE exposed", "medium", r"(?i)graphiql"),
    "wp-login.php": ("WordPress login", "info",
                     r"(?i)wp-login|wordpress|user_login|log-in"),
    "wp-json/": ("WordPress REST API", "info",
                 r"(?i)namespaces|routes|wp/v"),
    "xmlrpc.php": ("WordPress XML-RPC", "low",
                   r"(?i)xmlrpc|XML-RPC server accepts POST requests only"),
}


@dataclass
class PathHit:
    url: str
    status: int
    title: str
    severity: str
    excerpt: str


async def discover_paths(
    origin: str, guard: ScopeGuard, client: httpx.AsyncClient,
    concurrency: int = 12, extra_paths: tuple[str, ...] = (),
) -> list[PathHit]:
    import re
    base = origin.rstrip("/")
    sem = asyncio.Semaphore(concurrency)
    words = PATHS + extra_paths
    api_path = re.compile(r"graphql|gql|graphiql|api|wsdl|soap", re.I)
    gated_kw = ("admin", "manager", "phpmyadmin", "wp-admin", "wp-login",
                "graphql",
                "api", "debug", "internal", "private", "console", "config",
                "wsdl", "soap", "wp-json", "xmlrpc")

    # calibration: if a random nonexistent path also 401/403s, the whole app
    # sits behind auth and generic per-path 401s would be pure noise.
    async def _gated_everywhere() -> bool:
        try:
            guard.check_url(f"{base}/avci-calib-9f3e")
            r = await client.get(f"{base}/avci-calib-9f3e", timeout=12,
                                 follow_redirects=False)
            return r.status_code in (401, 403)
        except Exception:  # noqa: BLE001
            return False

    calib_gated = await _gated_everywhere()

    async def check(path: str) -> PathHit | None:
        url = f"{base}/{path}"
        try:
            guard.check_url(url)
        except Exception:  # noqa: BLE001
            return None
        async with sem:
            try:
                r = await client.get(url, timeout=12, follow_redirects=False)
            except Exception:  # noqa: BLE001
                return None
        if r.status_code not in (200, 401, 403) and not (
                r.status_code in (400, 405) and api_path.search(path)):
            return None
        body = r.text or ""
        if r.status_code == 200 and len(body.strip()) < 20:
            return None
        if path in HARD_HITS:
            title, sev, marker = HARD_HITS[path]
            if r.status_code == 200 and re.search(marker, body):
                return PathHit(url, r.status_code, title, sev, body[:160])
        for sig, title, sev in SIGNATURES:
            if r.status_code == 200 and re.search(sig, body):
                return PathHit(url, r.status_code, title, sev, body[:240])
        if r.status_code in (400, 405) and api_path.search(path):
            # POST-only API endpoints answer GET with 400/405 — that's
            # surface, not noise
            return PathHit(url, r.status_code, f"API endpoint reacts: {path}",
                           "info", f"{r.status_code} {body[:100]}")
        if (r.status_code == 200
                and any(s in path.lower() for s in gated_kw)
                and re.search(r"(?i)type=[\"']password|<form\b|login|sign[- ]?in",
                              body)):
            # an admin/console-flavored path serving a real interactive page:
            # a hidden admin login is prime surface even without a leak signature
            return PathHit(url, r.status_code, f"admin surface: {path}",
                           "low", body[:200])
        if r.status_code in (401, 403):
            if any(s in path.lower() for s in gated_kw):
                return PathHit(url, r.status_code,
                               f"protected surface: {path}", "info",
                               f"{r.status_code}")
            if not calib_gated:
                return PathHit(url, r.status_code, f"auth-gated path: {path}",
                               "info", f"{r.status_code}")
        return None

    results = await asyncio.gather(*(check(p) for p in words))
    hits = sorted((h for h in results if h),
                  key=lambda h: ("critical", "high", "medium", "low", "info")
                  .index(h.severity))
    log.info("paths %s: %d/%d hits", base, len(hits), len(words))
    return hits
