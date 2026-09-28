#!/usr/bin/env python3
"""Simple Share: zero-dependency LAN file sharing for Python 3.10+."""


import argparse
import html
import hmac
import ipaddress
import hashlib
import json
import logging
import mimetypes
import os
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
import webbrowser
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from datetime import datetime


ROOT: Path | None = None
MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024
JSON_BODY_LIMIT = 64 * 1024
ACCESS_TOKEN = ""
ACCESS_SECRET = b""
COOKIE_NAME = "simple_share_auth"
OTP_STEP_SECONDS = 30
OTP_DIGITS = 6
AUTH_WINDOW_SECONDS = 60
AUTH_MAX_FAILURES = 5
AUTH_FAILURES: dict[str, list[float]] = {}
AUTH_LOCK = threading.Lock()
REQUEST_LOGGER = logging.getLogger("simple_share.requests")
REQUEST_LOG_PATH: Path | None = None
CONSOLE_STATUS_LOCK = threading.RLock()
CONSOLE_STATUS_ACTIVE = False
CONSOLE_STATUS_WIDTH = 0


# ============================================================
# Registro y estado de consola
# ============================================================


def script_directory() -> Path:
    return Path(__file__).resolve().parent


def console_status_width() -> int:
    """Ancho seguro para evitar que la línea dinámica haga wrap."""
    columns = shutil.get_terminal_size(fallback=(80, 24)).columns

    # Evitamos ocupar la última columna: algunos terminales hacen wrap
    # automáticamente justo al escribir en ella.
    return max(1, columns - 1)


def current_console_status() -> str:
    code = current_access_code()
    remaining = seconds_until_next_code()
    max_width = console_status_width()

    variants = [
        f"Código de acceso LAN: {code} · cambia en {remaining:02d} s",
        f"OTP LAN: {code} · {remaining:02d} s",
        f"OTP {code} · {remaining:02d}s",
        f"{code} · {remaining:02d}s",
        code,
    ]

    for text in variants:
        if len(text) <= max_width:
            return text

    return code[:max_width]


def _clear_console_status_unlocked():
    global CONSOLE_STATUS_WIDTH

    if not CONSOLE_STATUS_ACTIVE or sys.stdout is None:
        return

    current_width = console_status_width()

    if sys.stdout.isatty():
        # Borra la línea completa sin imprimir una cadena de espacios que
        # podría volver a provocar wrap en terminales estrechos.
        sys.stdout.write("\r\033[2K")
    elif CONSOLE_STATUS_WIDTH > 0:
        clear_width = min(CONSOLE_STATUS_WIDTH, current_width)
        sys.stdout.write("\r" + (" " * clear_width) + "\r")

    sys.stdout.flush()
    CONSOLE_STATUS_WIDTH = 0


def _draw_console_status_unlocked():
    global CONSOLE_STATUS_WIDTH

    if not CONSOLE_STATUS_ACTIVE or sys.stdout is None:
        return

    text = current_console_status()

    # El ancho puede cambiar en cualquier momento al redimensionar la ventana.
    # Limpiamos primero y recalculamos en cada refresco.
    _clear_console_status_unlocked()
    text = text[:console_status_width()]
    CONSOLE_STATUS_WIDTH = len(text)

    sys.stdout.write("\r" + text)
    sys.stdout.flush()


def draw_console_status():
    with CONSOLE_STATUS_LOCK:
        _draw_console_status_unlocked()


def finish_console_status():
    global CONSOLE_STATUS_ACTIVE, CONSOLE_STATUS_WIDTH

    with CONSOLE_STATUS_LOCK:
        _clear_console_status_unlocked()
        CONSOLE_STATUS_ACTIVE = False
        CONSOLE_STATUS_WIDTH = 0


class StatusAwareConsoleHandler(logging.StreamHandler):
    """Escribe logs sin dejar rota la línea dinámica del OTP."""

    def emit(self, record):
        try:
            message = self.format(record)

            with CONSOLE_STATUS_LOCK:
                _clear_console_status_unlocked()
                self.stream.write(message + self.terminator)
                self.flush()
                _draw_console_status_unlocked()
        except Exception:
            self.handleError(record)


def shorten_middle(value: str, max_width: int) -> str:
    """Acorta texto largo conservando el principio y el final."""
    if len(value) <= max_width:
        return value

    if max_width <= 3:
        return value[:max_width]

    available = max_width - 1
    left = (available + 1) // 2
    right = available - left
    return f"{value[:left]}…{value[-right:] if right else ''}"


def supports_console_hyperlinks() -> bool:
    if sys.stdout is None or not sys.stdout.isatty():
        return False
    return os.environ.get("TERM", "").lower() != "dumb"


def console_hyperlink(text: str, target: str | None) -> str:
    """Crea un enlace OSC 8 cuando el terminal lo permite."""
    if not target or not supports_console_hyperlinks():
        return text

    return f"\033]8;;{target}\033\\{text}\033]8;;\033\\"


def print_console_grid(rows):
    """
    Imprime una tabla compacta adaptada al ancho de terminal.

    Cada fila puede ser (label, value) o (label, value, hyperlink_target).
    Tanto la columna de etiquetas como la de valores pueden encogerse.
    """
    normalized = []
    for row in rows:
        if len(row) == 2:
            label, value = row
            target = None
        else:
            label, value, target = row

        normalized.append((str(label), str(value), target))

    if not normalized:
        return

    terminal_width = shutil.get_terminal_size(fallback=(100, 24)).columns

    # Reservamos siempre la última columna. Algunos terminales hacen wrap
    # automático al escribir exactamente en ella.
    safe_width = max(1, terminal_width - 1)
    table_width = min(safe_width, 120)

    # Una tabla de dos columnas necesita 7 caracteres estructurales:
    # │ + espacios interiores + │ + espacios interiores + │.
    # Con anchos absurdamente pequeños degradamos a una sola línea por fila.
    if table_width < 9:
        for label, value, target in normalized:
            combined = f"{label}: {value}"
            visible = shorten_middle(combined, safe_width)
            print(console_hyperlink(visible, target))
        return

    desired_label_width = max(len(label) for label, _, _ in normalized)
    desired_value_width = max(len(value) for _, value, _ in normalized)
    content_budget = table_width - 7

    # Si todo cabe, conservamos el tamaño natural. Si no, repartimos el ancho
    # proporcionalmente: también se encogen etiquetas, URLs e IPs.
    desired_total = desired_label_width + desired_value_width
    if desired_total <= content_budget:
        label_width = desired_label_width
        value_width = desired_value_width
    else:
        label_width = max(
            1,
            round(content_budget * desired_label_width / max(1, desired_total)),
        )
        value_width = max(1, content_budget - label_width)

        # Si una columna ya cabe completa, cedemos el espacio sobrante a la otra.
        if label_width > desired_label_width:
            extra = label_width - desired_label_width
            label_width = desired_label_width
            value_width += extra

        if value_width > desired_value_width:
            extra = value_width - desired_value_width
            value_width = desired_value_width
            label_width += extra

        # Protege el presupuesto tras los reajustes.
        label_width = max(1, min(label_width, content_budget - 1))
        value_width = max(1, content_budget - label_width)

    visible_labels = [
        shorten_middle(label, label_width)
        for label, _, _ in normalized
    ]
    visible_values = [
        shorten_middle(value, value_width)
        for _, value, _ in normalized
    ]

    top = f"┌{'─' * (label_width + 2)}┬{'─' * (value_width + 2)}┐"
    middle = f"├{'─' * (label_width + 2)}┼{'─' * (value_width + 2)}┤"
    bottom = f"└{'─' * (label_width + 2)}┴{'─' * (value_width + 2)}┘"

    print(top)
    for index, ((_, _value, target), label, value) in enumerate(
        zip(normalized, visible_labels, visible_values)
    ):
        linked = console_hyperlink(value, target)
        label_padding = " " * (label_width - len(label))
        value_padding = " " * (value_width - len(value))

        print(
            f"│ {label}{label_padding} │ "
            f"{linked}{value_padding} │"
        )
        if index != len(normalized) - 1:
            print(middle)
    print(bottom)


def configure_request_logging(verbose: bool = False) -> Path:
    global REQUEST_LOG_PATH

    log_dir = script_directory() / "simple_share_logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    REQUEST_LOG_PATH = log_dir / f"simple_share_{datetime.now():%Y-%m-%d}.log"

    REQUEST_LOGGER.handlers.clear()
    REQUEST_LOGGER.setLevel(logging.INFO)
    REQUEST_LOGGER.propagate = False

    formatter = logging.Formatter(
        "%(asctime)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.FileHandler(
        REQUEST_LOG_PATH,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    REQUEST_LOGGER.addHandler(file_handler)

    if verbose and sys.stdout is not None:
        console_handler = StatusAwareConsoleHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        REQUEST_LOGGER.addHandler(console_handler)

    return REQUEST_LOG_PATH


# ============================================================
# Configuración y utilidades de rutas
# ============================================================


def get_default_directory() -> Path:
    if os.name == "nt":
        return Path(r"C:\shared")
    return Path.home() / "shared"


def require_root() -> Path:
    assert ROOT is not None
    return ROOT


def safe_path(relative_path: str) -> Path:
    """Convierte una ruta relativa en una ruta segura dentro de ROOT."""
    root = require_root()
    relative_path = urllib.parse.unquote(relative_path or "").lstrip("/")
    candidate = (root / relative_path).resolve()

    if candidate != root and root not in candidate.parents:
        raise ValueError("Ruta fuera de la carpeta compartida")

    return candidate


def relative_path(path: Path) -> str:
    root = require_root()
    rel = path.relative_to(root)
    return "" if str(rel) == "." else rel.as_posix()


def valid_name(name: str) -> bool:
    if not isinstance(name, str):
        return False

    name = name.strip()

    if not name or name in (".", ".."):
        return False

    if any(ch in name for ch in ("/", "\\", "\x00")):
        return False

    # Windows no admite estos caracteres en nombres de archivo.
    if os.name == "nt" and any(ch in name for ch in '<>:"|?*'):
        return False

    return True


def unique_path(directory: Path, name: str) -> Path:
    """Devuelve una ruta que no colisiona con una existente."""
    target = directory / name

    if not target.exists():
        return target

    original = Path(name)
    stem = original.stem
    suffix = original.suffix
    counter = 1

    while True:
        candidate = directory / f"{stem} ({counter}){suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


def human_size(size: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(size)

    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024

    return f"{size} B"


def current_access_code(offset: int = 0) -> str:
    """Genera un código TOTP local de 6 dígitos para el intervalo actual."""
    counter = int(time.time() // OTP_STEP_SECONDS) + offset
    message = counter.to_bytes(8, "big")
    digest = hmac.new(ACCESS_SECRET, message, hashlib.sha1).digest()

    # Truncado dinámico compatible con la idea de RFC 4226/6238.
    dynamic_offset = digest[-1] & 0x0F
    value = int.from_bytes(
        digest[dynamic_offset:dynamic_offset + 4],
        "big",
    ) & 0x7FFFFFFF

    return f"{value % (10 ** OTP_DIGITS):0{OTP_DIGITS}d}"


def access_code_matches(value: str) -> bool:
    """
    Acepta el intervalo actual y el inmediatamente anterior.
    Así un código no falla si cambia justo mientras se está escribiendo.
    """
    if len(value) != OTP_DIGITS or not value.isdigit():
        return False

    return any(
        hmac.compare_digest(value, current_access_code(offset))
        for offset in (0, -1)
    )


def seconds_until_next_code() -> int:
    remaining = OTP_STEP_SECONDS - int(time.time() % OTP_STEP_SECONDS)
    return max(1, remaining)


def otp_console_loop(stop_event: threading.Event):
    """Mantiene el OTP y su cuenta atrás en una única línea de consola."""
    global CONSOLE_STATUS_ACTIVE

    with CONSOLE_STATUS_LOCK:
        CONSOLE_STATUS_ACTIVE = True
        _draw_console_status_unlocked()

    try:
        while not stop_event.wait(0.25):
            draw_console_status()
    finally:
        finish_console_status()


def svg_icon(name: str, css_class: str = "icon") -> str:
    # Iconos SVG inline: cero dependencias, sin CDN ni fuentes externas.
    paths = {
        "share": '<path d="M8 6h8M8 12h8M8 18h8"/><circle cx="5" cy="6" r="2"/><circle cx="5" cy="12" r="2"/><circle cx="5" cy="18" r="2"/>',
        "folder": '<path d="M3 6.5A1.5 1.5 0 0 1 4.5 5H9l2 2h8.5A1.5 1.5 0 0 1 21 8.5v9A1.5 1.5 0 0 1 19.5 19h-15A1.5 1.5 0 0 1 3 17.5z"/>',
        "file": '<path d="M6 2.5h8l4 4V21H6z"/><path d="M14 2.5V7h4"/>',
        "up": '<path d="M12 18V5"/><path d="m7 10 5-5 5 5"/>',
        "upload": '<path d="M12 16V4"/><path d="m7 9 5-5 5 5"/><path d="M5 20h14"/>',
        "paperclip": '<path d="m9 12.5 5.2-5.2a3 3 0 1 1 4.2 4.2l-7.1 7.1a5 5 0 0 1-7.1-7.1l7.4-7.4"/>',
        "plus-folder": '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="M12 10v6M9 13h6"/>',
        "more": '<circle cx="12" cy="5" r="1.25" fill="currentColor" stroke="none"/><circle cx="12" cy="12" r="1.25" fill="currentColor" stroke="none"/><circle cx="12" cy="19" r="1.25" fill="currentColor" stroke="none"/>',
        "edit": '<path d="m4 20 4.5-1 10-10a2.1 2.1 0 0 0-3-3l-10 10z"/><path d="m14.5 7 3 3"/>',
        "move": '<path d="M4 12h16"/><path d="m15 7 5 5-5 5"/><path d="M9 7 4 12l5 5"/>',
        "copy": '<rect x="8" y="8" width="11" height="12" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h2"/>',
        "trash": '<path d="M4 7h16M9 7V4h6v3M7 7l1 14h8l1-14M10 11v6M14 11v6"/>',
        "check": '<path d="m5 12 4 4L19 6"/>',
        "select-all": '<rect x="4" y="4" width="16" height="16" rx="3"/><path d="m8 12 3 3 5-6"/>',
    }
    body = paths.get(name, paths["file"])
    return (
        f'<svg class="{css_class}" viewBox="0 0 24 24" aria-hidden="true" '
        'fill="none" stroke="currentColor" stroke-width="1.8" '
        'stroke-linecap="round" stroke-linejoin="round">'
        f'{body}</svg>'
    )

def local_ip() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def is_loopback_address(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def is_same_or_child(path: Path, possible_parent: Path) -> bool:
    """True si path es possible_parent o está dentro de él."""
    return path == possible_parent or possible_parent in path.parents


# ============================================================
# Servidor HTTP
# ============================================================


class ShareHandler(BaseHTTPRequestHandler):
    server_version = "SimpleShare/2.13"

    POST_ROUTES = {
        "/api/upload": "handle_upload",
        "/api/mkdir": "handle_mkdir",
        "/api/move": "handle_move",
        "/api/copy": "handle_copy",
        "/api/rename": "handle_rename",
        "/api/delete": "handle_delete",
    }

    def log_message(self, fmt, *args):
        REQUEST_LOGGER.info(
            "[%s] %s",
            self.address_string(),
            fmt % args,
        )

    # --------------------------------------------------------
    # Seguridad / sesión
    # --------------------------------------------------------

    def add_security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'",
        )

    def token_matches(self, value: str | None) -> bool:
        return bool(value) and hmac.compare_digest(value, ACCESS_TOKEN)

    def is_authenticated(self) -> bool:
        # El propio equipo puede acceder por localhost sin OTP.
        if is_loopback_address(self.client_address[0]):
            return True

        raw_cookie = self.headers.get("Cookie", "")
        if not raw_cookie:
            return False

        cookie = SimpleCookie()
        try:
            cookie.load(raw_cookie)
        except Exception:
            return False

        morsel = cookie.get(COOKIE_NAME)
        return morsel is not None and self.token_matches(morsel.value)

    def _auth_client_key(self) -> str:
        return self.client_address[0]

    def _auth_rate_limited(self) -> bool:
        now = time.monotonic()
        key = self._auth_client_key()

        with AUTH_LOCK:
            recent = [
                stamp
                for stamp in AUTH_FAILURES.get(key, [])
                if now - stamp < AUTH_WINDOW_SECONDS
            ]
            AUTH_FAILURES[key] = recent
            return len(recent) >= AUTH_MAX_FAILURES

    def _record_auth_failure(self):
        now = time.monotonic()
        key = self._auth_client_key()

        with AUTH_LOCK:
            recent = [
                stamp
                for stamp in AUTH_FAILURES.get(key, [])
                if now - stamp < AUTH_WINDOW_SECONDS
            ]
            recent.append(now)
            AUTH_FAILURES[key] = recent

    def _clear_auth_failures(self):
        with AUTH_LOCK:
            AUTH_FAILURES.pop(self._auth_client_key(), None)

    def send_login_page(self, error: str = "", status: int = 200):
        error_html = (
            f'<div class="error">{html.escape(error)}</div>'
            if error
            else ""
        )

        body = (
            '<!doctype html><html lang="es"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>Simple Share</title><style>'
            '*{box-sizing:border-box}body{margin:0;background:#111827;color:#e5e7eb;'
            'font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;'
            'display:grid;place-items:center;min-height:100vh;padding:24px}'
            '.card{width:min(100%,420px);background:#1f2937;border:1px solid #374151;'
            'border-radius:16px;padding:24px;box-shadow:0 18px 50px rgba(0,0,0,.25)}'
            'h1{margin:0 0 8px;font-size:1.45rem}p{color:#9ca3af;line-height:1.5;margin:0 0 20px}'
            'form{display:grid;gap:12px}input{width:100%;padding:14px 16px;border-radius:10px;'
            'border:1px solid #4b5563;background:#111827;color:#f9fafb;font:inherit;'
            'font-size:1.3rem;letter-spacing:.35em;text-align:center;outline:none}'
            'input:focus{border-color:#3b82f6}button{padding:13px 16px;border:0;border-radius:10px;'
            'background:#2563eb;color:white;font:inherit;font-weight:700;cursor:pointer}'
            '.error{margin-bottom:14px;padding:10px 12px;border-radius:9px;background:#3f1d24;'
            'color:#fecaca;font-size:.9rem}</style></head><body><main class="card">'
            '<h1>Simple Share</h1>'
            '<p>Introduce el código de 6 dígitos que aparece en la terminal. Cambia cada 30 segundos.</p>'
            f'{error_html}'
            '<form method="post" action="/auth">'
            '<input type="text" name="code" inputmode="numeric" pattern="[0-9]{6}" '
            'maxlength="6" autocomplete="one-time-code" autofocus required aria-label="Código de acceso">'
            '<button type="submit">Entrar</button>'
            '</form></main></body></html>'
        ).encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.add_security_headers()
        self.end_headers()
        self.wfile.write(body)

    def handle_auth(self):
        if self._auth_rate_limited():
            self.send_login_page(
                "Demasiados intentos. Espera un minuto antes de volver a probar.",
                status=429,
            )
            return

        # /auth no depende de Origin: algunos navegadores móviles
        # lo omiten o lo envían de forma distinta en formularios normales.
        # La protección aquí es OTP + rate limiting. Las operaciones de
        # archivos siguen exigiendo validación estricta de Origin.
        raw_length = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_length)
        except ValueError:
            length = 0

        if length <= 0 or length > 1024:
            self.send_login_page("Solicitud de acceso no válida.", status=400)
            return

        try:
            raw = self.rfile.read(length).decode("utf-8")
        except UnicodeDecodeError:
            self.send_login_page("Solicitud de acceso no válida.", status=400)
            return

        params = urllib.parse.parse_qs(raw, keep_blank_values=True)
        supplied = params.get("code", [""])[0].strip()

        if not access_code_matches(supplied):
            self._record_auth_failure()
            self.send_login_page("Código incorrecto.", status=401)
            return

        self._clear_auth_failures()

        self.send_response(303)
        self.send_header("Location", "/")
        self.send_header(
            "Set-Cookie",
            f"{COOKIE_NAME}={ACCESS_TOKEN}; Path=/; HttpOnly; SameSite=Strict",
        )
        self.send_header("Cache-Control", "no-store")
        self.add_security_headers()
        self.end_headers()

    def send_auth_required(self, api: bool = False):
        if api:
            self.api_error(
                401,
                "Sesión no autorizada. Vuelve a abrir Simple Share e introduce el código de acceso.",
            )
            return

        self.send_login_page()

    def valid_origin(self) -> bool:
        origin = self.headers.get("Origin")
        host = self.headers.get("Host")
        if not origin or not host:
            return False
        return hmac.compare_digest(origin.rstrip("/"), f"http://{host}".rstrip("/"))

    # --------------------------------------------------------
    # Routing
    # --------------------------------------------------------

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)

        if parsed.path == "/favicon.ico":
            self.send_response(204)
            self.add_security_headers()
            self.end_headers()
            return

        if not self.is_authenticated():
            self.send_auth_required(api=parsed.path.startswith("/api/"))
            return

        if parsed.path == "/api/directories":
            self.handle_directories()
            return

        try:
            path = safe_path(parsed.path)
        except ValueError:
            self.send_error(403, "Ruta no permitida")
            return

        if not path.exists():
            self.send_error(404, "No encontrado")
            return

        if path.is_dir():
            self.send_directory(path)
        else:
            self.send_file(path)

    def do_POST(self):
        route = urllib.parse.urlsplit(self.path).path

        if route == "/auth":
            self.handle_auth()
            return

        if not self.is_authenticated():
            self.send_auth_required(api=True)
            return

        if not self.valid_origin():
            self.api_error(403, "Origen de la solicitud no permitido")
            return

        method_name = self.POST_ROUTES.get(route)

        if not method_name:
            self.send_error(404)
            return

        getattr(self, method_name)()

    # --------------------------------------------------------
    # Helpers HTTP
    # --------------------------------------------------------

    def read_json(self):
        raw_length = self.headers.get("Content-Length")

        if raw_length is None:
            raise ValueError("Content-Length requerido")

        try:
            length = int(raw_length)
        except ValueError as exc:
            raise ValueError("Content-Length no válido") from exc

        if length < 0 or length > JSON_BODY_LIMIT:
            raise ValueError("Cuerpo JSON demasiado grande")

        raw = self.rfile.read(length)

        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("JSON no válido") from exc

        if not isinstance(data, dict):
            raise ValueError("Se esperaba un objeto JSON")

        return data

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.add_security_headers()
        self.end_headers()
        self.wfile.write(body)

    def api_error(self, status: int, message: str):
        self.send_json({"ok": False, "error": message}, status)

    def get_existing_source(self, value) -> Path | None:
        if not isinstance(value, str):
            self.api_error(400, "Ruta de origen no válida")
            return None

        try:
            source = safe_path(value)
        except ValueError:
            self.api_error(403, "Ruta no permitida")
            return None

        if source == require_root():
            self.api_error(400, "No se puede modificar la carpeta raíz")
            return None

        if not source.exists():
            self.api_error(404, "El origen no existe")
            return None

        return source

    def get_existing_directory(self, value) -> Path | None:
        if not isinstance(value, str):
            self.api_error(400, "Carpeta destino no válida")
            return None

        try:
            directory = safe_path(value)
        except ValueError:
            self.api_error(403, "Ruta no permitida")
            return None

        if not directory.exists() or not directory.is_dir():
            self.api_error(400, "La carpeta destino no existe")
            return None

        return directory

    # --------------------------------------------------------
    # API: directorios
    # --------------------------------------------------------

    def handle_directories(self):
        root = require_root()
        directories = [{"path": "", "label": "/"}]

        try:
            for current, dirnames, _ in os.walk(root, followlinks=False):
                current_path = Path(current)

                # No descendemos por enlaces simbólicos.
                dirnames[:] = [
                    name
                    for name in dirnames
                    if not (current_path / name).is_symlink()
                ]

                for name in dirnames:
                    path = current_path / name
                    rel = relative_path(path)
                    directories.append({"path": rel, "label": f"/{rel}"})

        except OSError as exc:
            self.api_error(500, f"No se pudieron listar las carpetas: {exc}")
            return

        directories.sort(key=lambda item: item["label"].lower())
        self.send_json({"ok": True, "directories": directories})

    # --------------------------------------------------------
    # API: upload
    # --------------------------------------------------------

    def handle_upload(self):
        parsed = urllib.parse.urlsplit(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        directory_name = params.get("dir", [""])[0]
        filename = params.get("name", [""])[0]

        if not valid_name(filename):
            self.api_error(400, "Nombre de archivo no válido")
            return

        directory = self.get_existing_directory(directory_name)
        if directory is None:
            return

        raw_length = self.headers.get("Content-Length")

        if raw_length is None:
            self.api_error(411, "Content-Length requerido")
            return

        try:
            length = int(raw_length)
        except ValueError:
            self.api_error(400, "Content-Length no válido")
            return

        if length < 0:
            self.api_error(400, "Tamaño de archivo no válido")
            return

        if length > MAX_UPLOAD_BYTES:
            self.api_error(
                413,
                f"Archivo demasiado grande. Máximo: {human_size(MAX_UPLOAD_BYTES)}",
            )
            return

        target = unique_path(directory, filename)
        temp = directory / f".upload-{uuid.uuid4().hex}.part"
        remaining = length

        try:
            with open(temp, "wb") as output:
                while remaining > 0:
                    chunk = self.rfile.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ConnectionError(
                            "La conexión terminó antes de completar la subida"
                        )
                    output.write(chunk)
                    remaining -= len(chunk)

            os.replace(temp, target)

        except Exception as exc:
            try:
                temp.unlink(missing_ok=True)
            except Exception:
                pass

            print(f"Error subiendo {filename}: {exc}")
            self.api_error(500, "Error guardando el archivo")
            return

        print(
            f"↑ SUBIDO: {relative_path(target)} "
            f"({human_size(length)})"
        )

        self.send_json(
            {
                "ok": True,
                "name": target.name,
                "path": relative_path(target),
                "size": length,
            }
        )

    # --------------------------------------------------------
    # API: crear carpeta
    # --------------------------------------------------------

    def handle_mkdir(self):
        try:
            data = self.read_json()
        except ValueError as exc:
            self.api_error(400, str(exc))
            return

        directory = self.get_existing_directory(data.get("dir", ""))
        if directory is None:
            return

        name = data.get("name", "")

        if not valid_name(name):
            self.api_error(400, "Nombre de carpeta no válido")
            return

        target = directory / name.strip()

        if target.exists():
            self.api_error(409, "Ya existe un archivo o carpeta con ese nombre")
            return

        try:
            target.mkdir()
        except OSError as exc:
            self.api_error(500, f"No se pudo crear la carpeta: {exc}")
            return

        print(f"+ CARPETA: {relative_path(target)}")
        self.send_json({"ok": True, "path": relative_path(target)})

    # --------------------------------------------------------
    # API: mover
    # --------------------------------------------------------

    def handle_move(self):
        try:
            data = self.read_json()
        except ValueError as exc:
            self.api_error(400, str(exc))
            return

        source = self.get_existing_source(data.get("source"))
        if source is None:
            return

        destination = self.get_existing_directory(data.get("destination", ""))
        if destination is None:
            return

        if source.parent == destination:
            self.api_error(400, "El elemento ya está en esa carpeta")
            return

        if source.is_dir() and is_same_or_child(destination, source):
            self.api_error(400, "No puedes mover una carpeta dentro de sí misma")
            return

        target = unique_path(destination, source.name)

        try:
            moved = Path(shutil.move(str(source), str(target)))
        except OSError as exc:
            self.api_error(500, f"No se pudo mover: {exc}")
            return

        print(f"→ MOVIDO: {relative_path(source)} -> {relative_path(moved)}")
        self.send_json({"ok": True, "path": relative_path(moved)})

    # --------------------------------------------------------
    # API: copiar
    # --------------------------------------------------------

    def handle_copy(self):
        try:
            data = self.read_json()
        except ValueError as exc:
            self.api_error(400, str(exc))
            return

        source = self.get_existing_source(data.get("source"))
        if source is None:
            return

        destination = self.get_existing_directory(data.get("destination", ""))
        if destination is None:
            return

        if source.is_dir() and is_same_or_child(destination, source):
            self.api_error(400, "No puedes copiar una carpeta dentro de sí misma")
            return

        target = unique_path(destination, source.name)

        try:
            if source.is_dir():
                shutil.copytree(source, target)
            else:
                shutil.copy2(source, target)
        except OSError as exc:
            self.api_error(500, f"No se pudo copiar: {exc}")
            return

        print(f"⧉ COPIADO: {relative_path(source)} -> {relative_path(target)}")
        self.send_json({"ok": True, "path": relative_path(target)})

    # --------------------------------------------------------
    # API: renombrar
    # --------------------------------------------------------

    def handle_rename(self):
        try:
            data = self.read_json()
        except ValueError as exc:
            self.api_error(400, str(exc))
            return

        source = self.get_existing_source(data.get("source"))
        if source is None:
            return

        name = data.get("name", "")

        if not valid_name(name):
            self.api_error(400, "Nombre no válido")
            return

        name = name.strip()
        target = source.parent / name

        if target == source:
            self.send_json({"ok": True, "path": relative_path(source)})
            return

        if target.exists():
            self.api_error(409, "Ya existe un archivo o carpeta con ese nombre")
            return

        try:
            renamed = source.rename(target)
        except OSError as exc:
            self.api_error(500, f"No se pudo renombrar: {exc}")
            return

        print(f"✎ RENOMBRADO: {relative_path(source)} -> {relative_path(renamed)}")
        self.send_json({"ok": True, "path": relative_path(renamed)})

    # --------------------------------------------------------
    # API: eliminar
    # --------------------------------------------------------

    def handle_delete(self):
        try:
            data = self.read_json()
        except ValueError as exc:
            self.api_error(400, str(exc))
            return

        source = self.get_existing_source(data.get("source"))
        if source is None:
            return

        old_path = relative_path(source)

        try:
            if source.is_dir():
                shutil.rmtree(source)
            else:
                source.unlink()
        except OSError as exc:
            self.api_error(500, f"No se pudo eliminar: {exc}")
            return

        print(f"× ELIMINADO: {old_path}")
        self.send_json({"ok": True})

    # --------------------------------------------------------
    # Descarga
    # --------------------------------------------------------

    def send_file(self, path: Path):
        try:
            size = path.stat().st_size
            content_type, _ = mimetypes.guess_type(path.name)
            content_type = content_type or "application/octet-stream"
            encoded_filename = urllib.parse.quote(path.name)

            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(size))
            self.send_header(
                "Content-Disposition",
                f"attachment; filename*=UTF-8''{encoded_filename}",
            )
            self.send_header("Cache-Control", "no-store")
            self.add_security_headers()
            self.end_headers()

            with open(path, "rb") as file:
                shutil.copyfileobj(file, self.wfile, length=1024 * 1024)

            print(f"↓ DESCARGADO: {relative_path(path)} ({human_size(size)})")

        except (BrokenPipeError, ConnectionResetError):
            pass
        except OSError as exc:
            print(f"Error enviando {path}: {exc}")

    # --------------------------------------------------------
    # Interfaz web
    # --------------------------------------------------------

    def send_directory(self, directory: Path):
        try:
            rel_dir = relative_path(directory)
            entries = sorted(
                directory.iterdir(),
                key=lambda p: (not p.is_dir(), p.name.lower()),
            )
        except OSError:
            self.send_error(403, "No se puede leer la carpeta")
            return

        rows = []

        if directory != require_root():
            parent = relative_path(directory.parent)
            parent_url = "/" if not parent else "/" + urllib.parse.quote(parent, safe="/") + "/"
            rows.append(
                f"""
                <a class="item parent-row" href="{parent_url}">
                    <span class="item-icon">{svg_icon("up")}</span>
                    <span class="item-main">
                        <span class="item-name">..</span>
                        <span class="item-meta">Subir un nivel</span>
                    </span>
                </a>
                """
            )

        visible = 0

        for entry in entries:
            if entry.is_symlink():
                continue

            if entry.name.startswith(".upload-") and entry.name.endswith(".part"):
                continue

            visible += 1
            rel_entry = relative_path(entry)
            url = "/" + urllib.parse.quote(rel_entry, safe="/")
            display_name = html.escape(entry.name)
            attr_path = html.escape(rel_entry, quote=True)
            attr_name = html.escape(entry.name, quote=True)

            if entry.is_dir():
                main = f"""
                    <a class="item-link" href="{url}/">
                        <span class="item-icon">{svg_icon("folder")}</span>
                        <span class="item-main">
                            <span class="item-name">{display_name}</span>
                            <span class="item-meta">Carpeta</span>
                        </span>
                    </a>
                """
                kind = "folder"
            else:
                try:
                    size = human_size(entry.stat().st_size)
                except OSError:
                    size = "?"

                main = f"""
                    <a class="item-link" href="{url}">
                        <span class="item-icon">{svg_icon("file")}</span>
                        <span class="item-main">
                            <span class="item-name">{display_name}</span>
                            <span class="item-meta">{size}</span>
                        </span>
                    </a>
                """
                kind = "file"

            rows.append(
                f"""
                <div class="item">
                    <label class="check-wrap" title="Seleccionar">
                        <input
                            class="item-check"
                            type="checkbox"
                            data-path="{attr_path}"
                            data-name="{attr_name}"
                            data-kind="{kind}"
                            aria-label="Seleccionar {attr_name}"
                        >
                        <span class="check-ui">{svg_icon("check", "check-icon")}</span>
                    </label>
                    {main}
                    <button
                        class="menu-button"
                        type="button"
                        aria-label="Acciones de {attr_name}"
                        data-path="{attr_path}"
                        data-name="{attr_name}"
                        data-kind="{kind}"
                    >{svg_icon("more", "menu-icon")}</button>
                </div>
                """
            )

        if visible == 0:
            rows.append('<div class="empty">Esta carpeta está vacía</div>')

        current_dir_json = json.dumps(rel_dir)
        display_path = "/" if not rel_dir else "/" + html.escape(rel_dir)

        page = r'''<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Simple Share</title>
<style>
:root { color-scheme: dark; --bg:#111827; --panel:#1f2937; --panel-2:#111827; --border:#374151; --border-strong:#4b5563; --text:#e5e7eb; --muted:#9ca3af; --primary:#2563eb; --primary-hover:#1d4ed8; --danger:#dc2626; --danger-hover:#b91c1c; --selected:rgba(37,99,235,.12); }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text); font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
button,input,select { font:inherit; } button { touch-action:manipulation; }
.icon,.item-icon svg,.button-icon,.menu-icon,.check-icon { width:1.15rem; height:1.15rem; flex:0 0 auto; }
main { width:min(100%,900px); margin:0 auto; padding:18px; }
.brand { display:flex; align-items:center; gap:9px; }.brand svg { width:1.35rem; height:1.35rem; color:#93c5fd; }
h1 { margin:0 0 4px; font-size:1.45rem; }.path { margin-bottom:18px; color:var(--muted); word-break:break-all; }
.toolbar { display:grid; gap:10px; margin-bottom:14px; }.upload-box { padding:10px; border:1px solid var(--border); border-radius:12px; background:var(--panel); }.upload-row { display:grid; grid-template-columns:1fr 1fr; gap:8px; }input[type=file] { display:none; }
.button { min-height:44px; border:0; border-radius:8px; padding:10px 14px; display:inline-flex; align-items:center; justify-content:center; gap:8px; font-weight:650; cursor:pointer; }.button:disabled { opacity:.45; cursor:default; }.button-primary { background:var(--primary); color:white; }.button-primary:hover:not(:disabled) { background:var(--primary-hover); }.button-secondary { background:#374151; color:var(--text); }.button-secondary:hover:not(:disabled) { background:#4b5563; }.button-danger { background:var(--danger); color:white; }.button-danger:hover:not(:disabled) { background:var(--danger-hover); }.button-wide { width:100%; }
.selection,.progress { display:none; margin-top:8px; font-size:.86rem; }.selection.visible,.progress.visible { display:block; }.selection { color:var(--muted); overflow-wrap:anywhere; }.progress { color:#93c5fd; }
.batch-bar { display:none; gap:8px; align-items:center; margin-bottom:10px; padding:10px; border:1px solid #365b92; border-radius:12px; background:rgba(30,64,175,.12); }.batch-bar.visible { display:grid; }.batch-summary { display:flex; align-items:center; justify-content:space-between; gap:10px; color:#bfdbfe; font-size:.9rem; }.batch-actions { display:grid; grid-template-columns:repeat(3,1fr); gap:8px; }.batch-actions .button { min-height:40px; padding:8px 10px; font-size:.9rem; }.batch-clear { border:0; background:transparent; color:#93c5fd; cursor:pointer; padding:4px; }
.list-head { display:flex; justify-content:flex-end; margin-bottom:8px; }.select-all-button { border:0; background:transparent; color:var(--muted); display:inline-flex; align-items:center; gap:7px; padding:5px 4px; cursor:pointer; font-size:.84rem; }.select-all-button:hover { color:var(--text); }
.files { overflow:hidden; border:1px solid var(--border); border-radius:12px; }.item { min-height:62px; display:flex; align-items:stretch; border-bottom:1px solid var(--border); transition:background .12s ease; }.item:last-child { border-bottom:0; }.item:hover { background:var(--panel); }.item.is-selected { background:var(--selected); }.item-link,.parent-row { flex:1; min-width:0; display:flex; align-items:center; gap:12px; padding:11px 12px; color:inherit; text-decoration:none; }.parent-row { border-bottom:1px solid var(--border); }.item-icon { flex:0 0 auto; display:inline-flex; color:#93c5fd; }.item-main { min-width:0; display:flex; flex-direction:column; gap:2px; }.item-name { overflow-wrap:anywhere; font-weight:600; }.item-meta { color:var(--muted); font-size:.8rem; font-weight:400; }
.check-wrap { width:46px; flex:0 0 46px; display:grid; place-items:center; cursor:pointer; border-right:1px solid var(--border); }.item-check { position:absolute; opacity:0; pointer-events:none; }.check-ui { width:20px; height:20px; border:1.5px solid #64748b; border-radius:6px; display:grid; place-items:center; color:transparent; transition:.12s ease; }.check-icon { width:14px; height:14px; }.item-check:checked + .check-ui { border-color:#3b82f6; background:#2563eb; color:white; }.item-check:focus-visible + .check-ui { outline:2px solid #60a5fa; outline-offset:2px; }
.menu-button { width:50px; flex:0 0 50px; border:0; border-left:1px solid var(--border); background:transparent; color:var(--muted); display:grid; place-items:center; cursor:pointer; }.menu-button:hover { background:#374151; color:var(--text); }.menu-icon { width:20px; height:20px; }.empty { padding:28px 18px; text-align:center; color:var(--muted); }
.modal-backdrop { position:fixed; inset:0; z-index:50; display:none; align-items:flex-end; justify-content:center; padding:14px; background:rgba(0,0,0,.58); }.modal-backdrop.visible { display:flex; }.modal { width:min(100%,520px); max-height:min(82vh,680px); overflow:auto; padding:18px; border:1px solid var(--border-strong); border-radius:16px; background:var(--panel); box-shadow:0 20px 60px rgba(0,0,0,.35); }.modal h2 { margin:0 0 6px; font-size:1.1rem; overflow-wrap:anywhere; }.modal-text { margin:0 0 15px; color:var(--muted); font-size:.92rem; overflow-wrap:anywhere; white-space:pre-line; }.modal-body { display:grid; gap:10px; }.modal-actions { display:grid; grid-template-columns:1fr 1fr; gap:8px; margin-top:15px; }.action-list { display:grid; gap:8px; }.field { width:100%; min-width:0; min-height:44px; border:1px solid var(--border-strong); border-radius:8px; padding:10px 12px; outline:none; background:var(--panel-2); color:var(--text); }.field:focus { border-color:#3b82f6; }
.toast { position:fixed; left:50%; bottom:18px; z-index:100; display:none; max-width:calc(100vw - 30px); transform:translateX(-50%); padding:10px 14px; border:1px solid var(--border-strong); border-radius:10px; background:#0f172a; color:var(--text); box-shadow:0 12px 30px rgba(0,0,0,.35); }.toast.visible { display:block; }.toast.error { border-color:#7f1d1d; }
@media (min-width:640px) { .modal-backdrop { align-items:center; }.batch-bar.visible { grid-template-columns:1fr auto; }.batch-actions { grid-template-columns:repeat(3,auto); } }
</style>
</head>
<body>
<main>
<div class="brand">__SHARE_ICON__<h1>Simple Share</h1></div><div class="path">__DISPLAY_PATH__</div>
<div class="toolbar"><div class="upload-box"><div class="upload-row"><label for="files" class="button button-secondary">__PAPERCLIP_ICON__<span>Elegir archivos</span></label><button id="uploadButton" class="button button-primary" type="button" disabled>__UPLOAD_ICON__<span>Subir</span></button></div><input id="files" type="file" multiple><div id="selection" class="selection"></div><div id="progress" class="progress"></div></div><button id="newFolderButton" class="button button-secondary button-wide" type="button">__PLUS_FOLDER_ICON__<span>Nueva carpeta</span></button></div>
<div id="batchBar" class="batch-bar"><div class="batch-summary"><strong id="batchCount">0 seleccionados</strong><button id="clearSelectionButton" class="batch-clear" type="button">Limpiar</button></div><div class="batch-actions"><button id="batchMoveButton" class="button button-secondary" type="button">__MOVE_ICON__<span>Mover</span></button><button id="batchCopyButton" class="button button-secondary" type="button">__COPY_ICON__<span>Copiar</span></button><button id="batchDeleteButton" class="button button-danger" type="button">__TRASH_ICON__<span>Eliminar</span></button></div></div>
<div class="list-head"><button id="selectAllButton" class="select-all-button" type="button">__SELECT_ALL_ICON__<span>Seleccionar todo</span></button></div>
<div class="files">__ROWS__</div>
</main>
<div id="modalBackdrop" class="modal-backdrop" aria-hidden="true"><div class="modal" role="dialog" aria-modal="true"><h2 id="modalTitle"></h2><p id="modalText" class="modal-text"></p><div id="modalBody" class="modal-body"></div><div id="modalActions" class="modal-actions"></div></div></div><div id="toast" class="toast"></div>
<script>
const currentDir=__CURRENT_DIR__;let selectedItem=null;let toastTimer=null;const selectedItems=new Map();
const ICONS={edit:'<svg class="button-icon" viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m4 20 4.5-1 10-10a2.1 2.1 0 0 0-3-3l-10 10z"/><path d="m14.5 7 3 3"/></svg>',move:'<svg class="button-icon" viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 12h16"/><path d="m15 7 5 5-5 5"/><path d="M9 7 4 12l5 5"/></svg>',copy:'<svg class="button-icon" viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="8" y="8" width="11" height="12" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h2"/></svg>',trash:'<svg class="button-icon" viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16M9 7V4h6v3M7 7l1 14h8l1-14M10 11v6M14 11v6"/></svg>'};
const fileInput=document.getElementById("files"),uploadButton=document.getElementById("uploadButton"),selection=document.getElementById("selection"),progress=document.getElementById("progress"),newFolderButton=document.getElementById("newFolderButton"),batchBar=document.getElementById("batchBar"),batchCount=document.getElementById("batchCount"),selectAllButton=document.getElementById("selectAllButton"),clearSelectionButton=document.getElementById("clearSelectionButton"),batchMoveButton=document.getElementById("batchMoveButton"),batchCopyButton=document.getElementById("batchCopyButton"),batchDeleteButton=document.getElementById("batchDeleteButton"),modalBackdrop=document.getElementById("modalBackdrop"),modalTitle=document.getElementById("modalTitle"),modalText=document.getElementById("modalText"),modalBody=document.getElementById("modalBody"),modalActions=document.getElementById("modalActions"),toast=document.getElementById("toast");
function showToast(message,isError=false){clearTimeout(toastTimer);toast.textContent=message;toast.className="toast visible"+(isError?" error":"");toastTimer=setTimeout(()=>{toast.className="toast";},2600);}async function api(url,options={}){const response=await fetch(url,options);let data=null;try{data=await response.json();}catch{data={};}if(!response.ok)throw new Error(data.error||`HTTP ${response.status}`);return data;}function postJson(url,data){return api(url,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(data)});}function button(label,className,onClick,iconName=null){const el=document.createElement("button");el.type="button";el.className=`button ${className}`;if(iconName&&ICONS[iconName])el.insertAdjacentHTML("beforeend",ICONS[iconName]);const text=document.createElement("span");text.textContent=label;el.appendChild(text);el.addEventListener("click",onClick);return el;}function field(value="",placeholder=""){const el=document.createElement("input");el.className="field";el.type="text";el.value=value;el.placeholder=placeholder;el.autocomplete="off";return el;}function openModal(title,text=""){modalTitle.textContent=title;modalText.textContent=text;modalBody.replaceChildren();modalActions.replaceChildren();modalBackdrop.classList.add("visible");modalBackdrop.setAttribute("aria-hidden","false");}function closeModal(){modalBackdrop.classList.remove("visible");modalBackdrop.setAttribute("aria-hidden","true");modalBody.replaceChildren();modalActions.replaceChildren();}function addCancelButton(){modalActions.appendChild(button("Cancelar","button-secondary",closeModal));}
modalBackdrop.addEventListener("click",e=>{if(e.target===modalBackdrop)closeModal();});document.addEventListener("keydown",e=>{if(e.key==="Escape"&&modalBackdrop.classList.contains("visible"))closeModal();});
fileInput.addEventListener("change",()=>{const files=[...fileInput.files];if(!files.length){selection.classList.remove("visible");selection.textContent="";uploadButton.disabled=true;return;}uploadButton.disabled=false;selection.classList.add("visible");selection.textContent=files.length===1?files[0].name:`${files.length} archivos seleccionados`;});uploadButton.addEventListener("click",async()=>{const files=[...fileInput.files];if(!files.length)return;uploadButton.disabled=true;progress.classList.add("visible");try{for(let i=0;i<files.length;i++){const file=files[i];progress.textContent=`Subiendo ${i+1}/${files.length} · ${file.name}`;const url="/api/upload?dir="+encodeURIComponent(currentDir)+"&name="+encodeURIComponent(file.name);await api(url,{method:"POST",headers:{"Content-Type":"application/octet-stream"},body:file});}progress.textContent=`${files.length} archivo(s) subido(s)`;setTimeout(()=>location.reload(),350);}catch(error){progress.textContent="Error: "+error.message;uploadButton.disabled=false;}});
newFolderButton.addEventListener("click",()=>{openModal("Nueva carpeta",`Se creará dentro de ${currentDir?"/"+currentDir:"/"}`);const input=field("","Nombre de la carpeta");modalBody.appendChild(input);addCancelButton();const create=button("Crear","button-primary",async()=>{const name=input.value.trim();if(!name){input.focus();return;}create.disabled=true;try{await postJson("/api/mkdir",{dir:currentDir,name});location.reload();}catch(error){showToast(error.message,true);create.disabled=false;input.focus();}});modalActions.appendChild(create);input.addEventListener("keydown",e=>{if(e.key==="Enter")create.click();});setTimeout(()=>input.focus(),0);});
function itemFromCheckbox(check){return{path:check.dataset.path,name:check.dataset.name,kind:check.dataset.kind};}function setChecked(check,checked){check.checked=checked;const item=itemFromCheckbox(check);if(checked)selectedItems.set(item.path,item);else selectedItems.delete(item.path);}function syncSelectionUI(){document.querySelectorAll(".item-check").forEach(check=>check.closest(".item").classList.toggle("is-selected",check.checked));const count=selectedItems.size;batchCount.textContent=count===1?"1 seleccionado":`${count} seleccionados`;batchBar.classList.toggle("visible",count>0);const checks=[...document.querySelectorAll(".item-check")];const allSelected=checks.length>0&&checks.every(check=>check.checked);selectAllButton.querySelector("span").textContent=allSelected?"Deseleccionar todo":"Seleccionar todo";}document.querySelectorAll(".item-check").forEach(check=>check.addEventListener("change",()=>{setChecked(check,check.checked);syncSelectionUI();}));selectAllButton.addEventListener("click",()=>{const checks=[...document.querySelectorAll(".item-check")];const shouldSelect=checks.length>0&&!checks.every(check=>check.checked);checks.forEach(check=>setChecked(check,shouldSelect));syncSelectionUI();});clearSelectionButton.addEventListener("click",()=>{document.querySelectorAll(".item-check").forEach(check=>setChecked(check,false));syncSelectionUI();});function selectedArray(){return[...selectedItems.values()];}
batchMoveButton.addEventListener("click",()=>openBatchDestination("move"));batchCopyButton.addEventListener("click",()=>openBatchDestination("copy"));batchDeleteButton.addEventListener("click",openBatchDelete);
async function openBatchDestination(operation){const items=selectedArray();if(!items.length)return;const title=operation==="move"?"Mover seleccionados":"Copiar seleccionados";openModal(title,`${items.length} elemento(s)`);const select=document.createElement("select");select.className="field";modalBody.appendChild(select);const loading=document.createElement("div");loading.className="modal-text";loading.textContent="Cargando carpetas…";modalBody.appendChild(loading);addCancelButton();const confirm=button(operation==="move"?"Mover":"Copiar","button-primary",async()=>{confirm.disabled=true;let completed=0,skipped=0;try{for(const item of items){const parent=item.path.includes("/")?item.path.slice(0,item.path.lastIndexOf("/")):"";if(operation==="move"&&parent===select.value){skipped++;continue;}await postJson(`/api/${operation}`,{source:item.path,destination:select.value});completed++;}if(completed===0&&skipped>0){showToast("Los elementos ya estaban en esa carpeta");closeModal();return;}location.reload();}catch(error){showToast(`${completed} completados. ${error.message}`,true);confirm.disabled=false;}},operation);confirm.disabled=true;modalActions.appendChild(confirm);try{const data=await api("/api/directories");select.replaceChildren();let count=0;for(const directory of data.directories){let forbidden=false;for(const item of items){if(item.kind!=="folder")continue;if(directory.path===item.path||directory.path.startsWith(item.path+"/")){forbidden=true;break;}}if(forbidden)continue;const option=document.createElement("option");option.value=directory.path;option.textContent=directory.label;if(directory.path===currentDir)option.selected=true;select.appendChild(option);count++;}loading.remove();if(!count){const message=document.createElement("div");message.className="modal-text";message.textContent="No hay carpetas destino disponibles.";modalBody.appendChild(message);select.remove();return;}confirm.disabled=false;}catch(error){loading.textContent="Error: "+error.message;showToast(error.message,true);}}
function openBatchDelete(){const items=selectedArray();if(!items.length)return;const folders=items.filter(i=>i.kind==="folder").length;const detail=folders?`${items.length} elemento(s) seleccionados. ${folders} carpeta(s) se eliminarán junto con todo su contenido.`:`${items.length} archivo(s) se eliminarán permanentemente.`;openModal("Eliminar seleccionados",detail);addCancelButton();const remove=button("Eliminar","button-danger",async()=>{remove.disabled=true;let completed=0;try{for(const item of items){await postJson("/api/delete",{source:item.path});completed++;}location.reload();}catch(error){showToast(`${completed} eliminados. ${error.message}`,true);remove.disabled=false;}},"trash");modalActions.appendChild(remove);}
document.querySelectorAll(".menu-button").forEach(el=>el.addEventListener("click",()=>{selectedItem={path:el.dataset.path,name:el.dataset.name,kind:el.dataset.kind};openItemMenu();}));function openItemMenu(){if(!selectedItem)return;openModal(selectedItem.name,selectedItem.kind==="folder"?"Carpeta":"Archivo");const list=document.createElement("div");list.className="action-list";list.appendChild(button("Renombrar","button-secondary",openRename,"edit"));list.appendChild(button("Mover","button-secondary",()=>openDestination("move"),"move"));list.appendChild(button("Copiar","button-secondary",()=>openDestination("copy"),"copy"));list.appendChild(button("Eliminar","button-danger",openDelete,"trash"));modalBody.appendChild(list);modalActions.appendChild(button("Cerrar","button-secondary",closeModal));}
function openRename(){openModal("Renombrar",selectedItem.path);const input=field(selectedItem.name,"Nuevo nombre");modalBody.appendChild(input);addCancelButton();const save=button("Guardar","button-primary",async()=>{const name=input.value.trim();if(!name){input.focus();return;}save.disabled=true;try{await postJson("/api/rename",{source:selectedItem.path,name});location.reload();}catch(error){showToast(error.message,true);save.disabled=false;input.focus();}});modalActions.appendChild(save);input.select();input.addEventListener("keydown",e=>{if(e.key==="Enter")save.click();});}
async function openDestination(operation){const title=operation==="move"?"Mover":"Copiar";openModal(title,selectedItem.path);const select=document.createElement("select");select.className="field";modalBody.appendChild(select);const loading=document.createElement("div");loading.className="modal-text";loading.textContent="Cargando carpetas…";modalBody.appendChild(loading);addCancelButton();const confirm=button(title,"button-primary",async()=>{confirm.disabled=true;try{await postJson(`/api/${operation}`,{source:selectedItem.path,destination:select.value});location.reload();}catch(error){showToast(error.message,true);confirm.disabled=false;}},operation);confirm.disabled=true;modalActions.appendChild(confirm);try{const data=await api("/api/directories");select.replaceChildren();const sourcePrefix=selectedItem.path+"/";const sourceParent=selectedItem.path.includes("/")?selectedItem.path.slice(0,selectedItem.path.lastIndexOf("/")):"";let count=0;for(const directory of data.directories){if(selectedItem.kind==="folder"&&(directory.path===selectedItem.path||directory.path.startsWith(sourcePrefix)))continue;if(operation==="move"&&directory.path===sourceParent)continue;const option=document.createElement("option");option.value=directory.path;option.textContent=directory.label;if(directory.path===currentDir)option.selected=true;select.appendChild(option);count++;}loading.remove();if(!count){const message=document.createElement("div");message.className="modal-text";message.textContent="No hay carpetas destino disponibles.";modalBody.appendChild(message);select.remove();return;}confirm.disabled=false;}catch(error){loading.textContent="Error: "+error.message;showToast(error.message,true);}}
function openDelete(){const what=selectedItem.kind==="folder"?"La carpeta y todo su contenido se eliminarán permanentemente.":"El archivo se eliminará permanentemente.";openModal("Eliminar",`${selectedItem.name}\n${what}`);addCancelButton();const remove=button("Eliminar","button-danger",async()=>{remove.disabled=true;try{await postJson("/api/delete",{source:selectedItem.path});location.reload();}catch(error){showToast(error.message,true);remove.disabled=false;}},"trash");modalActions.appendChild(remove);}syncSelectionUI();
</script>
</body>
</html>
'''
        replacements = {
            "__CURRENT_DIR__": current_dir_json,
            "__DISPLAY_PATH__": display_path,
            "__ROWS__": "".join(rows),
            "__SHARE_ICON__": svg_icon("share"),
            "__PAPERCLIP_ICON__": svg_icon("paperclip", "button-icon"),
            "__UPLOAD_ICON__": svg_icon("upload", "button-icon"),
            "__PLUS_FOLDER_ICON__": svg_icon("plus-folder", "button-icon"),
            "__MOVE_ICON__": svg_icon("move", "button-icon"),
            "__COPY_ICON__": svg_icon("copy", "button-icon"),
            "__TRASH_ICON__": svg_icon("trash", "button-icon"),
            "__SELECT_ALL_ICON__": svg_icon("select-all", "button-icon"),
        }
        for token, value in replacements.items():
            page = page.replace(token, value)

        body = page.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.add_security_headers()
        self.end_headers()
        self.wfile.write(body)

class ShareServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# ============================================================
# Arranque CLI / GUI
# ============================================================


def configure_runtime(args):
    global ROOT, MAX_UPLOAD_BYTES

    ROOT = (
        Path(args.directory).expanduser().resolve()
        if args.directory
        else get_default_directory().expanduser().resolve()
    )

    try:
        ROOT.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise RuntimeError(f"No se pudo crear la carpeta {ROOT}: {exc}") from exc

    if not ROOT.is_dir():
        raise RuntimeError(f"No es una carpeta: {ROOT}")

    if args.max_upload_mb <= 0:
        raise RuntimeError("--max-upload-mb debe ser mayor que 0")

    MAX_UPLOAD_BYTES = args.max_upload_mb * 1024 * 1024


def reset_auth():
    global ACCESS_TOKEN, ACCESS_SECRET

    ACCESS_TOKEN = secrets.token_urlsafe(32)
    ACCESS_SECRET = secrets.token_bytes(32)

    with AUTH_LOCK:
        AUTH_FAILURES.clear()


def display_host(bind: str) -> str:
    if bind in ("0.0.0.0", "::"):
        return local_ip()
    return bind


def create_server(args) -> ShareServer:
    reset_auth()

    try:
        return ShareServer((args.bind, args.port), ShareHandler)
    except OSError as exc:
        raise RuntimeError(f"No se pudo iniciar el servidor: {exc}") from exc


def open_shared_folder():
    folder = str(require_root())

    if os.name == "nt":
        os.startfile(folder)
        return

    command = ["open", folder] if sys.platform == "darwin" else ["xdg-open", folder]
    subprocess.Popen(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def run_cli(args):
    configure_runtime(args)
    server = create_server(args)
    host = display_host(args.bind)

    print()
    print("Simple Share 2.13")
    print("================")
    print_console_grid(
        [
            ("Carpeta", ROOT, ROOT.as_uri()),
            ("Puerto", args.port),
            ("Localhost", f"http://127.0.0.1:{args.port}/"),
            ("Red local", f"http://{host}:{args.port}/"),
            (
                "Registro",
                REQUEST_LOG_PATH or "No disponible",
                REQUEST_LOG_PATH.parent.as_uri()
                if REQUEST_LOG_PATH is not None
                else None,
            ),
        ]
    )
    print()
    print("Localhost entra directamente; el OTP solo protege el acceso desde la red local.")
    print("El código cambia cada 30 s; una sesión LAN iniciada permanece activa.")
    print("Las peticiones se guardan en el registro; usa --verbose para verlas también aquí.")
    print("Ctrl+C para detener.")
    print()

    otp_stop = threading.Event()
    otp_thread = threading.Thread(
        target=otp_console_loop,
        args=(otp_stop,),
        daemon=True,
    )
    otp_thread.start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        otp_stop.set()
        otp_thread.join(timeout=1)
        server.server_close()

    print("Servidor detenido.")


def run_web_gui(args):
    """Panel de control local en el navegador, sin dependencias externas."""
    try:
        configure_runtime(args)
    except RuntimeError as exc:
        print(exc)
        return 1

    control_token = secrets.token_urlsafe(32)
    share_url = f"http://{display_host(args.bind)}:{args.port}/"
    state_lock = threading.Lock()
    state = {"server": None, "thread": None}

    def running():
        with state_lock:
            return state["server"] is not None

    def start_share():
        with state_lock:
            if state["server"] is not None:
                return True, None

            try:
                server = create_server(args)
            except RuntimeError as exc:
                return False, str(exc)

            thread = threading.Thread(
                target=server.serve_forever,
                daemon=True,
                name="simple-share-http",
            )
            state["server"] = server
            state["thread"] = thread
            thread.start()
            return True, None

    def stop_share():
        with state_lock:
            server = state["server"]
            state["server"] = None
            state["thread"] = None

        if server is None:
            return

        try:
            server.shutdown()
        finally:
            server.server_close()

    class ControlHandler(BaseHTTPRequestHandler):
        server_version = "SimpleShareControl/1.0"

        def log_message(self, fmt, *args_):
            return

        def add_headers(self):
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'unsafe-inline'; "
                "style-src 'unsafe-inline'; connect-src 'self'; "
                "img-src 'self' data:; object-src 'none'; "
                "base-uri 'none'; frame-ancestors 'none'",
            )

        def authorized(self):
            supplied = self.headers.get("X-Simple-Share-Control", "")
            return hmac.compare_digest(supplied, control_token)

        def send_json(self, data, status=200):
            body = json.dumps(data, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.add_headers()
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = urllib.parse.urlsplit(self.path).path

            if path == "/favicon.ico":
                self.send_response(204)
                self.add_headers()
                self.end_headers()
                return

            if path == "/api/status":
                if not self.authorized():
                    self.send_json({"ok": False, "error": "No autorizado"}, 403)
                    return

                is_running = running()
                code = current_access_code() if is_running else ""
                self.send_json(
                    {
                        "ok": True,
                        "running": is_running,
                        "url": share_url,
                        "folder": str(require_root()),
                        "code": code,
                        "remaining": seconds_until_next_code() if is_running else 0,
                    }
                )
                return

            if path != "/":
                self.send_error(404)
                return

            page = r'''<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Simple Share · Control</title>
<style>
*{box-sizing:border-box}
:root{color-scheme:dark}
body{margin:0;min-height:100vh;background:#111827;color:#e5e7eb;
font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
display:grid;place-items:center;padding:24px}
.shell{width:min(100%,560px)}
header{display:flex;align-items:center;justify-content:space-between;margin-bottom:20px}
h1{font-size:1.6rem;margin:0}
.status{display:flex;align-items:center;gap:8px;font-size:.92rem;font-weight:700}
.dot{width:10px;height:10px;border-radius:999px;background:#6b7280}
.dot.active{background:#22c55e;box-shadow:0 0 0 4px rgba(34,197,94,.12)}
.card{background:#1f2937;border:1px solid #374151;border-radius:16px;padding:24px;
box-shadow:0 18px 50px rgba(0,0,0,.22)}
.otp{text-align:center;padding:8px 0 22px}
.eyebrow,.label{color:#9ca3af;font-size:.82rem}
.code{font:700 2.25rem ui-monospace,SFMono-Regular,Consolas,monospace;
letter-spacing:.13em;margin:6px 0}
.countdown{color:#9ca3af;font-size:.86rem}
.info{display:grid;gap:14px;margin-bottom:20px}
.value{margin-top:4px;font:500 .93rem ui-monospace,SFMono-Regular,Consolas,monospace;
overflow-wrap:anywhere}
.actions{display:grid;grid-template-columns:1fr 1fr;gap:10px}
button{appearance:none;border:0;border-radius:10px;padding:13px 15px;
font:700 .95rem system-ui;cursor:pointer;background:#374151;color:#fff}
button:hover:not(:disabled){background:#4b5563}
button.primary{background:#2563eb}
button.primary:hover:not(:disabled){background:#1d4ed8}
button:disabled{opacity:.42;cursor:not-allowed}
.message{min-height:22px;margin-top:14px;color:#9ca3af;font-size:.86rem;text-align:center}
.message.error{color:#fca5a5}
@media(max-width:480px){.actions{grid-template-columns:1fr}.card{padding:20px}.code{font-size:1.9rem}}
</style>
</head>
<body>
<main class="shell">
<header>
<h1>Simple Share</h1>
<div class="status"><span id="dot" class="dot"></span><span id="status">Detenido</span></div>
</header>
<section class="card">
<div class="otp">
<div class="eyebrow">Código de acceso</div>
<div id="code" class="code">--- ---</div>
<div id="countdown" class="countdown">Servidor detenido</div>
</div>
<div class="info">
<div><div class="label">URL local</div><div id="url" class="value">—</div></div>
<div><div class="label">Carpeta compartida</div><div id="folder" class="value">—</div></div>
</div>
<div class="actions">
<button id="start" class="primary">Iniciar</button>
<button id="stop">Detener</button>
<button id="folderButton">Abrir carpeta</button>
<button id="browserButton">Abrir navegador</button>
</div>
<div id="message" class="message"></div>
</section>
</main>
<script>
const TOKEN="__CONTROL_TOKEN__";
const headers={"X-Simple-Share-Control":TOKEN};
let currentUrl="";
const get=id=>document.getElementById(id);

async function status(){
  try{
    const response=await fetch("/api/status",{headers:headers,cache:"no-store"});
    const data=await response.json();
    if(!response.ok)throw new Error(data.error||"Error");
    currentUrl=data.url;
    get("url").textContent=data.url;
    get("folder").textContent=data.folder;
    get("status").textContent=data.running?"Activo":"Detenido";
    get("dot").classList.toggle("active",data.running);
    get("start").disabled=data.running;
    get("stop").disabled=!data.running;
    get("browserButton").disabled=!data.running;

    if(data.running){
      get("code").textContent=data.code.slice(0,3)+" "+data.code.slice(3);
      get("countdown").textContent="Cambia en "+data.remaining+" s · la sesión iniciada permanece activa";
    }else{
      get("code").textContent="--- ---";
      get("countdown").textContent="Servidor detenido";
    }
  }catch(error){
    show(error.message,true);
  }
}

function show(text,error){
  get("message").textContent=text||"";
  get("message").className="message"+(error?" error":"");
}

async function action(path){
  show("",false);
  const response=await fetch(path,{method:"POST",headers:headers});
  const data=await response.json();
  if(!response.ok)throw new Error(data.error||"Error");
  await status();
  return data;
}

get("start").addEventListener("click",async()=>{
  try{await action("/api/start");}catch(error){show(error.message,true);}
});
get("stop").addEventListener("click",async()=>{
  try{await action("/api/stop");}catch(error){show(error.message,true);}
});
get("folderButton").addEventListener("click",async()=>{
  try{
    const data=await action("/api/open-folder");
    show(data.message||"Carpeta abierta",false);
  }catch(error){show(error.message,true);}
});
get("browserButton").addEventListener("click",()=>{
  if(currentUrl)window.open(currentUrl,"_blank","noopener");
});

status();
setInterval(status,500);
</script>
</body>
</html>'''.replace("__CONTROL_TOKEN__", control_token)

            body = page.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.add_headers()
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if not self.authorized():
                self.send_json({"ok": False, "error": "No autorizado"}, 403)
                return

            path = urllib.parse.urlsplit(self.path).path

            if path == "/api/start":
                ok, error = start_share()
                if not ok:
                    self.send_json({"ok": False, "error": error}, 500)
                    return
                self.send_json({"ok": True})
                return

            if path == "/api/stop":
                threading.Thread(
                    target=stop_share,
                    daemon=True,
                    name="simple-share-stop",
                ).start()
                self.send_json({"ok": True})
                return

            if path == "/api/open-folder":
                try:
                    open_shared_folder()
                except Exception as exc:
                    self.send_json({"ok": False, "error": str(exc)}, 500)
                    return
                self.send_json({"ok": True, "message": "Carpeta abierta"})
                return

            self.send_error(404)

    try:
        control_server = ThreadingHTTPServer(("127.0.0.1", 0), ControlHandler)
    except OSError as exc:
        print(f"No se pudo iniciar el panel de control: {exc}")
        return 1

    control_port = control_server.server_address[1]
    control_url = f"http://127.0.0.1:{control_port}/"

    print()
    print("Simple Share 2.13 · Panel web")
    print("============================")
    print(f"Panel local:  {control_url}")
    print(f"Carpeta:      {ROOT}")
    print(f"Servidor LAN: {share_url}")
    print("El panel solo escucha en 127.0.0.1.")
    print("Ctrl+C para cerrar el panel.")
    print()

    webbrowser.open(control_url)

    try:
        control_server.serve_forever()
    except KeyboardInterrupt:
        print("\nPanel cerrado.")
    finally:
        stop_share()
        control_server.server_close()

    return 0


def run_gui(args):
    try:
        import tkinter as tk
        from tkinter import messagebox
    except ImportError:
        print("Tkinter no está disponible; abriendo el panel web local.")
        return run_web_gui(args)

    try:
        configure_runtime(args)
    except RuntimeError as exc:
        try:
            temp = tk.Tk()
            temp.withdraw()
            messagebox.showerror("Simple Share", str(exc))
            temp.destroy()
        except Exception:
            print(exc)
        return 1

    class SimpleShareGUI:
        BG = "#111827"
        PANEL = "#1f2937"
        BORDER = "#374151"
        TEXT = "#e5e7eb"
        MUTED = "#9ca3af"
        PRIMARY = "#2563eb"
        PRIMARY_HOVER = "#1d4ed8"
        SECONDARY = "#374151"
        SECONDARY_HOVER = "#4b5563"
        SUCCESS = "#22c55e"
        STOPPED = "#6b7280"

        def __init__(self):
            self.server = None
            self.server_thread = None
            self.url = f"http://{display_host(args.bind)}:{args.port}/"

            self.root = tk.Tk()
            self.root.title("Simple Share")
            self.root.configure(bg=self.BG)
            self.root.protocol("WM_DELETE_WINDOW", self.on_close)

            self.status_text = tk.StringVar(value="Detenido")
            self.url_text = tk.StringVar(value=self.url)
            self.folder_text = tk.StringVar(value=str(require_root()))
            self.otp_text = tk.StringVar(value="--- ---")
            self.countdown_text = tk.StringVar(value="Servidor detenido")

            self.build()
            self.fit_window_to_content()
            self.refresh_dynamic()

        def fit_window_to_content(self):
            """Ajusta la ventana al tamaño real de la interfaz y la centra."""
            self.root.update_idletasks()

            width = self.root.winfo_reqwidth()
            height = self.root.winfo_reqheight()

            screen_width = self.root.winfo_screenwidth()
            screen_height = self.root.winfo_screenheight()

            x = max(0, (screen_width - width) // 2)
            y = max(0, (screen_height - height) // 2)

            self.root.geometry(f"{width}x{height}+{x}+{y}")
            self.root.resizable(False, False)

        def make_button(self, parent, text, command, primary=False):
            normal = self.PRIMARY if primary else self.SECONDARY
            hover = self.PRIMARY_HOVER if primary else self.SECONDARY_HOVER

            button = tk.Button(
                parent,
                text=text,
                command=command,
                bg=normal,
                fg="white",
                activebackground=hover,
                activeforeground="white",
                disabledforeground="#6b7280",
                relief="flat",
                bd=0,
                padx=16,
                pady=12,
                font=("Segoe UI", 10, "bold"),
                cursor="hand2",
            )

            button.bind("<Enter>", lambda _e: button.config(bg=hover) if button["state"] == "normal" else None)
            button.bind("<Leave>", lambda _e: button.config(bg=normal) if button["state"] == "normal" else None)
            return button

        def make_readonly_entry(self, parent, variable):
            entry = tk.Entry(
                parent,
                textvariable=variable,
                state="readonly",
                readonlybackground=self.BG,
                fg=self.TEXT,
                relief="flat",
                bd=0,
                font=("Consolas", 10),
            )
            return entry

        def build(self):
            outer = tk.Frame(self.root, bg=self.BG, padx=24, pady=22)
            outer.pack(fill="both", expand=True)

            header = tk.Frame(outer, bg=self.BG)
            header.pack(fill="x")

            tk.Label(
                header,
                text="Simple Share",
                bg=self.BG,
                fg=self.TEXT,
                font=("Segoe UI", 20, "bold"),
            ).pack(side="left")

            status_wrap = tk.Frame(header, bg=self.BG)
            status_wrap.pack(side="right", pady=5)

            self.status_dot = tk.Canvas(
                status_wrap,
                width=14,
                height=14,
                bg=self.BG,
                highlightthickness=0,
            )
            self.status_dot.pack(side="left", padx=(0, 7))
            self.status_circle = self.status_dot.create_oval(
                2, 2, 12, 12,
                fill=self.STOPPED,
                outline="",
            )

            tk.Label(
                status_wrap,
                textvariable=self.status_text,
                bg=self.BG,
                fg=self.TEXT,
                font=("Segoe UI", 10, "bold"),
            ).pack(side="left")

            card = tk.Frame(
                outer,
                bg=self.PANEL,
                highlightbackground=self.BORDER,
                highlightthickness=1,
                padx=20,
                pady=18,
            )
            card.pack(fill="x", pady=(22, 16))

            tk.Label(
                card,
                text="Código de acceso",
                bg=self.PANEL,
                fg=self.MUTED,
                font=("Segoe UI", 9),
            ).pack()

            tk.Label(
                card,
                textvariable=self.otp_text,
                bg=self.PANEL,
                fg=self.TEXT,
                font=("Consolas", 28, "bold"),
            ).pack(pady=(4, 2))

            tk.Label(
                card,
                textvariable=self.countdown_text,
                bg=self.PANEL,
                fg=self.MUTED,
                font=("Segoe UI", 9),
            ).pack()

            info = tk.Frame(outer, bg=self.BG)
            info.pack(fill="x", pady=(0, 18))

            tk.Label(
                info,
                text="URL local",
                bg=self.BG,
                fg=self.MUTED,
                anchor="w",
                font=("Segoe UI", 9),
            ).pack(fill="x")
            self.make_readonly_entry(info, self.url_text).pack(fill="x", pady=(2, 10))

            tk.Label(
                info,
                text="Carpeta compartida",
                bg=self.BG,
                fg=self.MUTED,
                anchor="w",
                font=("Segoe UI", 9),
            ).pack(fill="x")
            self.make_readonly_entry(info, self.folder_text).pack(fill="x", pady=(2, 0))

            buttons = tk.Frame(outer, bg=self.BG)
            buttons.pack(fill="x")
            buttons.columnconfigure(0, weight=1)
            buttons.columnconfigure(1, weight=1)

            self.start_button = self.make_button(
                buttons,
                "Iniciar",
                self.start_server,
                primary=True,
            )
            self.start_button.grid(row=0, column=0, sticky="ew", padx=(0, 6), pady=(0, 8))

            self.stop_button = self.make_button(
                buttons,
                "Detener",
                self.stop_server,
            )
            self.stop_button.grid(row=0, column=1, sticky="ew", padx=(6, 0), pady=(0, 8))

            self.folder_button = self.make_button(
                buttons,
                "Abrir carpeta",
                self.open_folder,
            )
            self.folder_button.grid(row=1, column=0, sticky="ew", padx=(0, 6))

            self.browser_button = self.make_button(
                buttons,
                "Abrir navegador",
                self.open_browser,
            )
            self.browser_button.grid(row=1, column=1, sticky="ew", padx=(6, 0))

            self.apply_state()

        @property
        def running(self):
            return self.server is not None

        def apply_state(self):
            running = self.running

            self.status_text.set("Activo" if running else "Detenido")
            self.status_dot.itemconfigure(
                self.status_circle,
                fill=self.SUCCESS if running else self.STOPPED,
            )

            self.start_button.config(state="disabled" if running else "normal")
            self.stop_button.config(state="normal" if running else "disabled")
            self.browser_button.config(state="normal" if running else "disabled")

        def start_server(self):
            if self.running:
                return

            try:
                server = create_server(args)
            except RuntimeError as exc:
                messagebox.showerror("Simple Share", str(exc), parent=self.root)
                return

            self.server = server
            self.server_thread = threading.Thread(
                target=server.serve_forever,
                daemon=True,
                name="simple-share-http",
            )
            self.server_thread.start()
            self.apply_state()
            self.refresh_dynamic()

        def stop_server(self):
            if not self.running:
                return

            server = self.server
            self.server = None
            self.server_thread = None
            self.apply_state()
            self.otp_text.set("--- ---")
            self.countdown_text.set("Servidor detenido")

            def shutdown():
                server.shutdown()
                server.server_close()

            threading.Thread(
                target=shutdown,
                daemon=True,
                name="simple-share-shutdown",
            ).start()

        def open_folder(self):
            try:
                open_shared_folder()
            except Exception as exc:
                messagebox.showerror(
                    "Simple Share",
                    f"No se pudo abrir la carpeta:\n{exc}",
                    parent=self.root,
                )

        def open_browser(self):
            if self.running:
                webbrowser.open(self.url)

        def refresh_dynamic(self):
            if self.running:
                code = current_access_code()
                self.otp_text.set(f"{code[:3]} {code[3:]}")
                remaining = seconds_until_next_code()
                self.countdown_text.set(
                    f"Cambia en {remaining} s · la sesión ya iniciada permanece activa"
                )

            self.root.after(250, self.refresh_dynamic)

        def on_close(self):
            if self.running:
                should_close = messagebox.askyesno(
                    "Simple Share",
                    "El servidor está activo. ¿Detenerlo y salir?",
                    parent=self.root,
                )
                if not should_close:
                    return

                server = self.server
                self.server = None
                try:
                    server.shutdown()
                    server.server_close()
                except Exception:
                    pass

            self.root.destroy()

        def run(self):
            self.root.mainloop()

    app = SimpleShareGUI()
    app.run()
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        description=(
            "Servidor HTTP sencillo para compartir archivos entre dispositivos. "
            "Por defecto utiliza ~/shared en Linux/macOS y C:\\shared en Windows."
        )
    )

    parser.add_argument(
        "directory",
        nargs="?",
        default=None,
        help=(
            "Carpeta que quieres compartir. Si se omite, usa ~/shared "
            "en Linux/macOS y C:\\shared en Windows."
        ),
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=8000,
        help="Puerto HTTP (default: 8000)",
    )
    parser.add_argument(
        "-b",
        "--bind",
        default="0.0.0.0",
        help="IP donde escuchar (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--max-upload-mb",
        type=int,
        default=2048,
        help="Tamaño máximo por archivo en MB (default: 2048)",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Abrir la interfaz gráfica de control",
    )
    parser.add_argument(
        "--web-gui",
        action="store_true",
        help="Forzar el panel de control web local",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Mostrar también las peticiones HTTP en la consola",
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    try:
        configure_request_logging(args.verbose)
    except OSError as exc:
        print(f"No se pudo crear el registro de peticiones: {exc}")
        return 1

    if args.web_gui:
        return run_web_gui(args)

    if args.gui:
        return run_gui(args)

    try:
        run_cli(args)
    except RuntimeError as exc:
        print(exc)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
