#!/usr/bin/env python3
"""Simple Share: zero-dependency LAN file sharing for Python 3.10+."""


import argparse
import html
import hmac
import json
import mimetypes
import os
import secrets
import shutil
import socket
import sys
import threading
import time
import urllib.parse
import uuid
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT: Path | None = None
MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024
JSON_BODY_LIMIT = 64 * 1024
ACCESS_TOKEN = ""
ACCESS_CODE = ""
COOKIE_NAME = "simple_share_auth"
AUTH_WINDOW_SECONDS = 60
AUTH_MAX_FAILURES = 5
AUTH_FAILURES: dict[str, list[float]] = {}
AUTH_LOCK = threading.Lock()


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


def is_same_or_child(path: Path, possible_parent: Path) -> bool:
    """True si path es possible_parent o está dentro de él."""
    return path == possible_parent or possible_parent in path.parents


# ============================================================
# Servidor HTTP
# ============================================================


class ShareHandler(BaseHTTPRequestHandler):
    server_version = "SimpleShare/2.2"

    POST_ROUTES = {
        "/api/upload": "handle_upload",
        "/api/mkdir": "handle_mkdir",
        "/api/move": "handle_move",
        "/api/copy": "handle_copy",
        "/api/rename": "handle_rename",
        "/api/delete": "handle_delete",
    }

    def log_message(self, fmt, *args):
        print(f"[{self.address_string()}] {fmt % args}")

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
            '<p>Introduce el código de 6 dígitos que aparece en la terminal del ordenador.</p>'
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

        origin = self.headers.get("Origin")
        if origin and not self.valid_origin():
            self.send_login_page("Solicitud de acceso no válida.", status=403)
            return

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

        if not hmac.compare_digest(supplied, ACCESS_CODE):
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
# Main
# ============================================================


def main():
    global ROOT, MAX_UPLOAD_BYTES, ACCESS_TOKEN

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
    parser.add_argument("-p", "--port", type=int, default=8000, help="Puerto HTTP (default: 8000)")
    parser.add_argument("-b", "--bind", default="0.0.0.0", help="IP donde escuchar (default: 0.0.0.0)")
    parser.add_argument(
        "--max-upload-mb",
        type=int,
        default=2048,
        help="Tamaño máximo por archivo en MB (default: 2048)",
    )

    args = parser.parse_args()

    ROOT = (
        Path(args.directory).expanduser().resolve()
        if args.directory
        else get_default_directory().expanduser().resolve()
    )

    try:
        ROOT.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"No se pudo crear la carpeta {ROOT}: {exc}")
        sys.exit(1)

    if not ROOT.is_dir():
        print(f"No es una carpeta: {ROOT}")
        sys.exit(1)

    if args.max_upload_mb <= 0:
        print("--max-upload-mb debe ser mayor que 0")
        sys.exit(1)

    MAX_UPLOAD_BYTES = args.max_upload_mb * 1024 * 1024
    ACCESS_TOKEN = secrets.token_urlsafe(32)
    ACCESS_CODE = f"{secrets.randbelow(1_000_000):06d}"

    try:
        server = ShareServer((args.bind, args.port), ShareHandler)
    except OSError as exc:
        print(f"No se pudo iniciar el servidor: {exc}")
        sys.exit(1)

    ip = local_ip()

    print()
    print("Simple Share 2.2")
    print("================")
    print(f"Carpeta:      {ROOT}")
    print(f"Puerto:       {args.port}")
    print()
    print("Abre Simple Share desde el navegador:")
    print(f"Este equipo:  http://127.0.0.1:{args.port}/")
    print(f"Red local:    http://{ip}:{args.port}/")
    print()
    print(f"Código de acceso: {ACCESS_CODE}")
    print("El código y la sesión cambian cada vez que se inicia el servidor.")
    print()
    print("Funciones: subir, descargar, crear carpetas, mover, copiar, renombrar y eliminar.")
    print("Uso recomendado: redes locales de confianza. No expongas este puerto a Internet.")
    print("Ctrl+C para detener.")
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor detenido.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()