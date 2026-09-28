# Simple Share

A small, zero-dependency Python file server for sharing files across a trusted local network from any modern browser.

Simple Share turns a folder on your computer into a lightweight web file manager. Open the LAN URL shown in the terminal from your phone, tablet, or another computer, enter the short pairing code, and you can upload, download, organize, move, copy, rename, and delete files without installing an app on the client device.

Everything lives in a single Python file and uses only the Python standard library.

## Features

- Upload one or multiple files from the browser
- Download files
- Browse nested folders
- Create folders
- Rename files and folders
- Move files and folders
- Copy files and folders
- Delete files and folders
- Multi-select files and folders for batch move, copy, and delete
- Automatic collision-safe names such as `photo (1).jpg`
- Responsive interface designed for desktop and mobile browsers
- Inline SVG icons with no external assets or CDN
- Threaded HTTP server
- Configurable port, bind address, shared folder, and upload size limit
- Zero third-party Python dependencies

## Requirements

- Python 3.10 or newer
- Windows, Linux, or macOS
- Both devices must be able to reach each other over the local network

No `pip install` is required.

The control interface auto-detects what is available:

- `--gui` tries the native **Tkinter** window first on Windows, Linux, and macOS.
- If Tkinter is not available, `--gui` automatically falls back to the local browser-based control panel.
- `--web-gui` always forces the browser-based control panel.

The web control panel requires no extra Python packages.

## Quick start

Clone the repository or download `simple_share.py`, then run:

```bash
python3 simple_share.py
```

On Windows, depending on your Python installation:

```powershell
python simple_share.py
```

or:

```powershell
py simple_share.py
```

If no directory is specified, Simple Share automatically creates and uses:

- Linux/macOS: `~/shared`
- Windows: `C:\shared`

### Control panel

Simple Share includes a four-button control panel:

```bash
python3 simple_share.py --gui
```

The interface provides:

- **Start** — starts the LAN server and creates a fresh session/OTP secret
- **Stop** — stops the LAN server
- **Open folder** — opens the shared directory
- **Open browser** — opens the Simple Share LAN URL

It also shows the server status, LAN URL, current 6-digit OTP, and the countdown until the next code.

`--gui` uses Tkinter whenever the current Python installation provides it. This works on Windows and also on Linux/macOS installations where Tkinter is installed.

On Windows it can also be launched without a console window:

```powershell
pythonw.exe simple_share.py --gui
```

If Tkinter is unavailable, Simple Share automatically opens the zero-dependency browser control panel instead. That control panel listens only on `127.0.0.1`; the file-sharing server still listens on the configured LAN address when you press **Start**.

To force the browser control panel on any platform:

```bash
python3 simple_share.py --web-gui
```

At startup, the terminal prints the local URLs and a temporary 6-digit pairing code that rotates every 30 seconds:

```text
Simple Share 2.9
================
Carpeta:      /home/user/shared
Puerto:       8000

Abre Simple Share desde el navegador:
Este equipo:  http://127.0.0.1:8000/
Red local:    http://192.168.1.50:8000/

Código de acceso: 482731 (cambia en 17 s)
```

Open the **Red local** URL from the other device and enter the current 6-digit code. The pairing code changes every 30 seconds, but after a successful login the browser session stays active until the server restarts. You never need to type a long token into the URL.

## Custom shared folder

Pass a directory as the first argument:

```bash
python3 simple_share.py ~/Downloads/share
```

Windows example:

```powershell
python simple_share.py D:\Shared
```

The directory is created automatically if it does not exist.

## Options

```text
usage: simple_share.py [-h] [-p PORT] [-b BIND]
                       [--max-upload-mb MAX_UPLOAD_MB] [--gui] [--web-gui]
                       [-v] [directory]
```

Examples:

```bash
# Use port 8080
python3 simple_share.py -p 8080

# Share a custom directory
python3 simple_share.py ~/Downloads/share

# Limit each upload to 500 MB
python3 simple_share.py --max-upload-mb 500

# Listen only on the local machine
python3 simple_share.py --bind 127.0.0.1

# Open the platform-appropriate control panel
python3 simple_share.py --gui

# Force the zero-dependency browser control panel
python3 simple_share.py --web-gui

# Also show HTTP requests in the terminal
python3 simple_share.py --verbose
```

The default upload limit is **2048 MB per file**.


## Request logging

HTTP requests are logged automatically to a `simple_share_logs` directory next to `simple_share.py`.

For example:

```text
simple-share/
├── simple_share.py
└── simple_share_logs/
    └── simple_share_2026-09-29.log
```

A single log file is reused for each calendar day and new entries are appended to it.

By default, request lines are **not printed to the terminal**, keeping the CLI clean while the OTP refreshes in place on a single line.

The CLI summary table adapts to the current terminal width. Long filesystem paths are shortened in the middle with an ellipsis so the table border stays intact.

On terminals that support OSC 8 hyperlinks, the **shared folder path** is clickable and opens the folder. The **log path** links to the containing `simple_share_logs` directory. Some terminals require Ctrl+click or Cmd+click.

To also print HTTP requests to the terminal:

```bash
python3 simple_share.py --verbose
```

or:

```bash
python3 simple_share.py -v
```

When verbose mode is enabled, request lines are printed without breaking the live OTP status line.

## Security model

Simple Share is intended for **trusted local networks**. It is not designed to be exposed directly to the public Internet.

The server includes several protections while keeping the project dependency-free:

### Temporary pairing code and session token

Every time the server starts, Simple Share generates a cryptographically random secret used to derive a **6-digit time-based pairing code**. The visible code rotates every 30 seconds. A separate **cryptographically strong random session token** is used internally by the browser cookie.

Open the normal LAN URL and enter the current short pairing code. Simple Share accepts the current 30-second interval and the immediately previous interval so a code does not fail just because it rotated while you were typing. After successful pairing, the browser receives the session cookie and does not need to re-enter a code every 30 seconds. The long session token is never shown in the URL.

Requests coming directly from the same machine through the loopback interface (`127.0.0.1` or `::1`) are trusted and do **not** require the pairing code. The bypass is based on the actual client socket address, not on the `Host` header, so another device cannot gain local access merely by requesting a hostname such as `localhost`.

The cookie uses:

```text
HttpOnly
SameSite=Strict
Path=/
```

Failed pairing attempts are rate-limited per client. Restarting the server creates a new pairing secret and invalidates all existing sessions.

### Origin validation

All operations that modify data require requests to originate from the same Simple Share origin. Cross-origin write requests are rejected.

This helps protect the local service against browser-based cross-site request attacks.

### Path containment

Every requested path is resolved and checked to ensure it remains inside the configured shared directory. Attempts to escape the shared folder through paths such as `../` are rejected.

Symbolic links are not exposed in the browser interface.

### Browser security headers

Responses include defensive headers such as:

- `Content-Security-Policy`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Cache-Control: no-store` where appropriate

### Important limitations

The connection uses plain HTTP. Anyone capable of intercepting traffic on the local network may be able to observe transferred data. Use Simple Share only on networks you trust.

Do **not**:

- forward the Simple Share port from your router to the Internet
- expose it through a public tunnel without adding appropriate HTTPS and authentication
- run it on an untrusted public Wi-Fi unless you understand the network exposure
- place sensitive files in the shared directory unless you intend to make them available through Simple Share

Deletion is permanent; files are not moved to the operating system recycle bin or trash.

## How it works

Simple Share is intentionally built without a web framework. It uses Python's standard library:

- `http.server` for HTTP serving
- `ThreadingHTTPServer` for concurrent requests
- `pathlib` for filesystem paths
- `shutil` for file operations
- `urllib.parse` for URL handling
- `secrets`, `hmac`, and `hashlib` for rotating pairing codes and session tokens
- `http.cookies` for the session cookie
- `logging` for daily request logs
- `webbrowser` for launching the local browser control panel
- vanilla HTML, CSS, and JavaScript for the interfaces

The server exposes a small internal API:

```text
POST /auth
GET  /api/directories
POST /api/upload
POST /api/mkdir
POST /api/move
POST /api/copy
POST /api/rename
POST /api/delete
```

The web interface is embedded directly in `simple_share.py`, so the whole application remains portable as a single file.

## Design goals

Simple Share intentionally prioritizes:

1. **No dependencies** — copy one Python file and run it.
2. **No client app** — a browser is enough.
3. **Cross-platform use** — the same script works on Windows, Linux, and macOS.
4. **Useful defaults** — running the script with no arguments should be enough for normal use.
5. **Local-first operation** — no cloud service, account, database, or external API is required.
6. **A small codebase** — enough functionality to be useful without turning the project into a full file-management platform.

## Network/firewall notes

The default bind address is:

```text
0.0.0.0:8000
```

This allows other devices that can reach your computer over the network to connect to Simple Share. Your operating system firewall may ask whether Python should accept incoming connections.

If you only want to access Simple Share from the same computer, use:

```bash
python3 simple_share.py --bind 127.0.0.1
```

In a typical home network behind a NAT router, the service is not directly reachable from the Internet unless the port is explicitly forwarded or exposed through another mechanism. Devices on the same LAN may still be able to reach it, which is why pairing-code authentication is enabled by default.

## Current scope

Simple Share deliberately does not include:

- user accounts
- databases
- cloud storage
- public Internet hosting
- TLS certificate management
- permanent authentication credentials
- external JavaScript or CSS dependencies

Those are outside the project's local, zero-dependency goal.