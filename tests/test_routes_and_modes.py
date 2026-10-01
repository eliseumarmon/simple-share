import argparse
import concurrent.futures
import http.client
import json
import re
import socket
import urllib.parse
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import simple_share


class RouteAndModeTests(unittest.TestCase):
    def test_literal_percent_name_and_symlink_containment(self):
        with tempfile.TemporaryDirectory() as shared, tempfile.TemporaryDirectory() as outside:
            root = Path(shared)
            (root / "literal%2Fname.txt").write_bytes(b"literal")
            (root / "secret.txt").write_bytes(b"secret")
            (root / "__ROWS__").mkdir()
            dangerous_dir = root / "<" / "script><script>alert(1)<"
            try:
                dangerous_dir.mkdir(parents=True)
            except OSError:
                dangerous_dir = None
            (Path(outside) / "outside.txt").write_bytes(b"outside")
            try:
                (root / "link").symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError):
                pass

            with patch.object(simple_share, "ROOT", root):
                self.assertEqual(simple_share.safe_path("literal%2Fname.txt"), root / "literal%2Fname.txt")
                with self.assertRaises(ValueError):
                    simple_share.safe_path("../outside.txt")
                if (root / "link").is_symlink():
                    with self.assertRaises(ValueError):
                        simple_share.safe_path("link/outside.txt")

                server = simple_share.ShareServer(("127.0.0.1", 0), simple_share.ShareHandler)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    def get(path, host=None):
                        connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
                        headers = {"Host": host} if host else {}
                        connection.request("GET", path, headers=headers)
                        response = connection.getresponse()
                        result = response.status, response.read()
                        connection.close()
                        return result

                    self.assertEqual(get("/literal%252Fname.txt"), (200, b"literal"))
                    self.assertEqual(get("/secret.txt")[1], b"secret")
                    status, body = get("/__ROWS__/")
                    self.assertEqual(status, 200)
                    self.assertIn(b'const currentDir="__ROWS__";', body)
                    if dangerous_dir is not None:
                        url = "/" + urllib.parse.quote("</script><script>alert(1)<", safe="/") + "/"
                        status, body = get(url)
                        self.assertEqual(status, 200)
                        self.assertNotIn(b"</script><script>alert(1)", body)
                        self.assertIn(b"\\u003c/script", body)
                    status, body = get("/secret.txt", "evil.example")
                    self.assertNotEqual(body, b"secret")
                    self.assertIn(b"Simple Share", body)
                    if (root / "link").is_symlink():
                        self.assertEqual(get("/link/outside.txt")[0], 403)
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=2)

    def test_concurrent_uploads_keep_both_files(self):
        with tempfile.TemporaryDirectory() as shared:
            root = Path(shared)
            with patch.object(simple_share, "ROOT", root):
                server = simple_share.ShareServer(("127.0.0.1", 0), simple_share.ShareHandler)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    def upload(content):
                        connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
                        connection.request(
                            "POST", "/api/upload?name=igual.txt", body=content,
                            headers={"Origin": f"http://127.0.0.1:{server.server_port}"},
                        )
                        response = connection.getresponse()
                        status = response.status
                        response.read()
                        connection.close()
                        return status

                    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                        results = list(pool.map(upload, (b"uno", b"dos")))
                    self.assertEqual(results, [200, 200])
                    self.assertEqual(
                        {path.read_bytes() for path in root.iterdir()},
                        {b"uno", b"dos"},
                    )
                    self.assertEqual(len(list(root.iterdir())), 2)
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=2)

    def test_folder_upload_creates_subdirectories(self):
        with tempfile.TemporaryDirectory() as shared:
            root = Path(shared)
            (root / "Fotos").mkdir()
            with patch.object(simple_share, "ROOT", root):
                server = simple_share.ShareServer(("127.0.0.1", 0), simple_share.ShareHandler)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    def post(path, body, content_type="application/octet-stream"):
                        connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
                        connection.request(
                            "POST", path, body=body,
                            headers={
                                "Origin": f"http://127.0.0.1:{server.server_port}",
                                "Content-Type": content_type,
                            },
                        )
                        response = connection.getresponse()
                        result = response.status, response.read()
                        connection.close()
                        return result

                    status, body = post(
                        "/api/mkdir",
                        json.dumps({"dir": "", "name": "Fotos", "unique": True}),
                        "application/json",
                    )
                    self.assertEqual(status, 200)
                    created = json.loads(body)["path"]
                    self.assertEqual(created, "Fotos (1)")

                    query = urllib.parse.urlencode(
                        {"dir": created, "subdir": "2024/verano", "name": "playa.jpg"}
                    )
                    self.assertEqual(post("/api/upload?" + query, b"jpg")[0], 200)
                    self.assertEqual(
                        (root / "Fotos (1)" / "2024" / "verano" / "playa.jpg").read_bytes(),
                        b"jpg",
                    )

                    query = urllib.parse.urlencode(
                        {"dir": created, "subdir": "../fuera", "name": "x.txt"}
                    )
                    self.assertEqual(post("/api/upload?" + query, b"x")[0], 400)
                    self.assertFalse((root / "fuera").exists())
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=2)

    def test_resumable_chunked_upload(self):
        with tempfile.TemporaryDirectory() as shared:
            root = Path(shared)
            with patch.object(simple_share, "ROOT", root):
                server = simple_share.ShareServer(("127.0.0.1", 0), simple_share.ShareHandler)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    def chunk(offset, body, upload_id="ab" * 16, total=10):
                        query = urllib.parse.urlencode({
                            "name": "datos.bin", "id": upload_id,
                            "offset": offset, "total": total,
                        })
                        connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
                        connection.request(
                            "POST", "/api/upload?" + query, body=body,
                            headers={"Origin": f"http://127.0.0.1:{server.server_port}"},
                        )
                        response = connection.getresponse()
                        result = response.status, json.loads(response.read())
                        connection.close()
                        return result

                    status, data = chunk(0, b"01234")
                    self.assertEqual((status, data["received"]), (200, 5))
                    self.assertEqual(list(root.iterdir()), [root / f".upload-{'ab' * 16}.part"])

                    # Un trozo que se adelanta a lo recibido indica desde dónde seguir.
                    status, data = chunk(8, b"89")
                    self.assertEqual((status, data["received"]), (409, 5))

                    # Reenviar un trozo ya recibido lo sobrescribe sin duplicar datos.
                    self.assertEqual(chunk(0, b"01234")[0], 200)
                    status, data = chunk(5, b"56789")
                    self.assertEqual((status, data["path"]), (200, "datos.bin"))
                    self.assertEqual((root / "datos.bin").read_bytes(), b"0123456789")

                    # Si se pierde la respuesta final, repetir no crea otra copia.
                    status, data = chunk(5, b"56789")
                    self.assertEqual((status, data["path"]), (200, "datos.bin"))
                    self.assertEqual([p.name for p in root.iterdir()], ["datos.bin"])

                    self.assertEqual(chunk(0, b"x", upload_id="../x")[0], 400)
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=2)

    def test_web_flag_and_tk_fallback(self):
        self.assertTrue(simple_share.build_parser().parse_args(["--web"]).web)
        self.assertTrue(simple_share.build_parser().parse_args(["--web-gui"]).web)
        try:
            import tkinter
        except ImportError:
            self.skipTest("Tkinter no está instalado")
        with tempfile.TemporaryDirectory() as shared:
            args = argparse.Namespace(directory=shared, port=8000, bind="127.0.0.1", max_upload_mb=10)
            with (
                patch.object(tkinter, "Tk", side_effect=tkinter.TclError("sin pantalla")),
                patch.object(simple_share, "run_web_gui", return_value=23) as web,
            ):
                self.assertEqual(simple_share.run_gui(args), 23)
                web.assert_called_once_with(args)

    def test_web_panel_rejects_foreign_host(self):
        original_server = simple_share.ThreadingHTTPServer
        servers = []

        def capture_server(address, handler):
            server = original_server(address, handler)
            servers.append(server)
            return server

        with tempfile.TemporaryDirectory() as shared:
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                share_port = probe.getsockname()[1]
            args = argparse.Namespace(directory=shared, port=share_port, bind="127.0.0.1", max_upload_mb=10)
            with (
                patch.object(simple_share, "ThreadingHTTPServer", side_effect=capture_server),
                patch.object(simple_share.webbrowser, "open", return_value=False),
            ):
                thread = threading.Thread(target=simple_share.run_web_gui, args=(args,), daemon=True)
                thread.start()
                for _ in range(100):
                    if servers:
                        break
                    time.sleep(0.01)
                self.assertTrue(servers)
                server = servers[0]
                try:
                    connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
                    connection.request("GET", "/")
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    page = response.read()
                    connection.close()
                    token = re.search(rb'const TOKEN="([^"]+)"', page).group(1).decode()

                    def action(path):
                        connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
                        connection.request(
                            "POST", path, body=b"",
                            headers={
                                "X-Simple-Share-Control": token,
                                "Origin": f"http://127.0.0.1:{server.server_port}",
                            },
                        )
                        response = connection.getresponse()
                        result = response.status
                        response.read()
                        connection.close()
                        return result

                    self.assertEqual(action("/api/start"), 200)
                    self.assertEqual(action("/api/stop"), 200)
                    self.assertEqual(action("/api/start"), 200)
                    self.assertEqual(action("/api/stop"), 200)

                    connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
                    connection.request("GET", "/", headers={"Host": "evil.example"})
                    response = connection.getresponse()
                    self.assertEqual(response.status, 403)
                    connection.close()
                finally:
                    server.shutdown()
                    thread.join(timeout=2)
                self.assertFalse(thread.is_alive())


if __name__ == "__main__":
    unittest.main()
