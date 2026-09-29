import io
import os
import unittest
from unittest.mock import patch

import simple_share


ROWS = [
    ("Carpeta", "/home/una/ruta/muy/larga/que/no/cabe"),
    ("Puerto", "8000"),
    ("Localhost", "http://127.0.0.1:8000/"),
    ("Red local", "http://192.168.100.123:8000/"),
    ("Registro", "/home/una/ruta/simple_share_logs/registro.log"),
]


class TTY(io.StringIO):
    def isatty(self):
        return True


class ConsoleGridTests(unittest.TestCase):
    def test_dashboard_fits_width_and_height(self):
        with patch.object(simple_share, "supports_console_hyperlinks", return_value=False):
            for width in (2, 8, 17, 33, 59, 100):
                for height in (2, 3, 7, 12, 24):
                    with self.subTest(width=width, height=height):
                        lines = simple_share.build_console_dashboard(
                            ROWS, width - 1, height - 1,
                        )
                        self.assertLessEqual(len(lines), height - 1)
                        self.assertTrue(all(
                            simple_share.cell_width(line) <= width - 1
                            for line in lines
                        ))
                        if width >= 8:
                            self.assertIn(simple_share.current_access_code(), lines[-1])

    def test_small_terminal_keeps_lan_url_and_code(self):
        with patch.object(simple_share, "supports_console_hyperlinks", return_value=False):
            lines = simple_share.build_console_dashboard(ROWS, 32, 3)
        self.assertEqual(len(lines), 3)
        self.assertIn("LAN:", lines[1])
        self.assertIn(simple_share.current_access_code(), lines[2])

    def test_table_borders_and_url_shrink(self):
        with patch.object(simple_share, "supports_console_hyperlinks", return_value=False):
            lines = simple_share.build_console_grid(ROWS, 32, "Simple Share")
        self.assertTrue(lines[0].startswith("┌"))
        self.assertTrue(lines[-1].startswith("└"))
        self.assertNotIn("http://192.168.100.123:8000/", "\n".join(lines))
        self.assertIn("…", "\n".join(lines))

    def test_unicode_and_control_characters(self):
        rows = [("Carpeta", "/漢字/archivo\x1b[31m.txt")]
        with patch.object(simple_share, "supports_console_hyperlinks", return_value=False):
            lines = simple_share.build_console_grid(rows, 25, "Simple Share")
        self.assertTrue(all(simple_share.cell_width(line) <= 25 for line in lines))
        self.assertNotIn("\x1b", "\n".join(lines))

    def test_resize_redraws_same_screen_without_appending_dashboard(self):
        output = TTY()
        size = {"value": os.terminal_size((80, 25))}
        with (
            patch.object(simple_share.sys, "stdout", output),
            patch.object(simple_share.shutil, "get_terminal_size", side_effect=lambda fallback: size["value"]),
            patch.object(simple_share, "supports_console_hyperlinks", return_value=False),
            patch.dict(os.environ, {"TERM": "xterm-256color"}),
        ):
            dashboard = simple_share.ConsoleDashboard(ROWS)
            dashboard.start()
            size["value"] = os.terminal_size((22, 7))
            dashboard.refresh()
            dashboard.write_log("archivo subido")
            size["value"] = os.terminal_size((50, 12))
            dashboard.refresh()
            dashboard.stop()

        rendered = output.getvalue()
        self.assertTrue(rendered.startswith("\033[?1049h\033[?25l"))
        self.assertTrue(rendered.endswith("\033[?25h\033[?1049l"))
        self.assertEqual(rendered.count("\033[H\033[2J"), 4)
        self.assertNotIn("\033[1A", rendered)
        self.assertIn("archivo subido\n", rendered)
        last_frame = rendered.split("\033[H\033[2J")[-1]
        self.assertEqual(last_frame.count("Simple Share"), 1)


if __name__ == "__main__":
    unittest.main()
