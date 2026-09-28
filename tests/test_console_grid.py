import io
import os
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import simple_share


class ConsoleGridWidthTests(unittest.TestCase):
    ROWS = [
        ("Carpeta", "/home/eliseu/una/ruta/muy/larga/que/no/cabe"),
        ("Puerto", "8000"),
        ("Localhost", "http://127.0.0.1:8000/"),
        ("Red local", "http://192.168.100.123:8000/"),
        ("Registro", "/home/eliseu/proyectos/simple-share/simple_share_logs/registro.log"),
    ]

    def render(self, width):
        out = io.StringIO()
        size = os.terminal_size((width, 24))
        with (
            patch.object(simple_share.shutil, "get_terminal_size", return_value=size),
            patch.object(simple_share, "supports_console_hyperlinks", return_value=False),
            redirect_stdout(out),
        ):
            simple_share.print_console_grid(self.ROWS)
        return out.getvalue().splitlines()

    def test_grid_never_exceeds_safe_terminal_width(self):
        for width in (59, 44, 33):
            with self.subTest(width=width):
                lines = self.render(width)
                self.assertTrue(lines)
                self.assertTrue(all(len(line) <= width - 1 for line in lines))

    def test_ip_url_is_allowed_to_shrink(self):
        lines = self.render(33)
        rendered = "\n".join(lines)

        self.assertNotIn("http://192.168.100.123:8000/", rendered)
        self.assertIn("…", rendered)

    def test_table_borders_are_preserved_at_33_columns(self):
        lines = self.render(33)

        self.assertTrue(lines[0].startswith("┌"))
        self.assertTrue(lines[-1].startswith("└"))


if __name__ == "__main__":
    unittest.main()
