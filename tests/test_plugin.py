"""Tests for the Retriever plugin.

The fetch tests run against a real HTTP server on the loopback interface, so
they exercise status handling and URL encoding rather than a mock of them.
"""

import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from src.plugins.manifest import PluginManifest

PLUGIN_DIR = Path(__file__).parent.parent
MANIFEST_PATH = PLUGIN_DIR / "manifest.json"

# Loaded by path, as FiestaBoard's loader does: the directory name differs
# between a checkout and an install, so there is no fixed package to import.
_spec = importlib.util.spec_from_file_location("retriever_plugin", PLUGIN_DIR / "__init__.py")
retriever = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(retriever)
RetrieverPlugin = retriever.RetrieverPlugin

TOKEN = "s3cret/+ &="
PAYLOAD = {
    "count": 1,
    "text": "TEST0",
    "items": [{"title": "test0", "list": "Reminders", "due": "2026-10-05T06:15:00Z", "priority": 0}],
}


class FakeServer:
    """A stand-in for the Retriever server whose reply can be changed per test."""

    def __init__(self):
        self.status = 200
        self.body = json.dumps(PAYLOAD).encode()
        self.requests: list[str] = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                fake.requests.append(self.path)
                self.send_response(fake.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(fake.body)))
                self.end_headers()
                self.wfile.write(fake.body)

            def log_message(self, *args):
                pass

        self._httpd = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._httpd.server_port}"
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()

    def stop(self):
        self._httpd.shutdown()
        self._httpd.server_close()


@pytest.fixture
def server():
    fake = FakeServer()
    yield fake
    fake.stop()


@pytest.fixture
def manifest():
    """The parsed manifest dict, as the loader passes it to the constructor."""
    with open(MANIFEST_PATH) as f:
        return json.load(f)


@pytest.fixture
def plugin(manifest, server):
    plugin = RetrieverPlugin(manifest)
    plugin.config = {"server_url": server.url, "token": TOKEN}
    return plugin


class TestFetch:
    def test_plugin_id(self, plugin):
        assert plugin.plugin_id == "retriever"

    def test_response_passes_through_unchanged(self, plugin):
        result = plugin.fetch_data()
        assert result.available is True
        assert result.error is None
        assert result.data == {"reminders": PAYLOAD, "error": ""}
        assert result.formatted_lines is None

    def test_non_object_response_passes_through(self, plugin, server):
        server.body = b'[1, "two", null]'
        assert plugin.fetch_data().data["reminders"] == [1, "two", None]

    def test_request_path_and_token_encoding(self, plugin, server):
        plugin.fetch_data()
        assert server.requests == ["/reminders?token=s3cret%2F%2B+%26%3D"]

    def test_trailing_slash_in_server_url(self, plugin, server):
        plugin.config = {"server_url": server.url + "/", "token": TOKEN}
        assert plugin.fetch_data().data["error"] == ""
        assert server.requests[0].startswith("/reminders?")

    def test_fetch_reports_failure_by_raising(self, plugin, server):
        server.status = 401
        with pytest.raises(Exception, match="401"):
            plugin._fetch(server.url + "/reminders", TOKEN)

    def test_error_status(self, plugin, server):
        server.status, server.body = 401, b"{}"
        self.assert_failed(plugin.fetch_data(), "401")

    def test_invalid_json(self, plugin, server):
        server.body = b"not json"
        self.assert_failed(plugin.fetch_data())

    def test_unreachable_server(self, plugin, server):
        server.stop()
        self.assert_failed(plugin.fetch_data())

    def test_failure_after_success_shows_no_reminders(self, plugin, server):
        assert plugin.fetch_data().data["reminders"]["count"] == 1
        server.status = 500
        self.assert_failed(plugin.fetch_data(), "500")

    def test_recovers_after_failure(self, plugin, server):
        server.status = 500
        plugin.fetch_data()
        server.status = 200
        assert plugin.fetch_data().data == {"reminders": PAYLOAD, "error": ""}

    def test_errors_never_contain_the_token(self, plugin, server, caplog):
        server.status = 401
        first = plugin.fetch_data()
        server.stop()
        second = plugin.fetch_data()
        assert "s3cret" not in first.error + second.error + caplog.text

    @staticmethod
    def assert_failed(result, reason=""):
        """Templates still render: no reminders, and the reason in ``error``."""
        assert result.available is True
        assert result.data["reminders"] == {"count": 0, "text": "", "items": []}
        assert result.data["error"] and reason in result.data["error"]
        assert result.error == result.data["error"]


class TestConfig:
    @pytest.mark.parametrize(
        "config",
        [
            {},
            {"server_url": "http://192.0.2.10:42511"},
            {"token": TOKEN},
            {"server_url": "  ", "token": TOKEN},
            {"server_url": "192.0.2.10:42511", "token": TOKEN},
            {"server_url": "file:///etc/passwd", "token": TOKEN},
            {"server_url": 42511, "token": TOKEN},
        ],
    )
    def test_invalid_config(self, manifest, config):
        plugin = RetrieverPlugin(manifest)
        assert plugin.validate_config(config)
        plugin.config = config
        result = plugin.fetch_data()
        assert result.available is False
        assert result.error
        assert "s3cret" not in result.error

    def test_valid_config(self, manifest):
        plugin = RetrieverPlugin(manifest)
        assert plugin.validate_config({"server_url": "http://192.0.2.10:42511", "token": TOKEN}) == []


class TestManifest:
    def test_manifest_parses(self, manifest):
        assert PluginManifest.from_dict(manifest).id == "retriever"

    def test_settings(self, manifest):
        schema = manifest["settings_schema"]
        assert schema["required"] == ["server_url", "token"]
        assert schema["properties"]["token"]["ui:widget"] == "password"

    def test_fetch_reports_failure_by_raising(self, plugin, server):
        server.status = 401
        with pytest.raises(Exception, match="401"):
            plugin._fetch(server.url + "/reminders", TOKEN)

    def test_fetch_fits_inside_fiestaboard_render_timeout(self):
        assert retriever.TIMEOUT_SECONDS < 5
