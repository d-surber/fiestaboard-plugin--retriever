"""Tests for the Retriever plugin.

The fetch tests run against a real HTTP server on the loopback interface that
speaks the wire protocol, so they exercise the encryption and status handling
rather than a mock of them. ``vectors.json`` holds messages sealed by each
side for the other to open; RetrieverServer's tests read the same file.
"""

import base64
import importlib.util
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from src.plugins.manifest import PluginManifest, validate_manifest

PLUGIN_DIR = Path(__file__).parent.parent
MANIFEST_PATH = PLUGIN_DIR / "manifest.json"
VECTORS = json.loads((Path(__file__).parent / "vectors.json").read_text())

# Loaded by path, as FiestaBoard's loader does: the directory name differs
# between a checkout and an install, so there is no fixed package to import.
_spec = importlib.util.spec_from_file_location("retriever_plugin", PLUGIN_DIR / "__init__.py")
retriever = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(retriever)
RetrieverPlugin = retriever.RetrieverPlugin

KEY = bytes(range(32))
KEY_B64 = base64.b64encode(KEY).decode()
OTHER_KEY = bytes(range(1, 33))
VALUES = {
    "reminders": {
        "error": "",
        "data": {
            "count": 1,
            "text": "TEST0",
            "items": [{"title": "test0", "list": "Reminders", "due": "2026-10-05T06:15:00Z", "priority": 0}],
        },
    }
}
NO_REMINDERS = {"error": "", "data": {"count": 0, "text": "", "items": []}}


def seal(key, plaintext, context):
    nonce = os.urandom(12)
    return nonce + ChaCha20Poly1305(key).encrypt(nonce, plaintext, context)


class FakeServer:
    """A stand-in for RetrieverServer whose behaviour can be changed per test."""

    def __init__(self):
        self.key = KEY
        self.values = VALUES
        self.status = None  # refuse every request with this (status, reason)
        self.reply = None  # replace the response body: f(request dict) -> bytes
        self.requests: list[dict] = []
        self.bodies: list[bytes] = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                fake.bodies.append(body)
                if self.path != "/retrieve":
                    return self.answer(404, "Not Found")
                if fake.status:
                    return self.answer(*fake.status)
                try:
                    plaintext = ChaCha20Poly1305(fake.key).decrypt(body[:12], body[12:], retriever.REQUEST_CONTEXT)
                except Exception:
                    return self.answer(401, "Unauthorized")
                request = json.loads(plaintext)
                fake.requests.append(request)
                if fake.reply:
                    return self.answer(200, "OK", fake.reply(request))
                message = json.dumps({"id": request["id"], "data": fake.values}).encode()
                self.answer(200, "OK", seal(fake.key, message, retriever.RESPONSE_CONTEXT))

            def answer(self, status, reason, body=b""):
                self.send_response(status, reason)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

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
    plugin.config = {"server_url": server.url, "key": KEY_B64}
    return plugin


def assert_failed(result, reason=""):
    """Templates still render: no reminders, and the reason in ``error``."""
    assert result.available is True
    assert result.data["reminders"] == NO_REMINDERS
    assert result.data["error"] and reason in result.data["error"]
    assert result.error == result.data["error"]


class TestFetch:
    def test_plugin_id(self, plugin):
        assert plugin.plugin_id == "retriever"

    def test_values_pass_through_unchanged(self, plugin):
        result = plugin.fetch_data()
        assert result.available is True
        assert result.error is None
        assert result.data == {**VALUES, "error": ""}
        assert result.formatted_lines is None

    def test_a_value_with_its_own_error_passes_through(self, plugin, server):
        server.values = {"reminders": {"error": "Reminders could not be read", "data": NO_REMINDERS["data"]}}
        result = plugin.fetch_data()
        assert result.data == {**server.values, "error": ""}
        assert result.error is None

    def test_other_names_pass_through(self, plugin, server):
        server.values = {**VALUES, "calendar": {"error": "", "data": [1, "two", None]}}
        assert plugin.fetch_data().data["calendar"] == {"error": "", "data": [1, "two", None]}

    def test_request_carries_a_current_timestamp_and_a_fresh_id(self, plugin, server):
        plugin.fetch_data()
        plugin.fetch_data()
        first, second = server.requests
        assert set(first) == {"ts", "id"}
        assert abs(first["ts"] - time.time()) < 5
        assert len(first["id"]) == 32
        assert first["id"] != second["id"]

    def test_every_request_has_a_new_nonce(self, plugin, server):
        plugin.fetch_data()
        plugin.fetch_data()
        assert server.bodies[0][:12] != server.bodies[1][:12]

    def test_nothing_readable_is_sent(self, plugin, server):
        plugin.fetch_data()
        assert b"ts" not in server.bodies[0]
        assert KEY not in server.bodies[0]

    def test_trailing_slash_in_server_url(self, plugin, server):
        plugin.config = {"server_url": server.url + "/", "key": KEY_B64}
        assert plugin.fetch_data().data["error"] == ""

    def test_fetch_reports_failure_by_raising(self, plugin, server):
        server.status = (401, "Unauthorized")
        with pytest.raises(Exception, match="401"):
            plugin._fetch(server.url, KEY)

    def test_server_with_another_key_refuses(self, plugin, server):
        server.key = OTHER_KEY
        assert_failed(plugin.fetch_data(), "401")

    def test_stale_timestamp_is_reported_as_such(self, plugin, server):
        server.status = (400, "Stale Timestamp")
        assert_failed(plugin.fetch_data(), "Stale Timestamp")

    def test_response_sealed_with_another_key(self, plugin, server):
        server.reply = lambda request: seal(
            OTHER_KEY, json.dumps({"id": request["id"], "data": VALUES}).encode(), retriever.RESPONSE_CONTEXT
        )
        assert_failed(plugin.fetch_data(), "not encrypted with this key")

    def test_request_reflected_as_the_response(self, plugin, server):
        server.reply = lambda request: server.bodies[-1]
        assert_failed(plugin.fetch_data(), "not encrypted with this key")

    def test_plaintext_response(self, plugin, server):
        server.reply = lambda request: json.dumps({"id": request["id"], "data": VALUES}).encode()
        assert_failed(plugin.fetch_data(), "not encrypted with this key")

    def test_empty_response(self, plugin, server):
        server.reply = lambda request: b""
        assert_failed(plugin.fetch_data(), "not encrypted with this key")

    def test_response_to_another_request(self, plugin, server):
        server.reply = lambda request: seal(
            KEY, json.dumps({"id": "0" * 32, "data": VALUES}).encode(), retriever.RESPONSE_CONTEXT
        )
        assert_failed(plugin.fetch_data(), "does not answer this request")

    def test_response_without_values(self, plugin, server):
        server.reply = lambda request: seal(KEY, json.dumps({"id": request["id"]}).encode(), retriever.RESPONSE_CONTEXT)
        assert_failed(plugin.fetch_data(), "no values")

    def test_unreachable_server(self, plugin, server):
        server.stop()
        assert_failed(plugin.fetch_data())

    def test_failure_after_success_shows_no_reminders(self, plugin, server):
        assert plugin.fetch_data().data["reminders"]["data"]["count"] == 1
        server.status = (500, "Internal Server Error")
        assert_failed(plugin.fetch_data(), "500")

    def test_recovers_after_failure(self, plugin, server):
        server.status = (500, "Internal Server Error")
        plugin.fetch_data()
        server.status = None
        assert plugin.fetch_data().data == {**VALUES, "error": ""}

    def test_errors_never_contain_the_key(self, plugin, server, caplog):
        server.status = (401, "Unauthorized")
        first = plugin.fetch_data()
        server.stop()
        second = plugin.fetch_data()
        assert KEY_B64 not in first.error + second.error + caplog.text


class TestInterop:
    """Messages sealed by one side must open on the other."""

    key = base64.b64decode(VECTORS["key"])

    def test_opens_a_response_sealed_by_the_server(self):
        vector = VECTORS["response_from_server"]
        values = retriever.open_response(self.key, bytes.fromhex(vector["body"]), vector["id"])
        assert values == vector["values"]

    def test_request_vector_is_what_the_plugin_seals(self):
        """The server's tests open this body; check here that it is still a current-format request."""
        vector = VECTORS["request_from_plugin"]
        body = bytes.fromhex(vector["body"])
        plaintext = ChaCha20Poly1305(self.key).decrypt(body[:12], body[12:], retriever.REQUEST_CONTEXT)
        assert json.loads(plaintext) == {"ts": vector["ts"], "id": vector["id"]}

        fresh, request_id = retriever.seal_request(self.key, vector["ts"])
        plaintext = ChaCha20Poly1305(self.key).decrypt(fresh[:12], fresh[12:], retriever.REQUEST_CONTEXT)
        assert json.loads(plaintext) == {"ts": vector["ts"], "id": request_id}


class TestConfig:
    @pytest.mark.parametrize(
        "config",
        [
            {},
            {"server_url": "http://192.0.2.10:42511"},
            {"key": KEY_B64},
            {"server_url": "  ", "key": KEY_B64},
            {"server_url": "192.0.2.10:42511", "key": KEY_B64},
            {"server_url": "file:///etc/passwd", "key": KEY_B64},
            {"server_url": 42511, "key": KEY_B64},
            {"server_url": "http://192.0.2.10:42511", "key": "not base64!"},
            {"server_url": "http://192.0.2.10:42511", "key": base64.b64encode(bytes(16)).decode()},
            {"server_url": "http://192.0.2.10:42511", "key": 42},
        ],
    )
    def test_invalid_config(self, manifest, config):
        plugin = RetrieverPlugin(manifest)
        assert plugin.validate_config(config)
        plugin.config = config
        result = plugin.fetch_data()
        assert result.available is False
        assert result.error
        assert KEY_B64 not in result.error

    def test_valid_config(self, manifest):
        plugin = RetrieverPlugin(manifest)
        assert plugin.validate_config({"server_url": "http://192.0.2.10:42511", "key": f" {KEY_B64}\n"}) == []


class TestManifest:
    def test_manifest_parses(self, manifest):
        assert PluginManifest.from_dict(manifest).id == "retriever"

    def test_manifest_is_valid(self, manifest):
        valid, errors = validate_manifest(manifest)
        assert valid, errors

    def test_settings(self, manifest):
        schema = manifest["settings_schema"]
        assert schema["required"] == ["server_url", "key"]
        assert schema["properties"]["key"]["ui:widget"] == "password"
        assert "token" not in schema["properties"]

    @pytest.mark.parametrize(("device_type", "rows"), [("flagship", 6), ("note", 3)])
    def test_demo_page_per_board(self, manifest, device_type, rows):
        demo = PluginManifest.from_dict(manifest).demo[device_type]
        assert len(demo.template) == rows
        assert len(demo.line_metadata) == rows

    def test_cryptography_is_a_declared_requirement(self):
        assert "cryptography" in (PLUGIN_DIR / "requirements.txt").read_text().split()

    def test_fetch_fits_inside_fiestaboard_render_timeout(self):
        assert retriever.TIMEOUT_SECONDS < 5
