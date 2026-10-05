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
import urllib.error
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

RETRIEVE, CONFIG = retriever.RETRIEVE_PATH, retriever.CONFIG_PATH
KEY = bytes(range(32))
KEY_B64 = base64.b64encode(KEY).decode()
OTHER_KEY = bytes(range(1, 33))
SEQ = 7
SOURCES = {
    "reminders": {
        "type": "object",
        "properties": {"count": {"type": "integer"}, "text": {"type": "string"}, "items": {"type": "array"}},
        "default": {"count": 0, "text": "", "items": []},
    }
}
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
        self.seq = SEQ
        self.sources = SOURCES
        self.values = VALUES
        self.status = {}  # path -> (status, reason): refuse requests to that path
        self.delay = {}  # path -> seconds to wait before answering
        self.reply = None  # replace the response body: f(path, request dict) -> bytes
        self.paths: list[str] = []
        self.requests: list[dict] = []
        self.bodies: list[bytes] = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                fake.paths.append(self.path)
                fake.bodies.append(body)
                time.sleep(fake.delay.get(self.path, 0))
                if self.path not in (RETRIEVE, CONFIG):
                    return self.answer(404, "Not Found")
                if self.path in fake.status:
                    return self.answer(*fake.status[self.path])
                try:
                    context = retriever.request_context(self.path)
                    plaintext = ChaCha20Poly1305(fake.key).decrypt(body[:12], body[12:], context)
                except Exception:
                    return self.answer(401, "Unauthorized")
                request = json.loads(plaintext)
                fake.requests.append(request)
                if fake.reply:
                    return self.answer(200, "OK", fake.reply(self.path, request))
                data = fake.sources if self.path == CONFIG else fake.values
                self.answer(200, "OK", fake.sealed(self.path, {"id": request["id"], "seq": fake.seq, "data": data}))

            def answer(self, status, reason, body=b""):
                try:
                    self.send_response(status, reason)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except OSError:
                    pass  # the plugin gave up waiting

            def log_message(self, *args):
                pass

        self._httpd = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._httpd.server_port}"
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()

    def sealed(self, path, message, key=None):
        return seal(key or self.key, json.dumps(message).encode(), retriever.response_context(path))

    def refuse(self, status, reason, paths=(RETRIEVE, CONFIG)):
        self.status = {path: (status, reason) for path in paths}

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


def assert_failed(result, reason, values):
    """Templates still render: *values*, and the reason in ``error``."""
    assert result.available is True
    assert result.data == {**values, "error": result.data["error"]}
    assert result.data["error"].startswith(reason)
    assert result.error == result.data["error"]


def assert_retrieve_failed(result, reason):
    """The config is known, so reminders has its schema's default."""
    assert_failed(result, reason, {"reminders": NO_REMINDERS})
    assert retriever.CONFIG_PENDING not in result.error


def assert_config_pending(result, reason, values=None):
    assert_failed(result, reason, values or {})
    assert result.error == f"{reason}; config pending"


class TestRetrieve:
    def test_plugin_id(self, plugin):
        assert plugin.plugin_id == "retriever"

    def test_values_pass_through_unchanged(self, plugin):
        result = plugin.fetch_data()
        assert result.available is True
        assert result.error is None
        assert result.data == {**VALUES, "error": ""}
        assert result.formatted_lines is None

    def test_a_source_with_its_own_error_passes_through(self, plugin, server):
        server.values = {"reminders": {"error": "Reminders could not be read", "data": NO_REMINDERS["data"]}}
        result = plugin.fetch_data()
        assert result.data == {**server.values, "error": ""}
        assert result.error is None

    def test_other_sources_pass_through(self, plugin, server):
        server.values = {**VALUES, "calendar": {"error": "", "data": [1, "two", None]}}
        assert plugin.fetch_data().data["calendar"] == {"error": "", "data": [1, "two", None]}

    def test_request_carries_a_current_timestamp_and_a_fresh_id(self, plugin, server):
        plugin.fetch_data()
        ids = [request["id"] for request in server.requests]
        assert len(set(ids)) == len(ids) == 2
        for request in server.requests:
            assert set(request) == {"ts", "id"}
            assert abs(request["ts"] - time.time()) < 5
            assert len(request["id"]) == 32

    def test_every_request_has_a_new_nonce(self, plugin, server):
        plugin.fetch_data()
        plugin.fetch_data()
        nonces = [body[:12] for body in server.bodies]
        assert len(set(nonces)) == len(nonces) == 3

    def test_nothing_readable_is_sent(self, plugin, server):
        plugin.fetch_data()
        assert all(b"ts" not in body and KEY not in body for body in server.bodies)

    def test_trailing_slash_in_server_url(self, plugin, server):
        plugin.config = {"server_url": server.url + "/", "key": KEY_B64}
        assert plugin.fetch_data().data["error"] == ""

    def test_fetch_reports_failure_by_raising(self, plugin, server):
        server.refuse(401, "Unauthorized")
        with pytest.raises(urllib.error.HTTPError):
            plugin._fetch(server.url, RETRIEVE, KEY, time.monotonic() + 4)

    def test_fetch_past_its_deadline_raises_without_asking(self, plugin, server):
        with pytest.raises(TimeoutError):
            plugin._fetch(server.url, RETRIEVE, KEY, time.monotonic() - 1)
        assert server.paths == []

    def test_refused_retrieve_shows_the_defaults_and_the_reason(self, plugin, server):
        plugin.fetch_data()
        server.refuse(400, "Stale Timestamp", [RETRIEVE])
        assert_retrieve_failed(plugin.fetch_data(), "400 Stale Timestamp")

    def test_failure_after_success_shows_no_reminders(self, plugin, server):
        assert plugin.fetch_data().data["reminders"]["data"]["count"] == 1
        server.refuse(500, "Internal Server Error", [RETRIEVE])
        assert_retrieve_failed(plugin.fetch_data(), "500 Internal Server Error")

    def test_recovers_after_failure(self, plugin, server):
        plugin.fetch_data()
        server.refuse(500, "Internal Server Error", [RETRIEVE])
        plugin.fetch_data()
        server.status = {}
        assert plugin.fetch_data().data == {**VALUES, "error": ""}

    def test_unreachable_server_after_config(self, plugin, server):
        plugin.fetch_data()
        server.stop()
        assert_retrieve_failed(plugin.fetch_data(), "Connection refused")

    @pytest.mark.parametrize(
        ("reply", "reason"),
        [
            (lambda s, path, request: s.sealed(path, {"id": request["id"], "seq": SEQ, "data": VALUES}, OTHER_KEY), "wrong key"),
            (lambda s, path, request: s.sealed(CONFIG, {"id": request["id"], "seq": SEQ, "data": VALUES}), "wrong key"),
            (lambda s, path, request: s.bodies[-1], "wrong key"),
            (lambda s, path, request: json.dumps({"id": request["id"], "seq": SEQ, "data": VALUES}).encode(), "wrong key"),
            (lambda s, path, request: b"", "wrong key"),
            (lambda s, path, request: seal(KEY, b"not json", retriever.response_context(path)), "not JSON"),
            (lambda s, path, request: s.sealed(path, {"id": "0" * 32, "seq": SEQ, "data": VALUES}), "wrong ID"),
            (lambda s, path, request: s.sealed(path, {"id": request["id"], "data": VALUES}), "no seq"),
            (lambda s, path, request: s.sealed(path, {"id": request["id"], "seq": True, "data": VALUES}), "no seq"),
            (lambda s, path, request: s.sealed(path, {"id": request["id"], "seq": SEQ}), "no data"),
        ],
        ids=[
            "sealed with another key",
            "sealed for the other endpoint",
            "request reflected",
            "plaintext",
            "empty",
            "not json",
            "another request's id",
            "no seq",
            "seq not a number",
            "no data",
        ],
    )
    def test_a_response_that_is_not_the_servers_answer(self, plugin, server, reply, reason):
        plugin.fetch_data()
        server.reply = lambda path, request: reply(server, path, request)
        assert_retrieve_failed(plugin.fetch_data(), reason)

    def test_errors_never_contain_the_key(self, plugin, server, caplog):
        server.refuse(401, "Unauthorized")
        first = plugin.fetch_data()
        server.stop()
        second = plugin.fetch_data()
        assert KEY_B64 not in first.error + second.error + caplog.text


class TestServerConfig:
    def test_config_is_read_once(self, plugin, server):
        plugin.fetch_data()
        plugin.fetch_data()
        plugin.fetch_data()
        assert server.paths == [CONFIG, RETRIEVE, RETRIEVE, RETRIEVE]

    @pytest.mark.parametrize("new_seq", [SEQ + 1, SEQ - 1, 0])
    def test_config_is_read_again_when_the_sequence_number_changes(self, plugin, server, new_seq):
        plugin.fetch_data()
        server.seq = new_seq
        server.sources = {"reminders": {"type": "object", "default": {"count": -1}}}
        result = plugin.fetch_data()
        assert result.data == {**VALUES, "error": ""}
        assert server.paths == [CONFIG, RETRIEVE, RETRIEVE, CONFIG]

        plugin.fetch_data()
        assert server.paths[4:] == [RETRIEVE]
        server.refuse(500, "Internal Server Error", [RETRIEVE])
        assert plugin.fetch_data().data["reminders"] == {"error": "", "data": {"count": -1}}

    def test_config_is_read_again_when_settings_are_saved(self, plugin, server):
        plugin.fetch_data()
        plugin.config = {"server_url": server.url, "key": KEY_B64, "refresh_seconds": 120}
        plugin.fetch_data()
        assert server.paths == [CONFIG, RETRIEVE, CONFIG, RETRIEVE]

    def test_defaults_come_from_the_servers_config(self, plugin, server):
        server.sources = {
            "reminders": {"type": "object", "default": {"count": 0, "text": "NONE"}},
            "calendar": {"type": "array", "items": {"type": "string"}},
        }
        plugin.fetch_data()
        server.refuse(500, "Internal Server Error", [RETRIEVE])
        assert_failed(
            plugin.fetch_data(),
            "500 Internal Server Error",
            {"reminders": {"error": "", "data": {"count": 0, "text": "NONE"}}, "calendar": {"error": "", "data": []}},
        )

    def test_no_source_is_known_before_the_config_is_read(self, plugin, server):
        server.refuse(401, "Unauthorized")
        assert_config_pending(plugin.fetch_data(), "401 Unauthorized")
        assert server.paths == [CONFIG]

    def test_unreachable_server_before_the_config_is_read(self, plugin, server):
        server.stop()
        assert_config_pending(plugin.fetch_data(), "Connection refused")

    def test_config_is_tried_again_on_the_next_fetch(self, plugin, server):
        server.refuse(500, "Internal Server Error", [CONFIG])
        assert_config_pending(plugin.fetch_data(), "500 Internal Server Error")
        server.status = {}
        assert plugin.fetch_data().data == {**VALUES, "error": ""}
        assert server.paths == [CONFIG, CONFIG, RETRIEVE]

    def test_values_are_kept_when_the_changed_config_cannot_be_read(self, plugin, server):
        plugin.fetch_data()
        server.seq = SEQ + 1
        server.refuse(500, "Internal Server Error", [CONFIG])
        assert_config_pending(plugin.fetch_data(), "500 Internal Server Error", VALUES)

        server.status = {}
        assert plugin.fetch_data().data == {**VALUES, "error": ""}
        assert server.paths == [CONFIG, RETRIEVE, RETRIEVE, CONFIG, RETRIEVE, CONFIG]

    def test_a_config_response_cannot_be_passed_off_as_a_retrieve_response(self, plugin, server):
        plugin.fetch_data()
        server.reply = lambda path, request: server.sealed(CONFIG, {"id": request["id"], "seq": SEQ, "data": SOURCES})
        assert_retrieve_failed(plugin.fetch_data(), "wrong key")

    def test_all_requests_in_one_fetch_share_the_time_budget(self, plugin, server, monkeypatch):
        monkeypatch.setattr(retriever, "TIMEOUT_SECONDS", 0.6)
        server.delay = {CONFIG: 0.4, RETRIEVE: 0.4}
        started = time.monotonic()
        result = plugin.fetch_data()
        assert time.monotonic() - started < 0.9
        assert_retrieve_failed(result, "timed out")

    def test_slow_config_before_the_config_is_read(self, plugin, server, monkeypatch):
        monkeypatch.setattr(retriever, "TIMEOUT_SECONDS", 0.2)
        server.delay = {CONFIG: 0.5}
        assert_config_pending(plugin.fetch_data(), "timed out")


class TestDescribe:
    """Reasons are short, with what distinguishes them first."""

    @pytest.mark.parametrize(
        ("error", "reason"),
        [
            (urllib.error.HTTPError("http://x", 401, "Unauthorized", None, None), "401 Unauthorized"),
            (urllib.error.HTTPError("http://x", 400, "Stale Timestamp", None, None), "400 Stale Timestamp"),
            (urllib.error.URLError(TimeoutError("timed out")), "timed out"),
            (TimeoutError(), "timed out"),
            (urllib.error.URLError(ConnectionRefusedError(61, "Connection refused")), "Connection refused"),
            (urllib.error.URLError("unknown url type"), "<urlopen error unknown url type>"),
            (ValueError("wrong ID in response"), "wrong ID in response"),
            (KeyError(), "KeyError"),
        ],
    )
    def test_reason(self, error, reason):
        assert retriever.describe(error) == reason


class TestDefaultFor:
    @pytest.mark.parametrize(
        ("schema", "value"),
        [
            ({"type": "object", "default": {"count": 0}}, {"count": 0}),
            ({"type": "integer", "default": None}, None),
            ({"type": "object", "properties": {"n": {"type": "integer"}, "s": {"type": "string"}}}, {"n": 0, "s": ""}),
            ({"type": "object", "properties": {"n": {"type": "number", "default": 5}}}, {"n": 5}),
            ({"type": "object"}, {}),
            ({"type": "array", "items": {"type": "string"}}, []),
            ({"type": "string"}, ""),
            ({"type": "integer"}, 0),
            ({"type": "number"}, 0),
            ({"type": "boolean"}, False),
            ({"type": "null"}, None),
            ({}, None),
            ("not a schema", None),
        ],
    )
    def test_default(self, schema, value):
        assert retriever.default_for(schema) == value


class TestInterop:
    """Messages sealed by one side must open on the other."""

    key = base64.b64decode(VECTORS["key"])

    @pytest.mark.parametrize("path", [RETRIEVE, CONFIG])
    def test_opens_a_response_sealed_by_the_server(self, path):
        vector = VECTORS["responses_from_server"][path]
        seq, data = retriever.open_response(self.key, bytes.fromhex(vector["body"]), vector["id"], path)
        assert (seq, data) == (vector["seq"], vector["data"])

    def test_the_servers_config_gives_reminders_a_default(self):
        sources = VECTORS["responses_from_server"][CONFIG]["data"]
        assert retriever.default_for(sources["reminders"]) == NO_REMINDERS["data"]

    @pytest.mark.parametrize("path", [RETRIEVE, CONFIG])
    def test_request_vector_is_what_the_plugin_seals(self, path):
        """The server's tests open this body; check here that it is still a current-format request."""
        vector = VECTORS["requests_from_plugin"][path]
        body = bytes.fromhex(vector["body"])
        plaintext = ChaCha20Poly1305(self.key).decrypt(body[:12], body[12:], retriever.request_context(path))
        assert json.loads(plaintext) == {"ts": vector["ts"], "id": vector["id"]}

        fresh, request_id = retriever.seal_request(self.key, vector["ts"], path)
        plaintext = ChaCha20Poly1305(self.key).decrypt(fresh[:12], fresh[12:], retriever.request_context(path))
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
