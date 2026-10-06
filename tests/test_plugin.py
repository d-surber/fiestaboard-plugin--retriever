"""Tests for the Retriever plugin.

The fetch tests run against a real HTTP server on the loopback interface that
speaks the wire protocol, so they exercise the encryption and status handling
rather than a mock of them. ``vectors.json`` holds messages sealed by each
side for the other to open; RetrieverServer's tests read the same file.
"""

import base64
import http.client
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

PLUGIN_DIRECTORY = Path(__file__).parent.parent
MANIFEST_PATH = PLUGIN_DIRECTORY / "manifest.json"
INTEROP_VECTORS = json.loads((Path(__file__).parent / "vectors.json").read_text())

# Loaded by path, as FiestaBoard's loader does: the directory name differs
# between a checkout and an install, so there is no fixed package to import.
_module_spec = importlib.util.spec_from_file_location("retriever_plugin", PLUGIN_DIRECTORY / "__init__.py")
retriever = importlib.util.module_from_spec(_module_spec)
_module_spec.loader.exec_module(retriever)
RetrieverPlugin = retriever.RetrieverPlugin

# Whether FiestaBoard's formula engine gives a result with its type
# (evaluate_value). One that does not only renders text.
ENGINE_RETURNS_TYPES = retriever.evaluate_value is not None


def formula_number(value):
    """What a formula gives for a number: the number, or its text from an engine that only renders."""
    return value if ENGINE_RETURNS_TYPES else str(value)


SERVER_INFO_PATH, CONFIG_PATH, RETRIEVE_PATH = retriever.SERVER_INFO_PATH, retriever.CONFIG_PATH, retriever.RETRIEVE_PATH
TRANSPORT_KEY = bytes(range(32))
ENCODED_TRANSPORT_KEY = base64.b64encode(TRANSPORT_KEY).decode()
ANOTHER_TRANSPORT_KEY = bytes(range(1, 33))
CONFIG_FINGERPRINT = 7
SERVER_INFO = {"name": "FakeServer", "version": "9.9", "supported_protocol_version_range": {"min": 1, "max": 1}, "extra": ["anything", 1]}
SOURCE_SCHEMAS = {
    "reminders": {
        "type": "object",
        "properties": {"count": {"type": "integer"}, "items": {"type": "array"}},
        "default": {"count": 0, "items": []},
    }
}
SERVER_VALUES = {
    "reminders": {
        "error": "",
        "data": {
            "count": 1,
            "items": [{"title": "test0", "list": "Reminders", "due": "2026-10-05T06:15:00Z", "priority": 0}],
        },
    }
}
DEFAULT_REMINDERS = {"error": "", "data": {"count": 0, "items": []}}


def encrypt_message(transport_key, plaintext, associated_data):
    """One message in the wire format: nonce, ciphertext, tag. Written apart from the plugin's code, to check it."""
    nonce = os.urandom(12)
    return nonce + ChaCha20Poly1305(transport_key).encrypt(nonce, plaintext, associated_data)


class FakeServer:
    """A stand-in for RetrieverServer whose behaviour can be changed per test."""

    def __init__(self):
        self.transport_key = TRANSPORT_KEY
        self.config_fingerprint = CONFIG_FINGERPRINT
        self.server_info = SERVER_INFO
        self.source_schemas = SOURCE_SCHEMAS
        self.server_values = SERVER_VALUES
        self.refusals = {}  # endpoint path -> (status, reason): refuse requests to that endpoint
        self.delays = {}  # endpoint path -> seconds to wait before answering
        self.replacement_reply = None  # the response body instead: f(endpoint path, decrypted request) -> bytes
        self.requested_paths: list[str] = []
        self.requests: list[dict] = []
        self.request_bodies: list[bytes] = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                fake.requested_paths.append(self.path)
                fake.request_bodies.append(body)
                time.sleep(fake.delays.get(self.path, 0))
                if self.path not in (SERVER_INFO_PATH, CONFIG_PATH, RETRIEVE_PATH):
                    self.say_nothing()
                    return
                if self.path in fake.refusals:
                    self.answer(*fake.refusals[self.path])
                    return
                try:
                    associated_data = retriever.request_associated_data(self.path)
                    plaintext = ChaCha20Poly1305(fake.transport_key).decrypt(body[:12], body[12:], associated_data)
                except Exception:
                    self.say_nothing()
                    return
                request = json.loads(plaintext)
                fake.requests.append(request)
                if fake.replacement_reply:
                    self.answer(200, "OK", fake.replacement_reply(self.path, request))
                    return
                data = {SERVER_INFO_PATH: fake.server_info, CONFIG_PATH: fake.source_schemas, RETRIEVE_PATH: fake.server_values}[self.path]
                self.answer(200, "OK", fake.encrypted_response(self.path, {"request_id": request["request_id"], "config_fingerprint": fake.config_fingerprint, "data": data}))

            def say_nothing(self):
                """Close the connection without a response, as a server does for a request it cannot decrypt."""
                self.close_connection = True

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

    def encrypted_response(self, endpoint_path, message, transport_key=None):
        """A response body carrying *message*, as this server would send it from an endpoint, or under another key."""
        associated_data = retriever.response_associated_data(endpoint_path)
        return encrypt_message(transport_key or self.transport_key, json.dumps(message).encode(), associated_data)

    def refuse(self, status, reason, endpoint_paths=(SERVER_INFO_PATH, CONFIG_PATH, RETRIEVE_PATH)):
        """From now on answer requests to these endpoints with an HTTP status and nothing else."""
        self.refusals = dict.fromkeys(endpoint_paths, (status, reason))

    def stop(self):
        self._httpd.shutdown()
        self._httpd.server_close()


@pytest.fixture
def server():
    """A fake server, listening for as long as the test runs."""
    fake = FakeServer()
    yield fake
    fake.stop()


@pytest.fixture
def manifest():
    """The parsed manifest dict, as the loader passes it to the constructor."""
    with MANIFEST_PATH.open() as manifest_file:
        return json.load(manifest_file)


@pytest.fixture
def plugin(manifest, server):
    """A plugin set up to talk to the fake server, with no value rows."""
    plugin = RetrieverPlugin(manifest)
    plugin.config = {"server_url": server.url, "api_key": ENCODED_TRANSPORT_KEY}
    return plugin


def assert_fetch_failed(result, reason, values):
    """Templates still render: *values*, and the reason in ``error``."""
    assert result.available is True
    assert result.data == {**values, "error": result.data["error"]}
    assert result.data["error"].startswith(reason)
    assert result.error == result.data["error"]


def assert_retrieve_failed(result, reason):
    """The config is known, so reminders has its schema's default, and the server's info is kept."""
    assert_fetch_failed(result, reason, {"reminders": DEFAULT_REMINDERS, "server": SERVER_INFO})
    assert retriever.CONFIG_PENDING_SUFFIX not in result.error


def assert_config_pending(result, reason, values=None):
    """The server's info or config could not be read: only *values* are known, and the reason says so."""
    assert_fetch_failed(result, reason, values or {})
    assert result.error == f"{reason}; config pending"


class TestRetrieve:
    """One fetch against a server whose config is known: what templates see when it works and each way it fails."""

    def test_plugin_id(self, plugin):
        assert plugin.plugin_id == "retriever"

    def test_values_pass_through_unchanged(self, plugin):
        result = plugin.fetch_data()
        assert result.available is True
        assert result.error is None
        assert result.data == {**SERVER_VALUES, "server": SERVER_INFO, "error": ""}
        assert result.formatted_lines is None

    def test_a_source_with_its_own_error_passes_through(self, plugin, server):
        server.server_values = {"reminders": {"error": "Reminders could not be read", "data": DEFAULT_REMINDERS["data"]}}
        result = plugin.fetch_data()
        assert result.data == {**server.server_values, "server": SERVER_INFO, "error": ""}
        assert result.error is None

    def test_other_sources_pass_through(self, plugin, server):
        server.server_values = {**SERVER_VALUES, "calendar": {"error": "", "data": [1, "two", None]}}
        assert plugin.fetch_data().data["calendar"] == {"error": "", "data": [1, "two", None]}

    def test_request_carries_a_current_timestamp_and_a_fresh_id(self, plugin, server):
        plugin.fetch_data()
        request_ids = [request["request_id"] for request in server.requests]
        assert len(set(request_ids)) == len(request_ids) == 3
        for request in server.requests:
            assert set(request) - {"required_protocol_version"} == {"timestamp", "request_id"}
            assert abs(request["timestamp"] - time.time()) < 5
            assert len(request["request_id"]) == 32

    def test_every_request_has_a_new_nonce(self, plugin, server):
        plugin.fetch_data()
        plugin.fetch_data()
        nonces = [body[:12] for body in server.request_bodies]
        assert len(set(nonces)) == len(nonces) == 4

    def test_nothing_readable_is_sent(self, plugin, server):
        plugin.fetch_data()
        assert all(b"timestamp" not in body and TRANSPORT_KEY not in body for body in server.request_bodies)

    def test_trailing_slash_in_server_url(self, plugin, server):
        plugin.config = {"server_url": server.url + "/", "api_key": ENCODED_TRANSPORT_KEY}
        assert plugin.fetch_data().data["error"] == ""

    def test_fetch_reports_failure_by_raising(self, plugin, server):
        server.refuse(401, "Unauthorized")
        with pytest.raises(urllib.error.HTTPError):
            plugin._send_encrypted_request(server.url, RETRIEVE_PATH, TRANSPORT_KEY, time.monotonic() + 4)

    def test_fetch_past_its_deadline_raises_without_asking(self, plugin, server):
        with pytest.raises(TimeoutError):
            plugin._send_encrypted_request(server.url, RETRIEVE_PATH, TRANSPORT_KEY, time.monotonic() - 1)
        assert server.requested_paths == []

    def test_server_with_another_key_says_nothing(self, plugin, server):
        plugin.fetch_data()
        server.transport_key = ANOTHER_TRANSPORT_KEY
        assert_retrieve_failed(plugin.fetch_data(), "no response (wrong key?)")

    def test_wrong_key_from_the_start(self, plugin, server):
        server.transport_key = ANOTHER_TRANSPORT_KEY
        assert_config_pending(plugin.fetch_data(), "no response (wrong key?)")
        assert server.requested_paths == [SERVER_INFO_PATH]

    def test_refused_retrieve_shows_the_defaults_and_the_reason(self, plugin, server):
        plugin.fetch_data()
        server.refuse(400, "Stale Timestamp", [RETRIEVE_PATH])
        assert_retrieve_failed(plugin.fetch_data(), "400 Stale Timestamp")

    def test_failure_after_success_shows_no_reminders(self, plugin, server):
        assert plugin.fetch_data().data["reminders"]["data"]["count"] == 1
        server.refuse(500, "Internal Server Error", [RETRIEVE_PATH])
        assert_retrieve_failed(plugin.fetch_data(), "500 Internal Server Error")

    def test_recovers_after_failure(self, plugin, server):
        plugin.fetch_data()
        server.refuse(500, "Internal Server Error", [RETRIEVE_PATH])
        plugin.fetch_data()
        server.refusals = {}
        assert plugin.fetch_data().data == {**SERVER_VALUES, "server": SERVER_INFO, "error": ""}

    def test_unreachable_server_after_config(self, plugin, server):
        plugin.fetch_data()
        server.stop()
        assert_retrieve_failed(plugin.fetch_data(), "Connection refused")

    @pytest.mark.parametrize(
        ("reply", "reason"),
        [
            (lambda server, endpoint_path, request: server.encrypted_response(endpoint_path, {"request_id": request["request_id"], "config_fingerprint": CONFIG_FINGERPRINT, "data": SERVER_VALUES}, ANOTHER_TRANSPORT_KEY), "wrong key"),
            (lambda server, endpoint_path, request: server.encrypted_response(CONFIG_PATH, {"request_id": request["request_id"], "config_fingerprint": CONFIG_FINGERPRINT, "data": SERVER_VALUES}), "wrong key"),
            (lambda server, endpoint_path, request: server.request_bodies[-1], "wrong key"),
            (lambda server, endpoint_path, request: json.dumps({"request_id": request["request_id"], "config_fingerprint": CONFIG_FINGERPRINT, "data": SERVER_VALUES}).encode(), "wrong key"),
            (lambda server, endpoint_path, request: b"", "wrong key"),
            (lambda server, endpoint_path, request: encrypt_message(TRANSPORT_KEY, b"not json", retriever.response_associated_data(endpoint_path)), "not JSON"),
            (lambda server, endpoint_path, request: server.encrypted_response(endpoint_path, {"request_id": "0" * 32, "config_fingerprint": CONFIG_FINGERPRINT, "data": SERVER_VALUES}), "wrong ID"),
            (lambda server, endpoint_path, request: server.encrypted_response(endpoint_path, {"request_id": request["request_id"], "data": SERVER_VALUES}), "no config fingerprint"),
            (lambda server, endpoint_path, request: server.encrypted_response(endpoint_path, {"request_id": request["request_id"], "config_fingerprint": True, "data": SERVER_VALUES}), "no config fingerprint"),
            (lambda server, endpoint_path, request: server.encrypted_response(endpoint_path, {"request_id": request["request_id"], "config_fingerprint": CONFIG_FINGERPRINT}), "no data"),
        ],
        ids=[
            "sealed with another key",
            "sealed for the other endpoint",
            "request reflected",
            "plaintext",
            "empty",
            "not json",
            "another request's id",
            "no config fingerprint",
            "fingerprint not a number",
            "no data",
        ],
    )
    def test_a_response_that_is_not_the_servers_answer(self, plugin, server, reply, reason):
        plugin.fetch_data()
        server.replacement_reply = lambda path, request: reply(server, path, request)
        assert_retrieve_failed(plugin.fetch_data(), reason)

    def test_errors_never_contain_the_key(self, plugin, server, caplog):
        server.refuse(401, "Unauthorized")
        first = plugin.fetch_data()
        server.stop()
        second = plugin.fetch_data()
        assert ENCODED_TRANSPORT_KEY not in first.error + second.error + caplog.text


class TestServerConfig:
    """When the plugin reads the server's config, and what templates see before it has."""

    def test_config_is_read_once(self, plugin, server):
        plugin.fetch_data()
        plugin.fetch_data()
        plugin.fetch_data()
        assert server.requested_paths == [SERVER_INFO_PATH, CONFIG_PATH, RETRIEVE_PATH, RETRIEVE_PATH, RETRIEVE_PATH]

    @pytest.mark.parametrize("new_fingerprint", [CONFIG_FINGERPRINT + 1, CONFIG_FINGERPRINT - 1, 0])
    def test_config_is_read_again_when_the_fingerprint_changes(self, plugin, server, new_fingerprint):
        plugin.fetch_data()
        server.config_fingerprint = new_fingerprint
        server.source_schemas = {"reminders": {"type": "object", "default": {"count": -1}}}
        result = plugin.fetch_data()
        assert result.data == {**SERVER_VALUES, "server": SERVER_INFO, "error": ""}
        assert server.requested_paths == [SERVER_INFO_PATH, CONFIG_PATH, RETRIEVE_PATH, RETRIEVE_PATH, SERVER_INFO_PATH, CONFIG_PATH]

        plugin.fetch_data()
        assert server.requested_paths[6:] == [RETRIEVE_PATH]
        server.refuse(500, "Internal Server Error", [RETRIEVE_PATH])
        assert plugin.fetch_data().data["reminders"] == {"error": "", "data": {"count": -1}}

    def test_config_is_read_again_when_settings_are_saved(self, plugin, server):
        plugin.fetch_data()
        plugin.config = {"server_url": server.url, "api_key": ENCODED_TRANSPORT_KEY, "refresh_seconds": 120}
        plugin.fetch_data()
        assert server.requested_paths == [SERVER_INFO_PATH, CONFIG_PATH, RETRIEVE_PATH, SERVER_INFO_PATH, CONFIG_PATH, RETRIEVE_PATH]

    def test_defaults_come_from_the_servers_config(self, plugin, server):
        server.source_schemas = {
            "reminders": {"type": "object", "default": {"count": 0, "text": "NONE"}},
            "calendar": {"type": "array", "items": {"type": "string"}},
        }
        plugin.fetch_data()
        server.refuse(500, "Internal Server Error", [RETRIEVE_PATH])
        assert_fetch_failed(
            plugin.fetch_data(),
            "500 Internal Server Error",
            {
                "reminders": {"error": "", "data": {"count": 0, "text": "NONE"}},
                "calendar": {"error": "", "data": []},
                "server": SERVER_INFO,
            },
        )

    def test_no_source_is_known_before_the_config_is_read(self, plugin, server):
        server.refuse(401, "Unauthorized")
        assert_config_pending(plugin.fetch_data(), "401 Unauthorized")
        assert server.requested_paths == [SERVER_INFO_PATH]

    def test_unreachable_server_before_the_config_is_read(self, plugin, server):
        server.stop()
        assert_config_pending(plugin.fetch_data(), "Connection refused")

    def test_config_is_tried_again_on_the_next_fetch(self, plugin, server):
        server.refuse(500, "Internal Server Error", [CONFIG_PATH])
        assert_config_pending(plugin.fetch_data(), "500 Internal Server Error")
        server.refusals = {}
        assert plugin.fetch_data().data == {**SERVER_VALUES, "server": SERVER_INFO, "error": ""}
        assert server.requested_paths == [SERVER_INFO_PATH, CONFIG_PATH, SERVER_INFO_PATH, CONFIG_PATH, RETRIEVE_PATH]

    def test_values_are_kept_when_the_changed_config_cannot_be_read(self, plugin, server):
        plugin.fetch_data()
        server.config_fingerprint = CONFIG_FINGERPRINT + 1
        server.refuse(500, "Internal Server Error", [CONFIG_PATH])
        assert_config_pending(plugin.fetch_data(), "500 Internal Server Error", {**SERVER_VALUES, "server": SERVER_INFO})

        server.refusals = {}
        assert plugin.fetch_data().data == {**SERVER_VALUES, "server": SERVER_INFO, "error": ""}
        assert server.requested_paths == [SERVER_INFO_PATH, CONFIG_PATH, RETRIEVE_PATH, RETRIEVE_PATH, SERVER_INFO_PATH, CONFIG_PATH, RETRIEVE_PATH, SERVER_INFO_PATH, CONFIG_PATH]

    def test_a_config_response_cannot_be_passed_off_as_a_retrieve_response(self, plugin, server):
        plugin.fetch_data()
        server.replacement_reply = lambda path, request: server.encrypted_response(CONFIG_PATH, {"request_id": request["request_id"], "config_fingerprint": CONFIG_FINGERPRINT, "data": SOURCE_SCHEMAS})
        assert_retrieve_failed(plugin.fetch_data(), "wrong key")

    def test_all_requests_in_one_fetch_share_the_time_budget(self, plugin, server, monkeypatch):
        monkeypatch.setattr(retriever, "FETCH_TIME_LIMIT_SECONDS", 0.6)
        server.delays = {SERVER_INFO_PATH: 0.2, CONFIG_PATH: 0.2, RETRIEVE_PATH: 0.4}
        started = time.monotonic()
        result = plugin.fetch_data()
        assert time.monotonic() - started < 0.9
        assert_retrieve_failed(result, "timed out")

    def test_slow_config_before_the_config_is_read(self, plugin, server, monkeypatch):
        monkeypatch.setattr(retriever, "FETCH_TIME_LIMIT_SECONDS", 0.2)
        server.delays = {CONFIG_PATH: 0.5}
        assert_config_pending(plugin.fetch_data(), "timed out")


class TestServerInfo:
    """The server's own info, and the protocol version chosen from it."""

    def test_server_info_reaches_templates_unchanged(self, plugin, server):
        server.server_info = {**SERVER_INFO, "os": "macOS 26.6.2", "host": "example", "port": 42511, "nested": {"a": [1, 2]}}
        assert plugin.fetch_data().data["server"] == server.server_info

    def test_server_is_asked_before_config(self, plugin, server):
        plugin.fetch_data()
        assert server.requested_paths[:2] == [SERVER_INFO_PATH, CONFIG_PATH]

    def test_server_request_names_no_protocol_and_the_others_name_the_chosen_one(self, plugin, server):
        plugin.fetch_data()
        by_path = dict(zip(server.requested_paths, server.requests, strict=True))
        assert "required_protocol_version" not in by_path[SERVER_INFO_PATH]
        assert by_path[CONFIG_PATH]["required_protocol_version"] == 1
        assert by_path[RETRIEVE_PATH]["required_protocol_version"] == 1

    @pytest.mark.parametrize("offered", [{"min": 1, "max": 1}, {"min": 0, "max": 5}, {"min": 1, "max": 99}])
    def test_chooses_the_highest_protocol_both_sides_speak(self, plugin, server, offered, monkeypatch):
        monkeypatch.setattr(retriever, "SUPPORTED_PROTOCOL_VERSIONS", (1, 2, 3))
        server.server_info = {**SERVER_INFO, "supported_protocol_version_range": offered}
        plugin.fetch_data()
        assert server.requests[-1]["required_protocol_version"] == min(3, offered["max"])

    @pytest.mark.parametrize("offered", [{"min": 2, "max": 3}, {"min": 0, "max": 0}, {"min": 5, "max": 2}])
    def test_no_common_protocol(self, plugin, server, offered):
        server.server_info = {**SERVER_INFO, "supported_protocol_version_range": offered}
        assert_config_pending(plugin.fetch_data(), "no common protocol")
        assert server.requested_paths == [SERVER_INFO_PATH]

    @pytest.mark.parametrize(
        "info",
        [
            {"name": "x", "version": "1"},
            {"supported_protocol_version_range": [1, 1]},
            {"supported_protocol_version_range": {"min": 1}},
            {"supported_protocol_version_range": {"min": "1", "max": "1"}},
            {"supported_protocol_version_range": {"min": True, "max": True}},
        ],
    )
    def test_server_info_without_a_usable_protocol_range(self, plugin, server, info):
        server.server_info = info
        assert_config_pending(plugin.fetch_data(), "no protocol range in server info")
        assert server.requested_paths == [SERVER_INFO_PATH]

    def test_server_refuses_the_protocol(self, plugin, server):
        plugin.fetch_data()
        server.refuse(400, "Unsupported Protocol", [RETRIEVE_PATH])
        assert_retrieve_failed(plugin.fetch_data(), "400 Unsupported Protocol")

    def test_server_info_is_read_again_with_the_config(self, plugin, server):
        plugin.fetch_data()
        server.config_fingerprint = CONFIG_FINGERPRINT + 1
        server.server_info = {**SERVER_INFO, "version": "10.0"}
        assert plugin.fetch_data().data["server"]["version"] == "10.0"

    @pytest.mark.parametrize("name", ["error", "server"])
    def test_a_source_cannot_take_the_reserved_names(self, plugin, server, name):
        plugin.fetch_data()
        server.server_values = {**SERVER_VALUES, name: {"error": "", "data": "impostor"}}
        assert_retrieve_failed(plugin.fetch_data(), f"source named {name}: reserved name")

    @pytest.mark.parametrize("name", ["error", "server"])
    def test_a_config_cannot_list_the_reserved_names(self, plugin, server, name):
        server.source_schemas = {**SOURCE_SCHEMAS, name: {"type": "string"}}
        assert_config_pending(plugin.fetch_data(), f"source named {name}: reserved name")

    def test_server_info_may_use_those_names_itself(self, plugin, server):
        server.server_info = {**SERVER_INFO, "error": "none", "server": "this one"}
        data = plugin.fetch_data().data
        assert data["error"] == ""
        assert data["server"]["error"] == "none"


REMINDER_ITEMS = [
    {"title": "water plants", "list": "Home", "due": "2026-10-05T16:00:00Z", "priority": 1},
    {"title": "call dentist", "list": "Health", "due": "2026-10-05T18:30:00Z", "priority": 0},
]
FORMULA_CONTEXT = {
    "retriever": {
        "reminders": {"error": "", "data": {"count": 2, "items": REMINDER_ITEMS}},
        "music": {"error": "", "data": {"state": "playing", "title": "So What"}},
        "tags": {"error": "", "data": ["a", "b", "c"]},
        "server": {"name": "FakeServer"},
        "error": "",
    }
}


def value_rows(*pairs, default=""):
    """The Values setting as stored, from (name, definition) pairs that all share one default."""
    return [{"variable": name, "definition": definition, "default": default} for name, definition in pairs]


class TestValues:
    """Rows that name a value and define it by an expression over the server's values."""

    @pytest.mark.parametrize(
        ("definition", "value"),
        [
            ("retriever.reminders.data.count", 2),
            ("retriever.reminders.data.items", REMINDER_ITEMS),
            ("retriever.reminders.data", {"count": 2, "items": REMINDER_ITEMS}),
            ("retriever.reminders.data.items.1.title", "call dentist"),
            ("retriever.reminders.data.items[1].title", "call dentist"),
            ("  retriever.error  ", ""),
        ],
    )
    def test_a_definition_that_is_only_a_path_keeps_the_values_type(self, definition, value):
        assert retriever.build_user_variables(value_rows(("v", definition)), FORMULA_CONTEXT) == {"v": value}

    @pytest.mark.parametrize(
        ("definition", "value"),
        [
            ("UPPER(retriever.reminders.data.items[0].title)", "WATER PLANTS"),
            ("retriever.reminders.data.count + 1", formula_number(3)),
            ('COUNT(retriever.reminders.data.items) & " due"', "2 due"),
            ('IF(retriever.error = "", "ok", retriever.error)', "ok"),
            ('JOIN(retriever.reminders.data.items, ", ", "title")', "water plants, call dentist"),
        ],
    )
    def test_any_other_definition_is_a_formula(self, definition, value):
        assert retriever.build_user_variables(value_rows(("v", definition)), FORMULA_CONTEXT) == {"v": value}

    @pytest.mark.parametrize(
        ("definition", "code"),
        [
            ("retriever.reminders.data.items.9.title", "#REF"),
            ("retriever.nosuch", "#REF"),
            ("reminders.data.count", "#REF"),
            ("weather.temperature", "#REF"),
            ("UPPER(retriever.reminders.data.items[9].title)", "#REF"),
            ("retriever.reminders.data.count +", "#SYNTAX" if ENGINE_RETURNS_TYPES else "#SYNTAX:32"),
        ],
    )
    def test_a_failed_definition_gives_its_default_or_else_the_error_code(self, definition, code):
        assert retriever.build_user_variables(value_rows(("v", definition)), FORMULA_CONTEXT) == {"v": code}
        assert retriever.build_user_variables(value_rows(("v", definition), default="none"), FORMULA_CONTEXT) == {"v": "none"}

    def test_a_null_is_no_value(self):
        context = {"retriever": {"s": {"error": "", "data": {"nothing": None, "items": [{"t": None}, {"t": "b"}]}}}}
        assert retriever.build_user_variables(value_rows(("v", "retriever.s.data.nothing"), default="none"), context) == {"v": "none"}
        assert retriever.build_user_variables(value_rows(("v", "retriever.s.data.nothing")), context) == {"v": None}
        assert retriever.build_user_variables(value_rows(("l[x]", "retriever.s.data.items[x].t"), default="-"), context) == {"l": ["-", "b"]}
        assert retriever.build_user_variables(value_rows(("v", "UPPER(retriever.s.data.nothing)"), default="none"), context) == {"v": "none"}

    def test_a_list_that_is_missing_is_an_empty_list_whatever_the_default(self):
        assert retriever.build_user_variables(value_rows(("l[x]", "retriever.nosuch.data[x]"), default="none"), FORMULA_CONTEXT) == {"l": []}

    def test_text_that_reads_like_an_error_is_text(self):
        """Only an engine that gives types can tell; one that renders text shows the same for both."""
        context = {"retriever": {"s": {"error": "", "data": {"text": "#REF"}}}}
        assert retriever.build_user_variables(value_rows(("v", "retriever.s.data.text"), default="none"), context) == {"v": "#REF"}
        formula = value_rows(("v", 'retriever.s.data.text & ""'), default="none")
        assert retriever.build_user_variables(formula, context) == {"v": "#REF" if ENGINE_RETURNS_TYPES else "none"}

    @pytest.mark.skipif(not ENGINE_RETURNS_TYPES, reason="needs an engine that gives a result its type")
    def test_a_formulas_result_keeps_its_type(self):
        defined = retriever.build_user_variables(
            value_rows(
                ("whole", "retriever.reminders.data.count * 3"),
                ("part", "retriever.reminders.data.count / 4"),
                ("truth", "retriever.reminders.data.count > 1"),
                ("text", 'retriever.reminders.data.count & ""'),
                ("urgent", "FILTER(retriever.reminders.data.items, item.priority > 0)"),
                ("day", 'DATE("2026-12-25")'),
            ),
            FORMULA_CONTEXT,
        )
        assert defined == {"whole": 6, "part": 0.5, "truth": True, "text": "2", "urgent": [REMINDER_ITEMS[0]], "day": "2026-12-25 00:00"}
        assert type(defined["whole"]) is int

    def test_a_default_is_not_used_when_the_definition_works(self):
        assert retriever.build_user_variables(value_rows(("v", "retriever.reminders.data.count"), default="none"), FORMULA_CONTEXT) == {"v": 2}
        assert retriever.build_user_variables(value_rows(("v", "retriever.error"), default="none"), FORMULA_CONTEXT) == {"v": ""}
        # Text that merely starts with # is a result, not an error.
        assert retriever.build_user_variables(value_rows(("v", '"#1 of " & retriever.reminders.data.count'), default="none"), FORMULA_CONTEXT) == {
            "v": "#1 of 2"
        }

    def test_a_list_of_objects_is_built_field_by_field(self):
        defined = retriever.build_user_variables(
            value_rows(
                ("todo[x].what", "retriever.reminders.data.items[x].title"),
                ("todo[x].shout", "UPPER(retriever.reminders.data.items[x].title)"),
                ("todo[x].urgent", 'IF(retriever.reminders.data.items[x].priority = 1, "!", "")'),
            ),
            FORMULA_CONTEXT,
        )
        assert defined == {
            "todo": [
                {"what": "water plants", "shout": "WATER PLANTS", "urgent": "!"},
                {"what": "call dentist", "shout": "CALL DENTIST", "urgent": ""},
            ]
        }

    def test_a_list_of_plain_values(self):
        assert retriever.build_user_variables(value_rows(("titles[x]", "retriever.reminders.data.items[x].title")), FORMULA_CONTEXT) == {
            "titles": ["water plants", "call dentist"]
        }
        assert retriever.build_user_variables(value_rows(("letters[x]", "UPPER(retriever.tags.data[x])")), FORMULA_CONTEXT) == {
            "letters": ["A", "B", "C"]
        }

    def test_a_list_element_keeps_its_type_when_the_definition_is_only_a_path(self):
        assert retriever.build_user_variables(value_rows(("p[x]", "retriever.reminders.data.items[x].priority")), FORMULA_CONTEXT) == {"p": [1, 0]}
        assert retriever.build_user_variables(value_rows(("whole[x]", "retriever.reminders.data.items[x]")), FORMULA_CONTEXT) == {"whole": REMINDER_ITEMS}

    def test_two_lists_in_one_definition_give_as_many_elements_as_the_shorter(self):
        defined = retriever.build_user_variables(
            value_rows(("pair[x]", 'retriever.tags.data[x] & ":" & retriever.reminders.data.items[x].title')), FORMULA_CONTEXT
        )
        assert defined == {"pair": ["a:water plants", "b:call dentist"]}

    @pytest.mark.parametrize(
        "definition",
        ["retriever.reminders.data.count", "retriever.nosuch[x].title", "retriever.reminders.data[x]", '"fixed"'],
    )
    def test_a_list_with_nothing_to_index_is_empty(self, definition):
        assert retriever.build_user_variables(value_rows(("empty[x].f", definition)), FORMULA_CONTEXT) == {"empty": []}

    def test_a_missing_field_in_one_element_gets_the_default(self):
        context = {"retriever": {"things": {"data": [{"name": "a"}, {}]}}}
        defined = retriever.build_user_variables(value_rows(("t[x].name", "retriever.things.data[x].name"), default="?"), context)
        assert defined == {"t": [{"name": "a"}, {"name": "?"}]}

    def test_definitions_read_the_servers_values_never_another_rows(self):
        """So rows cannot depend on each other, and their order does not matter."""
        both = value_rows(("a", "retriever.reminders.data.count"), ("b", "retriever.a"))
        assert retriever.build_user_variables(both, FORMULA_CONTEXT) == {"a": 2, "b": "#REF"}
        assert retriever.build_user_variables(both[::-1], FORMULA_CONTEXT) == {"a": 2, "b": "#REF"}

    def test_a_row_may_take_a_servers_name_and_still_be_defined_from_it(self):
        defined = retriever.build_user_variables(value_rows(("reminders[x]", "retriever.reminders.data.items[x].title")), FORMULA_CONTEXT)
        assert defined == {"reminders": ["water plants", "call dentist"]}

    @pytest.mark.parametrize(
        "junk",
        [None, "", "not rows", 7, [None, "x", 7, {}, {"variable": "v"}, {"definition": "1"}, {"variable": "9bad", "definition": "1"}]],
    )
    def test_rows_that_are_not_rows_define_nothing(self, junk):
        assert retriever.build_user_variables(junk, FORMULA_CONTEXT) == {}

    @pytest.mark.parametrize(
        ("name", "parsed"),
        [
            ("due", ("due", [])),
            (" due_today2 ", ("due_today2", [])),
            ("todo[x]", ("todo", [("element", "x")])),
            ("todo[x].what", ("todo", [("element", "x"), ("field", "what")])),
            ("todo[row].a.b", ("todo", [("element", "row"), ("field", "a"), ("field", "b")])),
            ("grid[x][y]", ("grid", [("element", "x"), ("element", "y")])),
            (
                "lists[x].items[y].what",
                ("lists", [("element", "x"), ("field", "items"), ("element", "y"), ("field", "what")]),
            ),
            ("reminders.count", ("reminders", [("field", "count")])),
            ("a.b.c", ("a", [("field", "b"), ("field", "c")])),
            ("mine.list[x].what", ("mine", [("field", "list"), ("element", "x"), ("field", "what")])),
            ("todo.", None),
            (".todo", None),
            ("todo..what", None),
            ("retriever.reminders.data.items[0].title", None),
            ("todo[0].what", None),
            ("todo[*].what", None),
            ("todo[x].items[x]", None),  # one parameter cannot be two positions
            ("todo[retriever]", None),
            ("2do", None),
            ("", None),
            (None, None),
        ],
    )
    def test_names(self, name, parsed):
        assert retriever.parse_variable_name(name) == parsed


NESTED_LISTS_CONTEXT = {
    "retriever": {
        "todo": {
            "error": "",
            "data": {
                "lists": [
                    {"name": "Home", "items": [{"title": "water plants"}, {"title": "feed cat"}]},
                    {"name": "Work", "items": [{"title": "send report"}]},
                    {"name": "Empty", "items": []},
                ]
            },
        }
    }
}


class TestObjects:
    """A name with dots puts the value inside an object."""

    def test_rows_build_an_object_field_by_field(self):
        defined = retriever.build_user_variables(
            value_rows(
                ("mine.count", "retriever.reminders.data.count"),
                ("mine.next", "UPPER(retriever.reminders.data.items[0].title)"),
                ("mine.deep.er", "retriever.music.data.state"),
            ),
            FORMULA_CONTEXT,
        )
        assert defined == {"mine": {"count": 2, "next": "WATER PLANTS", "deep": {"er": "playing"}}}

    def test_a_field_of_one_of_the_servers_objects_is_added_to_it(self):
        """reminders.count sits beside reminders.error and reminders.data, which stay as sent."""
        defined = retriever.build_user_variables(
            value_rows(("reminders.count", "retriever.reminders.data.count"), ("reminders.next", "retriever.reminders.data.items[0].title")),
            FORMULA_CONTEXT,
        )
        assert defined == {
            "reminders": {"error": "", "data": {"count": 2, "items": REMINDER_ITEMS}, "count": 2, "next": "water plants"}
        }

    def test_the_servers_own_value_is_never_changed(self):
        before = json.dumps(FORMULA_CONTEXT, sort_keys=True)
        retriever.build_user_variables(value_rows(("reminders.data.count", '"overwritten"'), ("reminders.count", "1")), FORMULA_CONTEXT)
        assert json.dumps(FORMULA_CONTEXT, sort_keys=True) == before

    def test_a_field_can_replace_one_the_server_sent(self):
        defined = retriever.build_user_variables(value_rows(("reminders.error", '"mine"'), ("reminders.data.count", "retriever.reminders.data.count + 10")), FORMULA_CONTEXT)
        assert defined["reminders"]["error"] == "mine"
        assert defined["reminders"]["data"] == {"count": formula_number(12), "items": REMINDER_ITEMS}

    def test_a_list_inside_an_object(self):
        defined = retriever.build_user_variables(value_rows(("mine.todo[x].what", "retriever.reminders.data.items[x].title")), FORMULA_CONTEXT)
        assert defined == {"mine": {"todo": [{"what": "water plants"}, {"what": "call dentist"}]}}

    def test_taking_a_servers_name_outright_still_replaces_it(self):
        assert retriever.build_user_variables(value_rows(("reminders", "retriever.reminders.data.count")), FORMULA_CONTEXT) == {"reminders": 2}
        assert retriever.build_user_variables(value_rows(("reminders[x]", "retriever.reminders.data.items[x].title")), FORMULA_CONTEXT) == {
            "reminders": ["water plants", "call dentist"]
        }


class TestListParameters:
    """A parameter in brackets is the position of each element: an index in brackets, a number when bare."""

    def test_a_parameter_is_a_number_in_the_definition(self):
        defined = retriever.build_user_variables(
            value_rows(
                ("todo[x].line", '(x + 1) & ". " & retriever.reminders.data.items[x].title'),
                ("todo[x].position", "x"),
                ("todo[x].last", 'IF(x = COUNT(retriever.reminders.data.items) - 1, "last", "")'),
            ),
            FORMULA_CONTEXT,
        )
        assert defined == {
            "todo": [
                {"line": "1. water plants", "position": formula_number(0), "last": ""},
                {"line": "2. call dentist", "position": formula_number(1), "last": "last"},
            ]
        }

    def test_the_parameters_name_is_the_users_choice(self):
        defined = retriever.build_user_variables(
            value_rows(("todo[row].n", "row + 1"), ("todo[row].what", "retriever.reminders.data.items[row].title")), FORMULA_CONTEXT
        )
        assert defined == {"todo": [{"n": formula_number(1), "what": "water plants"}, {"n": formula_number(2), "what": "call dentist"}]}

    def test_a_row_that_indexes_nothing_adds_to_the_elements_the_other_rows_gave(self):
        """Brackets decide how many elements there are; a row without them cannot say."""
        assert retriever.build_user_variables(value_rows(("n[x]", "x + 1")), FORMULA_CONTEXT) == {"n": []}
        both = value_rows(("todo[x].n", "x + 1"), ("todo[x].what", "retriever.reminders.data.items[x].title"))
        expected = {"todo": [{"what": "water plants", "n": formula_number(1)}, {"what": "call dentist", "n": formula_number(2)}]}
        assert retriever.build_user_variables(both, FORMULA_CONTEXT) == expected
        assert retriever.build_user_variables(both[::-1], FORMULA_CONTEXT) == expected  # whichever order the rows are in

    def test_lists_nest_each_with_its_own_parameter(self):
        defined = retriever.build_user_variables(
            value_rows(
                ("lists[x].name", "retriever.todo.data.lists[x].name"),
                ("lists[x].items[y].what", "retriever.todo.data.lists[x].items[y].title"),
                ("lists[x].items[y].label", '(x + 1) & "." & (y + 1) & " " & UPPER(retriever.todo.data.lists[x].items[y].title)'),
            ),
            NESTED_LISTS_CONTEXT,
        )
        assert defined == {
            "lists": [
                {
                    "name": "Home",
                    "items": [
                        {"what": "water plants", "label": "1.1 WATER PLANTS"},
                        {"what": "feed cat", "label": "1.2 FEED CAT"},
                    ],
                },
                {"name": "Work", "items": [{"what": "send report", "label": "2.1 SEND REPORT"}]},
                {"name": "Empty", "items": []},
            ]
        }

    def test_a_list_of_lists(self):
        defined = retriever.build_user_variables(value_rows(("grid[x][y]", "retriever.todo.data.lists[x].items[y].title")), NESTED_LISTS_CONTEXT)
        assert defined == {"grid": [["water plants", "feed cat"], ["send report"], []]}

    def test_an_inner_list_of_plain_values(self):
        defined = retriever.build_user_variables(value_rows(("lists[x].titles[y]", "retriever.todo.data.lists[x].items[y].title")), NESTED_LISTS_CONTEXT)
        assert defined == {
            "lists": [{"titles": ["water plants", "feed cat"]}, {"titles": ["send report"]}, {"titles": []}]
        }

    def test_fields_below_a_parameter_may_nest(self):
        defined = retriever.build_user_variables(value_rows(("lists[x].info.name", "retriever.todo.data.lists[x].name")), NESTED_LISTS_CONTEXT)
        assert defined == {"lists": [{"info": {"name": "Home"}}, {"info": {"name": "Work"}}, {"info": {"name": "Empty"}}]}

    def test_the_outer_parameter_can_be_used_inside_the_inner_list(self):
        defined = retriever.build_user_variables(
            value_rows(("lists[x].items[y]", 'retriever.todo.data.lists[x].name & ": " & retriever.todo.data.lists[x].items[y].title')),
            NESTED_LISTS_CONTEXT,
        )
        assert defined["lists"][0] == {"items": ["Home: water plants", "Home: feed cat"]}

    def test_a_bare_parameter_keeps_working_beside_a_pure_path(self):
        """A definition that is only the parameter is a number, not a path to look up."""
        assert retriever.build_user_variables(value_rows(("p[x]", "x")), {"retriever": {}, "x": "wrong"}) == {"p": []}
        defined = retriever.build_user_variables(value_rows(("p[x].i", "x"), ("p[x].t", "retriever.tags.data[x]")), FORMULA_CONTEXT)
        assert defined == {"p": [{"i": formula_number(0), "t": "a"}, {"i": formula_number(1), "t": "b"}, {"i": formula_number(2), "t": "c"}]}


class TestValueRowErrors:
    """What the settings form is told about rows that cannot be used."""

    @pytest.mark.parametrize(
        "good",
        [
            None,
            [],
            value_rows(("due", "retriever.reminders.data.count")),
            value_rows(("first", "UPPER(retriever.reminders.data.items[0].title)")),
            value_rows(("todo[x].what", "retriever.reminders.data.items[x].title"), ("todo[x].when", "retriever.reminders.data.items[x].due")),
            value_rows(("titles[x]", "UPPER(retriever.reminders.data.items[x].title)")),
            value_rows(("todo[x].line", '(x + 1) & ". " & retriever.reminders.data.items[x].title')),
            value_rows(("lists[x].items[y].what", "retriever.todo.data.lists[x].items[y].title")),
            value_rows(("grid[row][col]", '(row + col) & retriever.a.data[row].b[col]')),
            value_rows(("todo[x].n", "x + 1"), ("todo[x].what", "retriever.reminders.data.items[x].title")),
            value_rows(("reminders.count", "retriever.reminders.data.count"), ("reminders.next", "retriever.reminders.data.items[0].title")),
            value_rows(("mine.count", "retriever.reminders.data.count"), ("mine.todo[x]", "retriever.reminders.data.items[x].title")),
        ],
    )
    def test_good_rows(self, good):
        assert retriever.value_row_errors(good) == []

    @pytest.mark.parametrize(
        ("bad", "words"),
        [
            ("rows", "must be a list"),
            (["x"], "is not a row"),
            (value_rows(("2do", "1")), "'2do' is not a name"),
            (value_rows(("todo.x.what", "retriever.a[x]")), "[x] in the definition needs [x] in the name"),
            (value_rows(("todo[0].what", "retriever.a")), "'todo[0].what' is not a name"),
            (value_rows(("due", "1"), ("due.soon", "2")), "due is defined both as a single value and as an object"),
            (value_rows(("todo.n", "1"), ("todo[x]", "retriever.a[x]")), "todo is defined both as an object and as a list"),
            (value_rows(("", "retriever.reminders.data.count")), "Value 1 has no name"),
            (value_rows(("  ", "retriever.reminders.data.count")), "Value 1 has no name"),
            (value_rows(("retriever.reminders.data.count", "retriever.reminders.data.count")), "the expression goes in the definition"),
            (value_rows(("due", "")), "has no definition"),
            (value_rows(("todo[x]", "retriever.reminders.data.count")), "must index a list with [x]"),
            (value_rows(("todo[x]", "x + 1")), "must index a list with [x]"),
            (value_rows(("due", "retriever.reminders.data.items[x].title")), "needs [x] in the name"),
            (value_rows(("todo[x]", "retriever.a[x].b[y]")), "[y] in the definition needs [y] in the name"),
            (value_rows(("todo[x].items[y]", "retriever.a[x].b")), "must index a list with [y]"),
            (value_rows(("todo[x].items[x]", "retriever.a[x]")), "each parameter used once"),
            (value_rows(("todo[*]", "retriever.a[*]")), "'todo[*]' is not a name"),
            (value_rows(("todo[x]", "retriever.a[x] +")), "'todo[x]'"),
            (value_rows(("due", "retriever.reminders.data.count +")), "'due'"),
            (value_rows(("due", "NOSUCHFUNCTION(1)")), "NOSUCHFUNCTION"),
            (value_rows(("todo", "1"), ("todo[x]", "retriever.a[x]")), "todo is defined both as a single value and as a list"),
        ],
    )
    def test_bad_rows(self, bad, words):
        errors = retriever.value_row_errors(bad)
        assert errors and any(words in error for error in errors), errors

    def test_bad_rows_are_reported_when_settings_are_saved(self, manifest):
        plugin = RetrieverPlugin(manifest)
        config = {"server_url": "http://192.0.2.10:42511", "api_key": ENCODED_TRANSPORT_KEY, "values": value_rows(("2do", "1"))}
        assert any("'2do' is not a name" in error for error in plugin.validate_config(config))


class TestValuesInAFetch:
    """The user's variables as templates see them, beside the server's, when a fetch works and when it fails."""

    def use_value_rows(self, plugin, server, *pairs, default=""):
        """Give the plugin these value rows, as saving its settings would."""
        plugin.config = {"server_url": server.url, "api_key": ENCODED_TRANSPORT_KEY, "values": value_rows(*pairs, default=default)}

    def test_defined_values_sit_beside_the_servers(self, plugin, server):
        self.use_value_rows(
            plugin,
            server,
            ("due", "retriever.reminders.data.count"),
            ("first", "UPPER(retriever.reminders.data.items[0].title)"),
            ("todo[x].what", "retriever.reminders.data.items[x].title"),
            ("who", "retriever.server.name"),
        )
        data = plugin.fetch_data().data
        assert data == {
            **SERVER_VALUES,
            "server": SERVER_INFO,
            "error": "",
            "due": 1,
            "first": "TEST0",
            "todo": [{"what": "test0"}],
            "who": "FakeServer",
        }

    def test_on_a_name_clash_the_users_value_wins(self, plugin, server):
        self.use_value_rows(
            plugin,
            server,
            ("reminders[x]", "retriever.reminders.data.items[x].title"),
            ("error", 'IF(retriever.error = "", "all well", retriever.error)'),
            ("server", "retriever.server.version"),
        )
        result = plugin.fetch_data()
        assert result.data == {"reminders": ["test0"], "error": "all well", "server": "9.9"}
        assert result.error is None  # what FiestaBoard itself is told is not the user's to redefine

    def test_values_are_defined_from_the_defaults_after_a_failed_retrieve(self, plugin, server):
        self.use_value_rows(
            plugin,
            server,
            ("due", "retriever.reminders.data.count"),
            ("first", "retriever.reminders.data.items[0].title"),
            ("todo[x].what", "retriever.reminders.data.items[x].title"),
            ("problem", "retriever.error"),
            default="-",
        )
        plugin.fetch_data()
        server.refuse(500, "Internal Server Error", [RETRIEVE_PATH])
        result = plugin.fetch_data()
        assert result.data["due"] == 0
        assert result.data["first"] == "-"
        assert result.data["todo"] == []
        assert result.data["problem"] == "500 Internal Server Error"
        assert result.error == "500 Internal Server Error"

    def test_values_exist_even_before_the_server_has_been_read(self, plugin, server):
        self.use_value_rows(plugin, server, ("due", "retriever.reminders.data.count"), ("problem", "retriever.error"), default="?")
        server.stop()
        data = plugin.fetch_data().data
        assert data == {"error": "Connection refused; config pending", "due": "?", "problem": "Connection refused; config pending"}

    def test_a_bad_row_does_not_stop_the_fetch(self, plugin, server):
        self.use_value_rows(plugin, server, ("2do", "1"), ("oops", "retriever.reminders.data.count +"), ("due", "retriever.reminders.data.count"))
        result = plugin.fetch_data()
        assert result.available is True
        assert result.data["due"] == 1
        assert result.data["oops"].startswith("#SYNTAX")
        assert "2do" not in result.data


class TestPreview:
    """The text for the settings form's "Test & Preview", which core cannot fetch for itself."""

    def test_preview_is_the_servers_values_under_the_name_definitions_use(self, plugin, server):
        document = json.loads(plugin.get_preview_text())
        assert document == {"retriever": {**SERVER_VALUES, "server": SERVER_INFO, "error": ""}}
        assert server.requested_paths == [SERVER_INFO_PATH, RETRIEVE_PATH]

    def test_a_path_from_the_preview_is_a_definition_that_works(self, plugin, server):
        document = json.loads(plugin.get_preview_text())
        # What clicking a value in the preview's tree puts in a row.
        clicked = "retriever.reminders.data.items[0].title"
        assert retriever.build_user_variables(value_rows(("t", clicked)), document) == {"t": "test0"}

    def test_preview_uses_the_settings_it_is_given_and_changes_nothing(self, plugin, server):
        plugin.fetch_data()
        before = plugin._server_self_description
        calls = len(server.requested_paths)
        plugin.get_preview_text()
        assert plugin._server_self_description is before
        assert server.requested_paths[calls:] == [SERVER_INFO_PATH, RETRIEVE_PATH]

    @pytest.mark.parametrize("config", [{}, {"server_url": "http://192.0.2.10:42511"}, {"api_key": ENCODED_TRANSPORT_KEY}])
    def test_preview_asks_for_the_settings_it_needs(self, manifest, config):
        plugin = RetrieverPlugin(manifest)
        plugin._config = config
        with pytest.raises(retriever.PreviewUnavailable, match="Enter the server URL and API key first"):
            plugin.get_preview_text()

    def test_preview_says_why_the_server_gave_nothing(self, plugin, server):
        server.transport_key = ANOTHER_TRANSPORT_KEY
        with pytest.raises(retriever.PreviewUnavailable, match=r"no response \(wrong key\?\)"):
            plugin.get_preview_text()
        server.stop()
        with pytest.raises(retriever.PreviewUnavailable, match="Connection refused"):
            plugin.get_preview_text()

    def test_the_reason_never_contains_the_key(self, plugin, server):
        server.refuse(400, "Stale Timestamp")
        with pytest.raises(retriever.PreviewUnavailable) as raised:
            plugin.get_preview_text()
        assert ENCODED_TRANSPORT_KEY not in str(raised.value)
        assert str(raised.value) == "400 Stale Timestamp"


class TestFailureReason:
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
            (http.client.RemoteDisconnected("Remote end closed connection without response"), "no response (wrong key?)"),
            (ConnectionResetError(54, "Connection reset by peer"), "no response (wrong key?)"),
            (urllib.error.URLError(ConnectionResetError(54, "Connection reset by peer")), "no response (wrong key?)"),
        ],
    )
    def test_reason(self, error, reason):
        assert retriever.failure_reason(error) == reason


class TestDefaultValueForSchema:
    """What is shown for a source when its value could not be retrieved."""

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
        assert retriever.default_value_for_schema(schema) == value


class TestInterop:
    """Messages sealed by one side must open on the other."""

    key = base64.b64decode(INTEROP_VECTORS["key"])

    @pytest.mark.parametrize("path", [SERVER_INFO_PATH, CONFIG_PATH, RETRIEVE_PATH])
    def test_opens_a_response_sealed_by_the_server(self, path):
        vector = INTEROP_VECTORS["responses_from_server"][path]
        fingerprint, data = retriever.decrypt_response(self.key, bytes.fromhex(vector["body"]), vector["request_id"], path)
        assert (fingerprint, data) == (vector["config_fingerprint"], vector["data"])

    def test_the_servers_config_gives_every_source_a_default(self):
        """Whatever sources the vectors hold: the plugin's defaults come from the config alone."""
        sources = INTEROP_VECTORS["responses_from_server"][CONFIG_PATH]["data"]
        values = INTEROP_VECTORS["responses_from_server"][RETRIEVE_PATH]["data"]
        assert set(sources) == set(values)
        for name, schema in sources.items():
            assert retriever.default_value_for_schema(schema) == schema["default"]
            assert set(values[name]) == {"error", "data"}

    @pytest.mark.parametrize("path", [SERVER_INFO_PATH, CONFIG_PATH, RETRIEVE_PATH])
    def test_request_vector_is_what_the_plugin_seals(self, path):
        """The server's tests open this body; check here that it is still a current-format request."""
        vector = INTEROP_VECTORS["requests_from_plugin"][path]
        body = bytes.fromhex(vector["body"])
        plaintext = ChaCha20Poly1305(self.key).decrypt(body[:12], body[12:], retriever.request_associated_data(path))
        expected = {"timestamp": vector["timestamp"], "request_id": vector["request_id"]}
        if "required_protocol_version" in vector:
            expected["required_protocol_version"] = vector["required_protocol_version"]
        assert json.loads(plaintext) == expected

        fresh, request_id = retriever.encrypt_request(self.key, vector["timestamp"], path, vector.get("required_protocol_version"))
        plaintext = ChaCha20Poly1305(self.key).decrypt(fresh[:12], fresh[12:], retriever.request_associated_data(path))
        assert json.loads(plaintext) == {**expected, "request_id": request_id}


class TestConnectionSettings:
    """The server URL and the key, checked without reaching the server."""

    @pytest.mark.parametrize(
        "config",
        [
            {},
            {"server_url": "http://192.0.2.10:42511"},
            {"api_key": ENCODED_TRANSPORT_KEY},
            {"server_url": "  ", "api_key": ENCODED_TRANSPORT_KEY},
            {"server_url": "192.0.2.10:42511", "api_key": ENCODED_TRANSPORT_KEY},
            {"server_url": "file:///etc/passwd", "api_key": ENCODED_TRANSPORT_KEY},
            {"server_url": 42511, "api_key": ENCODED_TRANSPORT_KEY},
            {"server_url": "http://192.0.2.10:42511", "api_key": "not base64!"},
            {"server_url": "http://192.0.2.10:42511", "api_key": base64.b64encode(bytes(16)).decode()},
            {"server_url": "http://192.0.2.10:42511", "api_key": 42},
        ],
    )
    def test_invalid_config(self, manifest, config):
        plugin = RetrieverPlugin(manifest)
        assert plugin.validate_config(config)
        plugin.config = config
        result = plugin.fetch_data()
        assert result.available is False
        assert result.error
        assert ENCODED_TRANSPORT_KEY not in result.error

    def test_a_key_stored_under_its_old_name_still_works(self, manifest, server):
        plugin = RetrieverPlugin(manifest)
        former_settings = {"server_url": server.url, "key": ENCODED_TRANSPORT_KEY}
        assert plugin.validate_config(former_settings) == []
        plugin.config = former_settings
        assert plugin.fetch_data().data["error"] == ""
        assert json.loads(plugin.get_preview_text())["retriever"]["error"] == ""

    def test_the_new_name_wins_over_the_old(self, manifest, server):
        plugin = RetrieverPlugin(manifest)
        plugin.config = {"server_url": server.url, "api_key": ENCODED_TRANSPORT_KEY, "key": base64.b64encode(bytes(32)).decode()}
        assert plugin.fetch_data().data["error"] == ""

    def test_valid_config(self, manifest):
        plugin = RetrieverPlugin(manifest)
        assert plugin.validate_config({"server_url": "http://192.0.2.10:42511", "api_key": f" {ENCODED_TRANSPORT_KEY}\n"}) == []


class TestManifest:
    """The manifest as FiestaBoard reads it."""

    def test_manifest_parses(self, manifest):
        assert PluginManifest.from_dict(manifest).id == "retriever"

    def test_manifest_is_valid(self, manifest):
        valid, errors = validate_manifest(manifest)
        assert valid, errors

    def test_settings(self, manifest):
        schema = manifest["settings_schema"]
        assert schema["required"] == ["server_url", "api_key"]
        assert schema["properties"]["api_key"]["ui:widget"] == "password"
        assert "token" not in schema["properties"]

    def test_the_key_setting_has_a_name_fiestaboard_hides(self, manifest):
        """FiestaBoard masks a setting in its API and forms by name alone; the password widget does not."""
        from src.config_manager import SENSITIVE_FIELDS

        assert retriever.TRANSPORT_KEY_SETTING in SENSITIVE_FIELDS
        assert retriever.TRANSPORT_KEY_SETTING in manifest["settings_schema"]["properties"]
        assert retriever.FORMER_TRANSPORT_KEY_SETTING not in manifest["settings_schema"]["properties"]

    @pytest.mark.parametrize(("device_type", "rows"), [("flagship", 6), ("note", 3)])
    def test_demo_page_per_board(self, manifest, device_type, rows):
        demo = PluginManifest.from_dict(manifest).demo[device_type]
        assert len(demo.template) == rows
        assert len(demo.line_metadata) == rows

    def test_values_are_edited_with_the_mapper_and_previewed_by_the_plugin(self, manifest):
        field = manifest["settings_schema"]["properties"]["values"]
        assert field["ui:widget"] == "json-path-mapper"
        assert field["ui:options"]["preview"] == "plugin"
        assert field["ui:options"]["keys"] == {"variable": "variable", "path": "definition", "default": "default"}
        assert set(field["items"]["properties"]) == {"variable", "definition", "default"}

    def test_cryptography_is_a_declared_requirement(self):
        assert "cryptography" in (PLUGIN_DIRECTORY / "requirements.txt").read_text().split()

    def test_fetch_fits_inside_fiestaboard_render_timeout(self):
        assert retriever.FETCH_TIME_LIMIT_SECONDS < 5



class TestNeverRaises:
    """Whatever the server sends and whatever the rows say, a fetch returns and the other values survive."""

    NUMBERS = {"retriever": {"s": {"error": "", "data": {"nan": float("nan"), "inf": float("inf"), "ok": 2, "l": [10, 20, 30]}}}}

    @pytest.mark.parametrize("name", ["nan", "inf"])
    def test_a_formula_over_a_number_that_is_not_one_is_an_error_value(self, name):
        both = value_rows(("bad", f"retriever.s.data.{name} + 1"), ("good", "retriever.s.data.ok + 1"))
        assert retriever.build_user_variables(both, self.NUMBERS) == {"bad": "#NUM", "good": formula_number(3)}
        assert retriever.build_user_variables(value_rows(("bad", f"retriever.s.data.{name} + 1"), default="none"), self.NUMBERS) == {"bad": "none"}

    def test_one_bad_element_does_not_spoil_a_list(self):
        context = {"retriever": {"s": {"error": "", "data": [1, float("nan"), 3]}}}
        assert retriever.build_user_variables(value_rows(("l[x]", "retriever.s.data[x] * 2")), context) == {"l": [formula_number(2), "#NUM", formula_number(6)]}

    def test_an_index_that_is_a_digit_but_not_a_number_leads_nowhere(self):
        assert retriever.build_user_variables(value_rows(("v", "retriever.s.data.l.\u00b2")), self.NUMBERS) == {"v": "#REF"}
        assert retriever.build_user_variables(value_rows(("v", "retriever.s.data.l[\u0662]")), self.NUMBERS) == {"v": 30}

    def test_a_row_that_fails_leaves_the_others_and_the_servers_value(self, monkeypatch):
        def fails(value):
            raise RecursionError("too deep")

        monkeypatch.setattr(retriever.copy, "deepcopy", fails)
        defined = retriever.build_user_variables(value_rows(("reminders.extra", '"x"'), ("mine", "retriever.reminders.data.count")), FORMULA_CONTEXT)
        assert defined == {"mine": 2}

    def test_a_fetch_returns_when_the_engine_raises(self, plugin, server, monkeypatch):
        def fails(expression, context):
            raise RuntimeError("engine fell over")

        monkeypatch.setattr(retriever, "evaluate_value" if ENGINE_RETURNS_TYPES else "evaluate", fails)
        plugin.config = {**plugin.config, "values": value_rows(("a", "1 + 1"), ("due", "retriever.reminders.data.count"))}
        data = plugin.fetch_data().data
        assert data["a"] == "#VALUE"
        assert data["due"] == 1
        assert data["error"] == ""

    def test_a_fetch_returns_when_defining_the_values_raises(self, plugin, server, monkeypatch):
        def fails(rows, context):
            raise RuntimeError("anything")

        monkeypatch.setattr(retriever, "build_user_variables", fails)
        plugin.config = {**plugin.config, "values": value_rows(("a", "1 + 1"))}
        assert plugin.fetch_data().data == {**SERVER_VALUES, "server": SERVER_INFO, "error": ""}


class TestDepth:
    """Names, paths and formulas may go MAX_DEPTH deep and no further."""

    DEEPEST = retriever.MAX_NESTING_DEPTH

    def nested_brackets(self, depth):
        """A formula whose value is 1, wrapped in this many pairs of brackets."""
        return "(" * depth + "1" + ")" * depth

    def test_depth_counts_steps_and_brackets(self):
        assert retriever.nesting_depth("retriever.a.b[x].c") == 4
        assert retriever.nesting_depth("UPPER(LEFT(retriever.a, 2))") == 2
        assert retriever.nesting_depth('"((((" & retriever.a') == 1

    def test_the_limit_itself_is_allowed(self):
        deep = value_rows(("a" + ".b" * self.DEEPEST, self.nested_brackets(self.DEEPEST)), ("p[x]", self.nested_brackets(self.DEEPEST - 1) + " & retriever.tags.data[x]"))
        assert retriever.value_row_errors(deep) == []
        defined = retriever.build_user_variables(deep, FORMULA_CONTEXT)
        assert defined["p"] == ["1a", "1b", "1c"]
        value = defined["a"]
        for _ in range(self.DEEPEST):
            value = value["b"]
        assert value == formula_number(1)

    def test_a_name_past_the_limit_is_refused_and_skipped(self):
        deep = value_rows(("a" + ".b" * (self.DEEPEST + 1), "1"))
        assert "steps deep" in retriever.value_row_errors(deep)[0]
        assert retriever.build_user_variables(deep, FORMULA_CONTEXT) == {}

    @pytest.mark.parametrize("depth", [DEEPEST + 1, 250, 5000])
    def test_a_formula_past_the_limit_is_refused_and_is_an_error_value(self, depth):
        deep = value_rows(("v", self.nested_brackets(depth)))
        assert "deep" in retriever.value_row_errors(deep)[0]
        assert retriever.build_user_variables(deep, FORMULA_CONTEXT) == {"v": "#SYNTAX"}
        assert retriever.build_user_variables(value_rows(("v", self.nested_brackets(depth)), default="none"), FORMULA_CONTEXT) == {"v": "none"}

    def test_a_path_past_the_limit_is_refused(self):
        deep = value_rows(("v", "retriever" + ".k" * (self.DEEPEST + 1)))
        assert "deep" in retriever.value_row_errors(deep)[0]
        assert retriever.build_user_variables(deep, FORMULA_CONTEXT) == {"v": "#SYNTAX"}



class TestRowsThatDisagree:
    """Every part of a name is one kind of thing, in every row; found when the settings are saved."""

    @pytest.mark.parametrize(
        ("pair", "words"),
        [
            ((("o.a", '"1"'), ("o.a.b", '"2"')), "o.a is defined both as a single value and as an object"),
            ((("q[x]", "retriever.tags.data[x]"), ("q[x].f", "retriever.tags.data[x]")), "q[x] is defined both as a single value and as an object"),
            ((("q[x].f", "retriever.tags.data[x]"), ("q[y]", "retriever.tags.data[y]")), "q[y] is defined both as an object and as a single value"),
            ((("m.a.b", '"1"'), ("m.a[x]", "retriever.tags.data[x]")), "m.a is defined both as an object and as a list"),
            ((("a", "1 + 1"), ("a", "2 + 2")), "a is defined twice"),
            ((("t[x].n", "retriever.tags.data[x]"), ("t[y].n", "retriever.tags.data[y]")), "t[y].n is defined twice"),
        ],
    )
    def test_they_are_refused(self, pair, words):
        assert any(words in error for error in retriever.value_row_errors(value_rows(*pair)))

    def test_rows_that_agree_are_not(self):
        agree = value_rows(("o.a.b", '"1"'), ("o.a.c", '"2"'), ("o.d", '"3"'), ("q[x].f", "retriever.tags.data[x]"), ("q[y].g", "retriever.tags.data[y]"))
        assert retriever.value_row_errors(agree) == []


class TestRowsAgainstTheServer:
    """A row may add to what the server sends, and may not make an object or a list of what is neither."""

    SHAPES = {
        "s": {
            "type": "object",
            "properties": {
                "error": {"type": "string"},
                "data": {
                    "type": "object",
                    "properties": {
                        "n": {"type": "integer"},
                        "names": {"type": "array", "items": {"type": "string"}},
                        "items": {"type": "array", "items": {"type": "object", "properties": {"t": {"type": "string"}}}},
                        "loose": {"type": "array"},
                        "maybe": {"type": ["string", "null"]},
                        "either": {"type": ["string", "object"]},
                    },
                },
            },
        },
        "error": {"type": "string"},
    }

    @pytest.mark.parametrize(
        ("name", "words"),
        [
            ("s.error.detail", "the server sends s.error as text, which cannot have the field detail"),
            ("s.data.n.sub", "the server sends s.data.n as a number, which cannot have the field sub"),
            ("s.data.names[x].len", "the server sends s.data.names[x] as text, which cannot have the field len"),
            ("s.data[x].t", "the server sends s.data as an object, which cannot have elements"),
            ("s.data.items.count", "the server sends s.data.items as a list, which cannot have the field count"),
            ("s.data.maybe.x", "the server sends s.data.maybe as text"),
            ("error.code", "the server sends error as text"),
        ],
    )
    def test_a_row_that_does_not_fit_is_refused(self, name, words):
        assert any(words in error for error in retriever.shape_errors(value_rows((name, '"x"')), self.SHAPES))

    @pytest.mark.parametrize(
        "name",
        ["s.extra", "s.error", "s.data.n", "s.data.extra.deep", "s.data.items[x].t", "s.data.items[x].k", "s.data.loose[x].k", "s.data.either.x",
         "mine.a.b", "s", "s[x].t"],
    )
    def test_a_row_that_adds_or_replaces_is_not(self, name):
        assert retriever.shape_errors(value_rows((name, '"x"')), self.SHAPES) == []

    def test_the_shape_of_a_value_in_hand(self):
        assert retriever.shape_of({"name": "S", "range": {"min": 1}, "tags": ["a"], "none": None, "on": True}) == {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "range": {"type": "object", "properties": {"min": {"type": "number"}}},
                "tags": {"type": "array", "items": {"type": "string"}},
                "none": {},
                "on": {"type": "boolean"},
            },
        }


class TestSavingChecksTheServer:
    """Saving rows that add to an object asks the server whether they fit what it sends."""

    def settings_with_rows(self, server, *pairs):
        """Settings about to be saved, pointing at the fake server."""
        return {"server_url": server.url, "api_key": ENCODED_TRANSPORT_KEY, "values": value_rows(*pairs)}

    def test_rows_that_fit_are_saved(self, plugin, server):
        fitting = self.settings_with_rows(server, ("reminders.next", "retriever.reminders.data.items[0].title"), ("mine.count", "retriever.reminders.data.count"), ("server.name", '"renamed"'))
        assert plugin.validate_config(fitting) == []
        assert server.requested_paths == [SERVER_INFO_PATH, CONFIG_PATH]

    @pytest.mark.parametrize(
        ("name", "words"),
        [
            ("reminders.error.detail", "reminders.error as text"),
            ("reminders.data.count.x", "reminders.data.count as a number"),
            ("server.name.x", "server.name as text"),
            ("server.supported_protocol_version_range.min.x", "server.supported_protocol_version_range.min as a number"),
            ("error.code", "error as text"),
        ],
    )
    def test_a_row_that_does_not_fit_what_the_server_sends_is_refused(self, plugin, server, name, words):
        errors = plugin.validate_config(self.settings_with_rows(server, (name, '"x"')))
        assert len(errors) == 1
        assert words in errors[0]

    def test_a_row_that_cannot_be_checked_cannot_be_saved(self, plugin, server):
        server.refuse(503, "Service Unavailable")
        errors = plugin.validate_config(self.settings_with_rows(server, ("mine.count", "retriever.reminders.data.count"), ("due", "retriever.reminders.data.count")))
        assert len(errors) == 1
        assert "503 Service Unavailable" in errors[0]
        assert "mine.count" in errors[0]
        assert "due" not in errors[0].split(":")[-1]

    def test_rows_that_add_to_nothing_do_not_ask_the_server(self, plugin, server):
        server.refuse(503, "Service Unavailable")
        plain = self.settings_with_rows(server, ("due", "retriever.reminders.data.count"), ("todo[x].what", "retriever.reminders.data.items[x].title"))
        assert plugin.validate_config(plain) == []
        assert server.requested_paths == []

    def test_bad_settings_are_reported_without_asking(self, plugin, server):
        errors = plugin.validate_config({"server_url": server.url, "api_key": "short", "values": value_rows(("mine.count", "1"))})
        assert errors == ["API key must be the base64 of 32 bytes"]
        assert server.requested_paths == []


class TestClashAtRunTime:
    """What saving could not catch: the server sends something other than it said. Its value stays; the log says so."""

    def test_the_servers_value_is_kept_and_the_row_reported_once(self, caplog):
        retriever._logged_warnings.clear()
        context = {"retriever": {"s": {"error": "sensor offline", "data": {"n": 5, "names": ["x", "y"], "items": [{"t": "a"}]}}, "error": ""}}
        clashing = value_rows(("s.error.detail", '"D"'), ("s.data.n.sub", '"oops"'), ("s.data.names[x].len", "retriever.s.data.names[x]"), ("error.code", '"E1"'), ("mine", "retriever.s.data.n"))
        with caplog.at_level("WARNING"):
            assert retriever.build_user_variables(clashing, context) == {"mine": 5}
            retriever.build_user_variables(clashing, context)
        skipped = [record.message for record in caplog.records if "skipped" in record.message]
        assert len(skipped) == 4
        assert "Value 's.error.detail' skipped: s.error is not an object or a list" in skipped[0]

    def test_rows_that_fit_still_add_beside_one_that_does_not(self):
        context = {"retriever": {"s": {"error": "", "data": {"n": 5, "items": [{"t": "a"}]}}}}
        defined = retriever.build_user_variables(value_rows(("s.data.items[x].k", "x"), ("s.data.n.sub", '"oops"'), ("s.data.extra", '"new"')), context)
        assert defined == {"s": {"error": "", "data": {"n": 5, "items": [{"t": "a", "k": formula_number(0)}], "extra": "new"}}}
