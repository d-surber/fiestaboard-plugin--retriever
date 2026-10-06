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

PLUGIN_DIR = Path(__file__).parent.parent
MANIFEST_PATH = PLUGIN_DIR / "manifest.json"
VECTORS = json.loads((Path(__file__).parent / "vectors.json").read_text())

# Loaded by path, as FiestaBoard's loader does: the directory name differs
# between a checkout and an install, so there is no fixed package to import.
_spec = importlib.util.spec_from_file_location("retriever_plugin", PLUGIN_DIR / "__init__.py")
retriever = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(retriever)
RetrieverPlugin = retriever.RetrieverPlugin

# Whether FiestaBoard's formula engine gives a result with its type
# (evaluate_value). One that does not only renders text.
TYPED = retriever.evaluate_value is not None


def number(value):
    """What a formula gives for a number: the number, or its text from an engine that only renders."""
    return value if TYPED else str(value)


SERVER, CONFIG, RETRIEVE = retriever.SERVER_PATH, retriever.CONFIG_PATH, retriever.RETRIEVE_PATH
KEY = bytes(range(32))
KEY_B64 = base64.b64encode(KEY).decode()
OTHER_KEY = bytes(range(1, 33))
SEQ = 7
SERVER_INFO = {"name": "FakeServer", "version": "9.9", "protocol": {"min": 1, "max": 1}, "extra": ["anything", 1]}
SOURCES = {
    "reminders": {
        "type": "object",
        "properties": {"count": {"type": "integer"}, "items": {"type": "array"}},
        "default": {"count": 0, "items": []},
    }
}
VALUES = {
    "reminders": {
        "error": "",
        "data": {
            "count": 1,
            "items": [{"title": "test0", "list": "Reminders", "due": "2026-10-05T06:15:00Z", "priority": 0}],
        },
    }
}
NO_REMINDERS = {"error": "", "data": {"count": 0, "items": []}}


def seal(key, plaintext, context):
    nonce = os.urandom(12)
    return nonce + ChaCha20Poly1305(key).encrypt(nonce, plaintext, context)


class FakeServer:
    """A stand-in for RetrieverServer whose behaviour can be changed per test."""

    def __init__(self):
        self.key = KEY
        self.seq = SEQ
        self.info = SERVER_INFO
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
                if self.path not in (SERVER, CONFIG, RETRIEVE):
                    return self.say_nothing()
                if self.path in fake.status:
                    return self.answer(*fake.status[self.path])
                try:
                    context = retriever.request_context(self.path)
                    plaintext = ChaCha20Poly1305(fake.key).decrypt(body[:12], body[12:], context)
                except Exception:
                    return self.say_nothing()
                request = json.loads(plaintext)
                fake.requests.append(request)
                if fake.reply:
                    return self.answer(200, "OK", fake.reply(self.path, request))
                data = {SERVER: fake.info, CONFIG: fake.sources, RETRIEVE: fake.values}[self.path]
                self.answer(200, "OK", fake.sealed(self.path, {"id": request["id"], "seq": fake.seq, "data": data}))

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

    def sealed(self, path, message, key=None):
        return seal(key or self.key, json.dumps(message).encode(), retriever.response_context(path))

    def refuse(self, status, reason, paths=(SERVER, CONFIG, RETRIEVE)):
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
    plugin.config = {"server_url": server.url, "api_key": KEY_B64}
    return plugin


def assert_failed(result, reason, values):
    """Templates still render: *values*, and the reason in ``error``."""
    assert result.available is True
    assert result.data == {**values, "error": result.data["error"]}
    assert result.data["error"].startswith(reason)
    assert result.error == result.data["error"]


def assert_retrieve_failed(result, reason):
    """The config is known, so reminders has its schema's default, and the server's info is kept."""
    assert_failed(result, reason, {"reminders": NO_REMINDERS, "server": SERVER_INFO})
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
        assert result.data == {**VALUES, "server": SERVER_INFO, "error": ""}
        assert result.formatted_lines is None

    def test_a_source_with_its_own_error_passes_through(self, plugin, server):
        server.values = {"reminders": {"error": "Reminders could not be read", "data": NO_REMINDERS["data"]}}
        result = plugin.fetch_data()
        assert result.data == {**server.values, "server": SERVER_INFO, "error": ""}
        assert result.error is None

    def test_other_sources_pass_through(self, plugin, server):
        server.values = {**VALUES, "calendar": {"error": "", "data": [1, "two", None]}}
        assert plugin.fetch_data().data["calendar"] == {"error": "", "data": [1, "two", None]}

    def test_request_carries_a_current_timestamp_and_a_fresh_id(self, plugin, server):
        plugin.fetch_data()
        ids = [request["id"] for request in server.requests]
        assert len(set(ids)) == len(ids) == 3
        for request in server.requests:
            assert set(request) - {"protocol"} == {"ts", "id"}
            assert abs(request["ts"] - time.time()) < 5
            assert len(request["id"]) == 32

    def test_every_request_has_a_new_nonce(self, plugin, server):
        plugin.fetch_data()
        plugin.fetch_data()
        nonces = [body[:12] for body in server.bodies]
        assert len(set(nonces)) == len(nonces) == 4

    def test_nothing_readable_is_sent(self, plugin, server):
        plugin.fetch_data()
        assert all(b"ts" not in body and KEY not in body for body in server.bodies)

    def test_trailing_slash_in_server_url(self, plugin, server):
        plugin.config = {"server_url": server.url + "/", "api_key": KEY_B64}
        assert plugin.fetch_data().data["error"] == ""

    def test_fetch_reports_failure_by_raising(self, plugin, server):
        server.refuse(401, "Unauthorized")
        with pytest.raises(urllib.error.HTTPError):
            plugin._fetch(server.url, RETRIEVE, KEY, time.monotonic() + 4)

    def test_fetch_past_its_deadline_raises_without_asking(self, plugin, server):
        with pytest.raises(TimeoutError):
            plugin._fetch(server.url, RETRIEVE, KEY, time.monotonic() - 1)
        assert server.paths == []

    def test_server_with_another_key_says_nothing(self, plugin, server):
        plugin.fetch_data()
        server.key = OTHER_KEY
        assert_retrieve_failed(plugin.fetch_data(), "no response (wrong key?)")

    def test_wrong_key_from_the_start(self, plugin, server):
        server.key = OTHER_KEY
        assert_config_pending(plugin.fetch_data(), "no response (wrong key?)")
        assert server.paths == [SERVER]

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
        assert plugin.fetch_data().data == {**VALUES, "server": SERVER_INFO, "error": ""}

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
        assert server.paths == [SERVER, CONFIG, RETRIEVE, RETRIEVE, RETRIEVE]

    @pytest.mark.parametrize("new_seq", [SEQ + 1, SEQ - 1, 0])
    def test_config_is_read_again_when_the_sequence_number_changes(self, plugin, server, new_seq):
        plugin.fetch_data()
        server.seq = new_seq
        server.sources = {"reminders": {"type": "object", "default": {"count": -1}}}
        result = plugin.fetch_data()
        assert result.data == {**VALUES, "server": SERVER_INFO, "error": ""}
        assert server.paths == [SERVER, CONFIG, RETRIEVE, RETRIEVE, SERVER, CONFIG]

        plugin.fetch_data()
        assert server.paths[6:] == [RETRIEVE]
        server.refuse(500, "Internal Server Error", [RETRIEVE])
        assert plugin.fetch_data().data["reminders"] == {"error": "", "data": {"count": -1}}

    def test_config_is_read_again_when_settings_are_saved(self, plugin, server):
        plugin.fetch_data()
        plugin.config = {"server_url": server.url, "api_key": KEY_B64, "refresh_seconds": 120}
        plugin.fetch_data()
        assert server.paths == [SERVER, CONFIG, RETRIEVE, SERVER, CONFIG, RETRIEVE]

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
            {
                "reminders": {"error": "", "data": {"count": 0, "text": "NONE"}},
                "calendar": {"error": "", "data": []},
                "server": SERVER_INFO,
            },
        )

    def test_no_source_is_known_before_the_config_is_read(self, plugin, server):
        server.refuse(401, "Unauthorized")
        assert_config_pending(plugin.fetch_data(), "401 Unauthorized")
        assert server.paths == [SERVER]

    def test_unreachable_server_before_the_config_is_read(self, plugin, server):
        server.stop()
        assert_config_pending(plugin.fetch_data(), "Connection refused")

    def test_config_is_tried_again_on_the_next_fetch(self, plugin, server):
        server.refuse(500, "Internal Server Error", [CONFIG])
        assert_config_pending(plugin.fetch_data(), "500 Internal Server Error")
        server.status = {}
        assert plugin.fetch_data().data == {**VALUES, "server": SERVER_INFO, "error": ""}
        assert server.paths == [SERVER, CONFIG, SERVER, CONFIG, RETRIEVE]

    def test_values_are_kept_when_the_changed_config_cannot_be_read(self, plugin, server):
        plugin.fetch_data()
        server.seq = SEQ + 1
        server.refuse(500, "Internal Server Error", [CONFIG])
        assert_config_pending(plugin.fetch_data(), "500 Internal Server Error", {**VALUES, "server": SERVER_INFO})

        server.status = {}
        assert plugin.fetch_data().data == {**VALUES, "server": SERVER_INFO, "error": ""}
        assert server.paths == [SERVER, CONFIG, RETRIEVE, RETRIEVE, SERVER, CONFIG, RETRIEVE, SERVER, CONFIG]

    def test_a_config_response_cannot_be_passed_off_as_a_retrieve_response(self, plugin, server):
        plugin.fetch_data()
        server.reply = lambda path, request: server.sealed(CONFIG, {"id": request["id"], "seq": SEQ, "data": SOURCES})
        assert_retrieve_failed(plugin.fetch_data(), "wrong key")

    def test_all_requests_in_one_fetch_share_the_time_budget(self, plugin, server, monkeypatch):
        monkeypatch.setattr(retriever, "TIMEOUT_SECONDS", 0.6)
        server.delay = {SERVER: 0.2, CONFIG: 0.2, RETRIEVE: 0.4}
        started = time.monotonic()
        result = plugin.fetch_data()
        assert time.monotonic() - started < 0.9
        assert_retrieve_failed(result, "timed out")

    def test_slow_config_before_the_config_is_read(self, plugin, server, monkeypatch):
        monkeypatch.setattr(retriever, "TIMEOUT_SECONDS", 0.2)
        server.delay = {CONFIG: 0.5}
        assert_config_pending(plugin.fetch_data(), "timed out")


class TestServerInfo:
    def test_server_info_reaches_templates_unchanged(self, plugin, server):
        server.info = {**SERVER_INFO, "os": "macOS 26.6.2", "host": "example", "port": 42511, "nested": {"a": [1, 2]}}
        assert plugin.fetch_data().data["server"] == server.info

    def test_server_is_asked_before_config(self, plugin, server):
        plugin.fetch_data()
        assert server.paths[:2] == [SERVER, CONFIG]

    def test_server_request_names_no_protocol_and_the_others_name_the_chosen_one(self, plugin, server):
        plugin.fetch_data()
        by_path = dict(zip(server.paths, server.requests))
        assert "protocol" not in by_path[SERVER]
        assert by_path[CONFIG]["protocol"] == 1
        assert by_path[RETRIEVE]["protocol"] == 1

    @pytest.mark.parametrize("offered", [{"min": 1, "max": 1}, {"min": 0, "max": 5}, {"min": 1, "max": 99}])
    def test_chooses_the_highest_protocol_both_sides_speak(self, plugin, server, offered, monkeypatch):
        monkeypatch.setattr(retriever, "PROTOCOLS", (1, 2, 3))
        server.info = {**SERVER_INFO, "protocol": offered}
        plugin.fetch_data()
        assert server.requests[-1]["protocol"] == min(3, offered["max"])

    @pytest.mark.parametrize("offered", [{"min": 2, "max": 3}, {"min": 0, "max": 0}, {"min": 5, "max": 2}])
    def test_no_common_protocol(self, plugin, server, offered):
        server.info = {**SERVER_INFO, "protocol": offered}
        assert_config_pending(plugin.fetch_data(), "no common protocol")
        assert server.paths == [SERVER]

    @pytest.mark.parametrize(
        "info",
        [
            {"name": "x", "version": "1"},
            {"protocol": [1, 1]},
            {"protocol": {"min": 1}},
            {"protocol": {"min": "1", "max": "1"}},
            {"protocol": {"min": True, "max": True}},
        ],
    )
    def test_server_info_without_a_usable_protocol_range(self, plugin, server, info):
        server.info = info
        assert_config_pending(plugin.fetch_data(), "no protocol range in server info")
        assert server.paths == [SERVER]

    def test_server_refuses_the_protocol(self, plugin, server):
        plugin.fetch_data()
        server.refuse(400, "Unsupported Protocol", [RETRIEVE])
        assert_retrieve_failed(plugin.fetch_data(), "400 Unsupported Protocol")

    def test_server_info_is_read_again_with_the_config(self, plugin, server):
        plugin.fetch_data()
        server.seq = SEQ + 1
        server.info = {**SERVER_INFO, "version": "10.0"}
        assert plugin.fetch_data().data["server"]["version"] == "10.0"

    @pytest.mark.parametrize("name", ["error", "server"])
    def test_a_source_cannot_take_the_reserved_names(self, plugin, server, name):
        plugin.fetch_data()
        server.values = {**VALUES, name: {"error": "", "data": "impostor"}}
        assert_retrieve_failed(plugin.fetch_data(), f"source named {name}: reserved name")

    @pytest.mark.parametrize("name", ["error", "server"])
    def test_a_config_cannot_list_the_reserved_names(self, plugin, server, name):
        server.sources = {**SOURCES, name: {"type": "string"}}
        assert_config_pending(plugin.fetch_data(), f"source named {name}: reserved name")

    def test_server_info_may_use_those_names_itself(self, plugin, server):
        server.info = {**SERVER_INFO, "error": "none", "server": "this one"}
        data = plugin.fetch_data().data
        assert data["error"] == ""
        assert data["server"]["error"] == "none"


ITEMS = [
    {"title": "water plants", "list": "Home", "due": "2026-10-05T16:00:00Z", "priority": 1},
    {"title": "call dentist", "list": "Health", "due": "2026-10-05T18:30:00Z", "priority": 0},
]
CONTEXT = {
    "retriever": {
        "reminders": {"error": "", "data": {"count": 2, "items": ITEMS}},
        "music": {"error": "", "data": {"state": "playing", "title": "So What"}},
        "tags": {"error": "", "data": ["a", "b", "c"]},
        "server": {"name": "FakeServer"},
        "error": "",
    }
}


def rows(*pairs, default=""):
    return [{"variable": name, "definition": definition, "default": default} for name, definition in pairs]


class TestValues:
    """Rows that name a value and define it by an expression over the server's values."""

    @pytest.mark.parametrize(
        ("definition", "value"),
        [
            ("retriever.reminders.data.count", 2),
            ("retriever.reminders.data.items", ITEMS),
            ("retriever.reminders.data", {"count": 2, "items": ITEMS}),
            ("retriever.reminders.data.items.1.title", "call dentist"),
            ("retriever.reminders.data.items[1].title", "call dentist"),
            ("  retriever.error  ", ""),
        ],
    )
    def test_a_definition_that_is_only_a_path_keeps_the_values_type(self, definition, value):
        assert retriever.define(rows(("v", definition)), CONTEXT) == {"v": value}

    @pytest.mark.parametrize(
        ("definition", "value"),
        [
            ("UPPER(retriever.reminders.data.items[0].title)", "WATER PLANTS"),
            ("retriever.reminders.data.count + 1", number(3)),
            ('COUNT(retriever.reminders.data.items) & " due"', "2 due"),
            ('IF(retriever.error = "", "ok", retriever.error)', "ok"),
            ('JOIN(retriever.reminders.data.items, ", ", "title")', "water plants, call dentist"),
        ],
    )
    def test_any_other_definition_is_a_formula(self, definition, value):
        assert retriever.define(rows(("v", definition)), CONTEXT) == {"v": value}

    @pytest.mark.parametrize(
        ("definition", "code"),
        [
            ("retriever.reminders.data.items.9.title", "#REF"),
            ("retriever.nosuch", "#REF"),
            ("reminders.data.count", "#REF"),
            ("weather.temperature", "#REF"),
            ("UPPER(retriever.reminders.data.items[9].title)", "#REF"),
            ("retriever.reminders.data.count +", "#SYNTAX" if TYPED else "#SYNTAX:32"),
        ],
    )
    def test_a_failed_definition_gives_its_default_or_else_the_error_code(self, definition, code):
        assert retriever.define(rows(("v", definition)), CONTEXT) == {"v": code}
        assert retriever.define(rows(("v", definition), default="none"), CONTEXT) == {"v": "none"}

    def test_a_null_is_no_value(self):
        context = {"retriever": {"s": {"error": "", "data": {"nothing": None, "items": [{"t": None}, {"t": "b"}]}}}}
        assert retriever.define(rows(("v", "retriever.s.data.nothing"), default="none"), context) == {"v": "none"}
        assert retriever.define(rows(("v", "retriever.s.data.nothing")), context) == {"v": None}
        assert retriever.define(rows(("l[x]", "retriever.s.data.items[x].t"), default="-"), context) == {"l": ["-", "b"]}
        assert retriever.define(rows(("v", "UPPER(retriever.s.data.nothing)"), default="none"), context) == {"v": "none"}

    def test_a_list_that_is_missing_is_an_empty_list_whatever_the_default(self):
        assert retriever.define(rows(("l[x]", "retriever.nosuch.data[x]"), default="none"), CONTEXT) == {"l": []}

    def test_text_that_reads_like_an_error_is_text(self):
        """Only an engine that gives types can tell; one that renders text shows the same for both."""
        context = {"retriever": {"s": {"error": "", "data": {"text": "#REF"}}}}
        assert retriever.define(rows(("v", "retriever.s.data.text"), default="none"), context) == {"v": "#REF"}
        formula = rows(("v", 'retriever.s.data.text & ""'), default="none")
        assert retriever.define(formula, context) == {"v": "#REF" if TYPED else "none"}

    @pytest.mark.skipif(not TYPED, reason="needs an engine that gives a result its type")
    def test_a_formulas_result_keeps_its_type(self):
        defined = retriever.define(
            rows(
                ("whole", "retriever.reminders.data.count * 3"),
                ("part", "retriever.reminders.data.count / 4"),
                ("truth", "retriever.reminders.data.count > 1"),
                ("text", 'retriever.reminders.data.count & ""'),
                ("urgent", "FILTER(retriever.reminders.data.items, item.priority > 0)"),
                ("day", 'DATE("2026-12-25")'),
            ),
            CONTEXT,
        )
        assert defined == {"whole": 6, "part": 0.5, "truth": True, "text": "2", "urgent": [ITEMS[0]], "day": "2026-12-25 00:00"}
        assert type(defined["whole"]) is int

    def test_a_default_is_not_used_when_the_definition_works(self):
        assert retriever.define(rows(("v", "retriever.reminders.data.count"), default="none"), CONTEXT) == {"v": 2}
        assert retriever.define(rows(("v", "retriever.error"), default="none"), CONTEXT) == {"v": ""}
        # Text that merely starts with # is a result, not an error.
        assert retriever.define(rows(("v", '"#1 of " & retriever.reminders.data.count'), default="none"), CONTEXT) == {
            "v": "#1 of 2"
        }

    def test_a_list_of_objects_is_built_field_by_field(self):
        defined = retriever.define(
            rows(
                ("todo[x].what", "retriever.reminders.data.items[x].title"),
                ("todo[x].shout", "UPPER(retriever.reminders.data.items[x].title)"),
                ("todo[x].urgent", 'IF(retriever.reminders.data.items[x].priority = 1, "!", "")'),
            ),
            CONTEXT,
        )
        assert defined == {
            "todo": [
                {"what": "water plants", "shout": "WATER PLANTS", "urgent": "!"},
                {"what": "call dentist", "shout": "CALL DENTIST", "urgent": ""},
            ]
        }

    def test_a_list_of_plain_values(self):
        assert retriever.define(rows(("titles[x]", "retriever.reminders.data.items[x].title")), CONTEXT) == {
            "titles": ["water plants", "call dentist"]
        }
        assert retriever.define(rows(("letters[x]", "UPPER(retriever.tags.data[x])")), CONTEXT) == {
            "letters": ["A", "B", "C"]
        }

    def test_a_list_element_keeps_its_type_when_the_definition_is_only_a_path(self):
        assert retriever.define(rows(("p[x]", "retriever.reminders.data.items[x].priority")), CONTEXT) == {"p": [1, 0]}
        assert retriever.define(rows(("whole[x]", "retriever.reminders.data.items[x]")), CONTEXT) == {"whole": ITEMS}

    def test_two_lists_in_one_definition_give_as_many_elements_as_the_shorter(self):
        defined = retriever.define(
            rows(("pair[x]", 'retriever.tags.data[x] & ":" & retriever.reminders.data.items[x].title')), CONTEXT
        )
        assert defined == {"pair": ["a:water plants", "b:call dentist"]}

    @pytest.mark.parametrize(
        "definition",
        ["retriever.reminders.data.count", "retriever.nosuch[x].title", "retriever.reminders.data[x]", '"fixed"'],
    )
    def test_a_list_with_nothing_to_index_is_empty(self, definition):
        assert retriever.define(rows(("empty[x].f", definition)), CONTEXT) == {"empty": []}

    def test_a_missing_field_in_one_element_gets_the_default(self):
        context = {"retriever": {"things": {"data": [{"name": "a"}, {}]}}}
        defined = retriever.define(rows(("t[x].name", "retriever.things.data[x].name"), default="?"), context)
        assert defined == {"t": [{"name": "a"}, {"name": "?"}]}

    def test_definitions_read_the_servers_values_never_another_rows(self):
        """So rows cannot depend on each other, and their order does not matter."""
        both = rows(("a", "retriever.reminders.data.count"), ("b", "retriever.a"))
        assert retriever.define(both, CONTEXT) == {"a": 2, "b": "#REF"}
        assert retriever.define(both[::-1], CONTEXT) == {"a": 2, "b": "#REF"}

    def test_a_row_may_take_a_servers_name_and_still_be_defined_from_it(self):
        defined = retriever.define(rows(("reminders[x]", "retriever.reminders.data.items[x].title")), CONTEXT)
        assert defined == {"reminders": ["water plants", "call dentist"]}

    @pytest.mark.parametrize(
        "junk",
        [None, "", "not rows", 7, [None, "x", 7, {}, {"variable": "v"}, {"definition": "1"}, {"variable": "9bad", "definition": "1"}]],
    )
    def test_rows_that_are_not_rows_define_nothing(self, junk):
        assert retriever.define(junk, CONTEXT) == {}

    @pytest.mark.parametrize(
        ("name", "parsed"),
        [
            ("due", ("due", [])),
            (" due_today2 ", ("due_today2", [])),
            ("todo[x]", ("todo", [("index", "x")])),
            ("todo[x].what", ("todo", [("index", "x"), ("key", "what")])),
            ("todo[row].a.b", ("todo", [("index", "row"), ("key", "a"), ("key", "b")])),
            ("grid[x][y]", ("grid", [("index", "x"), ("index", "y")])),
            (
                "lists[x].items[y].what",
                ("lists", [("index", "x"), ("key", "items"), ("index", "y"), ("key", "what")]),
            ),
            ("reminders.count", ("reminders", [("key", "count")])),
            ("a.b.c", ("a", [("key", "b"), ("key", "c")])),
            ("mine.list[x].what", ("mine", [("key", "list"), ("index", "x"), ("key", "what")])),
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
        assert retriever.parse_variable(name) == parsed


NESTED = {
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
        defined = retriever.define(
            rows(
                ("mine.count", "retriever.reminders.data.count"),
                ("mine.next", "UPPER(retriever.reminders.data.items[0].title)"),
                ("mine.deep.er", "retriever.music.data.state"),
            ),
            CONTEXT,
        )
        assert defined == {"mine": {"count": 2, "next": "WATER PLANTS", "deep": {"er": "playing"}}}

    def test_a_field_of_one_of_the_servers_objects_is_added_to_it(self):
        """reminders.count sits beside reminders.error and reminders.data, which stay as sent."""
        defined = retriever.define(
            rows(("reminders.count", "retriever.reminders.data.count"), ("reminders.next", "retriever.reminders.data.items[0].title")),
            CONTEXT,
        )
        assert defined == {
            "reminders": {"error": "", "data": {"count": 2, "items": ITEMS}, "count": 2, "next": "water plants"}
        }

    def test_the_servers_own_value_is_never_changed(self):
        before = json.dumps(CONTEXT, sort_keys=True)
        retriever.define(rows(("reminders.data.count", '"overwritten"'), ("reminders.count", "1")), CONTEXT)
        assert json.dumps(CONTEXT, sort_keys=True) == before

    def test_a_field_can_replace_one_the_server_sent(self):
        defined = retriever.define(rows(("reminders.error", '"mine"'), ("reminders.data.count", "retriever.reminders.data.count + 10")), CONTEXT)
        assert defined["reminders"]["error"] == "mine"
        assert defined["reminders"]["data"] == {"count": number(12), "items": ITEMS}

    def test_a_list_inside_an_object(self):
        defined = retriever.define(rows(("mine.todo[x].what", "retriever.reminders.data.items[x].title")), CONTEXT)
        assert defined == {"mine": {"todo": [{"what": "water plants"}, {"what": "call dentist"}]}}

    def test_taking_a_servers_name_outright_still_replaces_it(self):
        assert retriever.define(rows(("reminders", "retriever.reminders.data.count")), CONTEXT) == {"reminders": 2}
        assert retriever.define(rows(("reminders[x]", "retriever.reminders.data.items[x].title")), CONTEXT) == {
            "reminders": ["water plants", "call dentist"]
        }


class TestListParameters:
    """A parameter in brackets is the position of each element: an index in brackets, a number when bare."""

    def test_a_parameter_is_a_number_in_the_definition(self):
        defined = retriever.define(
            rows(
                ("todo[x].line", '(x + 1) & ". " & retriever.reminders.data.items[x].title'),
                ("todo[x].position", "x"),
                ("todo[x].last", 'IF(x = COUNT(retriever.reminders.data.items) - 1, "last", "")'),
            ),
            CONTEXT,
        )
        assert defined == {
            "todo": [
                {"line": "1. water plants", "position": number(0), "last": ""},
                {"line": "2. call dentist", "position": number(1), "last": "last"},
            ]
        }

    def test_the_parameters_name_is_the_users_choice(self):
        defined = retriever.define(
            rows(("todo[row].n", "row + 1"), ("todo[row].what", "retriever.reminders.data.items[row].title")), CONTEXT
        )
        assert defined == {"todo": [{"n": number(1), "what": "water plants"}, {"n": number(2), "what": "call dentist"}]}

    def test_a_row_that_indexes_nothing_adds_to_the_elements_the_other_rows_gave(self):
        """Brackets decide how many elements there are; a row without them cannot say."""
        assert retriever.define(rows(("n[x]", "x + 1")), CONTEXT) == {"n": []}
        both = rows(("todo[x].n", "x + 1"), ("todo[x].what", "retriever.reminders.data.items[x].title"))
        expected = {"todo": [{"what": "water plants", "n": number(1)}, {"what": "call dentist", "n": number(2)}]}
        assert retriever.define(both, CONTEXT) == expected
        assert retriever.define(both[::-1], CONTEXT) == expected  # whichever order the rows are in

    def test_lists_nest_each_with_its_own_parameter(self):
        defined = retriever.define(
            rows(
                ("lists[x].name", "retriever.todo.data.lists[x].name"),
                ("lists[x].items[y].what", "retriever.todo.data.lists[x].items[y].title"),
                ("lists[x].items[y].label", '(x + 1) & "." & (y + 1) & " " & UPPER(retriever.todo.data.lists[x].items[y].title)'),
            ),
            NESTED,
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
        defined = retriever.define(rows(("grid[x][y]", "retriever.todo.data.lists[x].items[y].title")), NESTED)
        assert defined == {"grid": [["water plants", "feed cat"], ["send report"], []]}

    def test_an_inner_list_of_plain_values(self):
        defined = retriever.define(rows(("lists[x].titles[y]", "retriever.todo.data.lists[x].items[y].title")), NESTED)
        assert defined == {
            "lists": [{"titles": ["water plants", "feed cat"]}, {"titles": ["send report"]}, {"titles": []}]
        }

    def test_fields_below_a_parameter_may_nest(self):
        defined = retriever.define(rows(("lists[x].info.name", "retriever.todo.data.lists[x].name")), NESTED)
        assert defined == {"lists": [{"info": {"name": "Home"}}, {"info": {"name": "Work"}}, {"info": {"name": "Empty"}}]}

    def test_the_outer_parameter_can_be_used_inside_the_inner_list(self):
        defined = retriever.define(
            rows(("lists[x].items[y]", 'retriever.todo.data.lists[x].name & ": " & retriever.todo.data.lists[x].items[y].title')),
            NESTED,
        )
        assert defined["lists"][0] == {"items": ["Home: water plants", "Home: feed cat"]}

    def test_a_bare_parameter_keeps_working_beside_a_pure_path(self):
        """A definition that is only the parameter is a number, not a path to look up."""
        assert retriever.define(rows(("p[x]", "x")), {"retriever": {}, "x": "wrong"}) == {"p": []}
        defined = retriever.define(rows(("p[x].i", "x"), ("p[x].t", "retriever.tags.data[x]")), CONTEXT)
        assert defined == {"p": [{"i": number(0), "t": "a"}, {"i": number(1), "t": "b"}, {"i": number(2), "t": "c"}]}


class TestValueErrors:
    @pytest.mark.parametrize(
        "good",
        [
            None,
            [],
            rows(("due", "retriever.reminders.data.count")),
            rows(("first", "UPPER(retriever.reminders.data.items[0].title)")),
            rows(("todo[x].what", "retriever.reminders.data.items[x].title"), ("todo[x].when", "retriever.reminders.data.items[x].due")),
            rows(("titles[x]", "UPPER(retriever.reminders.data.items[x].title)")),
            rows(("todo[x].line", '(x + 1) & ". " & retriever.reminders.data.items[x].title')),
            rows(("lists[x].items[y].what", "retriever.todo.data.lists[x].items[y].title")),
            rows(("grid[row][col]", '(row + col) & retriever.a.data[row].b[col]')),
            rows(("todo[x].n", "x + 1"), ("todo[x].what", "retriever.reminders.data.items[x].title")),
            rows(("reminders.count", "retriever.reminders.data.count"), ("reminders.next", "retriever.reminders.data.items[0].title")),
            rows(("mine.count", "retriever.reminders.data.count"), ("mine.todo[x]", "retriever.reminders.data.items[x].title")),
        ],
    )
    def test_good_rows(self, good):
        assert retriever.value_errors(good) == []

    @pytest.mark.parametrize(
        ("bad", "words"),
        [
            ("rows", "must be a list"),
            (["x"], "is not a row"),
            (rows(("2do", "1")), "'2do' is not a name"),
            (rows(("todo.x.what", "retriever.a[x]")), "[x] in the definition needs [x] in the name"),
            (rows(("todo[0].what", "retriever.a")), "'todo[0].what' is not a name"),
            (rows(("due", "1"), ("due.soon", "2")), "due is defined both as a single value and as an object"),
            (rows(("todo.n", "1"), ("todo[x]", "retriever.a[x]")), "todo is defined both as an object and as a list"),
            (rows(("", "retriever.reminders.data.count")), "Value 1 has no name"),
            (rows(("  ", "retriever.reminders.data.count")), "Value 1 has no name"),
            (rows(("retriever.reminders.data.count", "retriever.reminders.data.count")), "the expression goes in the definition"),
            (rows(("due", "")), "has no definition"),
            (rows(("todo[x]", "retriever.reminders.data.count")), "must index a list with [x]"),
            (rows(("todo[x]", "x + 1")), "must index a list with [x]"),
            (rows(("due", "retriever.reminders.data.items[x].title")), "needs [x] in the name"),
            (rows(("todo[x]", "retriever.a[x].b[y]")), "[y] in the definition needs [y] in the name"),
            (rows(("todo[x].items[y]", "retriever.a[x].b")), "must index a list with [y]"),
            (rows(("todo[x].items[x]", "retriever.a[x]")), "each parameter used once"),
            (rows(("todo[*]", "retriever.a[*]")), "'todo[*]' is not a name"),
            (rows(("todo[x]", "retriever.a[x] +")), "'todo[x]'"),
            (rows(("due", "retriever.reminders.data.count +")), "'due'"),
            (rows(("due", "NOSUCHFUNCTION(1)")), "NOSUCHFUNCTION"),
            (rows(("todo", "1"), ("todo[x]", "retriever.a[x]")), "todo is defined both as a single value and as a list"),
        ],
    )
    def test_bad_rows(self, bad, words):
        errors = retriever.value_errors(bad)
        assert errors and any(words in error for error in errors), errors

    def test_bad_rows_are_reported_when_settings_are_saved(self, manifest):
        plugin = RetrieverPlugin(manifest)
        config = {"server_url": "http://192.0.2.10:42511", "api_key": KEY_B64, "values": rows(("2do", "1"))}
        assert any("'2do' is not a name" in error for error in plugin.validate_config(config))


class TestValuesInAFetch:
    def configure(self, plugin, server, *pairs, default=""):
        plugin.config = {"server_url": server.url, "api_key": KEY_B64, "values": rows(*pairs, default=default)}

    def test_defined_values_sit_beside_the_servers(self, plugin, server):
        self.configure(
            plugin,
            server,
            ("due", "retriever.reminders.data.count"),
            ("first", "UPPER(retriever.reminders.data.items[0].title)"),
            ("todo[x].what", "retriever.reminders.data.items[x].title"),
            ("who", "retriever.server.name"),
        )
        data = plugin.fetch_data().data
        assert data == {
            **VALUES,
            "server": SERVER_INFO,
            "error": "",
            "due": 1,
            "first": "TEST0",
            "todo": [{"what": "test0"}],
            "who": "FakeServer",
        }

    def test_on_a_name_clash_the_users_value_wins(self, plugin, server):
        self.configure(
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
        self.configure(
            plugin,
            server,
            ("due", "retriever.reminders.data.count"),
            ("first", "retriever.reminders.data.items[0].title"),
            ("todo[x].what", "retriever.reminders.data.items[x].title"),
            ("problem", "retriever.error"),
            default="-",
        )
        plugin.fetch_data()
        server.refuse(500, "Internal Server Error", [RETRIEVE])
        result = plugin.fetch_data()
        assert result.data["due"] == 0
        assert result.data["first"] == "-"
        assert result.data["todo"] == []
        assert result.data["problem"] == "500 Internal Server Error"
        assert result.error == "500 Internal Server Error"

    def test_values_exist_even_before_the_server_has_been_read(self, plugin, server):
        self.configure(plugin, server, ("due", "retriever.reminders.data.count"), ("problem", "retriever.error"), default="?")
        server.stop()
        data = plugin.fetch_data().data
        assert data == {"error": "Connection refused; config pending", "due": "?", "problem": "Connection refused; config pending"}

    def test_a_bad_row_does_not_stop_the_fetch(self, plugin, server):
        self.configure(plugin, server, ("2do", "1"), ("oops", "retriever.reminders.data.count +"), ("due", "retriever.reminders.data.count"))
        result = plugin.fetch_data()
        assert result.available is True
        assert result.data["due"] == 1
        assert result.data["oops"].startswith("#SYNTAX")
        assert "2do" not in result.data


class TestPreview:
    """The text for the settings form's "Test & Preview", which core cannot fetch for itself."""

    def test_preview_is_the_servers_values_under_the_name_definitions_use(self, plugin, server):
        document = json.loads(plugin.get_preview_text())
        assert document == {"retriever": {**VALUES, "server": SERVER_INFO, "error": ""}}
        assert server.paths == [SERVER, RETRIEVE]

    def test_a_path_from_the_preview_is_a_definition_that_works(self, plugin, server):
        document = json.loads(plugin.get_preview_text())
        # What clicking a value in the preview's tree puts in a row.
        clicked = "retriever.reminders.data.items[0].title"
        assert retriever.define(rows(("t", clicked)), document) == {"t": "test0"}

    def test_preview_uses_the_settings_it_is_given_and_changes_nothing(self, plugin, server):
        plugin.fetch_data()
        before = plugin._server_config
        calls = len(server.paths)
        plugin.get_preview_text()
        assert plugin._server_config is before
        assert server.paths[calls:] == [SERVER, RETRIEVE]

    @pytest.mark.parametrize("config", [{}, {"server_url": "http://192.0.2.10:42511"}, {"api_key": KEY_B64}])
    def test_preview_asks_for_the_settings_it_needs(self, manifest, config):
        plugin = RetrieverPlugin(manifest)
        plugin._config = config
        with pytest.raises(retriever.PreviewUnavailable, match="Enter the server URL and API key first"):
            plugin.get_preview_text()

    def test_preview_says_why_the_server_gave_nothing(self, plugin, server):
        server.key = OTHER_KEY
        with pytest.raises(retriever.PreviewUnavailable, match=r"no response \(wrong key\?\)"):
            plugin.get_preview_text()
        server.stop()
        with pytest.raises(retriever.PreviewUnavailable, match="Connection refused"):
            plugin.get_preview_text()

    def test_the_reason_never_contains_the_key(self, plugin, server):
        server.refuse(400, "Stale Timestamp")
        with pytest.raises(retriever.PreviewUnavailable) as raised:
            plugin.get_preview_text()
        assert KEY_B64 not in str(raised.value)
        assert str(raised.value) == "400 Stale Timestamp"


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
            (http.client.RemoteDisconnected("Remote end closed connection without response"), "no response (wrong key?)"),
            (ConnectionResetError(54, "Connection reset by peer"), "no response (wrong key?)"),
            (urllib.error.URLError(ConnectionResetError(54, "Connection reset by peer")), "no response (wrong key?)"),
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

    @pytest.mark.parametrize("path", [SERVER, CONFIG, RETRIEVE])
    def test_opens_a_response_sealed_by_the_server(self, path):
        vector = VECTORS["responses_from_server"][path]
        seq, data = retriever.open_response(self.key, bytes.fromhex(vector["body"]), vector["id"], path)
        assert (seq, data) == (vector["seq"], vector["data"])

    def test_the_servers_config_gives_every_source_a_default(self):
        """Whatever sources the vectors hold: the plugin's defaults come from the config alone."""
        sources = VECTORS["responses_from_server"][CONFIG]["data"]
        values = VECTORS["responses_from_server"][RETRIEVE]["data"]
        assert set(sources) == set(values)
        for name, schema in sources.items():
            assert retriever.default_for(schema) == schema["default"]
            assert set(values[name]) == {"error", "data"}

    @pytest.mark.parametrize("path", [SERVER, CONFIG, RETRIEVE])
    def test_request_vector_is_what_the_plugin_seals(self, path):
        """The server's tests open this body; check here that it is still a current-format request."""
        vector = VECTORS["requests_from_plugin"][path]
        body = bytes.fromhex(vector["body"])
        plaintext = ChaCha20Poly1305(self.key).decrypt(body[:12], body[12:], retriever.request_context(path))
        expected = {"ts": vector["ts"], "id": vector["id"]}
        if "protocol" in vector:
            expected["protocol"] = vector["protocol"]
        assert json.loads(plaintext) == expected

        fresh, request_id = retriever.seal_request(self.key, vector["ts"], path, vector.get("protocol"))
        plaintext = ChaCha20Poly1305(self.key).decrypt(fresh[:12], fresh[12:], retriever.request_context(path))
        assert json.loads(plaintext) == {**expected, "id": request_id}


class TestConfig:
    @pytest.mark.parametrize(
        "config",
        [
            {},
            {"server_url": "http://192.0.2.10:42511"},
            {"api_key": KEY_B64},
            {"server_url": "  ", "api_key": KEY_B64},
            {"server_url": "192.0.2.10:42511", "api_key": KEY_B64},
            {"server_url": "file:///etc/passwd", "api_key": KEY_B64},
            {"server_url": 42511, "api_key": KEY_B64},
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
        assert KEY_B64 not in result.error

    def test_a_key_stored_under_its_old_name_still_works(self, manifest, server):
        plugin = RetrieverPlugin(manifest)
        old = {"server_url": server.url, "key": KEY_B64}
        assert plugin.validate_config(old) == []
        plugin.config = old
        assert plugin.fetch_data().data["error"] == ""
        assert json.loads(plugin.get_preview_text())["retriever"]["error"] == ""

    def test_the_new_name_wins_over_the_old(self, manifest, server):
        plugin = RetrieverPlugin(manifest)
        plugin.config = {"server_url": server.url, "api_key": KEY_B64, "key": base64.b64encode(bytes(32)).decode()}
        assert plugin.fetch_data().data["error"] == ""

    def test_valid_config(self, manifest):
        plugin = RetrieverPlugin(manifest)
        assert plugin.validate_config({"server_url": "http://192.0.2.10:42511", "api_key": f" {KEY_B64}\n"}) == []


class TestManifest:
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

        assert retriever.KEY_SETTING in SENSITIVE_FIELDS
        assert retriever.KEY_SETTING in manifest["settings_schema"]["properties"]
        assert retriever.OLD_KEY_SETTING not in manifest["settings_schema"]["properties"]

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
        assert "cryptography" in (PLUGIN_DIR / "requirements.txt").read_text().split()

    def test_fetch_fits_inside_fiestaboard_render_timeout(self):
        assert retriever.TIMEOUT_SECONDS < 5



class TestNeverRaises:
    """Whatever the server sends and whatever the rows say, a fetch returns and the other values survive."""

    NUMBERS = {"retriever": {"s": {"error": "", "data": {"nan": float("nan"), "inf": float("inf"), "ok": 2, "l": [10, 20, 30]}}}}

    @pytest.mark.parametrize("name", ["nan", "inf"])
    def test_a_formula_over_a_number_that_is_not_one_is_an_error_value(self, name):
        both = rows(("bad", f"retriever.s.data.{name} + 1"), ("good", "retriever.s.data.ok + 1"))
        assert retriever.define(both, self.NUMBERS) == {"bad": "#NUM", "good": number(3)}
        assert retriever.define(rows(("bad", f"retriever.s.data.{name} + 1"), default="none"), self.NUMBERS) == {"bad": "none"}

    def test_one_bad_element_does_not_spoil_a_list(self):
        context = {"retriever": {"s": {"error": "", "data": [1, float("nan"), 3]}}}
        assert retriever.define(rows(("l[x]", "retriever.s.data[x] * 2")), context) == {"l": [number(2), "#NUM", number(6)]}

    def test_an_index_that_is_a_digit_but_not_a_number_leads_nowhere(self):
        assert retriever.define(rows(("v", "retriever.s.data.l.\u00b2")), self.NUMBERS) == {"v": "#REF"}
        assert retriever.define(rows(("v", "retriever.s.data.l[\u0662]")), self.NUMBERS) == {"v": 30}

    def test_a_row_that_fails_leaves_the_others_and_the_servers_value(self, monkeypatch):
        def fails(value):
            raise RecursionError("too deep")

        monkeypatch.setattr(retriever.copy, "deepcopy", fails)
        defined = retriever.define(rows(("reminders.extra", '"x"'), ("mine", "retriever.reminders.data.count")), CONTEXT)
        assert defined == {"mine": 2}

    def test_a_fetch_returns_when_the_engine_raises(self, plugin, server, monkeypatch):
        def fails(expression, context):
            raise RuntimeError("engine fell over")

        monkeypatch.setattr(retriever, "evaluate_value" if TYPED else "evaluate", fails)
        plugin.config = {**plugin.config, "values": rows(("a", "1 + 1"), ("due", "retriever.reminders.data.count"))}
        data = plugin.fetch_data().data
        assert data["a"] == "#VALUE"
        assert data["due"] == 1
        assert data["error"] == ""

    def test_a_fetch_returns_when_defining_the_values_raises(self, plugin, server, monkeypatch):
        def fails(rows, context):
            raise RuntimeError("anything")

        monkeypatch.setattr(retriever, "define", fails)
        plugin.config = {**plugin.config, "values": rows(("a", "1 + 1"))}
        assert plugin.fetch_data().data == {**VALUES, "server": SERVER_INFO, "error": ""}


class TestDepth:
    """Names, paths and formulas may go MAX_DEPTH deep and no further."""

    DEEPEST = retriever.MAX_DEPTH

    def brackets(self, depth):
        return "(" * depth + "1" + ")" * depth

    def test_depth_counts_steps_and_brackets(self):
        assert retriever.depth_of("retriever.a.b[x].c") == 4
        assert retriever.depth_of("UPPER(LEFT(retriever.a, 2))") == 2
        assert retriever.depth_of('"((((" & retriever.a') == 1

    def test_the_limit_itself_is_allowed(self):
        deep = rows(("a" + ".b" * self.DEEPEST, self.brackets(self.DEEPEST)), ("p[x]", self.brackets(self.DEEPEST - 1) + " & retriever.tags.data[x]"))
        assert retriever.value_errors(deep) == []
        defined = retriever.define(deep, CONTEXT)
        assert defined["p"] == ["1a", "1b", "1c"]
        value = defined["a"]
        for _ in range(self.DEEPEST):
            value = value["b"]
        assert value == number(1)

    def test_a_name_past_the_limit_is_refused_and_skipped(self):
        deep = rows(("a" + ".b" * (self.DEEPEST + 1), "1"))
        assert "steps deep" in retriever.value_errors(deep)[0]
        assert retriever.define(deep, CONTEXT) == {}

    @pytest.mark.parametrize("depth", [DEEPEST + 1, 250, 5000])
    def test_a_formula_past_the_limit_is_refused_and_is_an_error_value(self, depth):
        deep = rows(("v", self.brackets(depth)))
        assert "deep" in retriever.value_errors(deep)[0]
        assert retriever.define(deep, CONTEXT) == {"v": "#SYNTAX"}
        assert retriever.define(rows(("v", self.brackets(depth)), default="none"), CONTEXT) == {"v": "none"}

    def test_a_path_past_the_limit_is_refused(self):
        deep = rows(("v", "retriever" + ".k" * (self.DEEPEST + 1)))
        assert "deep" in retriever.value_errors(deep)[0]
        assert retriever.define(deep, CONTEXT) == {"v": "#SYNTAX"}



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
        assert any(words in error for error in retriever.value_errors(rows(*pair)))

    def test_rows_that_agree_are_not(self):
        agree = rows(("o.a.b", '"1"'), ("o.a.c", '"2"'), ("o.d", '"3"'), ("q[x].f", "retriever.tags.data[x]"), ("q[y].g", "retriever.tags.data[y]"))
        assert retriever.value_errors(agree) == []


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
        assert any(words in error for error in retriever.shape_errors(rows((name, '"x"')), self.SHAPES))

    @pytest.mark.parametrize(
        "name",
        ["s.extra", "s.error", "s.data.n", "s.data.extra.deep", "s.data.items[x].t", "s.data.items[x].k", "s.data.loose[x].k", "s.data.either.x",
         "mine.a.b", "s", "s[x].t"],
    )
    def test_a_row_that_adds_or_replaces_is_not(self, name):
        assert retriever.shape_errors(rows((name, '"x"')), self.SHAPES) == []

    def test_the_shape_of_a_value_in_hand(self):
        assert retriever.shape_of({"name": "S", "protocol": {"min": 1}, "tags": ["a"], "none": None, "on": True}) == {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "protocol": {"type": "object", "properties": {"min": {"type": "number"}}},
                "tags": {"type": "array", "items": {"type": "string"}},
                "none": {},
                "on": {"type": "boolean"},
            },
        }


class TestSavingChecksTheServer:
    def config(self, server, *pairs):
        return {"server_url": server.url, "api_key": KEY_B64, "values": rows(*pairs)}

    def test_rows_that_fit_are_saved(self, plugin, server):
        fit = self.config(server, ("reminders.next", "retriever.reminders.data.items[0].title"), ("mine.count", "retriever.reminders.data.count"), ("server.name", '"renamed"'))
        assert plugin.validate_config(fit) == []
        assert server.paths == [SERVER, CONFIG]

    @pytest.mark.parametrize(
        ("name", "words"),
        [
            ("reminders.error.detail", "reminders.error as text"),
            ("reminders.data.count.x", "reminders.data.count as a number"),
            ("server.name.x", "server.name as text"),
            ("server.protocol.min.x", "server.protocol.min as a number"),
            ("error.code", "error as text"),
        ],
    )
    def test_a_row_that_does_not_fit_what_the_server_sends_is_refused(self, plugin, server, name, words):
        errors = plugin.validate_config(self.config(server, (name, '"x"')))
        assert len(errors) == 1
        assert words in errors[0]

    def test_a_row_that_cannot_be_checked_cannot_be_saved(self, plugin, server):
        server.refuse(503, "Service Unavailable")
        errors = plugin.validate_config(self.config(server, ("mine.count", "retriever.reminders.data.count"), ("due", "retriever.reminders.data.count")))
        assert len(errors) == 1
        assert "503 Service Unavailable" in errors[0]
        assert "mine.count" in errors[0]
        assert "due" not in errors[0].split(":")[-1]

    def test_rows_that_add_to_nothing_do_not_ask_the_server(self, plugin, server):
        server.refuse(503, "Service Unavailable")
        plain = self.config(server, ("due", "retriever.reminders.data.count"), ("todo[x].what", "retriever.reminders.data.items[x].title"))
        assert plugin.validate_config(plain) == []
        assert server.paths == []

    def test_bad_settings_are_reported_without_asking(self, plugin, server):
        errors = plugin.validate_config({"server_url": server.url, "api_key": "short", "values": rows(("mine.count", "1"))})
        assert errors == ["API key must be the base64 of 32 bytes"]
        assert server.paths == []


class TestClashAtRunTime:
    """What saving could not catch: the server sends something other than it said. Its value stays; the log says so."""

    def test_the_servers_value_is_kept_and_the_row_reported_once(self, caplog):
        retriever._reported.clear()
        context = {"retriever": {"s": {"error": "sensor offline", "data": {"n": 5, "names": ["x", "y"], "items": [{"t": "a"}]}}, "error": ""}}
        clashing = rows(("s.error.detail", '"D"'), ("s.data.n.sub", '"oops"'), ("s.data.names[x].len", "retriever.s.data.names[x]"), ("error.code", '"E1"'), ("mine", "retriever.s.data.n"))
        with caplog.at_level("WARNING"):
            assert retriever.define(clashing, context) == {"mine": 5}
            retriever.define(clashing, context)
        skipped = [record.message for record in caplog.records if "skipped" in record.message]
        assert len(skipped) == 4
        assert "Value 's.error.detail' skipped: s.error is not an object or a list" in skipped[0]

    def test_rows_that_fit_still_add_beside_one_that_does_not(self):
        context = {"retriever": {"s": {"error": "", "data": {"n": 5, "items": [{"t": "a"}]}}}}
        defined = retriever.define(rows(("s.data.items[x].k", "x"), ("s.data.n.sub", '"oops"'), ("s.data.extra", '"new"')), context)
        assert defined == {"s": {"error": "", "data": {"n": 5, "items": [{"t": "a", "k": number(0)}], "extra": "new"}}}
