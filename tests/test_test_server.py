"""Tests for the test server, with the plugin as its client.

The test server is a second, independent implementation of the protocol, so
these also check that the plugin and a server written from the description
of the protocol agree.
"""

import base64
import http.client
import importlib.util
import json
import socket
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).parent.parent


def _load_module(name, path):
    """Import a module from a file that is in no package."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


retriever = _load_module("retriever_plugin_for_test_server", REPOSITORY_ROOT / "__init__.py")
test_server = _load_module("retriever_test_server", REPOSITORY_ROOT / "test_server" / "retriever_test_server.py")

TRANSPORT_KEY = bytes(range(32))
ENCODED_TRANSPORT_KEY = base64.b64encode(TRANSPORT_KEY).decode()
ELEMENTS = [
    {"label": "first", "count": 2, "items": [{"title": "a", "parts": ["p", "q"]}, {"title": "b", "parts": ["r"]}]},
    {"label": "second", "count": 1, "items": [{"title": "c", "parts": []}]},
    {"label": "third", "count": 0, "items": []},
]


class RunningTestServer:
    """The test server, serving a list from a file a test can rewrite, for as long as the test runs."""

    def __init__(self, tmp_path, elements=ELEMENTS):
        self.list_file = tmp_path / "list.json"
        self.write(elements)
        self.log_lines = []
        self.http_server = test_server.create_server(str(self.list_file), TRANSPORT_KEY, 0, log=self.log_lines.append)
        self.url = f"http://127.0.0.1:{self.http_server.server_port}"
        threading.Thread(target=self.http_server.serve_forever, daemon=True).start()

    def write(self, elements):
        """Replace the file's contents: a list to be written as JSON, or text to be written as it is."""
        self.list_file.write_text(elements if isinstance(elements, str) else json.dumps(elements))

    def stop(self):
        self.http_server.shutdown()
        self.http_server.server_close()


@pytest.fixture
def running(tmp_path):
    """A test server serving ELEMENTS, stopped when the test ends."""
    test_server_running = RunningTestServer(tmp_path)
    yield test_server_running
    test_server_running.stop()


@pytest.fixture
def plugin(running):
    """The real plugin, set up to talk to the running test server."""
    plugin = retriever.RetrieverPlugin(json.loads((REPOSITORY_ROOT / "manifest.json").read_text()))
    plugin.config = {"server_url": running.url, "api_key": ENCODED_TRANSPORT_KEY}
    return plugin


def fetched_data(plugin):
    """The template variables from one fetch, which must have produced some."""
    result = plugin.fetch_data()
    assert result.available is True
    return result.data


class TestTheList:
    """The file's elements are served one per retrieve, in order, and the file may change underneath."""

    def test_each_retrieve_sends_the_next_element_and_wraps(self, plugin):
        seen = [fetched_data(plugin)["test"] for _ in range(7)]
        assert [entry["data"]["label"] for entry in seen] == ["first", "second", "third", "first", "second", "third", "first"]
        assert all(entry["error"] == "" for entry in seen)
        assert seen[0]["data"] == ELEMENTS[0]

    def test_only_a_retrieve_moves_on(self, plugin, running):
        key = retriever.decode_transport_key(ENCODED_TRANSPORT_KEY)
        for _ in range(3):
            plugin._send_encrypted_request(running.url, "/server", key, time.monotonic() + 4)
            plugin._send_encrypted_request(running.url, "/config", key, time.monotonic() + 4, 1)
        assert fetched_data(plugin)["test"]["data"]["label"] == "first"

    def test_an_edited_file_is_read_at_once(self, plugin, running):
        assert fetched_data(plugin)["test"]["data"]["label"] == "first"
        running.write([{"label": "x", "count": 9, "items": []}, {"label": "y", "count": 8, "items": []}, {"label": "z", "count": 7, "items": []}])
        assert fetched_data(plugin)["test"]["data"]["label"] == "y"  # the position carries on
        assert fetched_data(plugin)["test"]["data"]["label"] == "z"
        assert fetched_data(plugin)["test"]["data"]["label"] == "x"

    def test_a_shorter_list_wraps_where_it_now_ends(self, plugin, running):
        fetched_data(plugin), fetched_data(plugin)
        running.write([{"label": "only", "count": 0, "items": []}])
        assert fetched_data(plugin)["test"]["data"]["label"] == "only"
        assert fetched_data(plugin)["test"]["data"]["label"] == "only"

    def test_the_elements_can_be_anything(self, plugin, running):
        running.write([1, "two", [3], None, {"five": 5}])
        assert [fetched_data(plugin)["test"]["data"] for _ in range(5)] == [1, "two", [3], None, {"five": 5}]

    @pytest.mark.parametrize("content", ["not json", "{}", "[]", '"a string"'])
    def test_a_file_that_is_not_a_list_is_the_sources_error(self, plugin, running, content):
        running.write(content)
        entry = fetched_data(plugin)["test"]
        assert entry["data"] is None
        assert "list.json" in entry["error"]

    def test_a_missing_file_is_the_sources_error(self, plugin, running):
        running.list_file.unlink()
        assert "cannot read" in fetched_data(plugin)["test"]["error"]

    def test_the_source_can_be_named(self, tmp_path):
        file = tmp_path / "list.json"
        file.write_text("[1, 2]")
        server = test_server.create_server(str(file), TRANSPORT_KEY, 0, source_name="numbers", log=lambda line: None)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            plugin = retriever.RetrieverPlugin(json.loads((REPOSITORY_ROOT / "manifest.json").read_text()))
            plugin.config = {"server_url": f"http://127.0.0.1:{server.server_port}", "api_key": ENCODED_TRANSPORT_KEY}
            assert fetched_data(plugin)["numbers"] == {"error": "", "data": 1}
        finally:
            server.shutdown()
            server.server_close()


class TestConfig:
    """The config the test server makes up from the first element of its file."""

    def test_the_shape_comes_from_the_first_element(self, running):
        assert running.http_server.source.config() == {
            "test": {
                "type": "object",
                "properties": {
                    "label": {"type": "string"},
                    "count": {"type": "integer"},
                    "items": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {"title": {"type": "string"}, "parts": {"type": "array", "items": {"type": "string"}}},
                        },
                    },
                },
                "default": {"label": "", "count": 0, "items": []},
            }
        }

    def test_the_plugin_shows_the_default_when_a_retrieve_fails(self, plugin, running):
        fetched_data(plugin)
        running.stop()
        result = plugin.fetch_data()
        assert result.data["test"] == {"error": "", "data": {"label": "", "count": 0, "items": []}}
        assert result.data["error"] == "Connection refused"

    def test_a_change_of_shape_changes_the_sequence_number_and_the_plugin_reads_the_config_again(self, plugin, running):
        fetched_data(plugin)
        before = plugin._server_self_description.sequence_number
        running.write([{"label": "same shape", "count": 5, "items": [{"title": "z", "parts": ["k"]}]}])
        fetched_data(plugin)
        assert plugin._server_self_description.sequence_number == before  # other values, same shape: nothing to read again
        running.write([{"temperature": 21.5}])
        fetched_data(plugin)
        assert plugin._server_self_description.sequence_number != before
        assert plugin._server_self_description.source_schemas["test"]["default"] == {"temperature": 0}

    def test_server_info(self, plugin, running):
        info = fetched_data(plugin)["server"]
        assert info["name"] == "RetrieverTestServer"
        assert info["protocol"] == {"min": 1, "max": 1}
        assert info["port"] == running.http_server.server_port
        assert info["count"] == 3
        assert info["file"] == str(running.list_file)


class TestOneReadingPerResponse:
    """Every part of a response comes from the file as it was at one moment, however often the file changes."""

    def test_the_file_is_read_once_for_each_request(self, plugin, running, monkeypatch):
        source = running.http_server.source
        readings = []
        read_the_file = source.read_list

        def counted():
            readings.append(1)
            return read_the_file()

        monkeypatch.setattr(source, "read_list", counted)
        fetched_data(plugin)
        assert len(readings) == 3  # /server, /config and /retrieve

    def test_the_element_and_the_sequence_number_agree_when_the_file_changes_between_them(self, plugin, running, monkeypatch):
        """The file is rewritten the moment it has been read, as an editor might do in the middle of a request."""
        fetched_data(plugin)
        source = running.http_server.source
        read_the_file = source.read_list

        def read_then_change():
            elements = read_the_file()
            running.write([{"temperature": 21.5}])
            return elements

        monkeypatch.setattr(source, "read_list", read_then_change)
        contents = source.read_file()
        assert source.next_entry(contents)[0]["data"] == ELEMENTS[1]
        assert source.sequence_number(contents) == plugin._server_self_description.sequence_number
        assert source.sequence_number() != source.sequence_number(contents)  # the next request sees the new file


class TestAwkwardFiles:
    """Files the server must put up with, and bad data it must be able to send, being for tests."""

    def nested(self, depth):
        return "[" * depth + "]" * depth

    @pytest.mark.parametrize("depth", [2000, 100000])
    def test_a_file_nested_too_deeply_is_the_sources_error_and_the_server_carries_on(self, plugin, running, depth):
        running.write(f'[{{"deep": {self.nested(depth)}}}]')
        entry = fetched_data(plugin)["test"]
        assert entry["data"] is None
        assert "nested too deeply" in entry["error"]
        running.write(ELEMENTS)
        assert fetched_data(plugin)["test"]["data"]["label"] in ("first", "second", "third")

    def test_nesting_python_can_manage_is_served_with_no_limit_of_the_servers_own(self, plugin, running):
        running.write(f'[{{"deep": {self.nested(200)}}}]')
        value = fetched_data(plugin)["test"]["data"]["deep"]
        for _ in range(199):
            value = value[0]
        assert value == []

    def test_a_byte_order_mark_is_not_a_fault(self, plugin, running):
        running.list_file.write_bytes(b"\xef\xbb\xbf" + json.dumps(ELEMENTS).encode())
        assert fetched_data(plugin)["test"]["data"]["label"] == "first"

    def test_numbers_that_are_not_json_are_sent_as_they_are(self, running):
        running.write('[{"reading": NaN, "limit": Infinity}]')
        data = running.http_server.source.next_entry()[0]["data"]
        assert data["reading"] != data["reading"]
        assert data["limit"] == float("inf")

    def test_the_source_may_have_a_name_the_plugin_reserves(self):
        source = test_server.ListSource(str(REPOSITORY_ROOT / "test_server" / "example.json"), "error")
        assert list(source.config()) == ["error"]


class TestListRows:
    """The plugin's list rows, over data with lists inside lists."""

    def test_nested_rows_follow_each_element(self, plugin, running):
        plugin.config = {
            "server_url": running.url,
            "api_key": ENCODED_TRANSPORT_KEY,
            "values": [
                {"variable": "label", "definition": "UPPER(retriever.test.data.label)", "default": ""},
                {"variable": "things[x].title", "definition": "retriever.test.data.items[x].title", "default": ""},
                {"variable": "things[x].n", "definition": "x + 1", "default": ""},
                {"variable": "things[x].parts[y]", "definition": "retriever.test.data.items[x].parts[y]", "default": ""},
            ],
        }
        first, second, third = fetched_data(plugin), fetched_data(plugin), fetched_data(plugin)
        # Numbers, or their text from a formula engine that only renders.
        one, two = (1, 2) if retriever.evaluate_value else ("1", "2")
        assert first["label"] == "FIRST"
        assert first["things"] == [
            {"title": "a", "n": one, "parts": ["p", "q"]},
            {"title": "b", "n": two, "parts": ["r"]},
        ]
        assert second["things"] == [{"title": "c", "n": one, "parts": []}]
        assert third["label"] == "THIRD"
        assert third["things"] == []


class TestRefusals:
    """What the test server will not answer, and what it answers with a reason."""

    def send_unencrypted(self, running, endpoint_path, body=b"", method="POST"):
        """Send the server a request as it is, with no encryption. Raises if the server does not answer 2xx."""
        request = urllib.request.Request(running.url + endpoint_path, data=body if method == "POST" else None, method=method)
        return urllib.request.urlopen(request, timeout=5)

    @pytest.mark.parametrize(
        ("path", "body", "method"),
        [
            ("/retrieve", b"x" * 40, "POST"),
            ("/retrieve", b"", "POST"),
            ("/nowhere", b"x" * 40, "POST"),
            ("/retrieve", b"", "GET"),
        ],
    )
    def test_nothing_is_said_to_a_request_that_has_not_shown_the_key(self, running, path, body, method):
        with pytest.raises((http.client.RemoteDisconnected, ConnectionError)):
            self.send_unencrypted(running, path, body, method)
        assert "no response" in running.log_lines[-1]

    def test_a_request_sealed_for_another_endpoint_is_not_answered(self, running):
        body, _ = retriever.encrypt_request(TRANSPORT_KEY, time.time(), "/config", 1)
        with pytest.raises((http.client.RemoteDisconnected, ConnectionError)):
            self.send_unencrypted(running, "/retrieve", body)

    def test_a_stale_timestamp_is_said_to_be_one(self, running):
        body, _ = retriever.encrypt_request(TRANSPORT_KEY, time.time() - 120, "/retrieve", 1)
        with pytest.raises(urllib.error.HTTPError) as raised:
            self.send_unencrypted(running, "/retrieve", body)
        assert (raised.value.code, raised.value.reason) == (400, "Stale Timestamp")

    def test_a_protocol_outside_the_range_is_refused(self, running):
        body, _ = retriever.encrypt_request(TRANSPORT_KEY, time.time(), "/retrieve", 9)
        with pytest.raises(urllib.error.HTTPError) as raised:
            self.send_unencrypted(running, "/retrieve", body)
        assert (raised.value.code, raised.value.reason) == (400, "Unsupported Protocol")

    def test_a_refused_retrieve_does_not_use_up_an_element(self, plugin, running):
        for body in (retriever.encrypt_request(TRANSPORT_KEY, time.time() - 120, "/retrieve", 1)[0], b"x" * 40):
            with pytest.raises((urllib.error.HTTPError, http.client.RemoteDisconnected, ConnectionError)):
                self.send_unencrypted(running, "/retrieve", body)
        assert fetched_data(plugin)["test"]["data"]["label"] == "first"

    def test_a_plugin_with_another_key_gets_no_response(self, running):
        plugin = retriever.RetrieverPlugin(json.loads((REPOSITORY_ROOT / "manifest.json").read_text()))
        plugin.config = {"server_url": running.url, "api_key": base64.b64encode(bytes(32)).decode()}
        assert plugin.fetch_data().data == {"error": "no response (wrong key?); config pending"}


class TestAbandonedConnections:
    """A client that stops half-way is dropped after a while, so the server cleans up after a test that broke."""

    @pytest.mark.parametrize(
        "sent",
        [b"", b"POST /retrieve HTTP/1.1\r\n", b"POST /retrieve HTTP/1.1\r\nContent-Length: 100\r\n\r\nonly this much"],
        ids=["nothing", "part of the headers", "part of the body"],
    )
    def test_the_connection_is_closed_when_the_client_stops_sending(self, running, monkeypatch, sent):
        monkeypatch.setattr(running.http_server.RequestHandlerClass, "timeout", 0.2)
        with socket.create_connection(("127.0.0.1", running.http_server.server_port), timeout=5) as connection:
            connection.sendall(sent)
            assert connection.recv(100) == b""  # closed by the server, with nothing said

    def test_the_wait_is_a_minute(self):
        assert test_server.CLIENT_READ_TIMEOUT_SECONDS == 60


class TestTheExample:
    """The example file shipped beside the server."""

    def test_the_example_file_is_a_list_the_server_can_serve(self):
        source = test_server.ListSource(str(REPOSITORY_ROOT / "test_server" / "example.json"))
        elements = source.read_list()
        assert len(elements) >= 3
        assert [source.next_entry()[0]["data"] for _ in elements] == elements
