"""Tests for the test server, with the plugin as its client.

The test server is a second, independent implementation of the protocol, so
these also check that the plugin and a server written from the description
of the protocol agree.
"""

import base64
import http.client
import importlib.util
import json
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


retriever = _load("retriever_plugin_for_test_server", ROOT / "__init__.py")
test_server = _load("retriever_test_server", ROOT / "test_server" / "retriever_test_server.py")

KEY = bytes(range(32))
KEY_B64 = base64.b64encode(KEY).decode()
ELEMENTS = [
    {"label": "first", "count": 2, "items": [{"title": "a", "parts": ["p", "q"]}, {"title": "b", "parts": ["r"]}]},
    {"label": "second", "count": 1, "items": [{"title": "c", "parts": []}]},
    {"label": "third", "count": 0, "items": []},
]


class Running:
    def __init__(self, tmp_path, elements=ELEMENTS):
        self.file = tmp_path / "list.json"
        self.write(elements)
        self.lines = []
        self.server = test_server.serve(str(self.file), KEY, 0, log=self.lines.append)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def write(self, elements):
        self.file.write_text(elements if isinstance(elements, str) else json.dumps(elements))

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def running(tmp_path):
    server = Running(tmp_path)
    yield server
    server.stop()


@pytest.fixture
def plugin(running):
    plugin = retriever.RetrieverPlugin(json.loads((ROOT / "manifest.json").read_text()))
    plugin.config = {"server_url": running.url, "key": KEY_B64}
    return plugin


def data(plugin):
    result = plugin.fetch_data()
    assert result.available is True
    return result.data


class TestTheList:
    def test_each_retrieve_sends_the_next_element_and_wraps(self, plugin):
        seen = [data(plugin)["test"] for _ in range(7)]
        assert [entry["data"]["label"] for entry in seen] == ["first", "second", "third", "first", "second", "third", "first"]
        assert all(entry["error"] == "" for entry in seen)
        assert seen[0]["data"] == ELEMENTS[0]

    def test_only_a_retrieve_moves_on(self, plugin, running):
        key = retriever.decode_key(KEY_B64)
        for _ in range(3):
            plugin._fetch(running.url, "/server", key, time.monotonic() + 4)
            plugin._fetch(running.url, "/config", key, time.monotonic() + 4, 1)
        assert data(plugin)["test"]["data"]["label"] == "first"

    def test_an_edited_file_is_read_at_once(self, plugin, running):
        assert data(plugin)["test"]["data"]["label"] == "first"
        running.write([{"label": "x", "count": 9, "items": []}, {"label": "y", "count": 8, "items": []}, {"label": "z", "count": 7, "items": []}])
        assert data(plugin)["test"]["data"]["label"] == "y"  # the position carries on
        assert data(plugin)["test"]["data"]["label"] == "z"
        assert data(plugin)["test"]["data"]["label"] == "x"

    def test_a_shorter_list_wraps_where_it_now_ends(self, plugin, running):
        data(plugin), data(plugin)
        running.write([{"label": "only", "count": 0, "items": []}])
        assert data(plugin)["test"]["data"]["label"] == "only"
        assert data(plugin)["test"]["data"]["label"] == "only"

    def test_the_elements_can_be_anything(self, plugin, running):
        running.write([1, "two", [3], None, {"five": 5}])
        assert [data(plugin)["test"]["data"] for _ in range(5)] == [1, "two", [3], None, {"five": 5}]

    @pytest.mark.parametrize("content", ["not json", "{}", "[]", '"a string"'])
    def test_a_file_that_is_not_a_list_is_the_sources_error(self, plugin, running, content):
        running.write(content)
        entry = data(plugin)["test"]
        assert entry["data"] is None
        assert "list.json" in entry["error"]

    def test_a_missing_file_is_the_sources_error(self, plugin, running):
        running.file.unlink()
        assert "cannot read" in data(plugin)["test"]["error"]

    def test_the_source_can_be_named(self, tmp_path):
        file = tmp_path / "list.json"
        file.write_text("[1, 2]")
        server = test_server.serve(str(file), KEY, 0, name="numbers", log=lambda line: None)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            plugin = retriever.RetrieverPlugin(json.loads((ROOT / "manifest.json").read_text()))
            plugin.config = {"server_url": f"http://127.0.0.1:{server.server_port}", "key": KEY_B64}
            assert data(plugin)["numbers"] == {"error": "", "data": 1}
        finally:
            server.shutdown()
            server.server_close()


class TestConfig:
    def test_the_shape_comes_from_the_first_element(self, running):
        assert running.server.source.config() == {
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
        data(plugin)
        running.stop()
        result = plugin.fetch_data()
        assert result.data["test"] == {"error": "", "data": {"label": "", "count": 0, "items": []}}
        assert result.data["error"] == "Connection refused"

    def test_a_change_of_shape_changes_the_sequence_number_and_the_plugin_reads_the_config_again(self, plugin, running):
        data(plugin)
        before = plugin._server_config[0]
        running.write([{"label": "same shape", "count": 5, "items": [{"title": "z", "parts": ["k"]}]}])
        data(plugin)
        assert plugin._server_config[0] == before  # other values, same shape: nothing to read again
        running.write([{"temperature": 21.5}])
        data(plugin)
        assert plugin._server_config[0] != before
        assert plugin._server_config[1]["test"]["default"] == {"temperature": 0}

    def test_server_info(self, plugin, running):
        info = data(plugin)["server"]
        assert info["name"] == "RetrieverTestServer"
        assert info["protocol"] == {"min": 1, "max": 1}
        assert info["port"] == running.server.server_port
        assert info["count"] == 3
        assert info["file"] == str(running.file)


class TestListRows:
    """The plugin's list rows, over data with lists inside lists."""

    def test_nested_rows_follow_each_element(self, plugin, running):
        plugin.config = {
            "server_url": running.url,
            "key": KEY_B64,
            "values": [
                {"variable": "label", "definition": "UPPER(retriever.test.data.label)", "default": ""},
                {"variable": "things[x].title", "definition": "retriever.test.data.items[x].title", "default": ""},
                {"variable": "things[x].n", "definition": "x + 1", "default": ""},
                {"variable": "things[x].parts[y]", "definition": "retriever.test.data.items[x].parts[y]", "default": ""},
            ],
        }
        first, second, third = data(plugin), data(plugin), data(plugin)
        assert first["label"] == "FIRST"
        assert first["things"] == [
            {"title": "a", "n": "1", "parts": ["p", "q"]},
            {"title": "b", "n": "2", "parts": ["r"]},
        ]
        assert second["things"] == [{"title": "c", "n": "1", "parts": []}]
        assert third["label"] == "THIRD"
        assert third["things"] == []


class TestRefusals:
    def raw(self, running, path, body=b"", method="POST"):
        request = urllib.request.Request(running.url + path, data=body if method == "POST" else None, method=method)
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
            self.raw(running, path, body, method)
        assert "no response" in running.lines[-1]

    def test_a_request_sealed_for_another_endpoint_is_not_answered(self, running):
        body, _ = retriever.seal_request(KEY, time.time(), "/config", 1)
        with pytest.raises((http.client.RemoteDisconnected, ConnectionError)):
            self.raw(running, "/retrieve", body)

    def test_a_stale_timestamp_is_said_to_be_one(self, running):
        body, _ = retriever.seal_request(KEY, time.time() - 120, "/retrieve", 1)
        with pytest.raises(urllib.error.HTTPError) as raised:
            self.raw(running, "/retrieve", body)
        assert (raised.value.code, raised.value.reason) == (400, "Stale Timestamp")

    def test_a_protocol_outside_the_range_is_refused(self, running):
        body, _ = retriever.seal_request(KEY, time.time(), "/retrieve", 9)
        with pytest.raises(urllib.error.HTTPError) as raised:
            self.raw(running, "/retrieve", body)
        assert (raised.value.code, raised.value.reason) == (400, "Unsupported Protocol")

    def test_a_refused_retrieve_does_not_use_up_an_element(self, plugin, running):
        for body in (retriever.seal_request(KEY, time.time() - 120, "/retrieve", 1)[0], b"x" * 40):
            with pytest.raises(Exception):
                self.raw(running, "/retrieve", body)
        assert data(plugin)["test"]["data"]["label"] == "first"

    def test_a_plugin_with_another_key_gets_no_response(self, running):
        plugin = retriever.RetrieverPlugin(json.loads((ROOT / "manifest.json").read_text()))
        plugin.config = {"server_url": running.url, "key": base64.b64encode(bytes(32)).decode()}
        assert plugin.fetch_data().data == {"error": "no response (wrong key?); config pending"}


class TestTheExample:
    def test_the_example_file_is_a_list_the_server_can_serve(self):
        source = test_server.ListSource(str(ROOT / "test_server" / "example.json"))
        elements = source.elements()
        assert len(elements) >= 3
        assert [source.next()[0]["data"] for _ in elements] == elements
