#!/usr/bin/env python3
"""
Make the plugin's half of tests/vectors.json: requests as the plugin encrypts them.

The file has two halves, each made by the side that encrypts it, for the
other side's tests to open. This makes the requests; the server's tests make
the responses (see RetrieverServerTests.swift). Run both, and only when the
wire format changes.

Run it from a FiestaBoard source tree, which the plugin imports from:

  cd <FiestaBoard> && python <this file>
"""

import base64
import importlib.util
import json
import sys
from pathlib import Path

TESTS_DIRECTORY = Path(__file__).parent
VECTORS_FILE = TESTS_DIRECTORY / "vectors.json"
# A fixed moment, so that the server's tests can open the requests as of then.
TIMESTAMP = 1_800_000_000


def load_plugin():
    """Import the plugin from its file, as FiestaBoard's loader does. It imports FiestaBoard from the current folder."""
    sys.path.insert(0, str(Path.cwd()))
    spec = importlib.util.spec_from_file_location("retriever_plugin", TESTS_DIRECTORY.parent / "__init__.py")
    plugin = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(plugin)
    return plugin


def main() -> None:
    plugin = load_plugin()
    vectors = json.loads(VECTORS_FILE.read_text())
    transport_key = base64.b64decode(vectors["key"])
    requests = {}
    # A /server request names no protocol version; the others name the one chosen.
    for endpoint_path, protocol_version in ((plugin.SERVER_INFO_PATH, None), (plugin.CONFIG_PATH, 1), (plugin.RETRIEVE_PATH, 1)):
        body, request_id = plugin.encrypt_request(transport_key, TIMESTAMP, endpoint_path, protocol_version)
        requests[endpoint_path] = {"timestamp": TIMESTAMP, "request_id": request_id, "body": body.hex()}
        if protocol_version is not None:
            requests[endpoint_path]["required_protocol_version"] = protocol_version
    vectors["requests_from_plugin"] = requests
    VECTORS_FILE.write_text(json.dumps(vectors, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
