#!/usr/bin/env python3
"""
Run the system check: put the plugin, inside a real FiestaBoard, in front of a
server that misbehaves, and compare what FiestaBoard renders with what it
rendered before.

README.md beside this file says when this is worth doing and how to set it
up. In short: a spare instance of the plugin must point at a running
misbehaving_server.py, and this program must be able to reach FiestaBoard's
API and to hand that server a scenario.

  python run.py [--record] [--show] [group ...]

  group     which groups of cases to run: values, limits, answers, heavy.
            All of them if none is named.
  --record  take what is rendered as what is expected from now on, and write
            it to expected.json. Read the differences first.
  --show    print every result, not only the ones that differ.

Settings, from the environment:

  RETRIEVER_CHECK_FIESTABOARD  FiestaBoard's API, such as http://<host>:4420/api/v1 (required)
  RETRIEVER_CHECK_TOKEN_FILE   a file holding a FiestaBoard API token (required)
  RETRIEVER_CHECK_DELIVER      a shell command that reads a scenario on its standard
                               input and puts it where the misbehaving server reads
                               it, such as: ssh <host> 'cat > check/scenario.json' (required)
  RETRIEVER_CHECK_INSTANCE     the plugin instance to use (default retriever:test).
                               Its value rows are replaced while the check runs
                               and put back afterwards.

The exit status is 0 if everything rendered as expected, 1 if anything
differed, and 2 if the check could not be run.
"""

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))
from cases import GROUPS, Case, Row  # the path must be set first

EXPECTED_FILE = Path(__file__).parent / "expected.json"
# Probes are rendered for the largest board, with wrapping, so that as much of a value as possible shows.
RENDER_PATH = "/render?device_type=flagship"
REQUEST_TIMEOUT_SECONDS = 40
ATTEMPTS_TO_REACH_FIESTABOARD = 4
SECONDS_BETWEEN_ATTEMPTS = 3


class CannotRun(Exception):
    """The check could not be carried out; the message says why."""


class FiestaBoard:
    """FiestaBoard's API, and the plugin instance the check works through."""

    def __init__(self, api_url: str, token: str, instance: str):
        self.api_url = api_url.rstrip("/")
        self.token = token
        self.instance = instance

    def call(self, method: str, path: str, body: Any = None) -> tuple[int, Any]:
        """
        Make one call to the API.

        Returns:
            The HTTP status and the decoded JSON body; for a refusal, the
            status and whatever the body was.

        Raises:
            CannotRun: FiestaBoard could not be reached.
        """
        request = urllib.request.Request(
            self.api_url + path,
            method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"},
        )
        for attempts_left in reversed(range(ATTEMPTS_TO_REACH_FIESTABOARD)):
            try:
                with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                    return response.status, json.loads(response.read())
            except urllib.error.HTTPError as refusal:
                text = refusal.read().decode(errors="replace")
                try:
                    return refusal.code, json.loads(text)
                except ValueError:
                    return refusal.code, text
            except OSError as error:
                # A small machine on a home network drops the odd connection; that is not a result.
                if not attempts_left:
                    raise CannotRun(f"FiestaBoard could not be reached at {self.api_url}: {error}") from None
                time.sleep(SECONDS_BETWEEN_ATTEMPTS)
        raise CannotRun("FiestaBoard could not be reached")

    def settings(self) -> dict[str, Any]:
        """The instance's settings as stored, secrets masked. Raises CannotRun if there is no such instance."""
        status, plugin = self.call("GET", f"/plugins/{self.instance}")
        if status != 200 or "config" not in plugin:
            raise CannotRun(f"FiestaBoard has no plugin instance {self.instance} (status {status})")
        return plugin["config"]

    def save_rows(self, settings: dict[str, Any], rows: list[dict[str, str]]) -> list[str] | None:
        """
        Save the instance's settings with these value rows.

        A save that changes the rows also makes the instance fetch afresh.

        Returns:
            None if they were saved; otherwise the reasons FiestaBoard gave
            for refusing them.
        """
        status, answer = self.call("PATCH", f"/plugins/{self.instance}", {"config": {**settings, "values": rows}})
        if status == 200:
            return None
        detail = answer.get("detail") if isinstance(answer, dict) else None
        reasons = detail.get("errors") if isinstance(detail, dict) else None
        return reasons or [f"status {status}: {str(answer)[:200]}"]

    def render(self, probe: str) -> str:
        """What FiestaBoard renders for a probe, its lines joined by "/" and blank lines left out."""
        template = probe.replace("%", self.instance + ".")
        status, answer = self.call("POST", RENDER_PATH, {"template": [template], "line_metadata": [{"alignment": "left", "wrap": True}]})
        if status != 200 or "lines" not in answer:
            detail = answer.get("detail", answer) if isinstance(answer, dict) else answer
            return f"NOT RENDERED (status {status}): {str(detail)[:200]}"
        return "/".join(line.rstrip() for line in answer["lines"] if line.strip())


def stored(rows: list[Row]) -> list[dict[str, str]]:
    """Value rows in the form the plugin's settings hold them."""
    return [{"variable": name, "definition": definition, "default": default} for name, definition, default in rows]


def deliver(scenario: dict[str, Any], deliver_command: str) -> None:
    """Hand a scenario to the misbehaving server. Raises CannotRun if the command fails."""
    done = subprocess.run(deliver_command, shell=True, input=json.dumps(scenario), capture_output=True, text=True)
    if done.returncode != 0:
        raise CannotRun(f"the scenario could not be delivered: {done.stderr.strip() or done.returncode}")


def run_case(case: Case, marker: str, board: FiestaBoard, settings: dict[str, Any], deliver_command: str) -> tuple[dict[str, str], float]:
    """
    Run one case and collect what came of it.

    Args:
        marker: Text that is this case's alone. It names the scenario, so
            that the server starts its steps again, and it is a value row,
            so that every case changes the rows and so fetches afresh.

    Returns:
        What happened, by what was tried: each set of rows that should be
        refused, then each probe as rendered. And how long the first render,
        which is the one that waits for the fetch, took.
    """
    deliver({"case": marker, **case.scenario}, deliver_command)
    results = {}
    for label, rows in case.refused_rows:
        reasons = board.save_rows(settings, stored(rows))
        results[f"refused: {label}"] = "SAVED, and should not have been" if reasons is None else "; ".join(reasons)

    reasons = board.save_rows(settings, stored([("check_case", f'"{marker}"', ""), *case.rows]))
    if reasons is not None:
        results["rows"] = "NOT SAVED: " + "; ".join(reasons)

    started = time.monotonic()
    results["{{%check_case}} error=[{{%error}}]"] = board.render("{{%check_case}} error=[{{%error}}]")
    seconds_for_the_fetch = time.monotonic() - started
    for probe in case.probes:
        results[probe] = board.render(probe)
    time.sleep(case.seconds_to_wait_after)
    return results, seconds_for_the_fetch


def report(key: str, results: dict[str, str], expected: dict[str, str] | None, seconds: float, show_everything: bool) -> bool:
    """
    Print one case's outcome.

    Returns:
        True if every result is what was expected, or nothing was expected yet.
    """
    differing = [what for what in results if expected is not None and results[what] != expected.get(what)]
    verdict = "new" if expected is None else ("differs" if differing else "as expected")
    print(f"{verdict:12} {key}   [{seconds:.1f} s]")
    for what, rendered in results.items():
        if what in differing:
            print(f"    {what}\n        was: {expected.get(what)}\n        now: {rendered}")
        elif show_everything or expected is None:
            print(f"    {what}\n        {rendered}")
    return not differing


def environment(name: str) -> str:
    """A required setting. Raises CannotRun if it is not set."""
    value = os.environ.get(name, "").strip()
    if not value:
        raise CannotRun(f"{name} is not set; see the top of {Path(__file__).name}")
    return value


def main(arguments: list[str]) -> int:
    """Run the groups named, or all of them, and say how it went. Returns the exit status."""
    recording, show_everything = "--record" in arguments, "--show" in arguments
    groups = [argument for argument in arguments if not argument.startswith("--")] or list(GROUPS)
    unknown = [group for group in groups if group not in GROUPS]
    if unknown:
        print(f"No such group: {', '.join(unknown)}. The groups are {', '.join(GROUPS)}.", file=sys.stderr)
        return 2
    try:
        token = Path(environment("RETRIEVER_CHECK_TOKEN_FILE")).expanduser().read_text().strip()
        board = FiestaBoard(environment("RETRIEVER_CHECK_FIESTABOARD"), token, os.environ.get("RETRIEVER_CHECK_INSTANCE", "retriever:test"))
        deliver_command = environment("RETRIEVER_CHECK_DELIVER")
        settings = board.settings()
    except (CannotRun, OSError) as problem:
        print(problem, file=sys.stderr)
        return 2

    expected = json.loads(EXPECTED_FILE.read_text())["results"] if EXPECTED_FILE.exists() else {}
    everything_as_expected = True
    try:
        for group in groups:
            print(f"\n== {group}")
            rendered_in_group = {}
            for position, case in enumerate(GROUPS[group], start=1):
                key = f"{position:02d} {case.name}"
                results, seconds = run_case(case, f"{group} {position}", board, settings, deliver_command)
                rendered_in_group[key] = results
                everything_as_expected &= report(key, results, expected.get(group, {}).get(key), seconds, show_everything)
            if recording:
                expected[group] = rendered_in_group
    except CannotRun as problem:
        print(problem, file=sys.stderr)
        return 2
    finally:
        # Whatever happened, the instance gets its own rows back.
        still_refused = board.save_rows(settings, settings.get("values", []))
        print("\nThe instance's own rows are back." if still_refused is None else f"\nTHE INSTANCE'S ROWS WERE NOT PUT BACK: {still_refused}")

    if recording:
        note = "What FiestaBoard rendered for each case when this was last recorded; run.py compares against it."
        EXPECTED_FILE.write_text(json.dumps({"note": note, "results": expected}, indent=1, ensure_ascii=False, sort_keys=True) + "\n")
        print(f"Recorded in {EXPECTED_FILE.name}.")
        return 0
    print("Everything rendered as expected." if everything_as_expected else "Some results differ from what was expected; see above.")
    return 0 if everything_as_expected else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
