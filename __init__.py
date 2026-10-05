"""
Retriever plugin for FiestaBoard.

Fetches data from a companion server and exposes it to templates.
"""

import json
import logging
import urllib.parse
import urllib.request
from typing import Any

from src.plugins.base import PluginBase, PluginResult

logger = logging.getLogger(__name__)

# FiestaBoard abandons a fetch that takes longer than 5 s, and quarantines a
# plugin after three such fetches in a row. Stay inside that.
TIMEOUT_SECONDS = 4

# What the reminders endpoint returns when nothing is due.
NO_REMINDERS: dict[str, Any] = {"count": 0, "text": "", "items": []}


class RetrieverPlugin(PluginBase):
    """Retriever plugin implementation."""

    @property
    def plugin_id(self) -> str:
        """Return the plugin ID matching manifest.json."""
        return "retriever"

    def fetch_data(self) -> PluginResult:
        """
        Assign the template variables from one fetch. Never raises.

        _fetch tells the truth about the fetch; what the variables become
        when it fails is decided here: ``reminders`` is empty, because
        nothing is known, and ``error`` says why.

        Returns:
            PluginResult with:
            - available: False only if the plugin is not configured
            - data: {"reminders": <server response, unchanged>, "error": ""}
              or, after a failed fetch,
              {"reminders": <no reminders>, "error": <reason>}
            - error: The same reason, for FiestaBoard itself
        """
        errors = self.validate_config(self.config)
        if errors:
            return PluginResult(available=False, error="; ".join(errors))

        endpoint = self.config["server_url"].strip().rstrip("/") + "/reminders"

        try:
            reminders = self._fetch(endpoint, self.config["token"])
        except Exception as e:
            # Log the endpoint, never the full URL: that carries the token.
            logger.warning(f"Fetch from {endpoint} failed: {e}")
            return PluginResult(available=True, data={"reminders": NO_REMINDERS, "error": str(e)}, error=str(e))

        return PluginResult(available=True, data={"reminders": reminders, "error": ""})

    def _fetch(self, endpoint: str, token: str) -> Any:
        """
        Retrieve one endpoint's JSON from the server.

        The only place that talks to the server. Raises on any failure,
        including a non-2xx status.
        """
        url = f"{endpoint}?{urllib.parse.urlencode({'token': token})}"
        # The scheme is restricted to http(s) by validate_config.
        with urllib.request.urlopen(url, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
            return json.load(response)

    def validate_config(self, config: dict[str, Any]) -> list[str]:
        """
        Validate plugin configuration.

        This method is called when configuration is updated.
        Note: refresh_seconds validation is handled automatically by
        the base class using the manifest's settings_schema bounds.

        Args:
            config: The configuration dictionary to validate

        Returns:
            List of error messages (empty if valid)
        """
        errors = []

        server_url = config.get("server_url")
        if not isinstance(server_url, str) or not server_url.strip():
            errors.append("Server URL is required")
        elif not server_url.strip().lower().startswith(("http://", "https://")):
            errors.append("Server URL must start with http:// or https://")

        if not config.get("token"):
            errors.append("Token is required")

        return errors

    def cleanup(self) -> None:
        """
        Cleanup when plugin is disabled.

        Override this to clean up any resources (close connections, etc.)
        """
        logger.info(f"Plugin {self.plugin_id} cleanup")
