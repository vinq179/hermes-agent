"""One-click AIVaults DMCMS device consent in Hermes Dashboard.

Uses Hermes' existing RFC 8628 login_device() implementation, which already
handles MCP resource discovery, issuer checks, polling, secure token storage,
refresh-token issuer binding and client metadata.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

from tools.mcp_dashboard_oauth import DashboardOAuthFlow


DMCMS_RESOURCE = "https://dmcms.aivaults.top/mcp"
HUB_CLIENT_ID = "https://my.aivaults.top/.well-known/oauth-client/dmcms-device"
HUB_SCOPE = "dmcms.mcp offline_access"


def is_dmcms_oauth(cfg: dict) -> bool:
    return cfg.get("url") == DMCMS_RESOURCE and cfg.get("auth") == "oauth"


@dataclass
class DashboardDeviceOAuthFlow(DashboardOAuthFlow):
    user_code: str | None = None

    async def publish_device_authorization(self, data: dict) -> None:
        code = data.get("user_code")
        complete = data.get("verification_uri_complete")
        if not isinstance(code, str) or not isinstance(complete, str):
            raise ValueError("Device authorization missing verification code or URL")
        url = urlparse(complete)
        if (
            url.scheme != "https"
            or url.netloc != "my.aivaults.top"
            or url.path != "/oauth/consent"
            or url.fragment
            or parse_qs(url.query).get("user_code") != [code]
        ):
            raise ValueError("Unexpected device verification URL")
        with self._lock:
            if self.cancelled or self.status in {"approved", "error"}:
                raise RuntimeError("Device authorization cancelled or already completed")
            self.user_code = code
            self.authorization_url = complete
            self.status = "authorization_required"
            self._authorization_ready.set()

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "flow_id": self.flow_id,
                "server_name": self.server_name,
                "status": self.status,
                "authorization_url": self.authorization_url,
                "user_code": self.user_code,
                "error": self.error,
            }
