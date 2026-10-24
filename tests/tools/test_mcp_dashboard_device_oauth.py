"""Hermes Dashboard one-click DMCMS device authorization contracts."""
import asyncio

import pytest

from tools.mcp_dashboard_device_oauth import (
    DashboardDeviceOAuthFlow,
    DMCMS_RESOURCE,
    HUB_CLIENT_ID,
    HUB_SCOPE,
    is_dmcms_oauth,
)


def _flow():
    return DashboardDeviceOAuthFlow(
        flow_id="first-party",
        server_name="dmcms",
        profile=None,
        hermes_home="/tmp/hermes-device-test",
        redirect_uri="",
    )


def test_dmcms_device_auth_only_matches_first_party_mcp():
    assert is_dmcms_oauth({"url": DMCMS_RESOURCE, "auth": "oauth"})
    assert HUB_CLIENT_ID.startswith("https://my.aivaults.top/.well-known/oauth-client/")
    assert HUB_SCOPE == "dmcms.mcp offline_access"
    for cfg in [
        {"url": "http://dmcms.aivaults.top/mcp", "auth": "oauth"},
        {"url": "https://dmcms.aivaults.top/mcp/", "auth": "oauth"},
        {"url": "https://attacker.example/mcp", "auth": "oauth"},
        {"url": DMCMS_RESOURCE, "auth": "header"},
    ]:
        assert not is_dmcms_oauth(cfg)


def test_pending_flow_contains_only_verification_code_and_url():
    flow = _flow()
    asyncio.run(flow.publish_device_authorization({
        "user_code": "ABCD-2345",
        "verification_uri_complete": "https://my.aivaults.top/oauth/consent?user_code=ABCD-2345",
        "device_code": "secret-must-not-leak",
    }))
    public = flow.snapshot()
    assert public["status"] == "authorization_required"
    assert public["user_code"] == "ABCD-2345"
    assert "secret-must-not-leak" not in str(public)
    assert flow.expected_state is None  # no callback


@pytest.mark.parametrize("verification", [
    "http://my.aivaults.top/oauth/consent?user_code=ABCD-2345",
    "https://evil.example/oauth/consent?user_code=ABCD-2345",
    "https://my.aivaults.top/oauth/consent?user_code=ZZZZ-2345",
    "https://my.aivaults.top/oauth/consent/other?user_code=ABCD-2345",
    "https://my.aivaults.top/oauth/consent?user_code=ABCD-2345#unsafe",
])
def test_flow_rejects_unexpected_verification_urls(verification):
    flow = _flow()
    with pytest.raises(ValueError):
        asyncio.run(flow.publish_device_authorization({
            "user_code": "ABCD-2345", "verification_uri_complete": verification,
        }))


def test_cancelled_flow_cannot_resurrect():
    flow = _flow()
    flow.mark_error("Cancelled by user", cancelled=True)
    with pytest.raises(RuntimeError, match="cancelled"):
        asyncio.run(flow.publish_device_authorization({
            "user_code": "ABCD-2345",
            "verification_uri_complete": "https://my.aivaults.top/oauth/consent?user_code=ABCD-2345",
        }))
