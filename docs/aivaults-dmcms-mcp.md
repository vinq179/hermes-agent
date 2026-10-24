# AIVaults DMCMS MCP - one-click connection

From Hermes Dashboard, navigate to MCP, select AIVaults DMCMS and
Connect / Authorize. Hermes creates the remote server configuration if
missing, discovers the Hub device authorization endpoint and first-party
Client ID Metadata Document, then opens Hub sign-in. The user compares
the verification code shown on Hub with the code in Hermes and explicitly
approves. Hermes exchanges the device code, stores OAuth access/refresh
tokens in the selected profile's mcp-tokens directory, and tests tool access.

MCP resource: https://dmcms.aivaults.top/mcp
OAuth issuer: https://my.aivaults.top
Device grant: RFC 8628, expiry 600 seconds, minimum polling interval 5 seconds.
Application identifier: public, Hub-hosted CIMD URL. This identifier
is not a shared API key. No per-user client ID registration, client
secret, HTTPS callback, public Hermes domain, or manual copy/paste required.

The connection only receives permissions of the signed-in Hub account.
DMCMS validates audience and RBAC again for every tool. Other MCP
providers continue using Hermes' existing browser PKCE flow.

Hub and Hermes are separate codebases. Hub must first publish its
device authorization API and consent frontend. Hermes must then be
deployed with compatible MCP dependencies and should retain all current
config, profiles, sessions, tokens and gateway services. Do not overwrite
another upstream repo or a running installation without qualification.
