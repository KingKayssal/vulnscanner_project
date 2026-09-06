# API Authentication Decision

The API currently uses `SCANNER_API_KEY` together with the `X-Organization`
header as an interim deployment-neutral authentication and tenant-selection
scheme. Every endpoint requires both values, and database queries are scoped
to the selected organization.

This is not a final identity model. OIDC/OAuth2, user identity, key rotation,
role-based authorization, and organization membership are deferred product
decisions. Do not expose this development scheme as the long-term public
authentication contract without revisiting those decisions.