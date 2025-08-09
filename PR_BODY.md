## Automated weekly refresh of embedded trust resources

This pull request refreshes the embedded resources used by the default helpers:
- Cloudflare CFSSL CA bundle (PEM)
- Unified Certificate Transparency (CT) log list _(merged from Google + Apple)_

### Source references
- Cloudflare CFSSL CA bundle: https://raw.githubusercontent.com/cloudflare/cfssl_trust/master/ca-bundle.crt
- Google CT reference: https://www.gstatic.com/ct/log_list/v3/log_list_schema.json
- Apple CT log list: https://valid.apple.com/ct/log_list/current_log_list.json

Refresh time (UTC): 2025-08-09 12:06:56Z

### Changed files

| File | Type | Status | + | - | Size (bytes) |
|------|------|--------|---|---|--------------|
| src/resources/google-log-list.json | CT log list (JSON) | M | 2 | 2 | n/a |
| src/resources/unified-log-list.json | CT log list (JSON) | M | 2 | 2 | n/a |

**Please review and merge to keep embedded trust data current.**
