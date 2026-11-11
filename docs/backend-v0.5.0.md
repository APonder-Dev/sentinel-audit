# v0.5.0 Local Dashboard and API

This release adds a local dashboard and API. Existing CLI scan/export
commands still work; the shared engine now produces UTC report timestamps and
records the effective port rules. The release version is 0.5.0.

## Start

```powershell
python -m pip install -r requirements.txt
python -m sentinel_audit.main --serve
```

Open http://127.0.0.1:8765 for the dashboard. Use --port to change the port.
Use --config PATH at server startup to select port rules for scans.
The API does not accept config paths or shell commands in scan requests.
Stop the server with Ctrl+C; graceful shutdown waits for the current scan.
Use one server process per database. Do not run with multiple Uvicorn workers.

## Deep Scan (Windows)

Start the dashboard as your normal user. Select **Deep scan (UAC approval)**,
then **Run deep scan**. Windows requests consent or authorized administrator
credentials to launch a separate Python worker. The dashboard is never relaunched
with elevation. Standard scans remain the default and never request UAC.

While consent is pending, the scan is **Awaiting approval** and prevents another
scan from starting. Cancelling or denying the prompt produces **Approval denied**,
saves no report, and does not silently retry with normal privileges. Launch
failures, worker crashes, missing elevation, and transport errors fail the scan.
A separate, deliberate Run action is required to try again. Non-Windows hosts
disable Deep scan and reject API requests for it.

The worker performs the same read-only collectors with administrator visibility,
not additional exploit tests. Elevated access can still leave protected resources
unknown. If alternate administrator credentials are used, user-context telemetry
such as current user describes that administrator.

The dashboard loads port rules before elevation and sends only validated rule
data, not a config path. A random one-use secret authenticates a bounded JSON
connection on an ephemeral loopback port; no pickle, arbitrary command strings,
or report output paths are accepted. Only the normal dashboard process writes
scan history. The worker exits after one scan, on parent disconnect, or after a
three-minute execution limit. Time waiting in the native UAC dialog is controlled
by Windows and does not count toward that worker limit.

This is a trusted local development checkout, not a signed privileged service.
UAC identifies the Python executable, and approving it trusts this checkout and
its installed dependencies. Python isolated mode excludes PYTHONPATH and user-site
packages; dependencies must be installed in that interpreter or virtualenv.
The connection secret is passed on the worker command line: this is not a security
boundary against a malicious process running as the same local user. Do not run
the dashboard elevated or expose it through a proxy. Protect the checkout from
untrusted modification before approving UAC.

API: POST /api/scans accepts {"mode":"standard"} (default) or {"mode":"deep"}.
Session capabilities advertise deep_scan. History records mode and terminal
error_code; awaiting_approval and denied are valid status filters.
Database version 3 preserves existing scans and extends the single-active-scan
constraint to the approval state. Interrupted approval requests are failed on restart.

Automated tests simulate approval/denial and the transport without triggering UAC.
Native acceptance check: from a non-elevated dashboard, cancel one prompt and
verify no scan runs; then explicitly launch again, approve, and verify the report
execution field says mode=deep and elevated=true. Check the dashboard process
remains non-elevated and the worker exits. This requires a human UAC decision.

The dashboard includes scan launch, persisted collector progress, paginated
history with host/ID search and status filtering, and scan details. Findings
support text search, severity filters, title/severity sorting, and expandable
evidence and recommendations. Host details and raw collection output are separate
tabs. All assets (including Lucide icons) are local; no Node build is required.

The progress counter measures finished collectors, not elapsed time or protection.
Errors and unsupported collectors count as finished and remain explicitly labeled.
Older scans without progress records display "Progress not recorded".
Coverage is separate from execution progress: failed, partial, unsupported, and
unknown checks do not count as fully collected. An incomplete assessment banner
lists evidence and next steps, and labels the score provisional. Historical
reports without a recorded network status are treated as unknown, not clean.
History remains available after restarting the app. Connection failures disable
scan launch until reconnection; unfinished scans remain subject to restart recovery.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| GET | /api/health | Server availability |
| GET | /api/session | Process-lifetime request token |
| POST | /api/scans | Submit a scan with an empty JSON object; returns 202 |
| GET | /api/scans?limit=50&offset=0 | Paginated metadata, newest first |
| GET | /api/scans/active | Active scan and collector progress, or null |
| GET | /api/scans/{id} | Scan metadata and report when completed |
| GET | /openapi.json | Machine-readable API schema |

Mutation requests require X-Sentinel-Token from /api/session. Missing tokens,
non-local Host headers, and cross-origin requests are rejected. A concurrent
scan submission returns 409. Unknown IDs return 404; invalid inputs return 422.
Responses are not cached. Interactive API docs are disabled to avoid CDN assets.
History also accepts optional status and query (host/scan ID) parameters.
Database version 2 adds progress storage, migrating version 1 history in place.

## Socket and Process Inventory

Socket and process collection use psutil's local OS interfaces instead of parsing
netstat or running Windows tasklist /v. TCP listeners and bound UDP sockets have
structured protocol, address family, local address, port, binding scope, PID,
process name, and service hint fields. Unknown process identities remain explicit.
Service hints use the local service-name database; they are not application
fingerprints or verified vulnerabilities. Port rules apply to both TCP and UDP
inventory. Bindings describe the local endpoint, not firewall rules or internet
reachability. OS permissions may limit inventory visibility.

The Ports & services tab supports search, protocol, and binding filters. Old
scans retain their raw data and show that structured inventory was not recorded.
Successful empty inventory is distinguished from collection failure.
Process ownership gaps produce partial coverage and lower-bound privileged counts.
Disk access errors remain visible; unrecognized/mixed BitLocker results and
inconclusive Linux filesystem evidence cannot produce a verified encrypted state.
No automatic privilege elevation is performed.

```powershell
$base = "http://127.0.0.1:8765"
$session = Invoke-RestMethod "$base/api/session"
$headers = @{ "X-Sentinel-Token" = $session.token }
$scan = Invoke-RestMethod "$base/api/scans" -Method Post -Headers $headers -ContentType "application/json" -Body "{}"
Invoke-RestMethod "$base/api/scans/$($scan.id)"
Invoke-RestMethod "$base/api/scans"
```

## Storage and Lifecycle

SQLite history lives in:
- Windows: %LOCALAPPDATA%/SentinelAudit/scans.sqlite3
- Linux/macOS: $XDG_DATA_HOME/sentinel-audit/scans.sqlite3, falling back to ~/.local/share/sentinel-audit/scans.sqlite3

History contains sensitive, unsanitized host data. Sanitized CLI exports do not
sanitize this database. Unix directory/file permissions are restricted; Windows
uses inherited user-profile permissions (no custom ACL management yet).
The adjacent lock database prevents a second server from recovering an active
server's scans. Keep both files out of version control.

Scans transition queued -> running -> completed/failed. Results include a UUID,
UTC timestamps, duration, and schema version. A restart marks unfinished scans
failed rather than silently rerunning them. A completed scan may contain
collector errors or unsupported checks: completion does not mean a secure host.
Detailed unexpected errors are logged locally, not returned by the API.

This is a local-user trust boundary, not authentication against other local
processes. Do not expose the API through a reverse proxy or to a network.

## Validation

```powershell
python -m pip install -r requirements-dev.txt
python -m ruff check .
python -m pytest -q
```

Optional browser checks (isolated temporary databases, synthetic test results):

```powershell
python -m pip install -r requirements-browser.txt
python -m playwright install chromium
$env:SENTINEL_BROWSER_TESTS = "1"
python -m pytest tests/browser -q
```

Browser tests cover launch/progress/reload, history and finding filters,
pagination, errors/reconnection, keyboard tabs, untrusted text, and mobile layout.
Screenshots are saved under the ignored .cache/dashboard directory.

## Stored Reports and Comparison

Completed scans offer HTML, JSON, and Markdown downloads in the dashboard.
`GET /api/scans/{id}/export?format=html&sanitize=true` exports the stored result
without rerunning collectors. Sanitization is enabled by default: known host and
user identifiers, addresses, and raw command diagnostics are redacted or omitted.
Review exports before sharing; sanitization is not an anonymity guarantee.
Unchecking sanitization includes sensitive local evidence. Exports never modify
the stored scan. Incomplete or failed scans cannot be exported.

Findings now carry explicit stable rule IDs, collector ownership, and a kind
(risk, observation, or collection gap). Existing reports receive IDs through a
read-only compatibility adapter; unknown legacy titles have conservative fallback
IDs. Stored historical reports are not rewritten.

The Compare tab selects an earlier completed scan. The API is
`GET /api/scans/{id}/compare?baseline={earlier-id}`. Results group findings as new,
resolved, changed, unchanged, newly observed, no longer observed, or unverified. New/resolved labels
require matching hostname, scan mode, port rules, analysis version, and complete
coverage of the relevant collector in both scans. Only explicit risk findings with a risk severity
can be resolved; disappearing observations and collection gaps are instead
classified as no longer observed when coverage is complete. Missing evidence
remains unverified. Resolved indicates absence, not proof of remediation. A matching hostname is not
cryptographic machine identity. Changed evidence does not itself imply improved
security. Legacy reports with missing compatibility metadata remain conservative.

BitLocker results separately record encrypted data and active protection, with
per-volume evidence. Used Space Only Encrypted counts as encrypted. Protection
Off produces an independent warning even when data remains encrypted. Missing or
ambiguous protection output stays unknown; older scans are not retroactively
assigned a protection state. Run a new approved Deep scan to collect these fields.

Scan deletion remains a future milestone.
