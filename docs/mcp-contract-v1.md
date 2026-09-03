# MCP envelope contract v1

Status: Phase 2A foundation, maintainer-reviewed and pending CI
Contract version: `1.0`
Transport: MCP over stdio

This document defines the provider-neutral envelope used by `k8s-sec-mcp`.
It does not yet define tool-specific nested data schemas, a normalized evidence
model, a correlation algorithm, Kubernetes RBAC, or a production deployment
profile.

## Compatibility promise

The existing tool names, arguments, and successful top-level JSON values remain
the legacy compatibility surface. A successful v1 call returns:

1. one `TextContent` block containing the complete legacy JSON value; and
2. the same value in `structuredContent.data`, inside the v1 envelope.

Successful results are never silently truncated, sanitized, or reduced. When a
complete value exceeds a configured record, string, or serialized-response
limit, the call fails visibly with `isError: true` and
`response_too_large`. This deliberately prefers an explicit failure over an
apparently complete security result with omitted evidence. Callers should narrow
the query and retry.

Two current tools cannot be narrowed: `list_policy_summary` and
`list_image_registry_signals` accept no filter or pagination arguments. If either
exceeds a response limit, an operator can raise the applicable
`K8S_SEC_MCP_MAX_*` limit within its documented range and restart the MCP server,
after considering the additional model-context and untrusted-data exposure. The
tool still fails visibly if the complete result cannot fit. Filter and pagination
support is planned rather than added to the Phase 2A compatibility surface.

Text-only consumers therefore retain their existing value on success. They must
already handle MCP tool errors; oversized results now use that error path rather
than returning incomplete legacy arrays or objects.

Within major version 1:

- optional envelope fields may be added;
- limits may become stricter only with a release note and deprecation period;
- an envelope field's type, meaning, or unit will not change;
- a required envelope field, tool, or supported input enum will not be removed;
- tool renames and semantic changes require a new tool or contract major version.

MCP protocol revision support is independent from this application contract.

## Tool declarations

`tools/list` is authoritative. Each of the 18 current tools declares a stable
name, a closed input object, defaults, argument bounds, and an `outputSchema` for
the common success/error envelope. Input validation occurs at the MCP boundary.

The nested fields under `data` remain the legacy tool-specific JSON values and
are intentionally open in Phase 2A: array tools declare `array<object>` and
object tools declare `object`. Those declarations catch top-level shape drift,
but not field-level parser drift. Tool-specific schemas, CRD fixtures, stable
domain models, immutable identity, and deterministic correlation remain later
Phase 2 work. Until then, this must be described as a stable envelope contract,
not a fully typed result contract.

## Successful result

```json
{
  "contract_version": "1.0",
  "tool": "list_runtime_events",
  "ok": true,
  "data": [],
  "meta": {
    "generated_at": "2026-09-02T12:00:00+00:00",
    "returned": 0,
    "omitted": 0,
    "truncated": false,
    "limits": {
      "max_records": 200,
      "max_response_bytes": 262144,
      "max_string_chars": 8192
    },
    "provenance": [
      {
        "source": "mcp-event-sink",
        "transport": "http",
        "resource": "/events",
        "api_version": "event-sink/v1"
      }
    ],
    "freshness": {
      "status": "unknown",
      "observed_at": null,
      "reason": "no source-specific freshness policy is defined in contract v1"
    }
  }
}
```

`generated_at` is response assembly time, not evidence age. Provenance identifies
the deterministic adapter and queried source; it does not prove completeness,
freshness, or a causal relationship. `freshness.observed_at` is populated only
from a valid RFC 3339 timestamp already carried by a runtime result. Multiple
timestamps are compared as instants. Contract v1 defines no source-specific
freshness thresholds, so `status` remains `unknown`.

## Errors

Expected boundary and source failures are normal MCP tool results with
`isError: true`. Text content contains the same fixed-message JSON envelope so
text-only clients fail visibly. Error messages never include raw exception
strings, response bodies, kubeconfig paths, tokens, caller-supplied arguments,
or unadvertised tool names.

Stable v1 codes are:

| Code | Meaning | Normally retryable |
|---|---|---|
| `invalid_arguments` | Arguments do not match the declaration | no |
| `unknown_tool` | The requested name is not advertised | no |
| `response_too_large` | Complete legacy result exceeds a configured limit | no; narrow query |
| `source_unauthorized` | Source authentication failed | no |
| `source_forbidden` | Active identity lacks permission | no |
| `source_not_found` | CRD or endpoint is unavailable | no |
| `source_error` | A source rejected the request for another reason, including event-sink 400/422 query rejection | no |
| `source_timeout` | Source exceeded its timeout | yes |
| `source_unavailable` | Connection failure, HTTP 429 throttling, or upstream 5xx failure | yes |
| `invalid_source_data` | Source output cannot satisfy the envelope | no |
| `internal_error` | An unclassified server failure occurred | no |

## Response limits and untrusted data

Defaults are 200 entries per primary returned collection, 256 KiB for the
serialized MCP `CallToolResult`, and 8192 characters per string. Operators may
configure:

- `K8S_SEC_MCP_MAX_RECORDS` (`1..1000`);
- `K8S_SEC_MCP_MAX_RESPONSE_BYTES` (`4096..1048576`); and
- `K8S_SEC_MCP_MAX_STRING_CHARS` (`256..32768`).

The byte calculation includes both the text block and `structuredContent`; it
excludes JSON-RPC framing owned by the transport. The same budget applies to
success and error results. Unknown tool names are not echoed. Non-finite JSON
extensions such as `NaN` and infinities are rejected.

These controls reduce context exhaustion and injection surface. They do not make
resource names, labels, scanner messages, or runtime text trusted. Consumers
must treat every data field as evidence, never as an instruction.

## Verification

```bash
PYTHONPATH=mcp-server/src python -m unittest discover -s mcp-server/tests -v
```

The Phase 2A suite freezes the 18 tool names, validates declarations and
envelopes, checks exact text/structured success equivalence, verifies fail-visible
limits and bounded hostile-name errors, classifies source failures, rejects
non-finite JSON, validates runtime timestamps, and exercises an in-memory MCP
client/server call. It does not replace CRD parser fixtures, restricted-identity
tests, or end-to-end cluster validation.
