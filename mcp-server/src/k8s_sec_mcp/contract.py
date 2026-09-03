"""Versioned MCP envelope-contract helpers.

Domain handlers still return their legacy JSON text. This module validates that
value and adds a provider-neutral structured envelope without silently changing
successful legacy data.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from kubernetes.client.exceptions import ApiException
from mcp import types

CONTRACT_VERSION = "1.0"
CONTRACT_DOCUMENT = "docs/mcp-contract-v1.md"

DEFAULT_MAX_RECORDS = 200
DEFAULT_MAX_RESPONSE_BYTES = 256 * 1024
DEFAULT_MAX_STRING_CHARS = 8192


class UnknownToolError(ValueError):
    """Raised when a client calls a name that was not advertised."""


class InvalidArgumentsError(ValueError):
    """Raised when arguments do not satisfy an advertised tool schema."""


class ResponseLimitError(ValueError):
    """Raised when an exact legacy result cannot fit inside contract limits."""


class InvalidSourceDataError(ValueError):
    """Raised when a handler returns malformed or unsafe JSON data."""


@dataclass(frozen=True)
class ResponseLimits:
    max_records: int
    max_response_bytes: int
    max_string_chars: int

    @classmethod
    def from_environment(cls) -> ResponseLimits:
        return cls(
            max_records=_bounded_int(
                "K8S_SEC_MCP_MAX_RECORDS", DEFAULT_MAX_RECORDS, 1, 1000
            ),
            max_response_bytes=_bounded_int(
                "K8S_SEC_MCP_MAX_RESPONSE_BYTES",
                DEFAULT_MAX_RESPONSE_BYTES,
                4096,
                1024 * 1024,
            ),
            max_string_chars=_bounded_int(
                "K8S_SEC_MCP_MAX_STRING_CHARS",
                DEFAULT_MAX_STRING_CHARS,
                256,
                32768,
            ),
        )

    def as_dict(self) -> dict[str, int]:
        return {
            "max_records": self.max_records,
            "max_response_bytes": self.max_response_bytes,
            "max_string_chars": self.max_string_chars,
        }


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return min(maximum, max(minimum, value))


ARRAY_TOOLS = {
    "list_vuln_reports",
    "list_vuln_summary",
    "list_compliance_reports",
    "list_policy_summary",
    "list_policy_violations",
    "list_runtime_events",
    "list_config_audit_summary",
    "list_config_audit",
    "list_exposed_secrets",
    "list_rbac_issues",
    "list_infra_issues",
    "list_workloads",
    "list_image_registry_signals",
    "list_network_policies",
}

OBJECT_TOOLS = {
    "get_pod_status",
    "list_runtime_trends",
    "list_posture_trends",
    "list_network_exposure",
}

ALL_TOOLS = ARRAY_TOOLS | OBJECT_TOOLS
TREND_MAX_DAYS = 90

INPUT_DEFAULTS: dict[str, dict[str, Any]] = {
    "list_vuln_reports": {"namespace": "all", "severity": "ALL", "image": ""},
    "list_vuln_summary": {"namespace": "all", "severity": "CRITICAL"},
    "list_compliance_reports": {"framework": ""},
    "list_policy_violations": {"namespace": "all", "result": "fail"},
    "list_runtime_events": {
        "priority": "ALL",
        "namespace": "",
        "pod": "",
        "rule": "",
        "hours": 0,
        "limit": 50,
    },
    "list_runtime_trends": {"days": 7},
    "list_posture_trends": {"tool": "all", "namespace": "all", "days": 30},
    "list_config_audit_summary": {"namespace": "all", "severity": "HIGH"},
    "list_config_audit": {"namespace": "all", "severity": "HIGH"},
    "list_exposed_secrets": {"namespace": "all"},
    "list_rbac_issues": {"namespace": "all", "severity": "ALL"},
    "list_infra_issues": {"severity": "ALL"},
    "list_workloads": {"namespace": "all"},
    "list_network_exposure": {"namespace": "all"},
    "list_network_policies": {"namespace": "all"},
}

PROVENANCE: dict[str, list[dict[str, str]]] = {
    "list_vuln_reports": [
        {
            "source": "trivy-operator",
            "transport": "kubernetes",
            "resource": "vulnerabilityreports",
            "api_version": "aquasecurity.github.io/v1alpha1",
        }
    ],
    "list_vuln_summary": [
        {
            "source": "trivy-operator",
            "transport": "kubernetes",
            "resource": "vulnerabilityreports",
            "api_version": "aquasecurity.github.io/v1alpha1",
        }
    ],
    "list_config_audit": [
        {
            "source": "trivy-operator",
            "transport": "kubernetes",
            "resource": "configauditreports,clusterconfigauditreports",
            "api_version": "aquasecurity.github.io/v1alpha1",
        }
    ],
    "list_config_audit_summary": [
        {
            "source": "trivy-operator",
            "transport": "kubernetes",
            "resource": "configauditreports,clusterconfigauditreports",
            "api_version": "aquasecurity.github.io/v1alpha1",
        }
    ],
    "list_exposed_secrets": [
        {
            "source": "trivy-operator",
            "transport": "kubernetes",
            "resource": "exposedsecretreports",
            "api_version": "aquasecurity.github.io/v1alpha1",
        }
    ],
    "list_rbac_issues": [
        {
            "source": "trivy-operator",
            "transport": "kubernetes",
            "resource": "rbacassessmentreports,clusterrbacassessmentreports",
            "api_version": "aquasecurity.github.io/v1alpha1",
        }
    ],
    "list_infra_issues": [
        {
            "source": "trivy-operator",
            "transport": "kubernetes",
            "resource": "infraassessmentreports,clusterinfraassessmentreports",
            "api_version": "aquasecurity.github.io/v1alpha1",
        }
    ],
    "list_compliance_reports": [
        {
            "source": "kubescape-operator",
            "transport": "kubernetes",
            "resource": "clustercompliancereports",
            "api_version": "aquasecurity.github.io/v1alpha1",
        }
    ],
    "list_policy_summary": [
        {
            "source": "kyverno",
            "transport": "kubernetes",
            "resource": "policyreports,clusterpolicyreports,clusterpolicies",
            "api_version": "wgpolicyk8s.io/v1alpha2;kyverno.io/v1",
        }
    ],
    "list_policy_violations": [
        {
            "source": "kyverno",
            "transport": "kubernetes",
            "resource": "policyreports,clusterpolicyreports",
            "api_version": "wgpolicyk8s.io/v1alpha2",
        }
    ],
    "list_runtime_events": [
        {
            "source": "mcp-event-sink",
            "transport": "http",
            "resource": "/events",
            "api_version": "event-sink/v1",
        }
    ],
    "list_runtime_trends": [
        {
            "source": "mcp-event-sink",
            "transport": "http",
            "resource": "/events/trends",
            "api_version": "event-sink/v1",
        }
    ],
    "list_posture_trends": [
        {
            "source": "mcp-event-sink",
            "transport": "http",
            "resource": "/posture/trends",
            "api_version": "event-sink/v1",
        }
    ],
    "get_pod_status": [
        {
            "source": "kubernetes",
            "transport": "kubernetes",
            "resource": "pods",
            "api_version": "v1",
        }
    ],
    "list_workloads": [
        {
            "source": "kubernetes",
            "transport": "kubernetes",
            "resource": "deployments,daemonsets,pods",
            "api_version": "apps/v1;v1",
        }
    ],
    "list_image_registry_signals": [
        {
            "source": "kubernetes",
            "transport": "kubernetes",
            "resource": "deployments,daemonsets,pods",
            "api_version": "apps/v1;v1",
        }
    ],
    "list_network_exposure": [
        {
            "source": "kubernetes",
            "transport": "kubernetes",
            "resource": "services,ingresses",
            "api_version": "v1;networking.k8s.io/v1",
        }
    ],
    "list_network_policies": [
        {
            "source": "kubernetes",
            "transport": "kubernetes",
            "resource": "namespaces,networkpolicies",
            "api_version": "v1;networking.k8s.io/v1",
        }
    ],
}

ERROR_CODES = [
    "invalid_arguments",
    "unknown_tool",
    "response_too_large",
    "source_unauthorized",
    "source_forbidden",
    "source_not_found",
    "source_error",
    "source_timeout",
    "source_unavailable",
    "invalid_source_data",
    "internal_error",
]


def apply_tool_contract(tool: types.Tool) -> types.Tool:
    """Add input bounds, a closed argument object, and the v1 envelope schema."""
    schema = dict(tool.inputSchema)
    schema["additionalProperties"] = False
    properties = {
        name: dict(value) for name, value in schema.get("properties", {}).items()
    }
    for name, value in properties.items():
        if name in INPUT_DEFAULTS.get(tool.name, {}):
            value["default"] = INPUT_DEFAULTS[tool.name][name]
        if name == "severity" and "enum" in value and "UNKNOWN" not in value["enum"]:
            value["enum"] = [*value["enum"], "UNKNOWN"]
        elif name == "priority" and "enum" in value:
            value["enum"] = [
                "EMERGENCY",
                "ALERT",
                "CRITICAL",
                "ERROR",
                "WARNING",
                "NOTICE",
                "INFORMATIONAL",
                "DEBUG",
                "ALL",
            ]
        if value.get("type") == "string":
            value.setdefault("maxLength", 253)
        if name == "hours":
            value.update({"minimum": 0, "maximum": 720})
        elif name == "days":
            value.update({"minimum": 1, "maximum": TREND_MAX_DAYS})
        elif name == "limit":
            value.update({"minimum": 1, "maximum": 200})
    schema["properties"] = properties
    return tool.model_copy(
        update={"inputSchema": schema, "outputSchema": output_schema(tool.name)}
    )


def output_schema(tool_name: str) -> dict[str, Any]:
    """Return the v1 envelope schema; nested legacy data remains intentionally open."""
    if tool_name in ARRAY_TOOLS:
        data_schema: dict[str, Any] = {"type": "array", "items": {"type": "object"}}
    elif tool_name in OBJECT_TOOLS:
        data_schema = {"type": "object"}
    else:
        data_schema = {}

    provenance_schema = {
        "type": "array",
        "items": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "source": {"type": "string"},
                "transport": {"type": "string", "enum": ["kubernetes", "http"]},
                "resource": {"type": "string"},
                "api_version": {"type": "string"},
            },
            "required": ["source", "transport", "resource", "api_version"],
        },
    }
    limits_schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "max_records": {"type": "integer", "minimum": 1},
            "max_response_bytes": {"type": "integer", "minimum": 4096},
            "max_string_chars": {"type": "integer", "minimum": 256},
        },
        "required": ["max_records", "max_response_bytes", "max_string_chars"],
    }
    freshness_schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "status": {"type": "string", "enum": ["current", "stale", "unknown"]},
            "observed_at": {"type": ["string", "null"], "format": "date-time"},
            "reason": {"type": "string"},
        },
        "required": ["status", "observed_at", "reason"],
    }
    meta_schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "generated_at": {"type": "string", "format": "date-time"},
            "returned": {"type": "integer", "minimum": 0},
            "omitted": {"type": "integer", "minimum": 0},
            "truncated": {"type": "boolean"},
            "limits": limits_schema,
            "provenance": provenance_schema,
            "freshness": freshness_schema,
        },
        "required": [
            "generated_at",
            "returned",
            "omitted",
            "truncated",
            "limits",
            "provenance",
            "freshness",
        ],
    }
    common = {
        "contract_version": {"const": CONTRACT_VERSION},
        "tool": {"const": tool_name},
        "ok": {"type": "boolean"},
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "oneOf": [
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    **common,
                    "ok": {"const": True},
                    "data": data_schema,
                    "meta": meta_schema,
                },
                "required": ["contract_version", "tool", "ok", "data", "meta"],
            },
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    **common,
                    "ok": {"const": False},
                    "data": {"type": "null"},
                    "error": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "code": {"type": "string", "enum": ERROR_CODES},
                            "message": {"type": "string", "maxLength": 253},
                            "retryable": {"type": "boolean"},
                        },
                        "required": ["code", "message", "retryable"],
                    },
                    "meta": meta_schema,
                },
                "required": [
                    "contract_version",
                    "tool",
                    "ok",
                    "data",
                    "error",
                    "meta",
                ],
            },
        ],
    }


def validate_arguments(tool: types.Tool, arguments: Any) -> None:
    """Validate without exposing caller-controlled values in an error message."""
    if next(Draft202012Validator(tool.inputSchema).iter_errors(arguments), None):
        raise InvalidArgumentsError(tool.name)


def success_result(tool_name: str, legacy_json: str) -> types.CallToolResult:
    """Return an exact legacy value on success, or fail visibly if it cannot fit."""
    try:
        original = json.loads(legacy_json, parse_constant=_reject_json_constant)
    except (TypeError, ValueError) as error:
        raise InvalidSourceDataError("tool returned malformed JSON") from error

    limits = ResponseLimits.from_environment()
    _validate_data_limits(original, limits)
    result = _build_success_result(tool_name, original, limits)
    if _serialized_result_bytes(result) > limits.max_response_bytes:
        raise ResponseLimitError("complete result exceeds configured response limit")
    return result


def _build_success_result(
    tool_name: str, data: Any, limits: ResponseLimits
) -> types.CallToolResult:
    text = json.dumps(data, indent=2, allow_nan=False)
    envelope = {
        "contract_version": CONTRACT_VERSION,
        "tool": tool_name,
        "ok": True,
        "data": data,
        "meta": _metadata(
            tool_name,
            limits,
            data,
            omitted=0,
            truncated=False,
            freshness=_freshness(tool_name, data),
        ),
    }
    _validate_output(tool_name, envelope)
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=text)],
        structuredContent=envelope,
        isError=False,
    )


def error_result(tool_name: str, error: Exception) -> types.CallToolResult:
    """Return a bounded error that never echoes an unadvertised tool name."""
    safe_tool_name = tool_name if tool_name in ALL_TOOLS else "unknown"
    code, message, retryable = _classify_error(error)
    limits = ResponseLimits.from_environment()
    envelope = {
        "contract_version": CONTRACT_VERSION,
        "tool": safe_tool_name,
        "ok": False,
        "data": None,
        "error": {"code": code, "message": message, "retryable": retryable},
        "meta": _metadata(
            safe_tool_name,
            limits,
            None,
            omitted=0,
            truncated=False,
            freshness={
                "status": "unknown",
                "observed_at": None,
                "reason": "source query failed",
            },
        ),
    }
    _validate_output(safe_tool_name, envelope)
    result = types.CallToolResult(
        content=[
            types.TextContent(
                type="text", text=json.dumps(envelope, indent=2, allow_nan=False)
            )
        ],
        structuredContent=envelope,
        isError=True,
    )
    if _serialized_result_bytes(result) > limits.max_response_bytes:
        raise RuntimeError("fixed MCP error envelope exceeds configured minimum budget")
    return result


def _metadata(
    tool_name: str,
    limits: ResponseLimits,
    data: Any,
    omitted: int,
    truncated: bool,
    freshness: dict[str, Any],
) -> dict[str, Any]:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "returned": _record_count(data),
        "omitted": omitted,
        "truncated": truncated,
        "limits": limits.as_dict(),
        "provenance": PROVENANCE.get(tool_name, []),
        "freshness": freshness,
    }


def _validate_data_limits(data: Any, limits: ResponseLimits) -> None:
    if _record_count(data) > limits.max_records:
        raise ResponseLimitError("primary collection exceeds configured record limit")

    pending = [data]
    while pending:
        value = pending.pop()
        if isinstance(value, str):
            if len(value) > limits.max_string_chars:
                raise ResponseLimitError(
                    "source string exceeds configured character limit"
                )
        elif isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, dict):
            pending.extend(str(key) for key in value)
            pending.extend(value.values())


def _record_count(data: Any) -> int:
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        direct_lists = [value for value in data.values() if isinstance(value, list)]
        return (
            sum(len(value) for value in direct_lists)
            if direct_lists
            else (1 if data else 0)
        )
    return 0 if data is None else 1


def _freshness(tool_name: str, data: Any) -> dict[str, Any]:
    observed_at = None
    if tool_name == "list_runtime_events" and isinstance(data, list):
        timestamps = []
        for item in data:
            if not isinstance(item, dict):
                continue
            timestamp = item.get("time")
            parsed = _parse_rfc3339(timestamp)
            if parsed is not None:
                timestamps.append((parsed, timestamp))
        observed_at = (
            max(timestamps, key=lambda item: item[0])[1] if timestamps else None
        )
    return {
        "status": "unknown",
        "observed_at": observed_at,
        "reason": "no source-specific freshness policy is defined in contract v1",
    }


def _parse_rfc3339(value: Any) -> datetime | None:
    if not isinstance(value, str) or not FormatChecker().conforms(value, "date-time"):
        return None
    normalized = f"{value[:-1]}+00:00" if value.endswith(("Z", "z")) else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _validate_output(tool_name: str, envelope: dict[str, Any]) -> None:
    Draft202012Validator(
        output_schema(tool_name), format_checker=FormatChecker()
    ).validate(envelope)


def _serialized_result_bytes(result: types.CallToolResult) -> int:
    """Size of the complete MCP result, including text and structured copies."""
    return len(result.model_dump_json(by_alias=True, exclude_none=True).encode("utf-8"))


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def _classify_error(error: Exception) -> tuple[str, str, bool]:
    if isinstance(error, UnknownToolError):
        return "unknown_tool", "The requested tool is not available.", False
    if isinstance(error, InvalidArgumentsError):
        return (
            "invalid_arguments",
            "The tool arguments do not match the declared schema.",
            False,
        )
    if isinstance(error, ResponseLimitError):
        return (
            "response_too_large",
            "The complete result exceeds the configured response limits; narrow the query.",
            False,
        )
    if isinstance(error, InvalidSourceDataError):
        return (
            "invalid_source_data",
            "The source returned data that could not satisfy the MCP contract.",
            False,
        )
    if isinstance(error, ValidationError):
        return (
            "invalid_source_data",
            "The source returned data that could not satisfy the MCP contract.",
            False,
        )
    if isinstance(error, ApiException):
        status = error.status or 0
        if status == 401:
            return (
                "source_unauthorized",
                "The Kubernetes source rejected authentication.",
                False,
            )
        if status == 403:
            return (
                "source_forbidden",
                "The Kubernetes identity cannot read the requested source.",
                False,
            )
        if status == 404:
            return (
                "source_not_found",
                "The requested Kubernetes source is unavailable.",
                False,
            )
        if status == 429 or status >= 500:
            return (
                "source_unavailable",
                "The Kubernetes source is temporarily unavailable.",
                True,
            )
        return "source_error", "The Kubernetes source rejected the request.", False
    if isinstance(error, httpx.TimeoutException):
        return (
            "source_timeout",
            "The event source did not respond before the timeout.",
            True,
        )
    if isinstance(error, httpx.HTTPStatusError):
        status = error.response.status_code
        if status == 401:
            return (
                "source_unauthorized",
                "The event source rejected authentication.",
                False,
            )
        if status == 403:
            return "source_forbidden", "The event source rejected authorization.", False
        if status == 404:
            return (
                "source_not_found",
                "The requested event source endpoint is unavailable.",
                False,
            )
        if status == 429 or status >= 500:
            return (
                "source_unavailable",
                "The event source is temporarily unavailable.",
                True,
            )
        return "source_error", "The event source rejected the request.", False
    if isinstance(error, httpx.RequestError):
        return "source_unavailable", "The event source could not be reached.", True
    if isinstance(error, ValueError):
        return (
            "invalid_source_data",
            "The source returned data that could not satisfy the MCP contract.",
            False,
        )
    return "internal_error", "The tool could not complete the request.", False
