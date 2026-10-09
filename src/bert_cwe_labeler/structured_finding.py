"""Data contract for LLM API call 01: what a *structured finding* is.

One structured finding is produced per BERT-labeled finding in ``llm_context.json``.
It has three blocks: ``features`` (typed fields for XGBoost), ``structured_fields``
(extracted detail) and ``context`` (free text, never fed to ML).

Needs pydantic v2.
"""
from typing import Literal, get_args

from pydantic import BaseModel, ConfigDict, Field, model_validator

SCHEMA_VERSION = "structured_finding.v1"

# --------------------------------------------------------------------------- #
# Enums. Definitions live in dicts so the schema descriptions and Mohid's prompt
# can share one source of truth.
# --------------------------------------------------------------------------- #

Category = Literal[
    "injection",
    "cross_site_scripting",
    "access_control",
    "security_misconfiguration",
    "information_disclosure",
    "csrf",
    "outdated_component",
    "broken_authentication",
    "other",
]

CATEGORY_DEFINITIONS = {
    "injection": "Attacker input is interpreted as part of a query or command (e.g. SQL error after a probe).",
    "cross_site_scripting": "Input is reflected or stored in a page without encoding.",
    "access_control": "Privileged functionality or files are reachable without proper restriction (admin pages, path traversal, open redirect).",
    "security_misconfiguration": "Missing security headers, weak cookie flags, permissive CORS, default files.",
    "information_disclosure": "Files, listings, versions or configuration that reveal internal details.",
    "csrf": "State-changing request can be forged because no anti-forgery token is used.",
    "outdated_component": "Software version is older than the current release.",
    "broken_authentication": "Weak or insecure login or credential handling (e.g. password sent over HTTP).",
    "other": "Informational or unclassified.",
}

EndpointSensitivity = Literal["admin", "auth", "api", "static_resource", "config", "unknown"]

ENDPOINT_SENSITIVITY_DEFINITIONS = {
    "admin": "Administrative or management interface. If the scanner itself labels the resource an admin page/section, use admin even when it is a login form.",
    "auth": "Ordinary login, logout, registration, password-reset or session endpoint, not described as an admin area.",
    "api": "Programmatic endpoint returning data rather than a page (e.g. /api/..., /rest/...).",
    "static_resource": "Static asset such as CSS, JS, images or fonts.",
    "config": "Configuration, backup, repository or environment file (e.g. .git, .env, web.config, phpinfo).",
    "unknown": "Evidence does not support a confident choice. Prefer this over guessing.",
}

AuthState = Literal["authenticated", "unauthenticated"]
HttpMethod = Literal["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
TransportScheme = Literal["http", "https", "unknown"]
EvidenceConfidence = Literal["normal", "low"]

# Tuples of allowed values, handy for Mohid's prompt-drift test.
ENUM_VALUES = {
    "vulnerability_category": get_args(Category),
    "endpoint_sensitivity": get_args(EndpointSensitivity),
    "auth_state": get_args(AuthState),
    "http_method": get_args(HttpMethod),
    "transport_scheme": get_args(TransportScheme),
    "evidence_confidence": get_args(EvidenceConfidence),
}


def _describe(definitions: dict) -> str:
    return " ".join(f"{name}: {text}" for name, text in definitions.items())


# --------------------------------------------------------------------------- #
# S2: finding `type` -> vulnerability_category
# Covers every type in normalize/rules.py (MESSAGE_RULES, CHECK_TEMPLATES) plus
# the types emitted directly by normalize/adapters.py (gobuster path_*, crawler
# probes, "fallback"). Types with send=False never reach the LLM but are mapped
# anyway so the table is complete.
# --------------------------------------------------------------------------- #

TYPE_TO_CATEGORY = {
    # access_control
    "admin_page": "access_control",
    "probe_path_traversal": "access_control",   # CWE-22 is already under access_control in CATEGORY_CWES
    "probe_open_redirect": "access_control",    # CWE-601 is already under access_control in CATEGORY_CWES
    # injection / XSS / CSRF
    "sql_error": "injection",
    "reflected": "cross_site_scripting",
    "missing_csrf_token": "csrf",
    # broken authentication
    "password_over_http": "broken_authentication",
    # outdated component
    "outdated_component": "outdated_component",
    # security misconfiguration
    "header_missing": "security_misconfiguration",
    "xfo_deprecated": "security_misconfiguration",
    "cors_wildcard": "security_misconfiguration",
    "default_file": "security_misconfiguration",
    # DECISION: cookie_flag is a session-cookie *configuration* weakness (missing
    # HttpOnly/Secure), not a flaw in the login logic, so it is not broken_authentication.
    "cookie_flag": "security_misconfiguration",
    # information disclosure
    "version_disclosure": "information_disclosure",
    "config_disclosure": "information_disclosure",
    "dir_listing": "information_disclosure",
    "git_file": "information_disclosure",
    "ignore_file": "information_disclosure",
    "auth_file": "information_disclosure",
    "shell_history": "information_disclosure",
    "phpinfo": "information_disclosure",
    "interesting_path": "information_disclosure",
    "path_exposed": "information_disclosure",
    "robots_entry": "information_disclosure",
    "robots_info": "information_disclosure",
    # other (informational / unclassified)
    "uncommon_header": "other",
    "path_public": "other",
    "path_redirect": "other",
    "path_blocked": "other",
    "path_other": "other",
    "fallback": "other",
}


def category_for_type(finding_type: str | None) -> str:
    """Deterministic category from the rule engine's ``type``; unknown types -> ``other``."""
    return TYPE_TO_CATEGORY.get(finding_type, "other")


# --------------------------------------------------------------------------- #
# S1: the model
# --------------------------------------------------------------------------- #

class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Features(_Strict):
    vulnerability_category: Category = Field(description=_describe(CATEGORY_DEFINITIONS))
    cwe_primary: str | None = Field(description="cwe[0].cwe_id verbatim; null when the cwe list is empty.")
    cwe_candidate_count: int = Field(ge=0, description="len(cwe).")
    weak_cwe_signal: bool = Field(description="Copy of the finding's below_threshold.")
    bert_top_score: float | None = Field(ge=0, le=1, description="cwe[0].score; null when the cwe list is empty.")
    auth_state: AuthState
    http_method: HttpMethod | None = Field(description="HTTP method if shown in the evidence, else null.")
    http_status: int | None = Field(ge=100, le=599, description="HTTP status from the evidence, else null.")
    transport_scheme: TransportScheme = Field(description="http or https from the evidence; unknown if not shown.")
    endpoint_sensitivity: EndpointSensitivity = Field(description=_describe(ENDPOINT_SENSITIVITY_DEFINITIONS))
    user_input_involved: bool = Field(description="True only when a request parameter or form field is part of the evidence.")
    parameter_reflected: bool = Field(description="True only for type 'reflected' or equivalent XSS-probe evidence.")
    sensitive_data_exposed: bool = Field(description="True for git/htpasswd/auth-file/shell-history/phpinfo-style exposures.")
    component_outdated: bool = Field(description="True only for type 'outdated_component'.")
    corroborating_source_count: int = Field(ge=0, description="len(sources).")
    evidence_confidence: EvidenceConfidence = Field(description="Copy of the finding's confidence.")
    is_fallback_finding: bool = Field(description="Copy of the finding's fallback flag.")

    @model_validator(mode="after")
    def _empty_cwe_is_consistent(self):
        if self.cwe_primary is None and (self.cwe_candidate_count != 0 or self.bert_top_score is not None):
            raise ValueError("cwe_primary is null, so cwe_candidate_count must be 0 and bert_top_score must be null")
        if self.cwe_primary is not None and self.cwe_candidate_count < 1:
            raise ValueError("cwe_primary is set, so cwe_candidate_count must be at least 1")
        return self


class StructuredFields(_Strict):
    affected_endpoint: str | None = Field(description="Path or endpoint affected, else null.")
    parameter: str | None = Field(description="Request parameter name involved, else null.")
    component_name: str | None = Field(description="Software component name (e.g. Apache), else null.")
    component_version: str | None = Field(description="Version reported by the target, else null.")
    component_current_version: str | None = Field(description="Current release reported by the scanner, else null.")


class Context(_Strict):
    """Free text. Never fed to the ML model."""

    rule_based_description: str = Field(description="Copy of the original finding description.")
    llm_note: str = Field(default="", description="Short note on anything unclear; empty if nothing.")


class StructuredFinding(_Strict):
    finding_id: str = Field(min_length=1)
    scan_id: str = Field(min_length=1)
    target: str = Field(min_length=1)
    schema_version: str = SCHEMA_VERSION
    prompt_version: str = Field(min_length=1)
    features: Features
    structured_fields: StructuredFields
    context: Context


# --------------------------------------------------------------------------- #
# S3 / S4
# --------------------------------------------------------------------------- #

def validate_structured_finding(obj: dict) -> StructuredFinding:
    """Raises pydantic.ValidationError on schema/enum violation."""
    return StructuredFinding.model_validate(obj)
