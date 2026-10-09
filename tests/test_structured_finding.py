"""Tests for structured_finding.py (S1-S5). No scanners, Docker, BERT or API needed.

Run from the repository root:  pytest tests/test_structured_finding.py
Needs: pydantic>=2, jsonschema
"""
import copy

import pytest
from pydantic import ValidationError

from bert_cwe_labeler.normalize.rules import CHECK_TEMPLATES, MESSAGE_RULES
from bert_cwe_labeler.structured_finding import (
    ENUM_VALUES,
    TYPE_TO_CATEGORY,
    category_for_type,
    finding_json_schema,
    make_finding_id,
    mechanical_features,
    validate_structured_finding,
    validation_error_text,
)

# Types emitted outside the MESSAGE_RULES / CHECK_TEMPLATES tables (adapters.py).
# Update this set if adapters.py gains a new type.
ADAPTER_ONLY_TYPES = {
    "fallback", "path_blocked", "path_exposed", "path_other", "path_public", "path_redirect",
    "probe_open_redirect", "probe_path_traversal",
}

# Test-only copy of a real finding shape (cwe list is illustrative).
REAL_REFLECTED = {
    "target": "dvwa-docker-lab", "auth_state": "authenticated", "type": "reflected",
    "path": "/vulnerabilities/sqli/", "confidence": "normal", "fallback": False, "sources": ["crawler"],
    "description": "The id parameter of the /vulnerabilities/sqli/ page reflects submitted input ...",
    "evidence": [{"tool": "crawler", "auth_state": "authenticated", "check": "reflected",
                  "endpoint": "/vulnerabilities/sqli/", "http_status": 200, "url_scheme": "http",
                  "parameter": "id", "probe_value": "'"}],
    "cwe": [{"cwe_id": "CWE-79", "name": "XSS", "score": 0.8214}], "below_threshold": False,
}
REAL_OUTDATED = {
    "target": "dvwa-docker-lab", "auth_state": "unauthenticated", "type": "outdated_component", "path": None,
    "confidence": "normal", "fallback": False, "sources": ["nikto"],
    "description": "The server reports Apache 2.4.25, while the current release is at least 2.4.68. ...",
    "evidence": [{"tool": "nikto", "auth_state": "unauthenticated",
                  "line": "+ [600050] Apache/2.4.25 appears to be outdated (current is at least 2.4.68)."}],
    "cwe": [{"cwe_id": "CWE-1104", "name": "Unmaintained Third Party Components", "score": 0.61}],
    "below_threshold": False,
}


def make_valid():
    f = mechanical_features(REAL_REFLECTED)
    f.update(http_method=None, endpoint_sensitivity="unknown", user_input_involved=True, sensitive_data_exposed=False)
    return {
        "finding_id": make_finding_id("dvwa-docker-lab-20261007-101157", 3),
        "scan_id": "dvwa-docker-lab-20261007-101157", "target": "dvwa-docker-lab",
        "schema_version": "structured_finding.v1", "prompt_version": "p1",
        "features": f,
        "structured_fields": {"affected_endpoint": "/vulnerabilities/sqli/", "parameter": "id",
                              "component_name": None, "component_version": None, "component_current_version": None},
        "context": {"rule_based_description": REAL_REFLECTED["description"], "llm_note": ""},
    }


# ---- S5: validation ---------------------------------------------------------

def test_valid_finding_passes():
    sf = validate_structured_finding(make_valid())
    assert sf.features.cwe_primary == "CWE-79" and sf.features.parameter_reflected is True


@pytest.mark.parametrize("field", sorted(ENUM_VALUES))
def test_each_enum_rejects_out_of_vocabulary(field):
    bad = make_valid()
    bad["features"][field] = "not_a_real_value"
    with pytest.raises(ValidationError):
        validate_structured_finding(bad)


@pytest.mark.parametrize("field", ["affected_endpoint", "parameter", "component_name",
                                   "component_version", "component_current_version"])
def test_nullable_structured_fields_accept_null(field):
    ok = make_valid()
    ok["structured_fields"][field] = None
    validate_structured_finding(ok)


def test_nullable_features_accept_null():
    ok = make_valid()
    ok["features"].update(http_method=None, http_status=None)
    validate_structured_finding(ok)


def test_nullable_field_must_be_present():
    bad = make_valid()
    del bad["structured_fields"]["parameter"]
    with pytest.raises(ValidationError):
        validate_structured_finding(bad)


def test_unknown_field_rejected():
    bad = make_valid()
    bad["features"]["severity"] = "high"
    with pytest.raises(ValidationError):
        validate_structured_finding(bad)


def test_out_of_range_values_rejected():
    for field, value in [("bert_top_score", 1.5), ("cwe_candidate_count", -1), ("http_status", 99)]:
        bad = make_valid()
        bad["features"][field] = value
        with pytest.raises(ValidationError):
            validate_structured_finding(bad)


# ---- empty cwe --------------------------------------------------------------

def test_empty_cwe_does_not_crash_and_gives_null_primary():
    finding = copy.deepcopy(REAL_REFLECTED)
    finding["cwe"] = []
    feats = mechanical_features(finding)
    assert feats["cwe_primary"] is None and feats["cwe_candidate_count"] == 0 and feats["bert_top_score"] is None
    obj = make_valid()
    obj["features"].update(feats)
    validate_structured_finding(obj)


def test_missing_cwe_keys_do_not_crash():
    """Bundle produced with --no-model has no cwe / below_threshold keys."""
    finding = {k: v for k, v in REAL_REFLECTED.items() if k not in ("cwe", "below_threshold")}
    feats = mechanical_features(finding)
    assert feats["cwe_primary"] is None and feats["weak_cwe_signal"] is False


def test_contradictory_cwe_fields_rejected():
    bad = make_valid()
    bad["features"].update(cwe_primary=None)  # still says count=1 and a score
    with pytest.raises(ValidationError):
        validate_structured_finding(bad)


# ---- mechanical_features on real shapes -------------------------------------

def test_mechanical_features_reflected():
    f = mechanical_features(REAL_REFLECTED)
    assert f["vulnerability_category"] == "cross_site_scripting"
    assert f["http_status"] == 200 and f["transport_scheme"] == "http"
    assert f["parameter_reflected"] is True and f["component_outdated"] is False
    assert f["corroborating_source_count"] == 1 and f["bert_top_score"] == 0.8214


def test_mechanical_features_nikto_only_evidence():
    f = mechanical_features(REAL_OUTDATED)
    assert f["vulnerability_category"] == "outdated_component" and f["component_outdated"] is True
    assert f["http_status"] is None and f["transport_scheme"] == "unknown"


def test_weak_signal_copied_not_rederived():
    finding = copy.deepcopy(REAL_REFLECTED)
    finding["below_threshold"] = True
    assert mechanical_features(finding)["weak_cwe_signal"] is True


def test_finding_id_is_stable_and_unique_per_index():
    assert make_finding_id("scan", 7) == "scan-f0007" and make_finding_id("scan", 7) != make_finding_id("scan", 8)


def test_validation_error_text_is_compact_and_names_the_field():
    bad = make_valid()
    bad["features"]["endpoint_sensitivity"] = "login_page"
    with pytest.raises(ValidationError) as exc:
        validate_structured_finding(bad)
    text = validation_error_text(exc.value)
    assert "features.endpoint_sensitivity" in text and "login_page" in text and "errors.pydantic.dev" not in text


# ---- S2: category mapping ---------------------------------------------------

def test_every_rule_type_has_a_category():
    rule_types = {rule[0] for rule in MESSAGE_RULES} | set(CHECK_TEMPLATES)
    missing = sorted((rule_types | ADAPTER_ONLY_TYPES) - set(TYPE_TO_CATEGORY))
    assert not missing, f"types with no category (would silently become 'other'): {missing}"


def test_no_stale_or_misspelled_mapping_keys():
    known = {rule[0] for rule in MESSAGE_RULES} | set(CHECK_TEMPLATES) | ADAPTER_ONLY_TYPES
    assert not sorted(set(TYPE_TO_CATEGORY) - known)


def test_mapping_values_are_valid_categories():
    assert set(TYPE_TO_CATEGORY.values()) <= set(ENUM_VALUES["vulnerability_category"])
    assert category_for_type("brand_new_type") == "other" and category_for_type(None) == "other"


# ---- S4: JSON schema --------------------------------------------------------

def test_schema_round_trip():
    jsonschema = pytest.importorskip("jsonschema")
    schema = finding_json_schema()
    obj = make_valid()
    jsonschema.validate(obj, schema)          # satisfies the schema ...
    validate_structured_finding(obj)          # ... and the validator
    bad = make_valid()
    bad["features"]["endpoint_sensitivity"] = "login_page"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(bad, schema)


def test_schema_is_closed_and_lists_nullable_fields_as_required():
    schema = finding_json_schema()
    defs = schema["$defs"]
    assert schema["additionalProperties"] is False and defs["Features"]["additionalProperties"] is False
    assert "parameter" in defs["StructuredFields"]["required"]
    assert "endpoint_sensitivity" in defs["Features"]["required"]
