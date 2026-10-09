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
    validate_structured_finding,
)

# Types emitted outside the MESSAGE_RULES / CHECK_TEMPLATES tables (adapters.py).
# Update this set if adapters.py gains a new type.
ADAPTER_ONLY_TYPES = {
    "fallback", "path_blocked", "path_exposed", "path_other", "path_public", "path_redirect",
    "probe_open_redirect", "probe_path_traversal",
}


def make_valid():
    return {
        "finding_id": "dvwa-docker-lab-20261007-101157-f0003",
        "scan_id": "dvwa-docker-lab-20261007-101157", "target": "dvwa-docker-lab",
        "schema_version": "structured_finding.v1", "prompt_version": "p1",
        "features": {
            "vulnerability_category": "cross_site_scripting", "cwe_primary": "CWE-79", "cwe_candidate_count": 1,
            "weak_cwe_signal": False, "bert_top_score": 0.8214, "auth_state": "authenticated",
            "http_method": None, "http_status": 200, "transport_scheme": "http",
            "endpoint_sensitivity": "unknown", "user_input_involved": True, "parameter_reflected": True,
            "sensitive_data_exposed": False, "component_outdated": False, "corroborating_source_count": 1,
            "evidence_confidence": "normal", "is_fallback_finding": False,
        },
        "structured_fields": {"affected_endpoint": "/vulnerabilities/sqli/", "parameter": "id",
                              "component_name": None, "component_version": None, "component_current_version": None},
        "context": {"rule_based_description": "The id parameter of the /vulnerabilities/sqli/ page reflects ...",
                    "llm_note": ""},
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


def test_contradictory_cwe_fields_rejected():
    bad = make_valid()
    bad["features"].update(cwe_primary=None)  # still says count=1 and a score
    with pytest.raises(ValidationError):
        validate_structured_finding(bad)


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
