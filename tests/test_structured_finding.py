"""Tests for structured_finding.py (S1-S5). No scanners, Docker, BERT or API needed.

Run from the repository root:  pytest tests/test_structured_finding.py
Needs: pydantic>=2, jsonschema
"""
from bert_cwe_labeler.normalize.rules import CHECK_TEMPLATES, MESSAGE_RULES
from bert_cwe_labeler.structured_finding import (
    ENUM_VALUES,
    TYPE_TO_CATEGORY,
    category_for_type,
)

# Types emitted outside the MESSAGE_RULES / CHECK_TEMPLATES tables (adapters.py).
# Update this set if adapters.py gains a new type.
ADAPTER_ONLY_TYPES = {
    "fallback", "path_blocked", "path_exposed", "path_other", "path_public", "path_redirect",
    "probe_open_redirect", "probe_path_traversal",
}



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
