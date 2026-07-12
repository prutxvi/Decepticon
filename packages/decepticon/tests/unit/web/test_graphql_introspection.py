# -*- coding: utf-8 -*-
"""Introspection-parser + query-generator coverage for
``decepticon.tools.web.graphql``.

This GraphQL auditor parses an introspection blob and (a) enumerates
Query/Mutation fields, (b) finds IDOR-candidate fields (those taking an
``id`` / ``*Id`` argument), and (c) auto-generates minimal valid query
documents used as fuzzing baselines. A regression here is a silent
**false negative** (a missed IDOR hunting-ground) or an **invalid
generated query** (fuzzing that never reaches the server). This pins the
type-unwrapping, schema-parsing, IDOR-detection and placeholder branches
the existing suite left uncovered.

Pure-logic; no network / docker / LLM.
"""

from __future__ import annotations

import pytest

from decepticon.tools.web.graphql import GraphQLSchema, _unwrap_type


def _scalar(name: str) -> dict:
    return {"kind": "SCALAR", "name": name, "ofType": None}


def _obj(name: str) -> dict:
    return {"kind": "OBJECT", "name": name, "ofType": None}


def _non_null(of: dict) -> dict:
    return {"kind": "NON_NULL", "name": None, "ofType": of}


def _list(of: dict) -> dict:
    return {"kind": "LIST", "name": None, "ofType": of}


INTROSPECTION = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "subscriptionType": None,
            "types": [
                {
                    "name": "Query",
                    "kind": "OBJECT",
                    "fields": [
                        {
                            "name": "user",
                            "isDeprecated": False,
                            "type": _obj("User"),
                            "args": [
                                {
                                    "name": "id",
                                    "type": _non_null(_scalar("ID")),
                                    "defaultValue": None,
                                }
                            ],
                        },
                        {
                            "name": "search",
                            "isDeprecated": False,
                            "type": _list(_obj("User")),
                            "args": [
                                {"name": "term", "type": _scalar("String"), "defaultValue": None},
                                {"name": "limit", "type": _scalar("Int"), "defaultValue": None},
                                {
                                    "name": "active",
                                    "type": _scalar("Boolean"),
                                    "defaultValue": None,
                                },
                            ],
                        },
                        {
                            "name": "ping",
                            "isDeprecated": False,
                            "type": _scalar("String"),
                            "args": [],
                        },
                    ],
                },
                {
                    "name": "Mutation",
                    "kind": "OBJECT",
                    "fields": [
                        {
                            "name": "updateUser",
                            "isDeprecated": False,
                            "type": _obj("User"),
                            "args": [
                                {
                                    "name": "input",
                                    "type": {
                                        "kind": "INPUT_OBJECT",
                                        "name": "UserInput",
                                        "ofType": None,
                                    },
                                    "defaultValue": None,
                                }
                            ],
                        }
                    ],
                },
                {
                    "name": "User",
                    "kind": "OBJECT",
                    "fields": [
                        {"name": "id", "type": _scalar("ID"), "args": []},
                        {"name": "name", "type": _scalar("String"), "args": []},
                        {"name": "friends", "type": _list(_obj("User")), "args": []},
                        {
                            "name": "role",
                            "type": {"kind": "ENUM", "name": "Role", "ofType": None},
                            "args": [],
                        },
                    ],
                },
                {
                    "name": "UserInput",
                    "kind": "INPUT_OBJECT",
                    "inputFields": [
                        {"name": "name", "type": _non_null(_scalar("String"))},
                        {"name": "nickname", "type": _scalar("String")},  # optional -> skipped
                    ],
                },
                {
                    "name": "Role",
                    "kind": "ENUM",
                    "enumValues": [{"name": "ADMIN"}, {"name": "USER"}],
                },
                {
                    "name": "OptInput",
                    "kind": "INPUT_OBJECT",
                    "inputFields": [
                        {"name": "q", "type": _scalar("String")},  # all optional
                    ],
                },
                {"name": "DateTime", "kind": "SCALAR"},  # custom named scalar
                {
                    "name": "Tag",
                    "kind": "OBJECT",
                    "fields": [
                        {"name": "label", "type": _scalar("String"), "args": []},
                        # object-typed field: skipped by _default_selection (non-scalar)
                        {"name": "owner", "type": _obj("User"), "args": []},
                    ],
                },
                {"kind": "SCALAR"},  # nameless type -> skipped on parse
            ],
        }
    }
}


# ---------------------------------------------------------------- _unwrap_type


def test_unwrap_none_is_unknown():
    assert _unwrap_type(None) == ("Unknown", False, False)


def test_unwrap_plain_scalar():
    assert _unwrap_type(_scalar("String")) == ("String", False, False)


def test_unwrap_non_null():
    assert _unwrap_type(_non_null(_scalar("ID"))) == ("ID", False, True)


def test_unwrap_list():
    assert _unwrap_type(_list(_obj("User"))) == ("User", True, False)


def test_unwrap_non_null_list_of_non_null():
    nested = _non_null(_list(_non_null(_scalar("Int"))))
    assert _unwrap_type(nested) == ("Int", True, True)


# ---------------------------------------------------------------- from_introspection


def test_from_introspection_parses_root_types():
    schema = GraphQLSchema.from_introspection(INTROSPECTION)
    assert schema.query_type == "Query"
    assert schema.mutation_type == "Mutation"
    assert schema.subscription_type is None
    assert "User" in schema.types
    # the nameless SCALAR entry is skipped
    assert None not in schema.types


def test_from_introspection_missing_schema_returns_empty_and_warns(
    caplog: pytest.LogCaptureFixture,
):
    import logging

    # The ``decepticon`` logger is configured with propagate=False, so caplog
    # (which listens on the root logger) won't see records unless we re-enable
    # propagation for the duration of the call.
    decep = logging.getLogger("decepticon")
    prev = decep.propagate
    decep.propagate = True
    try:
        with caplog.at_level(logging.WARNING, logger="decepticon.tools.web.graphql"):
            schema = GraphQLSchema.from_introspection({"foo": 1})
    finally:
        decep.propagate = prev
    assert schema.query_type is None
    assert schema.types == {}
    assert any("introspection may be disabled" in r.message for r in caplog.records)


def test_placeholder_input_object_branches():
    schema = GraphQLSchema.from_introspection(INTROSPECTION)
    # All-optional input object -> empty/null depending on non_null flag.
    assert schema._placeholder("OptInput", non_null=True) == "{}"
    assert schema._placeholder("OptInput", non_null=False) == "null"
    # Depth exhausted on a (would-be-recursive) input object.
    assert schema._placeholder("UserInput", non_null=True, depth=0) == "{}"
    assert schema._placeholder("UserInput", non_null=False, depth=0) == "null"
    # A custom (named) scalar stubs as a string.
    assert schema._placeholder("DateTime") == '"test"'


def test_default_selection_depth_and_small_object():
    schema = GraphQLSchema.from_introspection(INTROSPECTION)
    # Depth exhausted -> no selection set.
    assert schema._default_selection("User", depth=0) == ""
    # An object with fewer than 3 scalar fields exits the loop naturally.
    assert schema._default_selection("Tag", depth=2) == "{ label }"


# ---------------------------------------------------------------- field enumeration


def test_query_and_mutation_fields_enumerated():
    schema = GraphQLSchema.from_introspection(INTROSPECTION)
    assert {f.name for f in schema.query_fields()} == {"user", "search", "ping"}
    assert {f.name for f in schema.mutation_fields()} == {"updateUser"}


def test_search_field_return_type_is_list():
    schema = GraphQLSchema.from_introspection(INTROSPECTION)
    search = next(f for f in schema.query_fields() if f.name == "search")
    assert search.return_type == "User"
    assert search.is_list is True


# ---------------------------------------------------------------- IDOR candidates


def test_idor_candidates_finds_id_arg_field_only():
    schema = GraphQLSchema.from_introspection(INTROSPECTION)
    candidates = schema.idor_candidates()
    names = {(kind, fld.name) for kind, fld in candidates}
    assert ("Query", "user") in names  # takes an `id` arg
    assert ("Query", "search") not in names  # term/limit/active -> no id arg
    assert ("Query", "ping") not in names  # no args


# ---------------------------------------------------------------- generate_query


def test_generate_query_stubs_id_arg_and_scalar_selection():
    schema = GraphQLSchema.from_introspection(INTROSPECTION)
    q = schema.generate_query("user")
    assert q.startswith("query { user(")
    assert 'id: "1"' in q  # ID placeholder
    assert "{ id name role }" in q  # scalar+enum selection, list field 'friends' skipped


def test_generate_query_scalar_arg_placeholders():
    schema = GraphQLSchema.from_introspection(INTROSPECTION)
    q = schema.generate_query("search")
    assert 'term: "test"' in q
    assert "limit: 1" in q
    assert "active: true" in q


def test_generate_query_input_object_includes_only_required_fields():
    schema = GraphQLSchema.from_introspection(INTROSPECTION)
    q = schema.generate_query("updateUser", kind="mutation")
    assert q.startswith("mutation { updateUser(")
    assert 'input: { name: "test" }' in q  # required 'name'; optional 'nickname' omitted


def test_generate_query_no_args_no_selection_for_scalar_return():
    schema = GraphQLSchema.from_introspection(INTROSPECTION)
    assert schema.generate_query("ping") == "query { ping }"


def test_generate_query_unknown_field_raises_keyerror():
    schema = GraphQLSchema.from_introspection(INTROSPECTION)
    with pytest.raises(KeyError):
        schema.generate_query("does_not_exist")


def test_generate_query_invalid_kind_raises_valueerror():
    schema = GraphQLSchema.from_introspection(INTROSPECTION)
    with pytest.raises(ValueError):
        schema.generate_query("user", kind="subscription")


# ---------------------------------------------------------------- _placeholder


def test_placeholder_primitive_types():
    schema = GraphQLSchema.from_introspection(INTROSPECTION)
    assert schema._placeholder("Int") == "1"
    assert schema._placeholder("Float") == "1"
    assert schema._placeholder("Boolean") == "true"
    assert schema._placeholder("ID") == '"1"'
    assert schema._placeholder("String") == '"test"'


def test_placeholder_list_wraps_item():
    schema = GraphQLSchema.from_introspection(INTROSPECTION)
    assert schema._placeholder("Int", is_list=True) == "[1]"


def test_placeholder_enum_picks_first_value():
    schema = GraphQLSchema.from_introspection(INTROSPECTION)
    assert schema._placeholder("Role") == "ADMIN"


def test_placeholder_unknown_type_respects_non_null():
    schema = GraphQLSchema.from_introspection(INTROSPECTION)
    assert schema._placeholder("Mystery", non_null=True) == '"test"'
    assert schema._placeholder("Mystery", non_null=False) == "null"
