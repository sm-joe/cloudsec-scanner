"""Bounded parsing of untrusted YAML and JSON documents."""
from __future__ import annotations

import json
import yaml


class UniqueLoader(yaml.SafeLoader):
    pass


def _mapping(loader, node):
    # Reject duplicate explicit keys before merge expansion; YAML merge overrides are valid.
    explicit = set()
    for key_node, _ in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            continue
        key = loader.construct_object(key_node)
        if key in explicit:
            raise ValueError("duplicate YAML mapping key")
        explicit.add(key)
    loader.flatten_mapping(node)
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        result[key] = loader.construct_object(value_node)
    return result


UniqueLoader.add_constructor("tag:yaml.org,2002:map", _mapping)


def validate_document(value, *, max_depth=64, max_nodes=100000):
    active = set()
    count = 0

    def walk(node, depth):
        nonlocal count
        count += 1
        if depth > max_depth or count > max_nodes:
            raise ValueError("document complexity limit exceeded")
        if not isinstance(node, (dict, list)):
            return
        identity = id(node)
        if identity in active:
            raise ValueError("recursive document alias")
        active.add(identity)
        for child in node.values() if isinstance(node, dict) else node:
            walk(child, depth + 1)
        active.remove(identity)

    walk(value, 0)


class CloudFormationLoader(UniqueLoader):
    """Construct only a fixed allowlist of intrinsic tags as inert data."""


_INTRINSICS = {
    "Ref": "Ref", "Condition": "Condition", "GetAtt": "Fn::GetAtt",
    "Sub": "Fn::Sub", "Join": "Fn::Join", "If": "Fn::If",
    "Select": "Fn::Select", "Split": "Fn::Split", "FindInMap": "Fn::FindInMap",
    "ImportValue": "Fn::ImportValue", "GetAZs": "Fn::GetAZs",
    "Base64": "Fn::Base64", "Cidr": "Fn::Cidr", "Equals": "Fn::Equals",
    "And": "Fn::And", "Or": "Fn::Or", "Not": "Fn::Not",
    "Length": "Fn::Length", "ToJsonString": "Fn::ToJsonString",
}


def _intrinsic(loader, suffix, node):
    if suffix not in _INTRINSICS:
        raise ValueError("unsupported YAML tag")
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    elif isinstance(node, yaml.MappingNode):
        value = loader.construct_mapping(node)
    else:
        raise ValueError("invalid intrinsic node")
    return {_INTRINSICS[suffix]: value}


CloudFormationLoader.add_multi_constructor("!", _intrinsic)


def safe_json_document(text):
    """Reject ambiguous mappings, NaN and excessive structural complexity."""
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON mapping key")
            result[key] = value
        return result

    def invalid_constant(_):
        raise ValueError("non-finite JSON number")

    try:
        value = json.loads(text, object_pairs_hook=unique, parse_constant=invalid_constant)
        validate_document(value)
        return value
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("invalid or excessively complex JSON") from exc


def _preflight_yaml(node, *, max_nodes=100000, max_depth=64):
    # Count expanded nodes BEFORE construction and flatten_mapping.
    pending = [(node, 0)]
    count = 0
    while pending:
        current, depth = pending.pop()
        count += 1
        if count > max_nodes or depth > max_depth:
            raise ValueError("YAML complexity limit exceeded")
        if isinstance(current, yaml.MappingNode):
            merges = 0
            for key, child in current.value:
                if key.tag == "tag:yaml.org,2002:merge":
                    merges += 1
                    if merges > 1:
                        raise ValueError("duplicate YAML merge key")
                pending.extend(((key, depth + 1), (child, depth + 1)))
        elif isinstance(current, yaml.SequenceNode):
            pending.extend((child, depth + 1) for child in current.value)


def safe_yaml_documents(text, *, cloudformation=False):
    try:
        loader = (CloudFormationLoader if cloudformation else UniqueLoader)(text)
        try:
            docs = []
            while loader.check_node():
                if len(docs) >= 1000:
                    raise ValueError("document count limit exceeded")
                node = loader.get_node()
                _preflight_yaml(node)
                doc = loader.construct_document(node)
                validate_document(doc)
                docs.append(doc)
            return docs
        finally:
            loader.dispose()
    except (yaml.YAMLError, RecursionError, TypeError) as exc:
        raise ValueError("invalid or excessively complex YAML") from exc
