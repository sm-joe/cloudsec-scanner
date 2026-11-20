"""Bounded parsing of untrusted YAML and JSON documents."""
from __future__ import annotations

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


def safe_yaml_documents(text):
    try:
        docs = list(yaml.load_all(text, Loader=UniqueLoader))
        for doc in docs:
            validate_document(doc)
        return docs
    except (yaml.YAMLError, RecursionError, TypeError) as exc:
        raise ValueError("invalid or excessively complex YAML") from exc
