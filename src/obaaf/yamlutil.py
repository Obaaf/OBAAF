"""YAML loading for workflow files, answer files and OBAAF data.

Two differences from PyYAML's SafeLoader matter here:

* Booleans follow YAML 1.2, as GitHub Actions does: only true/false are
  booleans. PyYAML follows YAML 1.1 and would read the workflow key `on`, and
  answers such as `yes` and `no`, as booleans.
* Every mapping remembers the line it starts on, and the line of each key, so
  findings can point at the right place.
"""

from __future__ import annotations

import re
from typing import Any

import yaml


class LineDict(dict):
    """A dict that remembers where it came from in the source file."""

    line: int = 0
    key_lines: dict

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.key_lines = {}

    def line_of(self, key: str) -> int:
        return self.key_lines.get(key, self.line)


class LineList(list):
    line: int = 0


class DuplicateKeyError(yaml.YAMLError):
    pass


class _Loader(yaml.SafeLoader):
    """SafeLoader with YAML 1.2 booleans, line numbers and duplicate-key errors."""


# Replace the YAML 1.1 boolean resolver with a YAML 1.2 one.
_Loader.yaml_implicit_resolvers = {
    key: [(tag, rx) for tag, rx in resolvers if tag != "tag:yaml.org,2002:bool"]
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_Loader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
    list("tTfF"),
)


def _construct_mapping(loader: _Loader, node: yaml.MappingNode) -> LineDict:
    loader.flatten_mapping(node)
    result = LineDict()
    result.line = node.start_mark.line + 1
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if not isinstance(key, (str, int, float, bool)) and key is not None:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping", node.start_mark, "found an unhashable key", key_node.start_mark
            )
        if key in result:
            raise DuplicateKeyError(f"duplicate key {key!r} on line {key_node.start_mark.line + 1}")
        result[key] = loader.construct_object(value_node, deep=True)
        result.key_lines[key] = key_node.start_mark.line + 1
    return result


def _construct_sequence(loader: _Loader, node: yaml.SequenceNode) -> LineList:
    result = LineList(loader.construct_object(child, deep=True) for child in node.value)
    result.line = node.start_mark.line + 1
    return result


_Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)
_Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_SEQUENCE_TAG, _construct_sequence)


def load(text: str) -> Any:
    """Parse one YAML document."""
    return yaml.load(text, Loader=_Loader)  # noqa: S506 - _Loader derives from SafeLoader


def load_file(path) -> Any:
    with open(path, encoding="utf-8") as handle:
        return load(handle.read())


def dump(data: Any) -> str:
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=100)
