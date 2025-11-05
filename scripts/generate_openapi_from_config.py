#!/usr/bin/env python3
"""Regenerate permission-related sections in static/openapi.yaml from .config/config.py

This implementation uses PyYAML to parse the OpenAPI spec, update the
relevant nodes (schema descriptions, examples, and counts), and write the
result back. It is more robust than text substitution and updates all
occurrences of permission examples and counts.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any, Dict, List

import yaml


def load_config(config_path: Path) -> List[Dict[str, Any]]:
    spec = importlib.util.spec_from_file_location("project_config", str(config_path))
    if spec is None or spec.loader is None:
        raise SystemExit(f"Unable to load config module from {config_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore
    if not hasattr(module, "PERMISSIONS"):
        raise SystemExit("config.py does not define PERMISSIONS")
    return getattr(module, "PERMISSIONS")


def compute_permission_metadata(permissions: List[Dict[str, Any]]):
    total = len(permissions)
    max_value = (1 << total) - 1 if total > 0 else 0
    # Build example list for YAML spec
    example_perms = []
    for p in permissions:
        value = p.get("value")
        if value is None:
            bit = p.get("bit")
            value = (1 << bit) if isinstance(bit, int) else None
        example_perms.append({
            "name": p.get("name"),
            "bit": p.get("bit"),
            "value": value,
            "description": p.get("description", ""),
        })
    return total, max_value, example_perms


def update_api_key_schema(spec: Dict[str, Any], permissions: List[Dict[str, Any]]):
    # Update components.schemas.APIKey.properties.permissions.description
    schemas = spec.get("components", {}).get("schemas", {})
    api_key = schemas.get("APIKey")
    if not api_key:
        return
    props = api_key.get("properties", {})
    perms_prop = props.get("permissions")
    if not perms_prop:
        return
    # Create a multi-line description enumerating bits
    lines = ["Permission bitmap:"]
    for p in permissions:
        bit = p.get("bit")
        value = p.get("value")
        if value is None:
            value = (1 << bit) if isinstance(bit, int) else None
        friendly = p.get("friendly_name", p.get("name", ""))
        desc = p.get("description", "")
        lines.append(f"- Bit {bit} ({value}): {friendly} - {desc}")
    perms_prop["description"] = "\n".join(lines)


def recursive_update_examples(node: Any, total: int, max_value: int, example_perms: Any):
    # Recursively find 'example' dicts and update keys inside those example dicts.
    # Specifically looks for 'permissions', 'total_permissions', and 'max_value'.
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "example" and isinstance(v, dict):
                changed = False
                if "permissions" in v:
                    v["permissions"] = example_perms
                    changed = True
                if "total_permissions" in v:
                    v["total_permissions"] = total
                    changed = True
                if "max_value" in v:
                    v["max_value"] = max_value
                    changed = True
                if changed:
                    # no-op return to continue walking other keys
                    pass
            else:
                recursive_update_examples(v, total, max_value, example_perms)
    elif isinstance(node, list):
        for item in node:
            recursive_update_examples(item, total, max_value, example_perms)


def recursive_update_fields(node: Any, total: int, max_value: int):
    # Update schema property examples for keys named 'max_value' or 'total_permissions'
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "max_value" and isinstance(v, dict):
                v["example"] = max_value
            elif k == "total_permissions" and isinstance(v, dict):
                v["example"] = total
            else:
                recursive_update_fields(v, total, max_value)
    elif isinstance(node, list):
        for item in node:
            recursive_update_fields(item, total, max_value)


def recursive_update_permissions_max(node: Any, max_value: int):
    # Find properties named 'permissions' and set their 'maximum' to max_value when present
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "permissions" and isinstance(v, dict) and "maximum" in v:
                v["maximum"] = max_value
            else:
                recursive_update_permissions_max(v, max_value)
    elif isinstance(node, list):
        for item in node:
            recursive_update_permissions_max(item, max_value)


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    config_path = repo_root / ".config" / "config.py"
    openapi_path = repo_root / "static" / "openapi.yaml"

    if not config_path.exists():
        print(f"Config file not found at {config_path}")
        return 2
    if not openapi_path.exists():
        print(f"OpenAPI spec not found at {openapi_path}")
        return 3

    permissions = load_config(config_path)
    total, max_value, example_perms = compute_permission_metadata(permissions)

    # Read YAML
    text = openapi_path.read_text(encoding="utf-8")
    spec = yaml.safe_load(text)

    # Update APIKey schema description
    update_api_key_schema(spec, permissions)

    # Update CreateAPIKey maximum if present
    try:
        create_schema = (
            spec["components"]["schemas"]["CreateAPIKey"]["properties"]["permissions"]
        )
        create_schema["maximum"] = max_value
    except Exception:
        # ignore if path not present
        pass

    # Recursively update example blocks across spec
    recursive_update_examples(spec, total, max_value, example_perms)
    # Update any scalar property examples (max_value, total_permissions)
    recursive_update_fields(spec, total, max_value)
    # Update permissions.maximum across the spec
    recursive_update_permissions_max(spec, max_value)

    new_text = yaml.safe_dump(spec, sort_keys=False)
    if new_text == text:
        print("openapi.yaml already up to date; no changes made")
        return 0

    backup = openapi_path.with_suffix(".yaml.bak")
    openapi_path.replace(backup)
    print(f"Backed up original openapi to {backup}")
    openapi_path.write_text(new_text, encoding="utf-8")
    print(f"Updated {openapi_path} with {len(permissions)} permissions from {config_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
