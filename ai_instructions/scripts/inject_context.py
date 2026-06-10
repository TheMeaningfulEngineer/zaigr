#!/usr/bin/env python3
"""Load path-specific context for Codex around file edits and file reads."""

import json
import os
from pathlib import Path
import sys
from fnmatch import fnmatch

try:
    import yaml
except ImportError:
    yaml = None


CONTEXT_DIR = Path("ai_instructions/context_injections")
CONTEXT_CONFIG = Path("ai_instructions/context_mapping.yaml")

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print_manual_context(sys.argv[2:])
        return 0

    parsed_payload = json_from_stdin()
    payload = relevant_payload(parsed_payload)
    hook_event = hook_event_name(parsed_payload)
    context_root = context_root_for(parsed_payload)
    context_rules = context_rules_from(context_root)
    context = map_payload_to_context(payload, hook_event, context_root, context_rules)
    print_context(parsed_payload, context)

    return 0


def json_from_stdin():
    try:
        return json.loads(sys.stdin.read())
    except json.JSONDecodeError:
        return {}


def hook_event_name(parsed_payload):
    event = parsed_payload.get("hook_event_name")
    if isinstance(event, str):
        return event
    return ""


def relevant_payload(parsed_payload):
    tool_input = parsed_payload.get("tool_input", {})
    if not isinstance(tool_input, dict):
        return ""

    values = []
    collect_string_values(tool_input, values)
    return "\n".join(values)


def collect_string_values(value, values):
    if isinstance(value, str):
        values.append(value)
        return

    if isinstance(value, dict):
        for item in value.values():
            collect_string_values(item, values)
        return

    if isinstance(value, list):
        for item in value:
            collect_string_values(item, values)


def context_root_for(parsed_payload):
    payload_cwd = Path(parsed_payload.get("cwd") or os.getcwd())
    return discover_repo_root(payload_cwd)


def map_payload_to_context(payload, hook_event, context_root, context_rules):
    context_files = context_files_for_text(payload, hook_event, context_rules)
    return read_context(context_files, context_root)


def print_context(parsed_payload, context):
    if not context:
        return

    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": parsed_payload.get("hook_event_name"),
            "additionalContext": context,
        }
    }))


def discover_repo_root(start):
    start = start.resolve()
    candidates = [start, *start.parents]

    for candidate in candidates:
        if (candidate / CONTEXT_DIR).is_dir():
            return candidate

    return Path(os.getcwd())


def context_rules_from(context_root):
    if yaml is None:
        raise SystemExit("Missing dependency: PyYAML is required to read ai_instructions/context_mapping.yaml")

    config_path = context_root / CONTEXT_CONFIG
    try:
        config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise SystemExit(f"context config not found: {config_path}") from error
    except yaml.YAMLError as error:
        raise SystemExit(f"invalid YAML in {config_path}: {error}") from error

    rules = config.get("rules") if isinstance(config, dict) else None
    if not isinstance(rules, list):
        raise SystemExit(f"expected 'rules' list in {config_path}")

    validate_context_rules(rules, config_path)
    return rules


def validate_context_rules(rules, config_path):
    for index, rule in enumerate(rules, start=1):
        if not isinstance(rule, dict):
            raise SystemExit(f"expected rule {index} in {config_path} to be a mapping")

        pattern = rule.get("when")
        if not isinstance(pattern, str) or pattern == "":
            raise SystemExit(f"expected non-empty 'when' string in rule {index} of {config_path}")

        has_injection = False
        injected_files = rule.get("inject")
        if injected_files is not None:
            validate_inject_list(injected_files, f"rule {index} of {config_path}")
            has_injection = True

        for event_name in ("PreToolUse", "PostToolUse"):
            event_config = rule.get(event_name)
            if event_config is None:
                continue
            if not isinstance(event_config, dict):
                raise SystemExit(f"expected '{event_name}' in rule {index} of {config_path} to be a mapping")
            event_injected_files = event_config.get("inject")
            validate_inject_list(event_injected_files, f"{event_name} in rule {index} of {config_path}")
            has_injection = True

        if not has_injection:
            raise SystemExit(f"expected shared or event-specific 'inject' in rule {index} of {config_path}")


def validate_inject_list(injected_files, location):
    if not isinstance(injected_files, list) or not injected_files:
        raise SystemExit(f"expected non-empty 'inject' list in {location}")
    for injected_file in injected_files:
        if not isinstance(injected_file, str) or injected_file == "":
            raise SystemExit(f"expected 'inject' entries in {location} to be strings")


def context_files_for_text(text, hook_event, context_rules):
    context_files = []

    for rule in context_rules:
        pattern = rule["when"]
        if text_matches_rule(text, pattern):
            context_files.extend(rule_context_files(rule, hook_event))

    return dedupe(context_files)


def rule_context_files(rule, hook_event):
    context_files = [CONTEXT_DIR / file for file in rule.get("inject", [])]

    event_config = rule.get(hook_event)
    if isinstance(event_config, dict):
        context_files.extend(CONTEXT_DIR / file for file in event_config.get("inject", []))

    return context_files


def text_matches_rule(text, pattern):
    for token in text.split():
        candidate = token.strip("'\"`:,;()[]{}<>")
        if path_matches_rule(candidate, pattern):
            return True

    if pattern.endswith("/**"):
        prefix = pattern.removesuffix("/**")
        return prefix == text or f"{prefix}/" in text

    return pattern in text


def context_files_for(edited_files):
    context_rules = context_rules_from(Path(os.getcwd()))
    context_files = []

    for edited_file in edited_files:
        for rule in context_rules:
            if path_matches_rule(edited_file, rule["when"]):
                context_files.extend(rule_context_files(rule, ""))

    return dedupe(context_files)


def path_matches_rule(path, pattern):
    if fnmatch(path, pattern):
        return True

    if pattern.endswith("/**"):
        prefix = pattern.removesuffix("/**")
        return path == prefix or path.startswith(prefix + "/")

    return False


def dedupe(items):
    seen = set()
    result = []

    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)

    return result


def read_context(context_files, repo_root):
    chunks = []

    for context_file in context_files:
        try:
            content = (repo_root / context_file).read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            continue

        if content:
            chunks.append(f"Context from {context_file.as_posix()}:\n{content}")

    return "\n\n".join(chunks)


def print_manual_context(edited_files):
    if not edited_files:
        print("Usage: inject_context.py --test <file> [file ...]")
        return

    repo_root = Path(os.getcwd())
    context_files = context_files_for(edited_files)
    if not context_files:
        print("No context matched.")
        return

    print("Matched context files:")
    for context_file in context_files:
        print(f"- {context_file.as_posix()}")

    context = read_context(context_files, repo_root)
    if context:
        print()
        print(context)


if __name__ == "__main__":
    raise SystemExit(main())
