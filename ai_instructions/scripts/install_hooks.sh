#!/bin/bash
set -eu

usage() {
	echo "Usage: $0 <codex|claude|all> [--force]" >&2
}

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
	usage
	exit 2
fi

agent="$1"
force=0
if [ "$#" -eq 2 ]; then
	if [ "$2" != "--force" ]; then
		usage
		exit 2
	fi
	force=1
fi

case "$agent" in
	codex|claude|all) ;;
	*)
		usage
		exit 2
		;;
esac

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/../.." && pwd)"
hook_script="$repo_root/ai_instructions/scripts/inject_context.py"

if [ ! -f "$hook_script" ]; then
	echo "hook script not found: $hook_script" >&2
	exit 1
fi

render_template() {
	template="$1"
	destination="$2"

	if [ -e "$destination" ] && [ "$force" -ne 1 ]; then
		echo "refusing to overwrite existing config: $destination" >&2
		echo "rerun with --force to replace it" >&2
		exit 1
	fi

	mkdir -p "$(dirname -- "$destination")"
	sed "s#__HOOK_SCRIPT__#$hook_script#g" "$template" > "$destination"
	echo "installed $destination"
}

install_codex() {
	config_dir="${CODEX_HOME:-$HOME/.codex}"
	render_template \
		"$repo_root/ai_instructions/hooks/codex/hooks.json" \
		"$config_dir/hooks.json"
}

install_claude() {
	config_dir="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
	render_template \
		"$repo_root/ai_instructions/hooks/claude/settings.json" \
		"$config_dir/settings.json"
}

case "$agent" in
	codex)
		install_codex
		;;
	claude)
		install_claude
		;;
	all)
		install_codex
		install_claude
		;;
esac
