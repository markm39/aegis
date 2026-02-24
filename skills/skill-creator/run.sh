#!/bin/bash
set -euo pipefail
INPUT=$(cat)
NAME=$(echo "$INPUT" | jq -r '.parameters.args[0] // ""')
CATEGORY=$(echo "$INPUT" | jq -r '.parameters.args[1] // "development"')

if [ -z "$NAME" ]; then
  echo '{"result": "Usage: /mkskill <skill-name> [category]\n\nCategories: development, productivity, macos, search, communication, ai", "artifacts": [], "messages": []}'
  exit 0
fi

# Validate name
if ! echo "$NAME" | grep -qE '^[a-z0-9-]+$'; then
  echo '{"result": "Skill name must contain only lowercase letters, numbers, and hyphens.", "artifacts": [], "messages": []}'
  exit 0
fi

SKILLS_DIR="${AEGIS_SKILLS_DIR:-./skills}"
SKILL_DIR="$SKILLS_DIR/$NAME"

if [ -d "$SKILL_DIR" ]; then
  RESULT_JSON=$(echo "Skill directory already exists: $SKILL_DIR" | jq -Rs .)
  echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
  exit 0
fi

mkdir -p "$SKILL_DIR"

# Write manifest
cat > "$SKILL_DIR/manifest.toml" << TOMLEOF
name = "$NAME"
version = "0.1.0"
description = "TODO: Add description"
author = "$(whoami)"
category = "$CATEGORY"
permissions = []
entry_point = "run.sh"
dependencies = []
min_aegis_version = "0.1.0"
required_bins = []
required_env = []
os = []

[[commands]]
name = "$NAME"
description = "TODO: Add description"
usage = "/$NAME [args...]"
aliases = []
TOMLEOF

# Write entry point
cat > "$SKILL_DIR/run.sh" << 'SHEOF'
#!/bin/bash
set -euo pipefail
INPUT=$(cat)
SUBCMD=$(echo "$INPUT" | jq -r '.parameters.args[0] // "help"')

case "$SUBCMD" in
  help|*)
    RESULT="TODO: Implement this skill"
    ;;
esac

RESULT_JSON=$(echo "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [], \"messages\": []}"
SHEOF

chmod +x "$SKILL_DIR/run.sh"

RESULT="Skill scaffolded at: $SKILL_DIR\n\nFiles created:\n- $SKILL_DIR/manifest.toml\n- $SKILL_DIR/run.sh\n\nNext steps:\n1. Edit manifest.toml to add description\n2. Implement run.sh\n3. Test with: echo '{\"action\":\"$NAME\",\"parameters\":{\"args\":[\"test\"]}}' | bash $SKILL_DIR/run.sh"

RESULT_JSON=$(echo -e "$RESULT" | jq -Rs .)
echo "{\"result\": $RESULT_JSON, \"artifacts\": [{\"type\": \"directory\", \"path\": \"$SKILL_DIR\"}], \"messages\": []}"
