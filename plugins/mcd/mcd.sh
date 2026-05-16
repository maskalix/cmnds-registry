#!/bin/bash
#
# Plugin Name: mcd
# Description: Create a directory and change into it
# Author: Martin Skalicky
# Version: 1.0.0
#

set -e  # Exit on error

# Colors for output
readonly GREEN='\033[0;32m'
readonly RED='\033[0;31m'
readonly NC='\033[0m'

# Plugin metadata
readonly PLUGIN_NAME="mcd"
readonly PLUGIN_VERSION="1.0.0"

# Show help
show_help() {
    cat << EOF

$PLUGIN_NAME v$PLUGIN_VERSION

Description:
  Creates a new directory (including parent directories if needed) and
  immediately changes into it. If the directory already exists, it just
  changes into it.

Usage:
  $PLUGIN_NAME <directory>

Options:
  -h, --help     Show this help message

Examples:
  $ mcd my-project
    Create 'my-project' directory and cd into it

  $ mcd /tmp/test/nested
    Create nested directories and cd into the deepest one

Author: Martin Skalicky

EOF
}

# Main functionality
mcd() {
    local dir="$1"

    if [ ! -d "$dir" ]; then
        if mkdir -p "$dir"; then
            echo -e "${GREEN}Directory $dir created${NC}"
            if cd "$dir"; then
                echo "Changed directory to: $PWD"
            else
                echo -e "${RED}Failed to change directory to $dir${NC}"
                return 1
            fi
        else
            echo -e "${RED}Failed to create directory $dir${NC}"
            return 1
        fi
    else
        echo -e "${RED}Directory $dir already exists${NC}"
        if cd "$dir"; then
            echo "Changed directory to: $PWD"
        else
            echo -e "${RED}Failed to change directory to $dir${NC}"
            return 1
        fi
    fi
}

# Parse arguments
case "${1:-}" in
    -h|--help|help)
        show_help
        exit 0
        ;;
    "")
        echo "Usage: mcd <directory>"
        exit 1
        ;;
    *)
        if mcd "$1"; then
            exit 0
        else
            exit 1
        fi
        ;;
esac
