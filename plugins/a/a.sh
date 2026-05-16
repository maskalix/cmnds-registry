#!/bin/bash
#
# Plugin Name: a
# Description: Quick apt package manager shortcuts
# Author: Martin Skalicky
# Version: 1.0.0
#

# Plugin metadata
readonly PLUGIN_NAME="a"
readonly PLUGIN_VERSION="1.0.0"

# Function to display help message
display_help() {
    cat << EOF

$PLUGIN_NAME v$PLUGIN_VERSION

Description:
  Convenient shortcuts for apt package manager commands. Provides short
  aliases for common apt operations like install, update, upgrade, remove, etc.

Usage:
  $PLUGIN_NAME [-y] <command> [arguments]

Commands:
  i, install      Install a package
  u, update       Update the list of available packages
  ug, upgrade     Upgrade installed packages
  r, remove       Remove a package
  p, purge        Remove a package along with its configuration files
  au, autoremove  Remove unused packages
  c, clean        Clear out the local repository of retrieved package files
  ac, autoclean   Clear out old package files
  s, source       Download the source code for a package
  h, help         Display this help message

Options:
  -y              Automatically answer 'yes' to prompts
  --help, -h      Show this help message

Examples:
  $ a i nginx
    Install nginx package

  $ a -y ug
    Upgrade all packages without prompts

  $ a u
    Update package lists

Author: Martin Skalicky

EOF
}

# Main function to handle apt commands
a() {
    local auto_yes=0

    # Check for help flags first
    case "$1" in
        --help|-h|help|h)
            display_help
            return 0
            ;;
    esac

    # Check if the command includes the '-y' flag
    if [[ "$1" == "-y" ]]; then
        auto_yes=1
        shift
    fi

    local command="$1"
    shift

    # Handle empty command
    if [ -z "$command" ]; then
        echo "Error: No command provided"
        echo "Use 'a help' for usage information"
        return 1
    fi

    # Convert hyphens and remove leading spaces
    command="$(echo "$command" | sed 's/-/ /' | sed 's/^ *//')"

    case "$command" in
        i|install)
            if [ $auto_yes -eq 1 ]; then
                apt install -y "$@"
            else
                apt install "$@"
            fi
            ;;
        u|update)
            apt update
            ;;
        ug|upgrade)
            if [ $auto_yes -eq 1 ]; then
                apt upgrade -y
            else
                apt upgrade
            fi
            ;;
        r|remove)
            apt remove "$@"
            ;;
        p|purge)
            apt purge "$@"
            ;;
        au|autoremove)
            apt autoremove
            ;;
        c|clean)
            apt clean
            ;;
        ac|autoclean)
            apt autoclean
            ;;
        s|source)
            apt source "$@"
            ;;
        h|help)
            display_help
            ;;
        *)
            echo "Invalid command: $command"
            echo "Use 'a help' to display available commands"
            return 1
            ;;
    esac
}

# Call the function with the provided command and arguments
a "$@"
