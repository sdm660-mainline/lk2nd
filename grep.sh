#!/bin/bash
set -x
grep --color -n --exclude-dir="build-lk2nd-*" --exclude=".vscode-ctags" "$@"
