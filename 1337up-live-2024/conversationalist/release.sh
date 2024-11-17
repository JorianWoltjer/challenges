#!/bin/bash
set -e

NAME=conversationalist
CWD="$(pwd)"

rm -rf "${NAME}_full.zip" "${NAME}_handout.zip"

# Prepare zip directory
tmp="$(mktemp -d)"
dir="$tmp/$NAME"
mkdir "$dir"
cp -r README.md app Dockerfile docker-compose.yml solve "$dir"
rm -r "$dir/app/target" "$dir/solve/target"  # remove compiled files
cd "$tmp"  # write relative paths in zip
zip -r "$CWD/${NAME}_full.zip" "$NAME"

# Hide solve script and .env file from handout
rm -r "$dir/solve"
mv "$dir/app/flag-dummy.txt" "$dir/app/flag.txt"
mv "$dir/app/messages-dummy.txt" "$dir/app/messages.txt"
zip -r "$CWD/${NAME}_handout.zip" "$NAME"

# Cleanup
rm -r "$tmp"
cd "$CWD"

echo "Release files created:"
ls -lh "${NAME}_full.zip" "${NAME}_handout.zip"
