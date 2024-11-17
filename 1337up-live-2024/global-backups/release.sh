#!/bin/bash
set -e

NAME=global-backups
CWD="$(pwd)"

rm -rf "${NAME}_full.zip" "${NAME}_handout.zip"

# Prepare zip directory
tmp="$(mktemp -d)"
dir="$tmp/$NAME"
mkdir "$dir"
cp -r README.md app backup docker-compose.yml .env{,-dummy} solve "$dir"
rm -r "$dir/app/node_modules"  # remove dependencies
cd "$tmp"  # write relative paths in zip
zip -r "$CWD/${NAME}_full.zip" "$NAME"

# Hide solve script and .env file from handout
rm -r "$dir/solve" "$dir/.env"
mv "$dir/app/flag-dummy.txt" "$dir/app/flag.txt"
mv "$dir/.env-dummy" "$dir/.env"
zip -r "$CWD/${NAME}_handout.zip" "$NAME"

# Cleanup
rm -r "$tmp"
cd "$CWD"

echo "Release files created:"
ls -lh "${NAME}_full.zip" "${NAME}_handout.zip"
