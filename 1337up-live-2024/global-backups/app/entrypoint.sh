#!/bin/bash
set -e

export SECRET=$RANDOM

echo "$SSH_PRIVATE_B64" | base64 -d > /home/user/.ssh/id_ed25519
echo "$SSH_PUBLIC" > /home/user/.ssh/id_ed25519.pub

bun run src/index.ts &
while ! curl -s 'http://localhost:8000' -o /dev/null; do sleep 1; done
for i in {1..5}; do
    curl -sL 'http://localhost:8000/login' -H 'Content-Type: application/x-www-form-urlencoded' -d "username=admin&password=$ADMIN_PASSWORD" -o /dev/null
done
kill %1

exec "$@"
