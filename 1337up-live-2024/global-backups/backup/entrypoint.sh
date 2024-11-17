#!/bin/sh
set -e

echo "$SSH_PUBLIC" > /home/admin/.ssh/authorized_keys
chown admin:admin /home/admin/.ssh/authorized_keys

exec "$@"
