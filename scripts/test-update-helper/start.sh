#!/bin/sh
# The container's main process: what an LXC's init would have brought up, then a wait.
mkdir -p /run/openrc
touch /run/openrc/softlevel
syslogd -O /var/log/messages
rc-service testnet start
exec sleep 2147483647
