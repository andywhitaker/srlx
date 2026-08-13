#!/bin/bash
set -e

pkill -f srlx-daemon.py || true
rm -f /etc/opt/srlinux/cli/plugins/srlx.py
