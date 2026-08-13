#!/bin/bash
set -e

chmod +x /opt/srlx/bin/srlx-daemon.py
chmod +x /opt/srlx/bin/get_vector.py

mkdir -p /etc/opt/srlinux/cli/plugins
ln -sf /opt/srlx/cli/srlx.py /etc/opt/srlinux/cli/plugins/srlx.py

rm -rf /etc/opt/srlinux/cli/plugins/__pycache__

# Automatically enable mTLS client authentication on SR Linux if clab-profile exists
sudo -n ip netns exec srbase-mgmt curl -k -s --cert /etc/opt/srlinux/tls/clab-profile.pem --key /etc/opt/srlinux/tls/clab-profile.key.pem -u admin:NokiaSrl1! -X POST https://127.0.0.1/jsonrpc -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "id": 1, "method": "cli", "params": {"commands": ["enter candidate", "set /system tls profile clab-profile trust-anchor ca.pem", "set /system tls profile clab-profile authenticate-client true", "commit stay"], "output-format": "text"}}' >/dev/null 2>&1 || true

# Reload appmgr so SR Linux registers srlx.yml and srlx.yang
sudo -n ip netns exec srbase-mgmt curl -k -s --cert /etc/opt/srlinux/tls/clab-profile.pem --key /etc/opt/srlinux/tls/clab-profile.key.pem -u admin:NokiaSrl1! -X POST https://127.0.0.1/jsonrpc -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "id": 1, "method": "cli", "params": {"commands": ["tools system app-management application app_mgr reload"], "output-format": "text"}}' >/dev/null 2>&1 || true

if ! pgrep -f srlx-daemon.py > /dev/null; then
    /opt/srlx/bin/srlx-daemon.py > /dev/null 2>&1 &
fi
