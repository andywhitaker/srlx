#!/bin/bash
set -e

chmod +x /opt/srlx/bin/srlx-daemon.py
chmod +x /opt/srlx/bin/get_vector.py

mkdir -p /etc/opt/srlinux/cli/plugins
ln -sf /opt/srlx/cli/srlx.py /etc/opt/srlinux/cli/plugins/srlx.py

rm -rf /etc/opt/srlinux/cli/plugins/__pycache__

# Configure mTLS and reload appmgr via local JSON-RPC
/opt/srlinux/python/virtual-env/bin/python3 -c '
import os, json, subprocess

def get_auth():
    netrc_path = os.path.expanduser("~/.netrc")
    if os.path.exists(netrc_path):
        return ["--netrc-file", netrc_path]
    user = os.environ.get("SRLX_USER")
    password = os.environ.get("SRLX_PASS", os.environ.get("SRLX_PASSWORD"))
    if not user or not password:
        config_path = os.path.expanduser("~/.srlx.json")
        if os.path.exists(config_path):
            try:
                with open(config_path) as f:
                    data = json.load(f)
                    user = user or data.get("username")
                    password = password or data.get("password")
            except Exception:
                pass
    u = user or "admin"
    p = password or "NokiaSrl1!"
    return ["-u", f"{u}:{p}"]

def exec_local_jsonrpc(commands):
    auth_flags = get_auth()
    # Try HTTP 80
    cmd = ["sudo", "-n", "ip", "netns", "exec", "srbase-mgmt", "curl", "-s"] + auth_flags + [
        "-X", "POST", "http://127.0.0.1:80/jsonrpc",
        "-H", "Content-Type: application/json",
        "-d", json.dumps({"jsonrpc": "2.0", "id": 1, "method": "cli", "params": {"commands": commands, "output-format": "text"}})
    ]
    try:
        subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=5)
        return True
    except Exception:
        pass
    # Fallback HTTPS 443 -k
    cmd_ssl = ["sudo", "-n", "ip", "netns", "exec", "srbase-mgmt", "curl", "-k", "-s"] + auth_flags + [
        "-X", "POST", "https://127.0.0.1:443/jsonrpc",
        "-H", "Content-Type: application/json",
        "-d", json.dumps({"jsonrpc": "2.0", "id": 1, "method": "cli", "params": {"commands": commands, "output-format": "text"}})
    ]
    try:
        subprocess.check_output(cmd_ssl, stderr=subprocess.DEVNULL, timeout=5)
        return True
    except Exception:
        return False

# 1. Detect CA and Profile to configure trust-anchor if present
ca_file = os.environ.get("SRLX_CA_CERT")
if not ca_file or not os.path.exists(ca_file):
    if os.path.exists("/etc/opt/srlinux/tls/ca.pem") and os.path.getsize("/etc/opt/srlinux/tls/ca.pem") > 0:
        ca_file = "/etc/opt/srlinux/tls/ca.pem"

profile_name = None
for prof in ["clab-profile", "__default__"]:
    if os.path.exists(f"/etc/opt/srlinux/tls/{prof}.pem"):
        profile_name = prof
        break

if ca_file and profile_name:
    try:
        ca_pem = open(ca_file).read().strip()
        cmds = [
            "enter candidate",
            f"set /system tls profile {profile_name} trust-anchor \"{ca_pem}\"",
            f"set /system tls profile {profile_name} authenticate-client true",
            "commit stay"
        ]
        if exec_local_jsonrpc(cmds):
            subprocess.run(["pkill", "-f", "json_rpc_server_main"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

# 2. Reload appmgr so SR Linux registers srlx.yml and srlx.yang
exec_local_jsonrpc(["tools system app-management application app_mgr reload"])
' || true

if ! pgrep -f srlx-daemon.py > /dev/null; then
    /opt/srlx/bin/srlx-daemon.py > /dev/null 2>&1 &
fi
