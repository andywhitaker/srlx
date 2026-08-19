#!/bin/bash
set -e

chmod +x /opt/srlx/bin/srlx-daemon.py

mkdir -p /etc/opt/srlinux/cli/plugins
ln -sf /opt/srlx/cli/srlx.py /etc/opt/srlinux/cli/plugins/srlx.py

rm -rf /etc/opt/srlinux/cli/plugins/__pycache__
rm -f /tmp/srlx-daemon.sock

# Clean up any previous daemon instances
pkill -f srlx-daemon.py || true

# Dynamic CPM filter configuration for SRLX gossip port 58080
/opt/srlinux/python/virtual-env/bin/python3 -c '
import urllib.request, json, base64, os, ssl, ctypes

CLONE_NEWNET = 0x40000000
try:
    _LIBC = ctypes.CDLL("libc.so.6", use_errno=True)
    _SETNS = _LIBC.setns
    _SETNS.argtypes = [ctypes.c_int, ctypes.c_int]
    _SETNS.restype = ctypes.c_int
except Exception:
    _SETNS = None

def switch_netns(netns_name="mgmt"):
    if not _SETNS:
        return False
    candidates = ["srbase-mgmt", "mgmt", "srbase", "default"]
    for base_dir in ["/var/run/netns", "/run/netns"]:
        for cand in candidates:
            cand_path = os.path.join(base_dir, cand)
            if os.path.exists(cand_path):
                try:
                    with open(cand_path, "r") as f:
                        if _SETNS(f.fileno(), CLONE_NEWNET) == 0:
                            return True
                except Exception:
                    pass
    return False

switch_netns("mgmt")

user = os.environ.get("SRLX_USER", "admin")
password = os.environ.get("SRLX_PASS", "NokiaSrl1!")
auth = base64.b64encode(f"{user}:{password}".encode()).decode()
headers = {"Content-Type": "application/json", "Authorization": f"Basic {auth}"}

port = 58080
port_env = os.environ.get("SRLX_GOSSIP_PORT")
if port_env and port_env.isdigit():
    port = int(port_env)

# Query existing CPM filter
get_body = json.dumps({
    "jsonrpc": "2.0", "id": 1, "method": "get",
    "params": {"commands": [{"path": "/acl/acl-filter[name=cpm]", "datastore": "state"}]}
}).encode()

existing_cpm = None
for url in ["http://127.0.0.1:80/jsonrpc", "https://127.0.0.1:443/jsonrpc"]:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, data=get_body, headers=headers)
        with urllib.request.urlopen(req, context=ctx if url.startswith("https") else None, timeout=3) as resp:
            data = json.loads(resp.read().decode())
            if "result" in data and data["result"]:
                existing_cpm = data["result"][0]
                break
    except Exception:
        pass

if existing_cpm:
    entries_v4 = []
    entries_v6 = []
    filter_list = existing_cpm if isinstance(existing_cpm, list) else [existing_cpm]
    already_present = False
    for f in filter_list:
        f_type = f.get("type", "")
        for e in f.get("entry", []):
            seq = e.get("sequence-id")
            match = e.get("match", {})
            trans = match.get("transport", {})
            dst_p = trans.get("destination-port", {}).get("value")
            src_p = trans.get("source-port", {}).get("value")
            if dst_p == port or src_p == port:
                already_present = True
            if "ipv4" in f_type and seq is not None:
                try: entries_v4.append(int(seq))
                except Exception: pass
            elif "ipv6" in f_type and seq is not None:
                try: entries_v6.append(int(seq))
                except Exception: pass

    if not already_present:
        def find_free(used):
            cand1 = 360
            while cand1 in used: cand1 += 1
            cand2 = cand1 + 1
            while cand2 in used: cand2 += 1
            return cand1, cand2

        s_v4_in, s_v4_out = find_free(set(entries_v4))
        s_v6_in, s_v6_out = find_free(set(entries_v6))

        set_body = json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "set",
            "params": {
                "commands": [
                    {
                        "action": "update",
                        "path": f"/acl/acl-filter[name=cpm][type=ipv4]/entry[sequence-id={s_v4_in}]",
                        "value": {
                            "description": f"Accept incoming SRLX Gossip destination-port {port}",
                            "match": {"ipv4": {"protocol": 6}, "transport": {"destination-port": {"operator": "eq", "value": port}}},
                            "action": {"accept": {}}
                        }
                    },
                    {
                        "action": "update",
                        "path": f"/acl/acl-filter[name=cpm][type=ipv4]/entry[sequence-id={s_v4_out}]",
                        "value": {
                            "description": f"Accept incoming SRLX Gossip replies source-port {port}",
                            "match": {"ipv4": {"protocol": 6}, "transport": {"source-port": {"operator": "eq", "value": port}}},
                            "action": {"accept": {}}
                        }
                    },
                    {
                        "action": "update",
                        "path": f"/acl/acl-filter[name=cpm][type=ipv6]/entry[sequence-id={s_v6_in}]",
                        "value": {
                            "description": f"Accept incoming SRLX Gossip destination-port {port}",
                            "match": {"ipv6": {"next-header": 6}, "transport": {"destination-port": {"operator": "eq", "value": port}}},
                            "action": {"accept": {}}
                        }
                    },
                    {
                        "action": "update",
                        "path": f"/acl/acl-filter[name=cpm][type=ipv6]/entry[sequence-id={s_v6_out}]",
                        "value": {
                            "description": f"Accept incoming SRLX Gossip replies source-port {port}",
                            "match": {"ipv6": {"next-header": 6}, "transport": {"source-port": {"operator": "eq", "value": port}}},
                            "action": {"accept": {}}
                        }
                    }
                ]
            }
        }).encode()

        for url in ["http://127.0.0.1:80/jsonrpc", "https://127.0.0.1:443/jsonrpc"]:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                req = urllib.request.Request(url, data=set_body, headers=headers)
                with urllib.request.urlopen(req, context=ctx if url.startswith("https") else None, timeout=3) as resp:
                    pass
                break
            except Exception:
                pass
' || true

# Reload app_mgr and restart srlx daemon under app_mgr supervision
if [ -x /opt/srlinux/bin/sr_cli ]; then
    /opt/srlinux/bin/sr_cli "tools system app-management application app_mgr reload" || true
    /opt/srlinux/bin/sr_cli "tools system app-management application srlx restart" || true
fi
