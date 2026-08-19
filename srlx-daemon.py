#!/usr/bin/env /opt/srlinux/python/virtual-env/bin/python3
"""
SRLX Daemon — Real-time SR Linux Topology Push Gossip & Multi-Node Coordination Daemon.

Key Architectural Principles:
1. Zero Polling: 100% reactive push-based gossip cascades triggered immediately on NDK topology events.
2. Pure Hop-by-Hop Push Gossip: Real-time peer-to-peer event push across direct LLDP adjacencies over 2-way mTLS (port 58080).
3. Zero Shell/Subprocess Execution: 100% in-process networking via ctypes.setns and Python sockets/ssl.
4. Native NDK Telemetry: Publishes discovered topology directly to SR Linux YANG state datastore (/srlx).
5. Dynamic Learning: Zero hardcoded topology or host assumptions; management addresses, VRFs/network instances,
   and certificate profiles learned dynamically.
"""

import base64
import ctypes
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# Add SDK protos path to sys.path if available
for p in [
    '/usr/lib/python3.13/dist-packages/sdk_protos',
    '/usr/lib/python3/dist-packages/sdk_protos',
    '/opt/srlinux/python/virtual-env/lib/python3.13/dist-packages/sdk_protos'
]:
    if os.path.exists(p) and p not in sys.path:
        sys.path.append(p)

try:
    import grpc
    import sdk_service_pb2 as sdk
    import sdk_service_pb2_grpc as sdk_grpc
    import lldp_service_pb2 as lldp
    import interface_service_pb2 as intf_pb
    import telemetry_service_pb2 as telem
    import telemetry_service_pb2_grpc as telem_grpc
    import sdk_common_pb2 as common
    NDK_AVAILABLE = True
except Exception:
    NDK_AVAILABLE = False

DAEMON_SOCKET_PATH = "/tmp/srlx-daemon.sock"
DEFAULT_GOSSIP_PORT = 58080
CLONE_NEWNET = 0x40000000

try:
    _LIBC = ctypes.CDLL("libc.so.6", use_errno=True)
    _SETNS = _LIBC.setns
    _SETNS.argtypes = [ctypes.c_int, ctypes.c_int]
    _SETNS.restype = ctypes.c_int
except Exception:
    _LIBC = None
    _SETNS = None


def switch_netns(netns_name="mgmt"):
    """
    Switches the network namespace of the calling thread using glibc setns.
    Operates strictly in-process with zero subprocess execution.
    """
    if not _SETNS:
        return False
    candidates = []
    if not netns_name or netns_name in ("default", "srbase", "srbase-default"):
        candidates = ["srbase", "default", "srbase-default"]
    elif netns_name.startswith("srbase-"):
        candidates = [netns_name, netns_name[7:]]
    else:
        candidates = [f"srbase-{netns_name}", netns_name]

    try:
        for base_dir in ["/var/run/netns", "/run/netns"]:
            for cand in candidates:
                cand_path = os.path.join(base_dir, cand)
                if os.path.exists(cand_path):
                    with open(cand_path, "r") as f:
                        return _SETNS(f.fileno(), CLONE_NEWNET) == 0
    except Exception:
        pass
    return False


def is_valid_ip(addr_str):
    """Validates whether a string is a valid IPv4 or IPv6 address (excluding loopback/unspecified)."""
    if not addr_str:
        return False
    try:
        clean = addr_str.split("/")[0].strip()
        ip = ipaddress.ip_address(clean)
        return not (ip.is_loopback or ip.is_unspecified)
    except ValueError:
        return False


def resolve_neighbor_ip(mgmt_addrs=None, name=None):
    """
    Tiered IP address resolution (IPv4 & IPv6 supported):
    1. Primary: Extract valid management IP advertised dynamically in LLDP TLVs.
    2. Secondary Fallback: Resolve hostname via /etc/hosts entries.
    3. Tertiary Fallback: Resolve hostname via local DNS / socket.gethostbyname().
    4. Final Fallback: Return hostname if unresolvable.
    """
    if mgmt_addrs:
        for addr in mgmt_addrs:
            if not addr:
                continue
            addr_str = str(addr).strip()
            clean_ip = addr_str.split("/")[0]
            if is_valid_ip(clean_ip):
                return clean_ip

    if name:
        name_str = str(name).strip()
        if is_valid_ip(name_str):
            return name_str

        # /etc/hosts resolution
        try:
            with open("/etc/hosts", "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        if is_valid_ip(ip) and name_str in parts[1:]:
                            return ip
        except Exception:
            pass

        # DNS resolution
        try:
            resolved = socket.gethostbyname(name_str)
            if is_valid_ip(resolved):
                return resolved
        except Exception:
            pass

        return name_str

    return "Unknown"


def get_auth_credentials():
    user = os.environ.get("SRLX_USER")
    password = os.environ.get("SRLX_PASS", os.environ.get("SRLX_PASSWORD"))

    if not user or not password:
        netrc_path = os.path.expanduser("~/.netrc")
        if os.path.exists(netrc_path):
            try:
                import netrc
                n = netrc.netrc(netrc_path)
                auth = n.authenticators("default") or next(iter(n.hosts.values()), None)
                if auth:
                    user = user or auth[0]
                    password = password or auth[2]
            except Exception:
                pass

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

    user = user or "admin"
    password = password or "NokiaSrl1!"
    return user, password


def get_auth_headers():
    user, password = get_auth_credentials()
    b64 = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("utf-8")
    return {
        "Content-Type": "application/json",
        "Authorization": f"Basic {b64}"
    }


def get_gossip_port():
    """Dynamically retrieves gossip listener port with environment and config overrides."""
    port_env = os.environ.get("SRLX_GOSSIP_PORT")
    if port_env and port_env.isdigit():
        return int(port_env)
    config_path = os.path.expanduser("~/.srlx.json")
    if os.path.exists(config_path):
        try:
            with open(config_path) as f:
                data = json.load(f)
                if "gossip_port" in data:
                    return int(data["gossip_port"])
        except Exception:
            pass
    return DEFAULT_GOSSIP_PORT


def resolve_tls_certificates():
    config_data = {}
    config_path = os.path.expanduser("~/.srlx.json")
    if os.path.exists(config_path):
        try:
            with open(config_path) as f:
                config_data = json.load(f)
        except Exception:
            pass

    ca_path = os.environ.get("SRLX_CA_CERT") or config_data.get("ca_cert") or config_data.get("ca_file")
    if not ca_path or not os.path.exists(ca_path):
        for candidate in [
            "/etc/opt/srlinux/tls/ca.pem",
            "/etc/opt/srlinux/tls/ca/ca.pem",
            "/etc/opt/srlinux/tls/clab-profile.ca.pem"
        ]:
            if os.path.exists(candidate) and os.path.getsize(candidate) > 0:
                ca_path = candidate
                break

    client_cert = os.environ.get("SRLX_CLIENT_CERT") or config_data.get("client_cert")
    client_key = os.environ.get("SRLX_CLIENT_KEY") or config_data.get("client_key")
    profile_name = "Custom" if client_cert else None

    if not (client_cert and client_key and os.path.exists(client_cert) and os.path.exists(client_key)):
        tls_dir = "/etc/opt/srlinux/tls"
        if os.path.exists(tls_dir):
            for prof in ["clab-profile", "__default__", "default-server-profile"]:
                c_cand = os.path.join(tls_dir, f"{prof}.pem")
                for k_ext in [".key.pem", ".key"]:
                    k_cand = os.path.join(tls_dir, f"{prof}{k_ext}")
                    if os.path.exists(c_cand) and os.path.exists(k_cand):
                        client_cert, client_key, profile_name = c_cand, k_cand, prof
                        break
                if client_cert:
                    break

            if not client_cert:
                try:
                    for fname in sorted(os.listdir(tls_dir)):
                        if fname.endswith(".pem") and not fname.endswith(".key.pem") and not fname.endswith(".ca.pem") and fname != "ca.pem":
                            base = fname[:-4]
                            for k_ext in [".key.pem", ".key"]:
                                k_cand = os.path.join(tls_dir, f"{base}{k_ext}")
                                c_cand = os.path.join(tls_dir, fname)
                                if os.path.exists(k_cand) and os.path.exists(c_cand):
                                    client_cert, client_key, profile_name = c_cand, k_cand, base
                                    break
                            if client_cert:
                                break
                except Exception:
                    pass

    return {
        "ca_cert": ca_path if (ca_path and os.path.exists(ca_path)) else None,
        "client_cert": client_cert if (client_cert and os.path.exists(client_cert)) else None,
        "client_key": client_key if (client_key and os.path.exists(client_key)) else None,
        "profile_name": profile_name or "System"
    }


def create_tls_server_context():
    """Creates a server-side SSLContext enforcing mutual TLS (mTLS) with root CA verification."""
    tls_info = resolve_tls_certificates()
    ca_file = tls_info.get("ca_cert")
    cert_file = tls_info.get("client_cert")
    key_file = tls_info.get("client_key")
    if not (ca_file and cert_file and key_file):
        return None
    try:
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=ca_file)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
        return ctx
    except Exception:
        return None


def create_tls_client_context():
    """Creates a client-side SSLContext enforcing mutual TLS (mTLS) with root CA verification."""
    tls_info = resolve_tls_certificates()
    ca_file = tls_info.get("ca_cert")
    cert_file = tls_info.get("client_cert")
    key_file = tls_info.get("client_key")
    if not (ca_file and cert_file and key_file):
        return None
    try:
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_file)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
        return ctx
    except Exception:
        return None


def query_local_state_once(path, netns="mgmt"):
    """
    Performs a one-time local datastore state read strictly in-process using JSON-RPC method 'get' (never 'cli').
    Only used during daemon initialization and context refresh for local node bootstrap.
    """
    switch_netns(netns)
    body = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "get",
        "params": {
            "commands": [{"path": path, "datastore": "state"}]
        }
    }).encode("utf-8")

    auth_headers = get_auth_headers()

    # Try local HTTP 127.0.0.1:80
    try:
        req = urllib.request.Request("http://127.0.0.1:80/jsonrpc", data=body, headers=auth_headers)
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if "result" in data and data["result"]:
                return data["result"][0]
    except Exception:
        pass

    # Try local HTTPS 127.0.0.1:443
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req_ssl = urllib.request.Request("https://127.0.0.1:443/jsonrpc", data=body, headers=auth_headers)
        with urllib.request.urlopen(req_ssl, context=ctx, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if "result" in data and data["result"]:
                return data["result"][0]
    except Exception:
        pass

    return None


def discover_network_topology_context(mgmt_netns_hint=None):
    """
    Dynamically discovers active network instances, the management network instance (where mgmt0 resides),
    and maps all interfaces/subinterfaces to their corresponding network instances.
    """
    mgmt_netns = mgmt_netns_hint or "mgmt"
    iface_to_netns = {}
    all_netns = set()

    # Try reading /network-instance from candidate netns (mgmt, default, etc.)
    res = None
    for cand in [mgmt_netns, "mgmt", "default", "srbase-mgmt", "srbase"]:
        try:
            res = query_local_state_once("/network-instance", netns=cand)
            if res and isinstance(res, dict):
                break
        except Exception:
            pass

    found_mgmt_from_iface = None
    if res and isinstance(res, dict):
        netns_list = res.get("srl_nokia-network-instance:network-instance", res.get("network-instance", []))
        if isinstance(netns_list, list):
            for ni in netns_list:
                ni_name = ni.get("name")
                if not ni_name:
                    continue
                all_netns.add(ni_name)
                for iface in ni.get("interface", []):
                    if_name = iface.get("name", "")
                    if if_name:
                        base_name = if_name.split(".")[0]
                        iface_to_netns[if_name] = ni_name
                        iface_to_netns[base_name] = ni_name
                        if base_name == "mgmt0" or if_name.startswith("mgmt0"):
                            found_mgmt_from_iface = ni_name

    # Also discover active netns from filesystem (/var/run/netns, /run/netns)
    for base_dir in ["/var/run/netns", "/run/netns"]:
        if os.path.exists(base_dir):
            try:
                for entry in os.listdir(base_dir):
                    if entry.startswith("srbase-"):
                        all_netns.add(entry[7:])
                    elif entry == "srbase":
                        all_netns.add("default")
                    elif not entry.startswith("."):
                        all_netns.add(entry)
            except Exception:
                pass

    if found_mgmt_from_iface:
        mgmt_netns = found_mgmt_from_iface
    elif "mgmt" in all_netns:
        mgmt_netns = "mgmt"
    elif "management" in all_netns:
        mgmt_netns = "management"
    elif "default" in all_netns:
        mgmt_netns = "default"
    else:
        mgmt_netns = "mgmt"

    all_netns.add(mgmt_netns)
    all_netns.add("default")

    return mgmt_netns, iface_to_netns, all_netns


def ensure_cpm_filter_rules(mgmt_netns="mgmt"):
    """
    Ensures SR Linux CPM ACL filter permits inbound and outbound traffic on gossip port.
    Inspects existing entries dynamically to avoid overwriting sequence IDs.
    Uses local JSON-RPC method 'set' in-process.
    """
    port = get_gossip_port()
    switch_netns(mgmt_netns)
    auth_headers = get_auth_headers()

    # 1. Query existing CPM filter configuration/state
    existing_cpm = query_local_state_once("/acl/acl-filter[name=cpm]", netns=mgmt_netns)
    if not existing_cpm:
        # If CPM filter is not configured on this switch, nothing to update
        return True

    # Check if port rule already exists
    entries_v4 = []
    entries_v6 = []
    filter_list = existing_cpm if isinstance(existing_cpm, list) else [existing_cpm]
    for f in filter_list:
        f_type = f.get("type", "")
        for e in f.get("entry", []):
            seq = e.get("sequence-id")
            match = e.get("match", {})
            trans = match.get("transport", {})
            dst_p = trans.get("destination-port", {}).get("value")
            src_p = trans.get("source-port", {}).get("value")
            if dst_p == port or src_p == port:
                return True
            if "ipv4" in f_type and seq is not None:
                try:
                    entries_v4.append(int(seq))
                except Exception:
                    pass
            elif "ipv6" in f_type and seq is not None:
                try:
                    entries_v6.append(int(seq))
                except Exception:
                    pass

    def find_two_free_seqs(used_seqs):
        cand1 = 360
        while cand1 in used_seqs:
            cand1 += 1
        cand2 = cand1 + 1
        while cand2 in used_seqs:
            cand2 += 1
        return cand1, cand2

    seq_v4_in, seq_v4_out = find_two_free_seqs(set(entries_v4))
    seq_v6_in, seq_v6_out = find_two_free_seqs(set(entries_v6))

    body = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "set",
        "params": {
            "commands": [
                {
                    "action": "update",
                    "path": f"/acl/acl-filter[name=cpm][type=ipv4]/entry[sequence-id={seq_v4_in}]",
                    "value": {
                        "description": f"Accept incoming SRLX Gossip destination-port {port}",
                        "match": {
                            "ipv4": {"protocol": 6},
                            "transport": {"destination-port": {"operator": "eq", "value": port}}
                        },
                        "action": {"accept": {}}
                    }
                },
                {
                    "action": "update",
                    "path": f"/acl/acl-filter[name=cpm][type=ipv4]/entry[sequence-id={seq_v4_out}]",
                    "value": {
                        "description": f"Accept incoming SRLX Gossip replies source-port {port}",
                        "match": {
                            "ipv4": {"protocol": 6},
                            "transport": {"source-port": {"operator": "eq", "value": port}}
                        },
                        "action": {"accept": {}}
                    }
                },
                {
                    "action": "update",
                    "path": f"/acl/acl-filter[name=cpm][type=ipv6]/entry[sequence-id={seq_v6_in}]",
                    "value": {
                        "description": f"Accept incoming SRLX Gossip destination-port {port}",
                        "match": {
                            "ipv6": {"next-header": 6},
                            "transport": {"destination-port": {"operator": "eq", "value": port}}
                        },
                        "action": {"accept": {}}
                    }
                },
                {
                    "action": "update",
                    "path": f"/acl/acl-filter[name=cpm][type=ipv6]/entry[sequence-id={seq_v6_out}]",
                    "value": {
                        "description": f"Accept incoming SRLX Gossip replies source-port {port}",
                        "match": {
                            "ipv6": {"next-header": 6},
                            "transport": {"source-port": {"operator": "eq", "value": port}}
                        },
                        "action": {"accept": {}}
                    }
                }
            ]
        }
    }).encode("utf-8")

    for target_url in ["http://127.0.0.1:80/jsonrpc", "https://127.0.0.1:443/jsonrpc"]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(target_url, data=body, headers=auth_headers)
            with urllib.request.urlopen(req, context=ctx if target_url.startswith("https") else None, timeout=3) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if "result" in data:
                    return True
        except Exception:
            pass
    return False


def get_local_hostname(mgmt_netns="mgmt"):
    """Retrieves switch hostname via local state datastore or socket."""
    res = query_local_state_once("/system/name", netns=mgmt_netns)
    if res and isinstance(res, dict) and "host-name" in res:
        return res["host-name"]
    return socket.gethostname()


def get_local_management_ip(local_hostname, mgmt_netns="mgmt"):
    """
    Dynamically discovers the local switch management IPv4/IPv6 address.
    Checks LLDP management-address config/state first, then management network-instance, then interfaces, then hostname resolution.
    """
    # 1. Check system LLDP configured management-address
    try:
        res = query_local_state_once("/system/lldp/management-address", netns=mgmt_netns)
        if res and isinstance(res, dict) and "management-address" in res:
            for item in res.get("management-address", []):
                subif = item.get("subinterface", "")
                if subif:
                    parts = subif.split(".")
                    if_name = parts[0]
                    sub_idx = parts[1] if len(parts) > 1 else "0"
                    ip_res = query_local_state_once(f"/interface[name={if_name}]/subinterface[index={sub_idx}]/ipv4/address", netns=mgmt_netns)
                    if ip_res and isinstance(ip_res, dict) and "address" in ip_res:
                        for addr_obj in ip_res["address"]:
                            ip = addr_obj.get("ip-prefix", "").split("/")[0]
                            if is_valid_ip(ip):
                                return ip
    except Exception:
        pass

    # 2. Check discovered mgmt network instance interfaces
    for cand_netns in [mgmt_netns, "mgmt", "management", "default"]:
        try:
            res = query_local_state_once(f"/network-instance[name={cand_netns}]/interface", netns=cand_netns)
            if res and isinstance(res, dict) and "interface" in res:
                for iface in res["interface"]:
                    if_name = iface.get("name", "")
                    if if_name:
                        parts = if_name.split(".")
                        b_name = parts[0]
                        s_idx = parts[1] if len(parts) > 1 else "0"
                        ip_res = query_local_state_once(f"/interface[name={b_name}]/subinterface[index={s_idx}]/ipv4/address", netns=cand_netns)
                        if ip_res and isinstance(ip_res, dict) and "address" in ip_res:
                            for addr_obj in ip_res["address"]:
                                ip = addr_obj.get("ip-prefix", "").split("/")[0]
                                if is_valid_ip(ip):
                                    return ip
        except Exception:
            pass

    # 3. Check /interface mgmt0 or system0
    for cand_if in ["mgmt0", "system0"]:
        for cand_netns in [mgmt_netns, "mgmt", "default"]:
            try:
                ip_res = query_local_state_once(f"/interface[name={cand_if}]/subinterface[index=0]/ipv4/address", netns=cand_netns)
                if ip_res and isinstance(ip_res, dict) and "address" in ip_res:
                    for addr_obj in ip_res["address"]:
                        ip = addr_obj.get("ip-prefix", "").split("/")[0]
                        if is_valid_ip(ip):
                            return ip
            except Exception:
                pass

    # 4. Fallback to DNS / /etc/hosts dynamic resolution
    return resolve_neighbor_ip(None, local_hostname)


class TopologyGraph:
    """Thread-safe topology graph tracking global fabric adjacencies and multi-hop gossip state."""

    def __init__(self, local_hostname, local_ip, mgmt_netns="mgmt"):
        self.local_hostname = local_hostname
        self.local_ip = local_ip
        self.mgmt_netns = mgmt_netns
        self.lock = threading.Lock()
        self.nodes = {}
        self.validated_nodes = set()
        self._init_local_node()

    def _init_local_node(self):
        with self.lock:
            self.nodes[self.local_hostname] = {
                "mgmt_addrs": [self.local_ip],
                "netns": self.mgmt_netns,
                "status": "Local",
                "learned_via": "Local",
                "last_updated": time.time(),
                "is_direct_lldp": False,
                "direct_neighbors": set()
            }
            self.validated_nodes.add(self.local_hostname)

    def update_single_direct_lldp(self, sys_name, resolved_ip, local_port, netns="mgmt"):
        if not sys_name or sys_name == self.local_hostname:
            return False
        now = time.time()
        with self.lock:
            clean_addrs = [resolved_ip]
            if sys_name not in self.nodes:
                self.nodes[sys_name] = {
                    "mgmt_addrs": clean_addrs,
                    "netns": netns,
                    "status": "Direct mTLS OK",
                    "learned_via": "Direct",
                    "last_updated": now,
                    "is_direct_lldp": True,
                    "port": local_port,
                    "direct_neighbors": {self.local_hostname}
                }
                self.validated_nodes.add(sys_name)
                self.nodes[self.local_hostname]["direct_neighbors"].add(sys_name)
                return True
            else:
                prev_addrs = self.nodes[sys_name].get("mgmt_addrs", [])
                was_direct = self.nodes[sys_name].get("is_direct_lldp", False)
                self.nodes[sys_name]["mgmt_addrs"] = clean_addrs
                self.nodes[sys_name]["is_direct_lldp"] = True
                self.nodes[sys_name]["port"] = local_port
                self.nodes[sys_name]["netns"] = netns
                self.nodes[sys_name]["last_updated"] = now
                self.nodes[sys_name]["status"] = "Direct mTLS OK"
                self.nodes[sys_name]["learned_via"] = "Direct"
                self.nodes[sys_name].setdefault("direct_neighbors", set()).add(self.local_hostname)
                self.nodes[self.local_hostname]["direct_neighbors"].add(sys_name)
                self.validated_nodes.add(sys_name)
                return (not was_direct) or (prev_addrs != clean_addrs)

    def remove_direct_lldp(self, sys_name):
        """
        Updates reachability status when direct LLDP stops advertising,
        without deleting the device from the state table (preserves manual clear behavior).
        """
        if not sys_name or sys_name == self.local_hostname:
            return False
        now = time.time()
        with self.lock:
            if sys_name in self.nodes:
                self.nodes[sys_name]["is_direct_lldp"] = False
                self.nodes[sys_name].setdefault("direct_neighbors", set()).discard(self.local_hostname)
                self.nodes[self.local_hostname]["direct_neighbors"].discard(sys_name)
                self.nodes[sys_name]["last_updated"] = now
                if self.nodes[sys_name]["direct_neighbors"]:
                    self.nodes[sys_name]["status"] = "Mesh Reachable"
                    self.nodes[sys_name]["learned_via"] = "Mesh"
                else:
                    self.nodes[sys_name]["status"] = "Unreachable"
                    self.nodes[sys_name]["learned_via"] = "Direct (Down)"
                return True
            return False

    def merge_peer_vector(self, peer_name, peer_nodes):
        """
        Merges a topology vector pushed in real-time by a direct peer over mTLS.
        peer_nodes can be a dict of nodes or list of node objects.
        """
        now = time.time()
        has_changes = False
        with self.lock:
            items = []
            if isinstance(peer_nodes, dict):
                for k, v in peer_nodes.items():
                    item = dict(v)
                    item.setdefault("name", k)
                    items.append(item)
            elif isinstance(peer_nodes, list):
                items = peer_nodes

            for item in items:
                dev_name = item.get("name")
                if not dev_name:
                    continue

                raw_mgmt = item.get("mgmt_addrs") or [item.get("mgmt-address")]
                mgmt_ip = resolve_neighbor_ip(raw_mgmt, dev_name)
                netns = item.get("netns", self.mgmt_netns)
                r_status = item.get("status", "mTLS OK")
                r_direct = set(item.get("direct_reporters") or item.get("direct-reporters") or [])

                if dev_name not in self.nodes:
                    has_changes = True
                    self.nodes[dev_name] = {
                        "mgmt_addrs": [mgmt_ip],
                        "netns": netns,
                        "status": "mTLS OK" if r_status != "Unreachable" else "Unreachable",
                        "learned_via": "Mesh",
                        "last_updated": now,
                        "is_direct_lldp": False,
                        "direct_neighbors": set()
                    }
                    if r_status != "Unreachable":
                        self.validated_nodes.add(dev_name)
                else:
                    if mgmt_ip and is_valid_ip(mgmt_ip) and self.nodes[dev_name]["mgmt_addrs"] != [mgmt_ip]:
                        self.nodes[dev_name]["mgmt_addrs"] = [mgmt_ip]
                        has_changes = True

                cur_d = self.nodes[dev_name].setdefault("direct_neighbors", set())
                for neighbor in r_direct:
                    if neighbor not in cur_d:
                        cur_d.add(neighbor)
                        has_changes = True
                    if neighbor not in self.nodes:
                        has_changes = True
                        self.nodes[neighbor] = {
                            "mgmt_addrs": [resolve_neighbor_ip(None, neighbor)],
                            "netns": self.mgmt_netns,
                            "status": "mTLS OK",
                            "learned_via": "Mesh",
                            "last_updated": now,
                            "is_direct_lldp": False,
                            "direct_neighbors": {dev_name}
                        }
                        self.validated_nodes.add(neighbor)
                    else:
                        if dev_name not in self.nodes[neighbor].setdefault("direct_neighbors", set()):
                            self.nodes[neighbor]["direct_neighbors"].add(dev_name)
                            has_changes = True

                if dev_name == self.local_hostname:
                    self.nodes[dev_name]["learned_via"] = "Local"
                    self.nodes[dev_name]["status"] = "Local"
                elif self.nodes[dev_name].get("is_direct_lldp"):
                    self.nodes[dev_name]["learned_via"] = "Direct"
                    self.nodes[dev_name]["status"] = "Direct mTLS OK"
                else:
                    self.nodes[dev_name]["learned_via"] = "Mesh"
                    if not self.nodes[dev_name].get("direct_neighbors") and r_status == "Unreachable":
                        self.nodes[dev_name]["status"] = "Unreachable"
                    else:
                        self.nodes[dev_name]["status"] = "mTLS OK" if r_status != "Unreachable" else "Unreachable"

                self.nodes[dev_name]["last_updated"] = now
        return has_changes

    def get_direct_lldp_neighbors(self):
        with self.lock:
            directs = []
            for name, data in self.nodes.items():
                if name != self.local_hostname and data.get("is_direct_lldp", False):
                    mgmt_addrs = data.get("mgmt_addrs", [])
                    host = mgmt_addrs[0] if mgmt_addrs else name
                    netns = data.get("netns", self.mgmt_netns)
                    directs.append((name, host, netns))
            return directs

    def clear_device(self, dev_name):
        with self.lock:
            self.validated_nodes.discard(dev_name)
            if dev_name in self.nodes and dev_name != self.local_hostname:
                del self.nodes[dev_name]
                return True
            return False

    def clear_all(self):
        with self.lock:
            self.validated_nodes = {self.local_hostname}
            keys = [k for k in self.nodes.keys() if k != self.local_hostname]
            for k in keys:
                del self.nodes[k]

    def export_vector(self):
        with self.lock:
            all_nodes = set(self.nodes.keys())
            nodes_export = {}
            for dev_name, data in self.nodes.items():
                d_reps = sorted([y for y in data.get("direct_neighbors", set()) if y != dev_name and y in all_nodes])
                m_reps = sorted([m for m in all_nodes if m != dev_name and m not in d_reps])

                nodes_export[dev_name] = {
                    "mgmt_addrs": data["mgmt_addrs"],
                    "netns": data.get("netns", self.mgmt_netns),
                    "direct_reporters": d_reps,
                    "mesh_reporters": m_reps,
                    "learned_via": data.get("learned_via", "Mesh"),
                    "status": data.get("status", "mTLS OK"),
                    "last_updated": data.get("last_updated", time.time())
                }

            return {
                "protocol": "srlx-gossip/v1",
                "origin_node": self.local_hostname,
                "timestamp": time.time(),
                "nodes": nodes_export
            }


class SrlNdkClient:
    """
    SR Linux Native NDK gRPC Event Streaming Client.
    Subscribes to real-time LLDP neighbor events and interface notifications.
    Publishes discovered topology state into the native SR Linux YANG datastore (/srlx).
    """

    def __init__(self, daemon):
        self.daemon = daemon
        self.channel = None
        self.sdk_stub = None
        self.notif_stub = None
        self.telem_stub = None
        self.app_id = 0
        self.stream_id = 0
        self.running = True

    def start(self):
        if not NDK_AVAILABLE:
            return False

        t_worker = threading.Thread(target=self._run_ndk_lifecycle, daemon=True)
        t_worker.start()
        return True

    def publish_topology_state(self, vector):
        """Publishes the live topology graph into Native NDK Telemetry (/srlx/node)."""
        if not self.telem_stub or not self.running:
            return
        metadata = [('agent_name', 'srlx')]
        nodes = vector.get("nodes", {})
        for dev_name, ndata in nodes.items():
            try:
                t_req = telem.TelemetryUpdateRequest()
                info = t_req.states.add()
                info.key.js_path = f'.srlx.node{{.name=="{dev_name}"}}'

                mgmt_addrs = ndata.get("mgmt_addrs", [])
                mgmt_ip = mgmt_addrs[0] if mgmt_addrs else dev_name
                netns = ndata.get("netns", self.daemon.mgmt_netns)
                status = ndata.get("status", "mTLS OK")
                learned_via = ndata.get("learned_via", "Mesh")
                last_updated = str(int(ndata.get("last_updated", time.time())))
                direct_reporters = [{"value": r} for r in ndata.get("direct_reporters", []) if r != dev_name]
                mesh_reporters = [{"value": m} for m in ndata.get("mesh_reporters", []) if m != dev_name]

                content = {
                    "name": {"value": dev_name},
                    "mgmt_address": {"value": mgmt_ip},
                    "netns": {"value": netns},
                    "status": {"value": status},
                    "learned_via": {"value": learned_via},
                    "last_updated": {"value": last_updated}
                }
                if direct_reporters:
                    content["direct_reporters"] = direct_reporters
                if mesh_reporters:
                    content["mesh_reporters"] = mesh_reporters

                info.data.json_content = json.dumps(content)
                self.telem_stub.TelemetryAddOrUpdate(t_req, metadata=metadata)
            except Exception:
                pass

    def delete_node_state(self, dev_name):
        """Deletes a node from the SR Linux YANG state datastore (/srlx/node)."""
        if not self.telem_stub or not self.running:
            return
        try:
            metadata = [('agent_name', 'srlx')]
            t_del = telem.TelemetryDeleteRequest()
            info = t_del.keys.add()
            info.js_path = f'.srlx.node{{.name=="{dev_name}"}}'
            self.telem_stub.TelemetryDelete(t_del, metadata=metadata)
        except Exception:
            pass

    def _run_ndk_lifecycle(self):
        """Lifecycle loop with automatic reconnect and re-registration."""
        backoff = 1.0
        while self.running:
            try:
                socket_path = "unix:///opt/srlinux/var/run/sr_sdk_service_manager:50053"
                try:
                    self.channel = grpc.insecure_channel(socket_path)
                except Exception:
                    self.channel = grpc.insecure_channel("localhost:50053")

                self.sdk_stub = sdk_grpc.SdkMgrServiceStub(self.channel)
                self.notif_stub = sdk_grpc.SdkNotificationServiceStub(self.channel)
                self.telem_stub = telem_grpc.SdkMgrTelemetryServiceStub(self.channel)

                # Register Agent
                reg_req = sdk.AgentRegistrationRequest()
                reg_req.js_paths.append('.srlx')
                reg_req.js_paths.append('.srlx.node')
                reg_req.agent_liveliness = 30
                metadata = [('agent_name', 'srlx')]
                reg_resp = self.sdk_stub.AgentRegister(reg_req, metadata=metadata)
                if reg_resp.status != common.SDK_MGR_STATUS_SUCCESS:
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 10.0)
                    continue

                self.app_id = reg_resp.app_id
                backoff = 1.0

                # Publish initial state to NDK telemetry
                self.publish_topology_state(self.daemon.graph.export_vector())

                # Create Notification Stream
                stream_req = sdk.NotificationRegisterRequest()
                stream_req.op = sdk.NotificationRegisterRequest.OPERATION_CREATE
                stream_resp = self.sdk_stub.NotificationRegister(stream_req, metadata=metadata)
                if stream_resp.status != common.SDK_MGR_STATUS_SUCCESS:
                    time.sleep(2)
                    continue

                self.stream_id = stream_resp.stream_id

                # 1. Subscribe to LLDP Neighbor Notifications
                sub_lldp = sdk.NotificationRegisterRequest()
                sub_lldp.op = sdk.NotificationRegisterRequest.OPERATION_ADD_SUBSCRIPTION
                sub_lldp.stream_id = self.stream_id
                sub_lldp.subscription_id = 1
                sub_lldp.lldp_neighbor.SetInParent()
                self.sdk_stub.NotificationRegister(sub_lldp, metadata=metadata)

                # 2. Subscribe to Interface Notifications
                sub_intf = sdk.NotificationRegisterRequest()
                sub_intf.op = sdk.NotificationRegisterRequest.OPERATION_ADD_SUBSCRIPTION
                sub_intf.stream_id = self.stream_id
                sub_intf.subscription_id = 2
                sub_intf.interface.key.interface_name = "*"
                self.sdk_stub.NotificationRegister(sub_intf, metadata=metadata)

                # Start Keepalive loop
                threading.Thread(target=self._keepalive_loop, daemon=True).start()

                # Stream Notifications (event-driven)
                self._stream_notifications(metadata)

            except Exception:
                time.sleep(backoff)
                backoff = min(backoff * 2, 10.0)

    def _keepalive_loop(self):
        metadata = [('agent_name', 'srlx')]
        while self.running and self.sdk_stub:
            try:
                ka_req = sdk.KeepAliveRequest()
                self.sdk_stub.KeepAlive(ka_req, metadata=metadata)
            except Exception:
                break
            time.sleep(10)

    def _stream_notifications(self, metadata):
        stream_query = sdk.NotificationStreamRequest()
        stream_query.stream_id = self.stream_id
        for notif in self.notif_stub.NotificationStream(stream_query, metadata=metadata):
            for n in notif.notifications:
                # LLDP Neighbor Event (<1ms native push)
                if n.HasField('lldp_neighbor'):
                    ln = n.lldp_neighbor
                    op_type = "CREATE_OR_UPDATE" if ln.op == common.SDK_MGR_OPERATION_CREATE_OR_UPDATE else "DELETE"
                    iface_name = ln.key.interface_name
                    sys_name = getattr(ln.data, 'system_name', '')
                    sys_desc = getattr(ln.data, 'system_description', '')

                    mgmt_addrs = []
                    if hasattr(ln.data, 'management_address'):
                        val = getattr(ln.data, 'management_address')
                        if isinstance(val, (list, tuple)) or hasattr(val, '__iter__'):
                            for item in val:
                                if hasattr(item, 'address'):
                                    mgmt_addrs.append(str(item.address))
                                elif isinstance(item, str):
                                    mgmt_addrs.append(item)
                        elif isinstance(val, str) and val:
                            mgmt_addrs.append(val)
                        elif hasattr(val, 'address'):
                            mgmt_addrs.append(str(val.address))

                    self.daemon.on_ndk_lldp_event(iface_name, sys_name, sys_desc, op_type, mgmt_addrs)

                # Interface State Event
                if n.HasField('interface'):
                    inf = n.interface
                    if inf.op == common.SDK_MGR_OPERATION_CREATE_OR_UPDATE:
                        self.daemon.refresh_netns_mappings()

                # Config Sync / Acknowledgment
                if n.HasField('config'):
                    try:
                        self.sdk_stub.AcknowledgeConfig(sdk.AcknowledgeConfigRequest(), metadata=metadata)
                    except Exception:
                        pass


class SRLXDaemon:
    """Main SRLX background daemon orchestrating real-time mTLS push gossip topology cascades."""

    def __init__(self):
        self.mgmt_netns, self.interface_to_netns, self.discovered_netns = discover_network_topology_context()
        self.local_hostname = get_local_hostname(self.mgmt_netns)
        self.local_ip = get_local_management_ip(self.local_hostname, self.mgmt_netns)
        self.graph = TopologyGraph(self.local_hostname, self.local_ip, self.mgmt_netns)
        self.running = True
        self.ndk_client = SrlNdkClient(self)
        self.push_pool = ThreadPoolExecutor(max_workers=10, thread_name_prefix="srlx-push")
        self.conn_pool = ThreadPoolExecutor(max_workers=20, thread_name_prefix="srlx-conn")
        self.active_gossip_listeners = {}
        self.gossip_lock = threading.Lock()
        self.known_lldp_neighbors = {}

    def get_interface_netns(self, iface_name):
        """Dynamically resolves network instance / VRF for a given interface name."""
        if not iface_name:
            return self.mgmt_netns
        base = iface_name.split(".")[0]
        if iface_name in self.interface_to_netns:
            return self.interface_to_netns[iface_name]
        if base in self.interface_to_netns:
            return self.interface_to_netns[base]

        # Refresh map once if interface is unknown
        self.refresh_netns_mappings()
        if iface_name in self.interface_to_netns:
            return self.interface_to_netns[iface_name]
        if base in self.interface_to_netns:
            return self.interface_to_netns[base]
        if base.startswith("mgmt"):
            return self.mgmt_netns
        return "default"

    def refresh_netns_mappings(self):
        """Refreshes network instances, interface mappings, and ensures gossip listeners are running."""
        mgmt_netns, iface_to_netns, all_netns = discover_network_topology_context(self.mgmt_netns)
        self.mgmt_netns = mgmt_netns
        self.interface_to_netns = iface_to_netns
        self.discovered_netns.update(all_netns)
        self.ensure_gossip_listeners()

    def on_ndk_lldp_event(self, iface_name, sys_name, sys_desc, op_type, mgmt_addrs=None):
        """Real-time event callback fired by NDK notification stream (<1ms push)."""
        if not sys_name or sys_name == self.local_hostname:
            return

        resolved_ip = resolve_neighbor_ip(mgmt_addrs, sys_name)
        resolved_netns = self.get_interface_netns(iface_name)

        if op_type == "CREATE_OR_UPDATE":
            self.known_lldp_neighbors[iface_name] = {
                "sys_name": sys_name,
                "sys_desc": sys_desc,
                "mgmt_addrs": mgmt_addrs or []
            }
            changed = self.graph.update_single_direct_lldp(sys_name, resolved_ip, iface_name, netns=resolved_netns)
        else:
            self.known_lldp_neighbors.pop(iface_name, None)
            changed = self.graph.remove_direct_lldp(sys_name)

        # Publish live state to NDK telemetry datastore
        self.ndk_client.publish_topology_state(self.graph.export_vector())

        # Pure Event-Driven Push: Cascade topology changes to direct LLDP neighbors over mTLS
        if changed:
            self.push_vector_to_direct_neighbors(except_peer=None)

    def reseed_and_sync_neighbors(self):
        """
        Grabs all currently active LLDP neighbors (from state datastore & cache),
        re-populates the direct neighbors in the local graph, and triggers a full gossip push cascade.
        """
        # 1. Query state datastore to capture all current LLDP neighbors
        try:
            raw_lldp = query_local_state_once("/system/lldp/interface", netns=self.mgmt_netns)
            if raw_lldp and isinstance(raw_lldp, dict):
                iface_list = raw_lldp.get("srl_nokia-lldp:interface", raw_lldp.get("interface", []))
                for iface_obj in iface_list:
                    iface_name = iface_obj.get("name", "")
                    for neigh in iface_obj.get("neighbor", []):
                        s_name = neigh.get("system-name", "")
                        s_desc = neigh.get("system-description", "")
                        m_addrs = [m.get("address") for m in neigh.get("management-address", []) if m.get("address")]
                        if s_name and s_name != self.local_hostname:
                            self.known_lldp_neighbors[iface_name] = {
                                "sys_name": s_name,
                                "sys_desc": s_desc,
                                "mgmt_addrs": m_addrs
                            }
        except Exception:
            pass

        # 2. Re-populate all direct neighbors in graph
        for iface_name, n_info in list(self.known_lldp_neighbors.items()):
            sys_name = n_info.get("sys_name")
            mgmt_addrs = n_info.get("mgmt_addrs", [])
            if not sys_name or sys_name == self.local_hostname:
                continue
            resolved_ip = resolve_neighbor_ip(mgmt_addrs, sys_name)
            resolved_netns = self.get_interface_netns(iface_name)
            self.graph.update_single_direct_lldp(sys_name, resolved_ip, iface_name, netns=resolved_netns)

        # 3. Publish to NDK datastore
        self.ndk_client.publish_topology_state(self.graph.export_vector())

        # 4. Cascade gossip push to all direct peers
        self.push_vector_to_direct_neighbors(except_peer=None)

    def push_vector_to_peer(self, peer_name, peer_ip, netns="mgmt"):
        """
        Pushes the current topology vector to a direct peer over mTLS port 58080.
        Operates strictly in-process with zero subprocess or shell execution.
        """
        port = get_gossip_port()
        tls_ctx = create_tls_client_context()
        if not tls_ctx:
            return False

        payload = {
            "type": "gossip_push",
            "protocol": "srlx-gossip/v1",
            "sender": self.local_hostname,
            "timestamp": time.time(),
            "vector": self.graph.export_vector()
        }
        data_bytes = json.dumps(payload).encode("utf-8") + b"\n"

        netns_candidates = [netns]
        if self.mgmt_netns not in netns_candidates:
            netns_candidates.append(self.mgmt_netns)
        if "mgmt" not in netns_candidates:
            netns_candidates.append("mgmt")
        if "default" not in netns_candidates:
            netns_candidates.append("default")

        for cand_netns in netns_candidates:
            switch_netns(cand_netns)
            raw_sock = None
            tls_sock = None
            try:
                raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                raw_sock.settimeout(2.5)
                tls_sock = tls_ctx.wrap_socket(raw_sock, server_side=False)
                tls_sock.connect((peer_ip, port))
                tls_sock.sendall(data_bytes)

                resp_buf = b""
                while b"\n" not in resp_buf:
                    chunk = tls_sock.recv(65536)
                    if not chunk:
                        break
                    resp_buf += chunk

                tls_sock.close()
                if resp_buf:
                    resp_line = resp_buf.split(b"\n")[0].decode("utf-8").strip()
                    resp_data = json.loads(resp_line)
                    if resp_data.get("status") == "ok":
                        r_sender = resp_data.get("sender")
                        r_vec = resp_data.get("vector", {}).get("nodes", {})
                        if r_sender and r_vec:
                            self.on_gossip_push_received(r_sender, r_vec)
                        return True
            except Exception:
                if tls_sock:
                    try:
                        tls_sock.close()
                    except Exception:
                        pass
                elif raw_sock:
                    try:
                        raw_sock.close()
                    except Exception:
                        pass
        return False

    def push_vector_to_direct_neighbors(self, except_peer=None):
        """Pushes the latest topology vector to all direct LLDP neighbors in parallel using thread pool."""
        direct_neighbors = self.graph.get_direct_lldp_neighbors()
        for p_name, p_ip, p_netns in direct_neighbors:
            if p_name != except_peer and p_name != self.local_hostname:
                self.push_pool.submit(self.push_vector_to_peer, p_name, p_ip, p_netns)

    def on_gossip_push_received(self, sender, peer_nodes):
        """
        Real-time event callback fired when a direct peer pushes its topology vector over mTLS.
        """
        if not peer_nodes or sender == self.local_hostname:
            return

        changed = self.graph.merge_peer_vector(sender, peer_nodes)
        if changed:
            # Publish updated state to native SR Linux NDK datastore (/srlx/node)
            self.ndk_client.publish_topology_state(self.graph.export_vector())
            # Real-time Cascade: Flood updated vector to other direct LLDP neighbors (split-horizon)
            self.push_vector_to_direct_neighbors(except_peer=sender)

    def trigger_sync_with_direct_neighbors(self):
        """Pushes local topology vector to all direct LLDP neighbors."""
        self.push_vector_to_direct_neighbors(except_peer=None)

    def ensure_gossip_listeners(self):
        """Ensures an in-process gossip listener server is running for every discovered network namespace."""
        with self.gossip_lock:
            for netns in list(self.discovered_netns):
                if netns not in self.active_gossip_listeners:
                    self.active_gossip_listeners[netns] = True
                    t = threading.Thread(target=self.run_gossip_server, args=(netns,), daemon=True)
                    t.start()

    def run_gossip_server(self, netns_name="mgmt"):
        """
        In-process real-time push gossip TLS server running on port 58080 (or SRLX_GOSSIP_PORT).
        Enforces strict 2-way mTLS with CA verification. Zero subprocess / zero shell execution.
        """
        switch_netns(netns_name)
        port = get_gossip_port()

        server_raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server_raw.bind(("0.0.0.0", port))
            server_raw.listen(20)
        except Exception:
            try:
                server_raw.close()
            except Exception:
                pass
            return

        while self.running:
            try:
                raw_conn, client_addr = server_raw.accept()
                self.conn_pool.submit(self._handle_gossip_connection, raw_conn, client_addr)
            except Exception:
                time.sleep(0.1)

    def _handle_gossip_connection(self, raw_conn, client_addr):
        tls_conn = None
        try:
            tls_ctx = create_tls_server_context()
            if not tls_ctx:
                raw_conn.close()
                return

            tls_conn = tls_ctx.wrap_socket(raw_conn, server_side=True)
            tls_conn.settimeout(5.0)

            # Read JSON payload until delimiter newline
            buffer = b""
            while b"\n" not in buffer:
                chunk = tls_conn.recv(65536)
                if not chunk:
                    break
                buffer += chunk

            if buffer:
                line = buffer.split(b"\n")[0].decode("utf-8").strip()
                if line:
                    msg = json.loads(line)
                    if msg.get("type") == "gossip_push":
                        sender = msg.get("sender")
                        vector_data = msg.get("vector", {})
                        nodes_data = vector_data.get("nodes", {}) if isinstance(vector_data, dict) else {}
                        if sender and nodes_data:
                            self.on_gossip_push_received(sender, nodes_data)

                # Return our current vector in the mTLS response
                resp_payload = {
                    "status": "ok",
                    "sender": self.local_hostname,
                    "vector": self.graph.export_vector()
                }
                tls_conn.sendall(json.dumps(resp_payload).encode("utf-8") + b"\n")
        except Exception:
            pass
        finally:
            if tls_conn:
                try:
                    tls_conn.close()
                except Exception:
                    pass
            else:
                try:
                    raw_conn.close()
                except Exception:
                    pass

    def handle_unix_client(self, client_sock):
        """Handles local CLI plugin queries over UNIX domain socket."""
        try:
            raw_data = client_sock.recv(65536).decode().strip()
            if not raw_data:
                client_sock.close()
                return

            req = json.loads(raw_data)
            action = req.get("action")

            if action == "get_devices":
                vector = self.graph.export_vector()
                resp = {"status": "ok", "vector": vector}
            elif action == "trigger_sync":
                self.trigger_sync_with_direct_neighbors()
                resp = {"status": "ok", "message": "Real-time push triggered"}
            elif action == "clear_device":
                dev = req.get("device")
                ok = self.graph.clear_device(dev)
                if ok:
                    self.ndk_client.delete_node_state(dev)
                self.ndk_client.publish_topology_state(self.graph.export_vector())
                self.reseed_and_sync_neighbors()
                resp = {"status": "ok" if ok else "error", "message": f"Device {dev} cleared and topology re-synced" if ok else f"Device {dev} not found"}
            elif action == "clear_all":
                self.graph.clear_all()
                self.ndk_client.publish_topology_state(self.graph.export_vector())
                self.reseed_and_sync_neighbors()
                resp = {"status": "ok", "message": "All devices cleared and topology re-synced"}
            else:
                resp = {"status": "error", "message": f"Unknown action {action}"}

            client_sock.sendall(json.dumps(resp).encode() + b"\n")
        except Exception as e:
            try:
                client_sock.sendall(json.dumps({"status": "error", "message": str(e)}) + b"\n")
            except Exception:
                pass
        finally:
            client_sock.close()

    def run_unix_socket_server(self):
        """Runs UNIX domain socket listener in /tmp for local CLI plugins."""
        try:
            if os.path.exists(DAEMON_SOCKET_PATH):
                os.unlink(DAEMON_SOCKET_PATH)
        except Exception:
            pass

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(DAEMON_SOCKET_PATH)
        os.chmod(DAEMON_SOCKET_PATH, 0o666)
        server.listen(10)

        while self.running:
            try:
                conn, _ = server.accept()
                t = threading.Thread(target=self.handle_unix_client, args=(conn,))
                t.daemon = True
                t.start()
            except Exception:
                pass


def main():
    # Singleton check
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(DAEMON_SOCKET_PATH)
        s.sendall(json.dumps({"action": "get_devices"}).encode() + b"\n")
        resp = s.recv(1024)
        s.close()
        if resp:
            sys.exit(0)
    except Exception:
        pass

    daemon = SRLXDaemon()
    daemon.ndk_client.start()

    # Dynamically bind in-process mTLS gossip push servers across all active network instances
    daemon.ensure_gossip_listeners()

    # Bootstrap worker: Ensure CPM ACL rules are programmed and trigger initial push
    def _bootstrap_worker():
        for _ in range(30):
            if ensure_cpm_filter_rules(daemon.mgmt_netns):
                break
            time.sleep(1.5)
        time.sleep(0.5)
        daemon.reseed_and_sync_neighbors()

    threading.Thread(target=_bootstrap_worker, daemon=True).start()

    # Serve local UNIX socket for CLI plugins in main thread
    daemon.run_unix_socket_server()


if __name__ == "__main__":
    main()
