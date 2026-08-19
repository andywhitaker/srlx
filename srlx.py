import base64
import ctypes
import ipaddress
import json
import os
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from srlinux.mgmt.cli.cli_plugin import CliPlugin
from srlinux.mgmt.cli.tools_plugin import ToolsPlugin
from srlinux.syntax import Syntax

try:
    from srlinux.schema.data_store import DataStore
    from srlinux.location import build_path
    DATASTORE_AVAILABLE = True
except Exception:
    DATASTORE_AVAILABLE = False

try:
    from srlinux.mgmt.cli.output_format import OutputFormat, OUTPUT_FORMAT_MODIFIABLE_COMMANDS
    if "srlx" not in OUTPUT_FORMAT_MODIFIABLE_COMMANDS:
        OUTPUT_FORMAT_MODIFIABLE_COMMANDS.append("srlx")
except Exception:
    class OutputFormat:
        text = "text"
        json = "json"
        yaml = "yaml"
        table = "table"
        xml = "xml"


def get_requested_output_format(output):
    if hasattr(output, "output_format"):
        fmt = output.output_format
        fmt_name = getattr(fmt, "name", str(fmt)).lower()
        if "json" in fmt_name:
            return "json"
        elif "yaml" in fmt_name:
            return "yaml"
        elif "table" in fmt_name:
            return "table"
        elif "xml" in fmt_name:
            return "xml"
    return "text"


def dump_simple_yaml(obj, indent_level=0):
    indent = "  " * indent_level
    if isinstance(obj, dict):
        lines = []
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                lines.append(f"{indent}{k}:")
                lines.append(dump_simple_yaml(v, indent_level + 1))
            else:
                lines.append(f"{indent}{k}: {v}")
        return "\n".join(lines)
    elif isinstance(obj, list):
        lines = []
        for item in obj:
            if isinstance(item, (dict, list)):
                lines.append(f"{indent}-")
                lines.append(dump_simple_yaml(item, indent_level + 1))
            else:
                lines.append(f"{indent}- {item}")
        return "\n".join(lines)
    else:
        return f"{indent}{obj}"


DAEMON_SOCKET_PATH = "/tmp/srlx-daemon.sock"
CLONE_NEWNET = 0x40000000

try:
    _LIBC = ctypes.CDLL("libc.so.6", use_errno=True)
    _SETNS = _LIBC.setns
    _SETNS.argtypes = [ctypes.c_int, ctypes.c_int]
    _SETNS.restype = ctypes.c_int
except Exception:
    _LIBC = None
    _SETNS = None

_CACHED_LOCAL_HOSTNAME = None


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


def natural_sort_key(name):
    return [int(c) if c.isdigit() else c.lower() for c in re.split(r"(\d+)", name)]


def query_daemon_socket(payload):
    """Queries local SRLX background daemon via UNIX domain socket."""
    if not os.path.exists(DAEMON_SOCKET_PATH):
        return None
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect(DAEMON_SOCKET_PATH)
        s.sendall(json.dumps(payload).encode() + b"\n")
        raw = s.recv(65536).decode().strip()
        s.close()
        return json.loads(raw)
    except Exception:
        return None


def parse_target_and_cmd_tokens(raw_tokens, known_devices=None):
    if known_devices is None:
        discovered = discover_srlinux_neighbors()
        known_devices = set(discovered.keys())

    dev_tokens = []
    cmd_tokens = []
    for t in raw_tokens:
        if not cmd_tokens and t in known_devices:
            dev_tokens.append(t)
        else:
            cmd_tokens.append(t)
    return dev_tokens, cmd_tokens


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


def query_local_state_once(paths, datastore="state", netns="mgmt"):
    """
    Executes a one-time in-process JSON-RPC query against local switch using method 'get' (never 'cli').
    Used only as a fallback if the daemon socket is unavailable.
    """
    switch_netns(netns)
    cmds = [{"path": p, "datastore": datastore} for p in paths]
    auth_headers = get_auth_headers()
    body = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "get",
        "params": {"commands": cmds}
    }).encode("utf-8")

    # 1. Local HTTP port 80 (in mgmt netns)
    try:
        req = urllib.request.Request("http://127.0.0.1:80/jsonrpc", data=body, headers=auth_headers)
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if "result" in data:
                return data["result"]
    except Exception:
        pass

    # 2. Local HTTPS port 443 (in mgmt netns)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req_ssl = urllib.request.Request("https://127.0.0.1:443/jsonrpc", data=body, headers=auth_headers)
        with urllib.request.urlopen(req_ssl, context=ctx, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if "result" in data:
                return data["result"]
    except Exception:
        pass

    return []


def discover_network_topology_context(mgmt_netns_hint=None):
    """
    Dynamically discovers active network instances, the management network instance (where mgmt0 resides),
    and maps all interfaces/subinterfaces to their corresponding network instances.
    """
    mgmt_netns = mgmt_netns_hint or "mgmt"
    iface_to_netns = {}
    all_netns = set()

    res = None
    for cand in [mgmt_netns, "mgmt", "default", "srbase-mgmt", "srbase"]:
        try:
            raw_res = query_local_state_once(["/network-instance"], netns=cand)
            if raw_res and len(raw_res) > 0 and isinstance(raw_res[0], dict):
                res = raw_res[0]
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


def get_local_hostname():
    global _CACHED_LOCAL_HOSTNAME
    if _CACHED_LOCAL_HOSTNAME:
        return _CACHED_LOCAL_HOSTNAME

    resp = query_daemon_socket({"action": "get_devices"})
    if resp and resp.get("status") == "ok":
        origin = resp.get("vector", {}).get("origin_node")
        if origin:
            _CACHED_LOCAL_HOSTNAME = origin
            return _CACHED_LOCAL_HOSTNAME

    try:
        results = query_local_state_once(["/system/name"])
        if results and isinstance(results[0], dict) and "host-name" in results[0]:
            _CACHED_LOCAL_HOSTNAME = results[0]["host-name"]
            return _CACHED_LOCAL_HOSTNAME
    except Exception:
        pass

    _CACHED_LOCAL_HOSTNAME = socket.gethostname()
    return _CACHED_LOCAL_HOSTNAME


def resolve_neighbor_ip(mgmt_addrs=None, name=None):
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

        try:
            resolved = socket.gethostbyname(name_str)
            if is_valid_ip(resolved):
                return resolved
        except Exception:
            pass

        return name_str

    return "Unknown"


def discover_srlinux_neighbors(state=None):
    """
    Discovers all fabric switches:
    Queries local daemon UNIX socket (/tmp/srlx-daemon.sock).
    Zero shell / zero subprocess calls.
    """
    resp = query_daemon_socket({"action": "get_devices"})
    if resp and resp.get("status") == "ok":
        vector = resp.get("vector", {})
        nodes = vector.get("nodes", {})
        if nodes:
            devices = {}
            for name, nd in nodes.items():
                devices[name] = {
                    "system_name": name,
                    "mgmt_addrs": nd.get("mgmt_addrs", [name]),
                    "netns": nd.get("netns", "mgmt"),
                    "direct_reporters": nd.get("direct_reporters", []),
                    "mesh_reporters": nd.get("mesh_reporters", []),
                    "learned_via": nd.get("learned_via", "Mesh"),
                    "status": nd.get("status", "mTLS OK")
                }
            return devices

    # Fallback if daemon socket is temporarily unavailable
    mgmt_netns, port_to_netns, _ = discover_network_topology_context()
    devices = {}
    local_name = get_local_hostname()
    if local_name:
        devices[local_name] = {
            "local_port": "local",
            "system_name": local_name,
            "chassis_id": "local",
            "system_description": "Local SR Linux Switch",
            "mgmt_addrs": [local_name],
            "netns": mgmt_netns,
            "is_local": True
        }

    try:
        results = query_local_state_once(["/network-instance", "/system/lldp/interface"], netns=mgmt_netns)
        netns_data = results[0] if len(results) > 0 else {}
        lldp_data = results[1] if len(results) > 1 else {}

        netns_list = netns_data.get("srl_nokia-network-instance:network-instance", netns_data.get("network-instance", []))
        for netns in netns_list:
            netns_name = netns.get("name")
            for iface in netns.get("interface", []):
                if_name = iface.get("name", "")
                base_name = if_name.split(".")[0]
                port_to_netns[if_name] = netns_name
                port_to_netns[base_name] = netns_name

        raw_neighbors = []
        for iface in lldp_data.get("interface", []):
            local_port = iface.get("name", "")
            for neigh in iface.get("neighbor", []):
                sys_desc = neigh.get("system-description", "")
                if "srlinux" in sys_desc.lower():
                    sys_name = neigh.get("system-name", "")
                    chassis_id = neigh.get("chassis-id", "")
                    mgmt_addrs = [m.get("address") for m in neigh.get("management-address", []) if m.get("address")]
                    resolved_ip = resolve_neighbor_ip(mgmt_addrs, sys_name)
                    netns = port_to_netns.get(local_port, mgmt_netns)
                    raw_neighbors.append({
                        "local_port": local_port,
                        "system_name": sys_name,
                        "chassis_id": chassis_id,
                        "system_description": sys_desc,
                        "mgmt_addrs": [resolved_ip],
                        "netns": netns,
                        "is_local": False
                    })

        grouped = {}
        for r in raw_neighbors:
            key = r["system_name"]
            grouped.setdefault(key, []).append(r)

        for name, entries in grouped.items():
            mgmt_entry = next((e for e in entries if e["local_port"].startswith("mgmt")), None)
            if mgmt_entry:
                selected = mgmt_entry
            else:
                selected = sorted(entries, key=lambda x: x["local_port"])[0]
            devices[name] = selected
    except Exception:
        pass

    return devices


def get_neighbor_choices(*args, **kwargs):
    discovered = discover_srlinux_neighbors()
    all_choices = sorted(list(discovered.keys()), key=natural_sort_key)
    typed_set = set()

    if len(args) >= 3 and args[2] is not None:
        try:
            raw_typed = args[2].get("srlx", "device")
            if not raw_typed:
                raw_typed = args[2].get("device")
            if isinstance(raw_typed, list):
                typed_set.update(raw_typed)
            elif isinstance(raw_typed, str) and raw_typed:
                typed_set.add(raw_typed)
        except Exception:
            pass

    return [choice for choice in all_choices if choice not in typed_set]


def extract_unnamed_argument_value(arguments, name, state=None):
    if arguments:
        if hasattr(arguments, "get"):
            try:
                val = arguments.get(name, name)
                if val:
                    return val[0] if isinstance(val, list) else str(val)
            except Exception:
                pass
            try:
                val = arguments.get(name)
                if val:
                    return val[0] if isinstance(val, list) else str(val)
            except Exception:
                pass
        curr = arguments
        while hasattr(curr, "parent") and curr.parent:
            curr = curr.parent
            if hasattr(curr, "get"):
                try:
                    val = curr.get(name, name)
                    if val:
                        return val[0] if isinstance(val, list) else str(val)
                except Exception:
                    pass
                try:
                    val = curr.get(name)
                    if val:
                        return val[0] if isinstance(val, list) else str(val)
                except Exception:
                    pass

    if state and hasattr(state, "line_commands"):
        try:
            line_str = str(state.line_commands)
            tokens = line_str.strip().split()
            if name in tokens:
                idx = tokens.index(name)
                if idx + 1 < len(tokens) and tokens[idx + 1] != "detail":
                    return tokens[idx + 1]
            elif "device" in tokens:
                idx = tokens.index("device")
                if idx + 1 < len(tokens) and tokens[idx + 1] != "detail":
                    return tokens[idx + 1]
        except Exception:
            pass
    return ""


def get_child_cmds(node, state):
    cmds = []
    if hasattr(node, "get_filtered_commands"):
        try:
            cmds.extend(node.get_filtered_commands(state))
        except Exception:
            pass
    if hasattr(node, "get_fixed_commands"):
        try:
            cmds.extend(node.get_fixed_commands())
        except Exception:
            pass
    return cmds


def get_dynamic_root_commands(state=None):
    root_cmds = set()
    if state:
        try:
            lp = state.create_line_parser(state)
            parsed_line = lp.parse("")
            cn = getattr(parsed_line.last_node, "node", None)
            if cn:
                for c in get_child_cmds(cn, state):
                    name = getattr(c, "name", "")
                    if name and name != "/":
                        root_cmds.add(name)
        except Exception:
            pass
    if not root_cmds:
        root_cmds = {"show", "tools", "info", "help", "environment", "monitor"}
    return sorted(list(root_cmds), key=natural_sort_key)


def get_srlx_unified_suggestions(*args, **kwargs):
    try:
        state = args[1] if len(args) >= 2 else None
        partial_word = args[3] if len(args) >= 4 else ""
        raw_line = args[4] if len(args) >= 5 else ""

        line_str = raw_line
        if state and hasattr(state, "line_commands"):
            real_line = str(state.line_commands)
            if real_line:
                line_str = real_line
                if raw_line.endswith(" ") and not line_str.endswith(" "):
                    line_str += " "

        discovered = discover_srlinux_neighbors(state)
        known_neighbors = set(discovered.keys())
        remaining_neighbors = sorted(list(known_neighbors), key=natural_sort_key)
        dynamic_root_commands = get_dynamic_root_commands(state)

        if not line_str or not line_str.startswith("srlx"):
            return remaining_neighbors + dynamic_root_commands

        tokens = line_str.split()
        raw_tokens = tokens[1:] if len(tokens) > 1 else []

        dev_tokens, cmd_tokens = parse_target_and_cmd_tokens(raw_tokens, known_neighbors)
        unused_neighbors = [n for n in remaining_neighbors if n not in dev_tokens]

        if not cmd_tokens:
            return unused_neighbors + dynamic_root_commands

        cmd_str = " ".join(cmd_tokens)
        if line_str.endswith(" "):
            cmd_str += " "

        if state:
            try:
                lp = state.create_line_parser(state)
                parsed_line = lp.parse(cmd_str)
                last_node_obj = parsed_line.last_node

                suggestions = set()
                cn = getattr(last_node_obj, "node", None)
                if cn:
                    for c in get_child_cmds(cn, state):
                        name = getattr(c, "name", "")
                        if name and name != "/":
                            suggestions.add(name)

                bound_args = set()
                all_args = getattr(last_node_obj, "all_arguments", None)
                if isinstance(all_args, dict):
                    bound_args = set(all_args.keys())
                elif hasattr(last_node_obj, "local_arguments") and isinstance(last_node_obj.local_arguments, dict):
                    bound_args = set(last_node_obj.local_arguments.keys())

                syntax_obj = getattr(last_node_obj, "syntax", None)
                syntax_args = getattr(syntax_obj, "arguments", []) if syntax_obj else []

                for arg in syntax_args:
                    arg_name = getattr(arg, "name", None)
                    if arg_name and arg_name in bound_args:
                        continue
                    if hasattr(arg, "get_values"):
                        vals = list(arg.get_values(state, last_node_obj, partial_word, cmd_str))
                        for v in vals:
                            if v:
                                suggestions.add(v)

                if suggestions:
                    return sorted(list(suggestions))
                else:
                    return []
            except Exception:
                pass

        return []
    except Exception:
        return get_dynamic_root_commands(state)


def _raw_exec_remote_cmd(host, command, target_netns="mgmt", output_format="text"):
    """
    Executes user-requested CLI commands on remote switches via JSON-RPC 'cli' method with strict mTLS authentication.
    Operates 100% in-process with zero subprocess or shell commands.
    """
    is_local = host in ("127.0.0.1", "localhost", "::1", get_local_hostname())
    auth_headers = get_auth_headers()
    tls_info = resolve_tls_certificates()

    body = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "cli",
        "params": {
            "commands": [command],
            "output-format": output_format
        }
    }).encode("utf-8")

    if is_local:
        switch_netns(target_netns)
        # Local switch execution
        try:
            req = urllib.request.Request("http://127.0.0.1:80/jsonrpc", data=body, headers=auth_headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if "result" in data and data["result"]:
                    obj = data["result"][0]
                    if output_format == "json":
                        return obj
                    return obj if isinstance(obj, str) else json.dumps(obj, indent=2)
        except Exception:
            pass

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req_ssl = urllib.request.Request("https://127.0.0.1:443/jsonrpc", data=body, headers=auth_headers)
            with urllib.request.urlopen(req_ssl, context=ctx, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if "result" in data and data["result"]:
                    obj = data["result"][0]
                    if output_format == "json":
                        return obj
                    return obj if isinstance(obj, str) else json.dumps(obj, indent=2)
                elif "error" in data:
                    if output_format == "json":
                        return {"error": data["error"]}
                    return f"JSON-RPC Error on local switch: {data['error']}\n"
        except Exception as e:
            if output_format == "json":
                return {"error": str(e)}
            return f"Local Execution Error: {e}\n"

    # Remote switch execution
    switch_netns(target_netns)
    ca_file = tls_info.get("ca_cert")
    if not ca_file:
        if output_format == "json":
            return {"error": "Security Alert: Trusted CA certificate bundle not found on switch."}
        return f"Security Alert on {host}: Trusted CA certificate bundle not found on switch. Aborting connection before sending credentials.\n"

    try:
        ctx = ssl.create_default_context(cafile=ca_file)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        if tls_info.get("client_cert") and tls_info.get("client_key"):
            ctx.load_cert_chain(tls_info["client_cert"], tls_info["client_key"])

        url = f"https://{host}:443/jsonrpc" if not host.startswith("http") else host
        req = urllib.request.Request(url, data=body, headers=auth_headers)
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if "result" in data and data["result"]:
                obj = data["result"][0]
                if output_format == "json":
                    return obj
                return obj if isinstance(obj, str) else json.dumps(obj, indent=2)
            elif "error" in data:
                if output_format == "json":
                    return {"error": data["error"]}
                return f"JSON-RPC Error on {host}: {data['error']}\n"
            return data if output_format == "json" else json.dumps(data, indent=2)
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            err_text = f"Authentication Failed on {host} ({target_netns}): Invalid username or password."
        else:
            err_text = f"HTTP Error {e.code} on {host}: {e.reason}"
        if output_format == "json":
            return {"error": err_text}
        return err_text + "\n"
    except ssl.SSLCertVerificationError as e:
        err_text = f"Security Alert: Untrusted Server CA / mTLS Verification Failed on {host}: {e}. Connection aborted before sending credentials."
        if output_format == "json":
            return {"error": err_text}
        return err_text + "\n"
    except ssl.SSLError as e:
        err_text = f"Security Alert: mTLS Handshake Failed on {host}: {e}"
        if output_format == "json":
            return {"error": err_text}
        return err_text + "\n"
    except urllib.error.URLError as e:
        err_text = f"Connection Failed on {host}: Host unreachable or timed out ({e.reason})."
        if output_format == "json":
            return {"error": err_text}
        return err_text + "\n"
    except Exception as e:
        if output_format == "json":
            return {"error": str(e)}
        return f"Execution Error on {host} ({target_netns}): {e}\n"


def exec_remote_cmd(host, command, netns="mgmt", output_format="text"):
    candidates = [netns]
    if "mgmt" not in candidates:
        candidates.append("mgmt")
    if "default" not in candidates:
        candidates.append("default")

    last_res = None
    for cand in candidates:
        res = _raw_exec_remote_cmd(host, command, cand, output_format=output_format)
        if isinstance(res, str) and ("Connection Failed" in res or "timed out" in res or "Execution Error" in res):
            last_res = res
            continue
        elif isinstance(res, dict) and "error" in res and ("Connection Failed" in str(res["error"]) or "timed out" in str(res["error"])):
            last_res = res
            continue
        return res
    return last_res if last_res is not None else _raw_exec_remote_cmd(host, command, netns, output_format=output_format)


def run_srlx_execution(output, target_devices, cmd):
    discovered = discover_srlinux_neighbors()
    local_name = get_local_hostname()
    requested_fmt = get_requested_output_format(output)

    if target_devices:
        targets = {}
        ordered_dev_names = []
        for d in target_devices:
            if d in discovered:
                targets[d] = discovered[d]
                if d not in ordered_dev_names:
                    ordered_dev_names.append(d)
            else:
                output.print_error_line(f"Error: Device \"{d}\" not found in discovered devices.")
    else:
        remote_dev_names = sorted([d for d in discovered.keys() if d != local_name], key=natural_sort_key)
        ordered_dev_names = remote_dev_names
        if local_name in discovered:
            ordered_dev_names.append(local_name)
        targets = discovered

    if not ordered_dev_names:
        output.print_line("No valid SRLinux devices to target.")
        return

    def _exec_info(dev_name):
        info = targets[dev_name]
        ip_list = info.get("mgmt_addrs", [])
        host = ip_list[0] if ip_list else dev_name
        netns = info.get("netns", "mgmt")
        return exec_remote_cmd(host, cmd, netns, output_format=requested_fmt)

    with ThreadPoolExecutor(max_workers=min(len(ordered_dev_names), 20)) as executor:
        futures = [(dev_name, executor.submit(_exec_info, dev_name)) for dev_name in ordered_dev_names]

        results = {}
        for dev_name, future in futures:
            try:
                output_val = future.result()
            except Exception as e:
                output_val = {"error": f"Execution error: {e}"} if requested_fmt == "json" else f"Execution error on {dev_name}: {e}\n"
            results[dev_name] = output_val

        if requested_fmt == "json":
            output.print_line(json.dumps(results, indent=2))
        elif requested_fmt == "yaml":
            for dev_name in ordered_dev_names:
                output.print_line("---")
                output.print_line(f"# Device: {dev_name}")
                val = results[dev_name]
                if isinstance(val, str):
                    output.print(val if val.endswith("\n") else val + "\n")
                else:
                    output.print_line(dump_simple_yaml({dev_name: val}))
        else:
            for dev_name in ordered_dev_names:
                info = targets[dev_name]
                ip_list = info.get("mgmt_addrs", [])
                target_ip = ip_list[0] if ip_list else dev_name
                netns = info.get("netns", "mgmt")
                output_text = str(results[dev_name])
                banner = f"\n======================================================================\n" \
                         f" Device: {dev_name} (IP: {target_ip} | VRF/NetNS: {netns})\n" \
                         f" Command: {cmd}\n" \
                         f"======================================================================\n"
                output.print(banner)
                output.print(output_text)
                if not output_text.endswith("\n"):
                    output.print_line("")


def format_reporter_list(dev_name, reporter_list, local_name=None):
    clean_list = sorted(list(set([r for r in (reporter_list or []) if r != dev_name])), key=natural_sort_key)
    return ", ".join(clean_list) if clean_list else "None"


def show_srlx_devices_callback(state, output, arguments, **_kwargs):
    resp = query_daemon_socket({"action": "get_devices"})
    local_name = get_local_hostname()
    requested_fmt = get_requested_output_format(output)

    if not resp or resp.get("status") != "ok":
        nodes = discover_srlinux_neighbors(state)
    else:
        vector = resp.get("vector", {})
        nodes = vector.get("nodes", {})
        if not nodes:
            nodes = discover_srlinux_neighbors(state)

    dev_names = sorted(list(nodes.keys()), key=natural_sort_key)
    if local_name in dev_names:
        dev_names.remove(local_name)
        dev_names.append(local_name)

    now = time.time()

    if requested_fmt == "json":
        topo_dict = {}
        for d in dev_names:
            data = nodes[d]
            ip = resolve_neighbor_ip(data.get("mgmt_addrs", []), d)
            direct_reporters = [r for r in data.get("direct_reporters", []) if r != d]
            mesh_reporters = [m for m in data.get("mesh_reporters", []) if m not in direct_reporters and m != d]
            learned_via = data.get("learned_via") or ("Local" if d == local_name else ("Direct" if local_name in direct_reporters else "Mesh"))
            raw_status = data.get("status", "")
            if d == local_name:
                reachable = "Local"
            elif raw_status == "FAIL" or "Fail" in raw_status:
                reachable = "FAIL"
            elif "Unreachable" in raw_status:
                reachable = "Unreachable"
            else:
                reachable = "mTLS OK"
            last_ts = data.get("last_updated", now)
            elapsed = int(now - last_ts)
            last_seen = "Local" if d == local_name else (f"{elapsed}s ago" if elapsed > 0 else "Instant")
            topo_dict[d] = {
                "management_ip": ip,
                "learned_via": learned_via,
                "direct_reporters": direct_reporters,
                "mesh_reporters": mesh_reporters,
                "reachable": reachable,
                "last_seen": last_seen
            }
        output.print_line(json.dumps(topo_dict, indent=2))
        return
    elif requested_fmt == "yaml":
        topo_dict = {}
        for d in dev_names:
            data = nodes[d]
            ip = resolve_neighbor_ip(data.get("mgmt_addrs", []), d)
            direct_reporters = [r for r in data.get("direct_reporters", []) if r != d]
            mesh_reporters = [m for m in data.get("mesh_reporters", []) if m not in direct_reporters and m != d]
            learned_via = data.get("learned_via") or ("Local" if d == local_name else ("Direct" if local_name in direct_reporters else "Mesh"))
            raw_status = data.get("status", "")
            if d == local_name:
                reachable = "Local"
            elif raw_status == "FAIL" or "Fail" in raw_status:
                reachable = "FAIL"
            elif "Unreachable" in raw_status:
                reachable = "Unreachable"
            else:
                reachable = "mTLS OK"
            last_ts = data.get("last_updated", now)
            elapsed = int(now - last_ts)
            last_seen = "Local" if d == local_name else (f"{elapsed}s ago" if elapsed > 0 else "Instant")
            topo_dict[d] = {
                "management_ip": ip,
                "learned_via": learned_via,
                "direct_reporters": direct_reporters,
                "mesh_reporters": mesh_reporters,
                "reachable": reachable,
                "last_seen": last_seen
            }
        output.print_line("---")
        output.print_line(dump_simple_yaml({"topology": topo_dict}))
        return

    output.print_line("\n======================================================================================================")
    output.print_line(f" SRLX Discovered Fabric Topology ({len(dev_names)} Nodes Discovered)")
    output.print_line("======================================================================================================")

    headers = ["Device Name", "Mgmt IP", "Learned Via", "Direct Reporters", "Mesh Reporters", "Reachable", "Last Seen"]
    rows = []

    for d in dev_names:
        data = nodes[d]
        ip = resolve_neighbor_ip(data.get("mgmt_addrs", []), d)
        direct_reporters = [r for r in data.get("direct_reporters", []) if r != d]
        mesh_reporters = [m for m in data.get("mesh_reporters", []) if m not in direct_reporters and m != d]
        direct_str = format_reporter_list(d, direct_reporters, local_name)
        mesh_str = format_reporter_list(d, mesh_reporters, local_name)

        learned_via = data.get("learned_via")
        if not learned_via:
            learned_via = "Local" if d == local_name else ("Direct" if local_name in direct_reporters else "Mesh")

        raw_status = data.get("status", "")
        if d == local_name:
            reachable = "Local"
        elif raw_status == "FAIL" or "Fail" in raw_status:
            reachable = "FAIL"
        elif "Unreachable" in raw_status:
            reachable = "Unreachable"
        else:
            reachable = "mTLS OK"

        last_ts = data.get("last_updated", now)
        elapsed = int(now - last_ts)
        last_seen = "Local" if d == local_name else (f"{elapsed}s ago" if elapsed > 0 else "Instant")

        rows.append([d, ip, learned_via, direct_str, mesh_str, reachable, last_seen])

    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            col_widths[i] = max(col_widths[i], len(val))

    def _fmt_row(vals):
        return "| " + " | ".join(val.ljust(col_widths[i]) for i, val in enumerate(vals)) + " |"

    sep = "+" + "+".join("=" * (col_widths[i] + 2) for i in range(len(headers))) + "+"
    thin_sep = "+" + "+".join("-" * (col_widths[i] + 2) for i in range(len(headers))) + "+"

    output.print_line(sep)
    output.print_line(_fmt_row(headers))
    output.print_line(sep)
    for r in rows:
        output.print_line(_fmt_row(r))
    output.print_line(thin_sep + "\n")


def show_srlx_device_detail_callback(state, output, arguments, **_kwargs):
    if hasattr(state, "is_last_command") and not state.is_last_command:
        return

    target_name = extract_unnamed_argument_value(arguments, "device", state)
    if not target_name:
        target_name = get_local_hostname()

    requested_fmt = get_requested_output_format(output)
    resp = query_daemon_socket({"action": "get_devices"})
    local_name = get_local_hostname()

    if not resp or resp.get("status") != "ok":
        nodes = discover_srlinux_neighbors(state)
    else:
        nodes = resp.get("vector", {}).get("nodes", {})
        if not nodes:
            nodes = discover_srlinux_neighbors(state)

    if target_name not in nodes:
        output.print_error_line(f"Device '{target_name}' not found in topology database.")
        return

    data = nodes[target_name]
    ip = resolve_neighbor_ip(data.get("mgmt_addrs", []), target_name)
    netns = data.get("netns", "mgmt")

    direct_reporters = [r for r in data.get("direct_reporters", []) if r != target_name]
    mesh_reporters = [m for m in data.get("mesh_reporters", []) if m not in direct_reporters and m != target_name]

    direct_str = format_reporter_list(target_name, direct_reporters, local_name)
    mesh_str = format_reporter_list(target_name, mesh_reporters, local_name)

    learned_via = data.get("learned_via")
    if not learned_via:
        learned_via = "Local" if target_name == local_name else ("Direct" if local_name in direct_reporters else "Mesh")

    raw_status = data.get("status", "")
    if target_name == local_name:
        reachable = "Local"
    elif raw_status == "FAIL" or "Fail" in raw_status:
        reachable = "FAIL"
    elif "Unreachable" in raw_status:
        reachable = "Unreachable"
    else:
        reachable = "mTLS OK"

    tls_info = resolve_tls_certificates()
    ca_desc = os.path.basename(tls_info['ca_cert']) if tls_info.get('ca_cert') else "None"
    profile_desc = tls_info.get('profile_name', 'System')

    is_mtls_verified = (reachable == "mTLS OK" or reachable == "Local")

    if requested_fmt == "json":
        detail_dict = {
            "device_name": target_name,
            "management_address": ip,
            "network_instance": netns,
            "learned_via": learned_via,
            "reachable": reachable,
            "direct_reporters": direct_reporters,
            "mesh_reporters": mesh_reporters,
            "mtls_security_state": {
                "verified": is_mtls_verified,
                "ca_certificate": ca_desc,
                "tls_profile": profile_desc
            }
        }
        output.print_line(json.dumps(detail_dict, indent=2))
        return
    elif requested_fmt == "yaml":
        detail_dict = {
            "device_name": target_name,
            "management_address": ip,
            "network_instance": netns,
            "learned_via": learned_via,
            "reachable": reachable,
            "direct_reporters": direct_reporters,
            "mesh_reporters": mesh_reporters,
            "mtls_security_state": {
                "verified": is_mtls_verified,
                "ca_certificate": ca_desc,
                "tls_profile": profile_desc
            }
        }
        output.print_line("---")
        output.print_line(dump_simple_yaml({"device_detail": detail_dict}))
        return

    sec_status_str = f"Verified (CA: {ca_desc}, Profile: {profile_desc})" if is_mtls_verified else f"Failed / Unreachable (CA: {ca_desc}, Profile: {profile_desc})"

    output.print_line("\n======================================================================")
    output.print_line(f" Device Detail: {target_name}")
    output.print_line("======================================================================")
    output.print_line(f" Management Address    : {ip}")
    output.print_line(f" Network Instance / VRF: {netns}")
    output.print_line(f" Learned Via           : {learned_via}")
    output.print_line(f" Reachable             : {reachable}")
    output.print_line(f" Direct Reporters      : {direct_str}")
    output.print_line(f" Mesh Reporters        : {mesh_str}")
    output.print_line(f" mTLS Security State   : {sec_status_str}")
    output.print_line("======================================================================\n")


def tools_srlx_clear_device_callback(state, output, arguments, **_kwargs):
    target_name = extract_unnamed_argument_value(arguments, "device", state)
    if not target_name:
        output.print_error_line("Please specify a device name to clear.")
        return

    resp = query_daemon_socket({"action": "clear_device", "device": target_name})
    if resp and resp.get("status") == "ok":
        output.print_line(f"Device '{target_name}' cleared from local cache and topology re-synced.")
    else:
        output.print_error_line(f"Failed to clear device '{target_name}': {resp.get('message') if resp else 'Daemon unavailable'}")


def tools_srlx_clear_all_callback(state, output, arguments, **_kwargs):
    resp = query_daemon_socket({"action": "clear_all"})
    if resp and resp.get("status") == "ok":
        output.print_line("Local SRLX topology cache cleared and re-synced with direct LLDP neighbors.")
    else:
        output.print_error_line(f"Failed to clear topology cache: {resp.get('message') if resp else 'Daemon unavailable'}")


def standalone_srlx_callback(state, output, arguments, **_kwargs):
    raw_args = arguments.get("srlx", "[target-device...] command") if arguments else None
    if isinstance(raw_args, str):
        raw_args = [raw_args]
    elif not raw_args:
        raw_args = []

    discovered = discover_srlinux_neighbors(state)
    known_devices = set(discovered.keys())

    target_devices, cmd_tokens = parse_target_and_cmd_tokens(raw_args, known_devices)
    cmd = " ".join(cmd_tokens) if cmd_tokens else "show version"
    run_srlx_execution(output, target_devices, cmd)


class Plugin(ToolsPlugin):
    def load(self, cli, **_kwargs):
        # 1. show srlx devices & show srlx device <device> [detail]
        show_root = cli.show_mode.root
        if not show_root.get_command_or_none("srlx"):
            show_srlx = Syntax("srlx", help="SRLX Gossip Protocol Topology Information")
            devices_syntax = Syntax("devices", help="Show all discovered fabric switches and topology mesh")

            device_syntax = Syntax("device", help="Show detailed topology attribution for a single device")
            device_syntax.add_unnamed_argument("device", default=None, suggestions=get_neighbor_choices, help="Target device name")

            show_node = show_root.add_command(show_srlx, update_location=False)
            show_node.add_command(devices_syntax, update_location=False, callback=show_srlx_devices_callback)

            dev_node = show_node.add_command(device_syntax, update_location=False, callback=show_srlx_device_detail_callback)
            dev_node.add_command(Syntax("detail", help="Detailed attribution"), update_location=False, callback=show_srlx_device_detail_callback)

        # 2. Standalone global execution (srlx [devices...] <cmd...>)
        syntax_standalone = Syntax("srlx", help="Execute command on switch(es) without local command leakage")
        syntax_standalone.add_unnamed_argument(
            "[target-device...] command",
            default=None,
            min_count=1,
            max_count="*",
            suggestions=get_srlx_unified_suggestions,
            help="Optional target switch(es) followed by remote CLI command (defaults to all fabric switches if omitted)"
        )
        cli.add_global_command(syntax_standalone, update_location=False, only_at_start_of_line=True, callback=standalone_srlx_callback)

    def on_tools_load(self, state):
        # 3. tools srlx clear all & tools srlx clear device <node>
        tools_root = state.command_tree.tools_mode.root
        if not tools_root.get_command_or_none("srlx"):
            tools_srlx = Syntax("srlx", help="SRLX Gossip Protocol Topology Management Tools")
            clear_syntax = Syntax("clear", help="Clear local topology cache")

            clear_device_syntax = Syntax("device", help="Clear a specific device from local cache")
            clear_device_syntax.add_unnamed_argument("device", default=None, suggestions=get_neighbor_choices, help="Target device name to clear")

            tools_node = tools_root.add_command(tools_srlx, update_location=False)

            clear_node = tools_node.add_command(clear_syntax, update_location=False)
            clear_node.add_command(Syntax("all", help="Clear all devices from local topology cache"), update_location=False, callback=tools_srlx_clear_all_callback)
            clear_node.add_command(clear_device_syntax, update_location=False, callback=tools_srlx_clear_device_callback)
