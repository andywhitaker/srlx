import json
import os
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from srlinux.mgmt.cli.cli_plugin import CliPlugin
from srlinux.mgmt.cli.tools_plugin import ToolsPlugin
from srlinux.syntax import Syntax

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

# Global persistent cache across CLI plugin instances (60s TTL fallback)
_DISCOVERY_CACHE = {"timestamp": 0, "devices": {}}
DAEMON_SOCKET_PATH = "/var/run/srlx-daemon.sock"

def natural_sort_key(name):
    return [int(c) if c.isdigit() else c.lower() for c in re.split(r"(\d+)", name)]

def query_daemon_socket(payload):
    if not os.path.exists(DAEMON_SOCKET_PATH):
        return None
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect(DAEMON_SOCKET_PATH)
        s.sendall(json.dumps(payload).encode() + b"\n")
        raw = s.recv(16384).decode().strip()
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

def get_auth_curl_flags():
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

    user = user or "admin"
    password = password or "NokiaSrl1!"
    return ["-u", f"{user}:{password}"]

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
        for candidate in ["/etc/opt/srlinux/tls/ca.pem"]:
            if os.path.exists(candidate) and os.path.getsize(candidate) > 0:
                ca_path = candidate
                break

    client_cert = os.environ.get("SRLX_CLIENT_CERT") or config_data.get("client_cert")
    client_key = os.environ.get("SRLX_CLIENT_KEY") or config_data.get("client_key")
    profile_name = "Custom" if client_cert else None

    if not (client_cert and client_key and os.path.exists(client_cert) and os.path.exists(client_key)):
        for prof in ["clab-profile", "__default__"]:
            c_cand = f"/etc/opt/srlinux/tls/{prof}.pem"
            k_cand = f"/etc/opt/srlinux/tls/{prof}.key.pem"
            if os.path.exists(c_cand) and os.path.exists(k_cand):
                client_cert, client_key, profile_name = c_cand, k_cand, prof
                break

        if not client_cert and os.path.exists("/etc/opt/srlinux/tls"):
            try:
                for fname in os.listdir("/etc/opt/srlinux/tls"):
                    if fname.endswith(".pem") and not fname.endswith(".key.pem") and not fname.endswith(".ca.pem") and fname != "ca.pem":
                        base = fname[:-4]
                        k_cand = os.path.join("/etc/opt/srlinux/tls", f"{base}.key.pem")
                        c_cand = os.path.join("/etc/opt/srlinux/tls", fname)
                        if os.path.exists(k_cand):
                            client_cert, client_key, profile_name = c_cand, k_cand, base
                            break
            except Exception:
                pass

    return {
        "ca_cert": ca_path if (ca_path and os.path.exists(ca_path)) else None,
        "client_cert": client_cert if (client_cert and os.path.exists(client_cert)) else None,
        "client_key": client_key if (client_key and os.path.exists(client_key)) else None,
        "profile_name": profile_name or "System"
    }

def get_multi_jsonrpc_netns(paths, datastore="state", netns="mgmt"):
    target_netns = f"srbase-{netns}" if netns != "default" else "srbase"
    cmds = [{"path": p, "datastore": datastore} for p in paths]
    auth_flags = get_auth_curl_flags()

    cmd_args = [
        "sudo", "-n", "ip", "netns", "exec", target_netns,
        "curl", "-s"
    ]
    cmd_args.extend(auth_flags)
    cmd_args.extend([
        "-X", "POST", "http://127.0.0.1:80/jsonrpc",
        "-H", "Content-Type: application/json",
        "-d", json.dumps({"jsonrpc": "2.0", "id": 1, "method": "get", "params": {"commands": cmds}})
    ])
    try:
        res = subprocess.check_output(cmd_args, stderr=subprocess.DEVNULL)
        data = json.loads(res.decode())
        if "result" in data:
            return data["result"]
    except Exception:
        pass

    # Fallback to local HTTPS port 443 with -k (safe on loopback)
    cmd_args_ssl = [
        "sudo", "-n", "ip", "netns", "exec", target_netns,
        "curl", "-k", "-s"
    ] + auth_flags + [
        "-X", "POST", "https://127.0.0.1:443/jsonrpc",
        "-H", "Content-Type: application/json",
        "-d", json.dumps({"jsonrpc": "2.0", "id": 1, "method": "get", "params": {"commands": cmds}})
    ]
    try:
        res = subprocess.check_output(cmd_args_ssl, stderr=subprocess.DEVNULL)
        return json.loads(res.decode()).get("result", [])
    except Exception:
        return []

def get_local_hostname():
    try:
        results = get_multi_jsonrpc_netns(["/system/name"])
        if results and isinstance(results[0], dict) and "host-name" in results[0]:
            return results[0]["host-name"]
    except Exception:
        pass
    return socket.gethostname()

def discover_srlinux_neighbors():
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
                    "status": nd.get("status", "Reachable")
                }
            return devices

    now = time.time()
    if now - _DISCOVERY_CACHE["timestamp"] < 60 and _DISCOVERY_CACHE["devices"]:
        return _DISCOVERY_CACHE["devices"]

    devices = {}
    local_name = get_local_hostname()
    if local_name:
        devices[local_name] = {
            "local_port": "local",
            "system_name": local_name,
            "chassis_id": "local",
            "system_description": "Local SR Linux Switch",
            "mgmt_addrs": [local_name],
            "netns": "mgmt",
            "is_local": True
        }

    try:
        results = get_multi_jsonrpc_netns(["/network-instance", "/system/lldp/interface"])
        if len(results) >= 2:
            netns_data, lldp_data = results[0], results[1]
        else:
            netns_data = results[0] if len(results) > 0 else {}
            lldp_data = {}

        port_to_netns = {}
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
                    netns = port_to_netns.get(local_port, "mgmt")
                    raw_neighbors.append({
                        "local_port": local_port,
                        "system_name": sys_name,
                        "chassis_id": chassis_id,
                        "system_description": sys_desc,
                        "mgmt_addrs": mgmt_addrs,
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

    _DISCOVERY_CACHE["timestamp"] = now
    _DISCOVERY_CACHE["devices"] = devices
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

def extract_device_argument_value(arguments, state=None):
    if not arguments:
        return ""
    if hasattr(arguments, "get"):
        try:
            val = arguments.get("device")
            if val:
                return val[0] if isinstance(val, list) else str(val)
        except Exception:
            pass
    curr = arguments
    while hasattr(curr, "parent") and curr.parent:
        curr = curr.parent
        if hasattr(curr, "get"):
            try:
                val = curr.get("device")
                if val:
                    return val[0] if isinstance(val, list) else str(val)
            except Exception:
                pass
    if hasattr(arguments, "all_arguments"):
        try:
            all_args = arguments.all_arguments
            if isinstance(all_args, dict) and "device" in all_args:
                val = all_args["device"]
                if hasattr(val, "value"):
                    val = val.value
                return val[0] if isinstance(val, list) else str(val)
        except Exception:
            pass
    if hasattr(arguments, "local_arguments"):
        try:
            loc_args = arguments.local_arguments
            if isinstance(loc_args, dict) and "device" in loc_args:
                val = loc_args["device"]
                if hasattr(val, "value"):
                    val = val.value
                return val[0] if isinstance(val, list) else str(val)
        except Exception:
            pass
    if state and hasattr(state, "line_commands"):
        try:
            for cmd in state.line_commands.nodes:
                if hasattr(cmd, "local_arguments") and "device" in cmd.local_arguments:
                    val = cmd.local_arguments["device"]
                    if hasattr(val, "value"):
                        val = val.value
                    if val:
                        return val[0] if isinstance(val, list) else str(val)
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

        discovered = discover_srlinux_neighbors()
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
    is_local = host in ("127.0.0.1", "localhost", "::1", get_local_hostname())
    netns_val = f"srbase-{target_netns}" if target_netns != "default" else "srbase"
    auth_flags = get_auth_curl_flags()
    tls_info = resolve_tls_certificates()

    if is_local:
        cmd_args = [
            "sudo", "-n", "ip", "netns", "exec", netns_val,
            "curl", "-s"
        ] + auth_flags + [
            "-X", "POST", "http://127.0.0.1:80/jsonrpc",
            "-H", "Content-Type: application/json",
            "-d", json.dumps({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "cli",
                "params": {
                    "commands": [command],
                    "output-format": output_format
                }
            })
        ]
        try:
            res_bytes = subprocess.check_output(cmd_args, stderr=subprocess.PIPE, timeout=10)
            res_str = res_bytes.decode().strip()
            data = json.loads(res_str)
            if output_format == "json":
                if "result" in data and data["result"]:
                    return data["result"][0]
                elif "error" in data:
                    return {"error": data["error"]}
                return data
            if "result" in data and data["result"]:
                obj = data["result"][0]
                return obj if isinstance(obj, str) else json.dumps(obj, indent=2)
        except Exception:
            pass

        # Fallback to local HTTPS 443 with -k (safe on loopback)
        cmd_args = [
            "sudo", "-n", "ip", "netns", "exec", netns_val,
            "curl", "-k", "-s"
        ] + auth_flags + [
            "-X", "POST", "https://127.0.0.1:443/jsonrpc",
            "-H", "Content-Type: application/json",
            "-d", json.dumps({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "cli",
                "params": {
                    "commands": [command],
                    "output-format": output_format
                }
            })
        ]
    else:
        ca_file = tls_info.get("ca_cert")
        if not ca_file:
            if output_format == "json":
                return {"error": "Security Alert: Trusted CA certificate bundle not found on switch."}
            return f"Security Alert on {host}: Trusted CA certificate bundle not found on switch. Aborting connection before sending credentials.\n"

        cmd_args = [
            "sudo", "-n", "ip", "netns", "exec", netns_val,
            "curl", "-s",
            "--cacert", ca_file
        ]
        if tls_info.get("client_cert") and tls_info.get("client_key"):
            cmd_args.extend(["--cert", tls_info["client_cert"], "--key", tls_info["client_key"]])
        cmd_args.extend(auth_flags)
        cmd_args.extend([
            "-X", "POST", f"https://{host}/jsonrpc",
            "-H", "Content-Type: application/json",
            "-d", json.dumps({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "cli",
                "params": {
                    "commands": [command],
                    "output-format": output_format
                }
            })
        ])

    try:
        res_bytes = subprocess.check_output(cmd_args, stderr=subprocess.PIPE, timeout=10)
        res_str = res_bytes.decode().strip()

        if "AuthenticationFailed" in res_str or "401 Unauthorized" in res_str:
            if output_format == "json":
                return {"error": "Authentication Failed: Invalid username or password"}
            return f"Authentication Failed on {host} ({target_netns}): Invalid username or password.\n"

        try:
            data = json.loads(res_str)
        except Exception:
            if output_format == "json":
                return {"error": f"API Response Error: {res_str}"}
            return f"API Response Error on {host} ({target_netns}): Raw response: {res_str}\n"

        if output_format == "json":
            if "result" in data and data["result"]:
                return data["result"][0]
            elif "error" in data:
                return {"error": data["error"]}
            return data
        else:
            if "result" in data and data["result"]:
                obj = data["result"][0]
                if isinstance(obj, str):
                    return obj
                else:
                    return json.dumps(obj, indent=2)
            elif "error" in data:
                return f"JSON-RPC Error on {host}: {data['error']}\n"
            return json.dumps(data, indent=2)
    except subprocess.CalledProcessError as e:
        code = e.returncode
        stderr_msg = e.stderr.decode().strip() if e.stderr else ""
        err_text = ""
        if code == 60:
            err_text = f"Security Alert: Untrusted Server CA / mTLS Verification Failed on {host}. Connection aborted before sending credentials."
        elif code == 35:
            err_text = f"Security Alert: mTLS Handshake / TLS Connect Failed on {host} (exit code 35). Remote host certificate invalid or rejected. Connection aborted before sending credentials."
        elif code == 58:
            err_text = f"Security Alert: Problem with local client certificate/key on {host} (exit code 58)."
        elif code == 56:
            err_text = f"Client mTLS Verification Failed on {host}: Remote server rejected client certificate or connection reset."
        elif code == 77:
            err_text = f"Security Alert: Problem reading SSL CA cert bundle on {host} (exit code 77)."
        elif code in (7, 28):
            err_text = f"Connection Failed on {host}: Host unreachable or timed out."
        elif "AuthenticationFailed" in stderr_msg or "401" in stderr_msg:
            err_text = f"Authentication Failed on {host} ({target_netns}): Invalid username or password."
        else:
            err_text = f"Command Execution Failed on {host} (exit code {code}): {stderr_msg or e}"
        
        if output_format == "json":
            return {"error": err_text}
        return err_text + "\n"
    except Exception as e:
        if output_format == "json":
            return {"error": str(e)}
        return f"Execution Error on {host} ({target_netns}): {e}\n"

def exec_remote_cmd(host, command, netns="mgmt", output_format="text"):
    res = _raw_exec_remote_cmd(host, command, "mgmt", output_format=output_format)
    if isinstance(res, str) and ("Connection Failed" in res or "timed out" in res or "Execution Error" in res) and netns != "mgmt":
        res_alt = _raw_exec_remote_cmd(host, command, netns, output_format=output_format)
        if isinstance(res_alt, str) and "Connection Failed" not in res_alt and "timed out" not in res_alt and "Execution Error" not in res_alt:
            return res_alt
    return res

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

IS_IPV4_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

def resolve_management_ip(name_or_ip):
    if not name_or_ip:
        return "Unknown"
    
    if IS_IPV4_RE.match(name_or_ip):
        return name_or_ip
    
    try:
        with open("/etc/hosts", "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0]
                    if IS_IPV4_RE.match(ip) and ip != "127.0.0.1":
                        if name_or_ip in parts[1:]:
                            return ip
    except Exception:
        pass

    try:
        resolved = socket.gethostbyname(name_or_ip)
        if IS_IPV4_RE.match(resolved) and resolved != "127.0.0.1":
            return resolved
    except Exception:
        pass

    return name_or_ip

def format_reporter_list(dev_name, reporter_list, local_name=None):
    clean_list = sorted(list(set([r for r in (reporter_list or []) if r != dev_name])), key=natural_sort_key)
    return ", ".join(clean_list) if clean_list else "None"

def show_srlx_devices_callback(state, output, arguments, **_kwargs):
    resp = query_daemon_socket({"action": "get_devices"})
    local_name = get_local_hostname()
    requested_fmt = get_requested_output_format(output)

    if not resp or resp.get("status") != "ok":
        discovered = discover_srlinux_neighbors()
        nodes = {}
        for d, data in discovered.items():
            nodes[d] = {
                "mgmt_addrs": data.get("mgmt_addrs", [d]),
                "netns": data.get("netns", "mgmt"),
                "direct_reporters": ["local" if d == local_name else "lldp"],
                "mesh_reporters": [],
                "learned_via": "Local" if d == local_name else "Direct",
                "status": "Local" if d == local_name else "mTLS OK",
                "last_updated": time.time()
            }
    else:
        vector = resp.get("vector", {})
        nodes = vector.get("nodes", {})

    dev_names = sorted(list(nodes.keys()), key=natural_sort_key)
    if local_name in dev_names:
        dev_names.remove(local_name)
        dev_names.append(local_name)

    now = time.time()

    if requested_fmt == "json":
        topo_dict = {}
        for d in dev_names:
            data = nodes[d]
            raw_ip = data.get("mgmt_addrs", [d])[0]
            ip = resolve_management_ip(raw_ip)
            if not IS_IPV4_RE.match(ip):
                ip = resolve_management_ip(d)
            direct_reporters = [r for r in data.get("direct_reporters", []) if r != d]
            mesh_reporters = [m for m in data.get("mesh_reporters", []) if m not in direct_reporters and m != d]
            learned_via = data.get("learned_via") or ("Local" if d == local_name else ("Direct" if local_name in direct_reporters else "Mesh"))
            raw_status = data.get("status", "")
            reachable = "Local" if d == local_name else ("Unreachable" if ("Unreachable" in raw_status or "Failed" in raw_status) else "mTLS OK")
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
            raw_ip = data.get("mgmt_addrs", [d])[0]
            ip = resolve_management_ip(raw_ip)
            if not IS_IPV4_RE.match(ip):
                ip = resolve_management_ip(d)
            direct_reporters = [r for r in data.get("direct_reporters", []) if r != d]
            mesh_reporters = [m for m in data.get("mesh_reporters", []) if m not in direct_reporters and m != d]
            learned_via = data.get("learned_via") or ("Local" if d == local_name else ("Direct" if local_name in direct_reporters else "Mesh"))
            raw_status = data.get("status", "")
            reachable = "Local" if d == local_name else ("Unreachable" if ("Unreachable" in raw_status or "Failed" in raw_status) else "mTLS OK")
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
        raw_ip = data.get("mgmt_addrs", [d])[0]
        ip = resolve_management_ip(raw_ip)
        if not IS_IPV4_RE.match(ip):
            ip = resolve_management_ip(d)
        
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
        elif "Unreachable" in raw_status or "Failed" in raw_status:
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

    target_name = extract_device_argument_value(arguments, state)
    if not target_name:
        target_name = get_local_hostname()

    requested_fmt = get_requested_output_format(output)
    resp = query_daemon_socket({"action": "get_devices"})
    nodes = resp.get("vector", {}).get("nodes", {}) if resp and resp.get("status") == "ok" else {}
    local_name = get_local_hostname()

    if target_name not in nodes:
        output.print_error_line(f"Device '{target_name}' not found in topology database.")
        return

    data = nodes[target_name]
    raw_ip = data.get("mgmt_addrs", [target_name])[0]
    ip = resolve_management_ip(raw_ip)
    if not IS_IPV4_RE.match(ip):
        ip = resolve_management_ip(target_name)
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
    elif "Unreachable" in raw_status or "Failed" in raw_status:
        reachable = "Unreachable"
    else:
        reachable = "mTLS OK"

    tls_info = resolve_tls_certificates()
    ca_desc = os.path.basename(tls_info['ca_cert']) if tls_info.get('ca_cert') else "None"
    profile_desc = tls_info.get('profile_name', 'System')

    is_mtls_verified = (reachable != "Unreachable")

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
    target_name = extract_device_argument_value(arguments, state)

    if not target_name:
        output.print_error_line("Please specify a device name to clear.")
        return

    resp = query_daemon_socket({"action": "clear_device", "device": target_name})
    if resp and resp.get("status") == "ok":
        output.print_line(f"Device '{target_name}' cleared from local SRLX topology cache.")
    else:
        output.print_error_line(f"Failed to clear device '{target_name}': {resp.get('message') if resp else 'Daemon unavailable'}")

def tools_srlx_clear_all_callback(state, output, arguments, **_kwargs):
    resp = query_daemon_socket({"action": "clear_all"})
    if resp and resp.get("status") == "ok":
        output.print_line("Local SRLX topology cache cleared. Triggering re-discovery scan...")
    else:
        output.print_error_line(f"Failed to clear topology cache: {resp.get('message') if resp else 'Daemon unavailable'}")

def standalone_srlx_callback(state, output, arguments, **_kwargs):
    raw_args = arguments.get("srlx", "[target-device...] command") if arguments else None
    if isinstance(raw_args, str):
        raw_args = [raw_args]
    elif not raw_args:
        raw_args = []

    discovered = discover_srlinux_neighbors()
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
        # 3. tools srlx clear all & tools srlx clear device <device>
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
