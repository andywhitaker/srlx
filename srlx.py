import json
import os
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from srlinux.mgmt.cli.cli_plugin import CliPlugin
from srlinux.syntax import Syntax

# Global persistent cache across CLI plugin instances (60s TTL)
_DISCOVERY_CACHE = {"timestamp": 0, "devices": {}}

def natural_sort_key(name):
    return [int(c) if c.isdigit() else c.lower() for c in re.split(r"(\d+)", name)]

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

def get_multi_jsonrpc_netns(paths, datastore="state", netns="mgmt"):
    target_netns = f"srbase-{netns}" if netns != "default" else "srbase"
    cmds = [{"path": p, "datastore": datastore} for p in paths]

    cmd_args = [
        "sudo", "-n", "ip", "netns", "exec", target_netns,
        "curl", "-k", "-s",
        "--cert", "/etc/opt/srlinux/tls/clab-profile.pem",
        "--key", "/etc/opt/srlinux/tls/clab-profile.key.pem",
        "-u", "admin:NokiaSrl1!",
        "-X", "POST", "https://127.0.0.1/jsonrpc",
        "-H", "Content-Type: application/json",
        "-d", json.dumps({"jsonrpc": "2.0", "id": 1, "method": "get", "params": {"commands": cmds}})
    ]
    try:
        res = subprocess.check_output(cmd_args, stderr=subprocess.DEVNULL)
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

def exec_remote_cmd(host, command, netns="mgmt"):
    target_netns = f"srbase-{netns}" if netns != "default" else "srbase"
    auth_flags = get_auth_curl_flags()

    cmd_args = [
        "sudo", "-n", "ip", "netns", "exec", target_netns,
        "curl", "-s"
    ]
    cmd_args.extend(auth_flags)
    cmd_args.extend([
        "--cacert", "/etc/opt/srlinux/tls/ca.pem",
        "--cert", "/etc/opt/srlinux/tls/clab-profile.pem",
        "--key", "/etc/opt/srlinux/tls/clab-profile.key.pem",
        "-X", "POST", f"https://{host}/jsonrpc",
        "-H", "Content-Type: application/json",
        "-d", json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "cli",
            "params": {
                "commands": [command],
                "output-format": "text"
            }
        })
    ])
    try:
        res_bytes = subprocess.check_output(cmd_args, stderr=subprocess.PIPE, timeout=10)
        res_str = res_bytes.decode().strip()

        if "AuthenticationFailed" in res_str or "401 Unauthorized" in res_str:
            return f"Authentication Failed on {host} ({target_netns}): Invalid username or password.\n"

        try:
            data = json.loads(res_str)
        except Exception:
            return f"API Response Error on {host} ({target_netns}): Raw response: {res_str}\n"

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
        if code == 60:
            return f"Untrusted Server CA / mTLS Verification Failed on {host}: Server TLS certificate not trusted.\n"
        elif code == 56:
            return f"Client mTLS Verification Failed on {host}: Remote server rejected client certificate.\n"
        elif code in (7, 28):
            return f"Connection Failed on {host}: Host unreachable or timed out.\n"
        elif "AuthenticationFailed" in stderr_msg or "401" in stderr_msg:
            return f"Authentication Failed on {host} ({target_netns}): Invalid username or password.\n"
        return f"Command Execution Failed on {host} (exit code {code}): {stderr_msg or e}\n"
    except Exception as e:
        return f"Execution Error on {host} ({target_netns}): {e}\n"

def run_srlx_execution(output, target_devices, cmd):
    discovered = discover_srlinux_neighbors()
    local_name = get_local_hostname()

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
        return exec_remote_cmd(host, cmd, netns)

    with ThreadPoolExecutor(max_workers=min(len(ordered_dev_names), 20)) as executor:
        futures = [(dev_name, executor.submit(_exec_info, dev_name)) for dev_name in ordered_dev_names]

        for dev_name, future in futures:
            info = targets[dev_name]
            ip_list = info.get("mgmt_addrs", [])
            target_ip = ip_list[0] if ip_list else dev_name
            netns = info.get("netns", "mgmt")
            port = info.get("local_port", "")

            try:
                output_text = future.result()
            except Exception as e:
                output_text = f"Execution error on {dev_name}: {e}\n"

            banner = f"\n======================================================================\n" \
                     f" Device: {dev_name} (IP: {target_ip} | VRF/NetNS: {netns} | Port: {port})\n" \
                     f" Command: {cmd}\n" \
                     f"======================================================================\n"
            output.print(banner)
            output.print(output_text)
            if not output_text.endswith("\n"):
                output.print_line("")

def standalone_srlx_callback(state, output, arguments, **_kwargs):
    raw_args = arguments.get("srlx", "target_and_cmd") if arguments else None
    if isinstance(raw_args, str):
        raw_args = [raw_args]
    elif not raw_args:
        raw_args = []

    discovered = discover_srlinux_neighbors()
    known_devices = set(discovered.keys())

    target_devices, cmd_tokens = parse_target_and_cmd_tokens(raw_args, known_devices)

    cmd = " ".join(cmd_tokens) if cmd_tokens else "show version"
    run_srlx_execution(output, target_devices, cmd)

class Plugin(CliPlugin):
    def load(self, cli, **_kwargs):
        syntax_standalone = Syntax("srlx", help="Execute command on switch(es) without local command leakage")
        syntax_standalone.add_unnamed_argument(
            "target_and_cmd",
            default=None,
            min_count=1,
            max_count="*",
            suggestions=get_srlx_unified_suggestions,
            help="Target switch device(s) followed by remote CLI command"
        )
        cli.add_global_command(syntax_standalone, update_location=False, only_at_start_of_line=True, callback=standalone_srlx_callback)
