#!/usr/bin/env /opt/srlinux/python/virtual-env/bin/python3
import json
import os
import re
import select
import socket
import socketserver
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

DAEMON_SOCKET_PATH = "/var/run/srlx-daemon.sock"

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

class TopologyGraph:
    def __init__(self, local_hostname):
        self.local_hostname = local_hostname
        self.lock = threading.Lock()
        self.nodes = {}
        self._init_local_node()

    def _init_local_node(self):
        with self.lock:
            local_ip = resolve_management_ip(self.local_hostname)
            self.nodes[self.local_hostname] = {
                "mgmt_addrs": [local_ip],
                "netns": "mgmt",
                "reporters": {self.local_hostname: {"type": "direct", "timestamp": time.time()}},
                "status": "Local",
                "last_updated": time.time(),
                "last_probe_ok": time.time()
            }

    def update_direct_lldp(self, raw_neighbors, port_to_netns):
        now = time.time()
        with self.lock:
            current_direct_names = set()
            for neigh in raw_neighbors:
                sys_name = neigh.get("system_name")
                if not sys_name:
                    continue

                current_direct_names.add(sys_name)
                mgmt_addrs_raw = neigh.get("mgmt_addrs", [])
                clean_addrs = [resolve_management_ip(a) for a in mgmt_addrs_raw if IS_IPV4_RE.match(resolve_management_ip(a))]
                if not clean_addrs:
                    clean_addrs = [resolve_management_ip(sys_name)]

                local_port = neigh.get("local_port", "")
                netns = port_to_netns.get(local_port, "mgmt")

                if sys_name not in self.nodes:
                    self.nodes[sys_name] = {
                        "mgmt_addrs": clean_addrs,
                        "netns": netns,
                        "reporters": {},
                        "status": "Direct mTLS OK",
                        "last_updated": now,
                        "last_probe_ok": now
                    }
                else:
                    if clean_addrs and IS_IPV4_RE.match(clean_addrs[0]):
                        self.nodes[sys_name]["mgmt_addrs"] = clean_addrs
                    self.nodes[sys_name]["netns"] = netns
                    self.nodes[sys_name]["status"] = "Direct mTLS OK"

                self.nodes[sys_name]["reporters"][self.local_hostname] = {"type": "direct", "timestamp": now}
                self.nodes[sys_name]["last_updated"] = now
                self.nodes[sys_name]["last_probe_ok"] = now

            # Clean up local_hostname from reporters for switches no longer in LLDP
            for dev_name, data in list(self.nodes.items()):
                if dev_name == self.local_hostname:
                    continue
                if dev_name not in current_direct_names:
                    data.get("reporters", {}).pop(self.local_hostname, None)

    def merge_remote_vector(self, remote_node, vector):
        now = time.time()
        with self.lock:
            remote_nodes = vector.get("nodes", {})
            for dev_name, rdata in remote_nodes.items():
                r_direct = rdata.get("direct_reporters", [])
                r_mesh = rdata.get("mesh_reporters", [])
                r_mgmt_raw = rdata.get("mgmt_addrs", [])
                clean_mgmt = [resolve_management_ip(m) for m in r_mgmt_raw if IS_IPV4_RE.match(resolve_management_ip(m))]
                if not clean_mgmt:
                    clean_mgmt = [resolve_management_ip(dev_name)]
                r_netns = rdata.get("netns", "mgmt")

                if dev_name not in self.nodes:
                    self.nodes[dev_name] = {
                        "mgmt_addrs": clean_mgmt,
                        "netns": r_netns,
                        "reporters": {},
                        "status": "Local" if dev_name == self.local_hostname else "Mesh Reachable",
                        "last_updated": now,
                        "last_probe_ok": now if dev_name == self.local_hostname else 0.0
                    }

                # 1. Merge direct reporters reported by remote node
                for dr in r_direct:
                    if dr != dev_name:
                        self.nodes[dev_name]["reporters"][dr] = {"type": "direct", "timestamp": now}

                # 2. Merge mesh reporters reported by remote node (if not already recorded as direct)
                for mr in r_mesh:
                    if mr != dev_name:
                        if mr not in self.nodes[dev_name]["reporters"] or self.nodes[dev_name]["reporters"][mr]["type"] != "direct":
                            self.nodes[dev_name]["reporters"][mr] = {"type": "mesh", "timestamp": now}

                # 3. Also record remote_node itself as a reporter if it sent us this node
                if remote_node != dev_name and remote_node not in self.nodes[dev_name]["reporters"]:
                    self.nodes[dev_name]["reporters"][remote_node] = {"type": "mesh", "timestamp": now}

                if clean_mgmt and IS_IPV4_RE.match(clean_mgmt[0]) and dev_name != self.local_hostname:
                    self.nodes[dev_name]["mgmt_addrs"] = clean_mgmt
                if dev_name != self.local_hostname:
                    self.nodes[dev_name]["last_updated"] = now

    def evaluate_reachability_and_purge(self, probe_func):
        now = time.time()
        nodes_to_probe = []
        with self.lock:
            for dev_name, data in list(self.nodes.items()):
                if dev_name == self.local_hostname:
                    continue

                # Remove stale reporters (>90s old)
                stale_reporters = [r for r, info in data.get("reporters", {}).items() if now - info.get("timestamp", 0) > 90]
                for r in stale_reporters:
                    data["reporters"].pop(r, None)

                # Deletion Safeguard Algorithm:
                # If no reporters report this node, probe directly before purging
                if not data["reporters"]:
                    nodes_to_probe.append((dev_name, data["mgmt_addrs"], data["netns"]))

        # Execute direct probes outside lock
        for dev_name, mgmt_addrs, netns in nodes_to_probe:
            target_host = mgmt_addrs[0] if mgmt_addrs else dev_name
            is_ok = probe_func(target_host, netns)
            with self.lock:
                if dev_name in self.nodes:
                    if is_ok:
                        self.nodes[dev_name]["status"] = "Direct mTLS OK"
                        self.nodes[dev_name]["last_probe_ok"] = time.time()
                        self.nodes[dev_name]["reporters"][self.local_hostname] = {"type": "direct", "timestamp": time.time()}
                    else:
                        # Direct probe failed and no reporters -> Purge or mark Unreachable
                        if now - self.nodes[dev_name].get("last_updated", 0) > 60:
                            del self.nodes[dev_name]
                        else:
                            self.nodes[dev_name]["status"] = "Unreachable"

    def clear_device(self, dev_name):
        with self.lock:
            if dev_name in self.nodes and dev_name != self.local_hostname:
                del self.nodes[dev_name]
                return True
            return False

    def clear_all(self):
        with self.lock:
            keys = [k for k in self.nodes.keys() if k != self.local_hostname]
            for k in keys:
                del self.nodes[k]

    def export_vector(self):
        with self.lock:
            nodes_export = {}
            for dev_name, data in self.nodes.items():
                reporters_dict = data.get("reporters", {})
                direct_reporters = [r for r, info in reporters_dict.items() if info.get("type") == "direct"]
                mesh_reporters = [r for r, info in reporters_dict.items() if info.get("type") == "mesh"]

                if dev_name == self.local_hostname:
                    learned_via = "Local"
                    reachable = "Local"
                elif self.local_hostname in direct_reporters or len(direct_reporters) > 0:
                    learned_via = "Direct" if self.local_hostname in direct_reporters else "Mesh"
                    reachable = "Unreachable" if data["status"] == "Unreachable" else "mTLS OK"
                else:
                    learned_via = "Mesh"
                    reachable = "Unreachable" if data["status"] == "Unreachable" else "mTLS OK"

                nodes_export[dev_name] = {
                    "mgmt_addrs": data["mgmt_addrs"],
                    "netns": data["netns"],
                    "direct_reporters": direct_reporters,
                    "mesh_reporters": mesh_reporters,
                    "learned_via": learned_via,
                    "status": reachable,
                    "last_updated": data["last_updated"]
                }

            return {
                "protocol": "srlx-gossip/v1",
                "origin_node": self.local_hostname,
                "timestamp": time.time(),
                "nodes": nodes_export
            }

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

def exec_curl_jsonrpc(host, commands, netns="mgmt", timeout=5):
    target_netns = f"srbase-{netns}" if netns != "default" else "srbase"
    auth_flags = get_auth_curl_flags()
    tls_info = resolve_tls_certificates()
    is_local = host in ("127.0.0.1", "localhost", "::1")

    if is_local:
        cmd_args = [
            "sudo", "-n", "ip", "netns", "exec", target_netns,
            "curl", "-s"
        ] + auth_flags + [
            "-X", "POST", "http://127.0.0.1:80/jsonrpc",
            "-H", "Content-Type: application/json",
            "-d", json.dumps({"jsonrpc": "2.0", "id": 1, "method": "get", "params": {"commands": commands}})
        ]
        try:
            res = subprocess.check_output(cmd_args, stderr=subprocess.DEVNULL, timeout=timeout)
            data = json.loads(res.decode())
            if "result" in data:
                return data["result"]
        except Exception:
            pass

        cmd_args_ssl = [
            "sudo", "-n", "ip", "netns", "exec", target_netns,
            "curl", "-k", "-s"
        ] + auth_flags + [
            "-X", "POST", "https://127.0.0.1:443/jsonrpc",
            "-H", "Content-Type: application/json",
            "-d", json.dumps({"jsonrpc": "2.0", "id": 1, "method": "get", "params": {"commands": commands}})
        ]
        try:
            res = subprocess.check_output(cmd_args_ssl, stderr=subprocess.DEVNULL, timeout=timeout)
            return json.loads(res.decode()).get("result", [])
        except Exception:
            return []

    ca_file = tls_info.get("ca_cert")
    if not ca_file:
        return []

    cmd_args = [
        "sudo", "-n", "ip", "netns", "exec", target_netns,
        "curl", "-s",
        "--cacert", ca_file
    ]
    if tls_info.get("client_cert") and tls_info.get("client_key"):
        cmd_args.extend(["--cert", tls_info["client_cert"], "--key", tls_info["client_key"]])
    cmd_args.extend(auth_flags)
    cmd_args.extend([
        "-X", "POST", f"https://{host}/jsonrpc",
        "-H", "Content-Type: application/json",
        "-d", json.dumps({"jsonrpc": "2.0", "id": 1, "method": "get", "params": {"commands": commands}})
    ])
    try:
        res = subprocess.check_output(cmd_args, stderr=subprocess.DEVNULL, timeout=timeout)
        return json.loads(res.decode()).get("result", [])
    except Exception:
        return []

def get_local_hostname():
    res = exec_curl_jsonrpc("127.0.0.1", [{"path": "/system/name", "datastore": "state"}])
    if res and isinstance(res[0], dict) and "host-name" in res[0]:
        return res[0]["host-name"]
    return socket.gethostname()

def probe_mtls_reachability(host, netns="mgmt"):
    res = exec_curl_jsonrpc(host, [{"path": "/system/name", "datastore": "state"}], netns=netns, timeout=3)
    if res:
        return True
    if netns != "mgmt":
        res_mgmt = exec_curl_jsonrpc(host, [{"path": "/system/name", "datastore": "state"}], netns="mgmt", timeout=3)
        return len(res_mgmt) > 0
    return False

def fetch_remote_vector(host, netns="mgmt"):
    cmd_str = "bash /opt/srlinux/python/virtual-env/bin/python3 /opt/srlx/bin/get_vector.py"
    target_netns = f"srbase-{netns}" if netns != "default" else "srbase"
    auth_flags = get_auth_curl_flags()
    tls_info = resolve_tls_certificates()
    is_local = host in ("127.0.0.1", "localhost", "::1")

    if is_local:
        cmd_args = [
            "sudo", "-n", "ip", "netns", "exec", target_netns,
            "curl", "-s"
        ] + auth_flags + [
            "-X", "POST", "http://127.0.0.1:80/jsonrpc",
            "-H", "Content-Type: application/json",
            "-d", json.dumps({"jsonrpc": "2.0", "id": 1, "method": "cli", "params": {"commands": [cmd_str], "output-format": "text"}})
        ]
        try:
            res = subprocess.check_output(cmd_args, stderr=subprocess.DEVNULL, timeout=5)
            data = json.loads(res.decode())
            if "result" in data and data["result"]:
                parsed = json.loads(data["result"][0].strip())
                if parsed.get("status") == "ok":
                    return parsed.get("vector")
        except Exception:
            pass
        return None

    ca_file = tls_info.get("ca_cert")
    if not ca_file:
        return None

    cmd_args = [
        "sudo", "-n", "ip", "netns", "exec", target_netns,
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
                "commands": [cmd_str],
                "output-format": "text"
            }
        })
    ])
    try:
        res = subprocess.check_output(cmd_args, stderr=subprocess.DEVNULL, timeout=5)
        data = json.loads(res.decode())
        if "result" in data and data["result"]:
            raw_out = data["result"][0]
            parsed = json.loads(raw_out.strip())
            if parsed.get("status") == "ok":
                return parsed.get("vector")
    except Exception:
        pass

    if netns != "mgmt":
        return fetch_remote_vector(host, netns="mgmt")

    return None

class SRLXDaemon:
    def __init__(self):
        self.local_hostname = get_local_hostname()
        self.graph = TopologyGraph(self.local_hostname)
        self.running = True

    def scan_local_lldp(self):
        try:
            results = exec_curl_jsonrpc("127.0.0.1", [
                {"path": "/network-instance", "datastore": "state"},
                {"path": "/system/lldp/interface", "datastore": "state"}
            ])

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
                        mgmt_addrs = [m.get("address") for m in neigh.get("management-address", []) if m.get("address")]
                        raw_neighbors.append({
                            "local_port": local_port,
                            "system_name": sys_name,
                            "mgmt_addrs": mgmt_addrs
                        })

            self.graph.update_direct_lldp(raw_neighbors, port_to_netns)
        except Exception as e:
            pass

    def gossip_sync_round(self):
        local_vector = self.graph.export_vector()
        current_nodes = list(local_vector["nodes"].items())

        def _sync_peer(peer_name, peer_data):
            if peer_name == self.local_hostname:
                return
            mgmt_addrs = peer_data.get("mgmt_addrs", [])
            target_host = mgmt_addrs[0] if mgmt_addrs else peer_name
            netns = peer_data.get("netns", "mgmt")

            remote_vector = fetch_remote_vector(target_host, netns=netns)
            if remote_vector:
                self.graph.merge_remote_vector(peer_name, remote_vector)

        with ThreadPoolExecutor(max_workers=10) as executor:
            for peer_name, peer_data in current_nodes:
                executor.submit(_sync_peer, peer_name, peer_data)

    def background_loop(self):
        while self.running:
            self.scan_local_lldp()
            self.graph.evaluate_reachability_and_purge(probe_mtls_reachability)
            self.gossip_sync_round()
            time.sleep(10)

    def handle_unix_client(self, client_sock):
        try:
            raw_data = client_sock.recv(4096).decode().strip()
            if not raw_data:
                client_sock.close()
                return

            req = json.loads(raw_data)
            action = req.get("action")

            if action == "get_devices":
                vector = self.graph.export_vector()
                resp = {"status": "ok", "vector": vector}
            elif action == "clear_device":
                dev = req.get("device")
                ok = self.graph.clear_device(dev)
                resp = {"status": "ok" if ok else "error", "message": f"Device {dev} cleared" if ok else f"Device {dev} not found"}
            elif action == "clear_all":
                self.graph.clear_all()
                self.scan_local_lldp()
                resp = {"status": "ok", "message": "All devices cleared and re-scanned"}
            else:
                resp = {"status": "error", "message": f"Unknown action {action}"}

            client_sock.sendall(json.dumps(resp).encode() + b"\n")
        except Exception as e:
            try:
                client_sock.sendall(json.dumps({"status": "error", "message": str(e)}).encode() + b"\n")
            except Exception:
                pass
        finally:
            client_sock.close()

    def run_unix_socket_server(self):
        if os.path.exists(DAEMON_SOCKET_PATH):
            try:
                os.remove(DAEMON_SOCKET_PATH)
            except Exception:
                pass

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(DAEMON_SOCKET_PATH)
        os.chmod(DAEMON_SOCKET_PATH, 0o666)
        server.listen(10)

        while self.running:
            try:
                server.settimeout(2.0)
                try:
                    conn, _ = server.accept()
                    t = threading.Thread(target=self.handle_unix_client, args=(conn,))
                    t.daemon = True
                    t.start()
                except socket.timeout:
                    continue
            except Exception:
                pass

def main():
    daemon = SRLXDaemon()
    bg_thread = threading.Thread(target=daemon.background_loop)
    bg_thread.daemon = True
    bg_thread.start()

    daemon.run_unix_socket_server()

if __name__ == "__main__":
    main()
