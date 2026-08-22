# SRLX Architecture & Development Rules

Guidelines, invariants, and constraints for developing and maintaining the SRLX multi-node topology mesh and command execution suite on Nokia SR Linux.

---

## 1. Real-Time Topology & Zero Polling
- **100% Event-Driven Push**: Never use background polling loops or timer-based periodic state polling for topology discovery or neighbor reachability.
- **NDK Event Streaming**: Use SR Linux Native Development Kit (NDK) gRPC streaming (`NotificationStream`) for sub-millisecond LLDP and interface event notifications.
- **Hop-by-Hop mTLS Push Gossip**: Propagate topology changes in real-time across direct LLDP peers over mutual TLS on port `58080` (or `SRLX_GOSSIP_PORT`) with split-horizon flooding.

---

## 2. Zero Shell / Subprocess Execution
- **Pure In-Process Networking**: Never use `subprocess.run`, `subprocess.Popen`, `os.system`, `os.popen`, or shell wrappers in the daemon (`srlx-daemon.py`) or CLI plugin (`srlx.py`).
- **In-Process Network Namespace Switching**: Switch network namespaces strictly in-process using direct libc `setns(CLONE_NEWNET)` syscalls via `ctypes.CDLL("libc.so.6")`.

---

## 3. CLI Callout Restrictions & JSON-RPC Method Isolation
- **No CLI Callouts for Internal State**: Never execute commands via CLI callouts, screen-scraping, or JSON-RPC `method: "cli"` to query local state or topology.
- **Allowed JSON-RPC Methods**:
  - Local state discovery fallback: `method: "get"`.
  - Local CPM ACL filter configuration: `method: "set"`.
  - Native datastore publishing: NDK `TelemetryAddOrUpdate`.
- **Sole Exception for `method: "cli"`**: JSON-RPC `method: "cli"` is strictly reserved for executing remote user-typed CLI commands on target fabric switches during `srlx <command>` execution.

---

## 4. Zero Hardcoded Topology, VRF, or Environment Data
- **Dynamic Management VRF**: Dynamically query `/network-instance` to detect which network instance `mgmt0` / `mgmt0.0` is bound to, falling back to `mgmt`, `management`, or `default`.
- **Dynamic Interface-to-VRF Mapping**: Map incoming LLDP interface events (e.g. `ethernet-1/1`) dynamically to their respective network instances.
- **Dynamic CPM ACL Allocation**: Inspect existing `/acl/acl-filter[name=cpm]` entries to allocate non-conflicting sequence IDs dynamically instead of hardcoding entry numbers.
- **Dynamic Gossip Listeners**: Bind in-process mTLS gossip server listeners for all discovered active network instances on the switch.

---

## 5. Topology State Retention & Manual Clear Behavior
- **No Automatic Pruning on LLDP Loss**: When an LLDP neighbor stops advertising or a link drops, do not delete the device from the topology table. Transition reachability to `"Mesh Reachable"` (if reported by others) or `"Unreachable"`.
- **Manual Clear Only**: Devices are removed from the topology state table only when explicitly cleared by the user via `tools srlx clear device <node>` or `tools srlx clear all`.
- **Immediate Reseed on Clear**: When a clear command is executed, immediately re-populate active direct LLDP neighbors from the local state datastore / cache and trigger an immediate gossip sync cascade to restore the multi-hop mesh.

---

## 6. Build & Test Workflow
- **Package Build**: `./build-deb.sh` (produces `srlx_0.0.6.deb`).
- **Lab Deployment**: `clab deploy -c -t lab/srlx-test.clab.yaml` (run directly without sudo).
- **Package Installation**: Install across test nodes using:
  ```bash
  for node in srl1 srl2 srl3 srl4 srl5; do
    docker cp srlx_0.0.6.deb $node:/tmp/
    docker exec $node dpkg -i /tmp/srlx_0.0.6.deb
  done
  ```
- **Verification**: Verify topology and reporters with `sr_cli "show srlx devices"` and test multi-node execution with `sr_cli "srlx show version"`.
