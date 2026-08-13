# SR Linux `srlx` Multi-Node Command Executor

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`srlx` is a custom Nokia SR Linux CLI plugin and topology management suite that enables network operators to execute CLI commands across neighboring SR Linux switches directly from their terminal prompt **with zero local command leakage**.

It includes a lightweight background daemon (`srlx-daemon.py`) managed by SR Linux `appmgr` that performs **realtime LLDP event subscriptions**, validates direct **Mutual TLS (mTLS)** reachability, and gossips node information across the fabric to maintain a resilient mesh topology view.

---

## Key Features & Highlights

- **Realtime LLDP Event Subscriptions**: Detects local LLDP neighbor events in **sub-millisecond time** via local Unix socket gNMI streaming.
- **Topology Gossip Engine**: Exchanges nodes over mTLS JSON-RPC across fabric peers to learn nodes multiple hops away.
- **Strict Mutual TLS (mTLS) Security**: Enforces 2-way certificate validation, protecting administrative credentials from untrusted or unmanaged devices.
- **YANG State Datastore Integration**: Exposes `/srlx/node` in SR Linux's state datastore.

---

## CLI Menu Hierarchy

- **Show Mode (`show srlx ...`)**:
  - `show srlx devices`: Displays a formatted ASCII table of all fabric switches, management IP addresses, learning method (`Learned Via`: `Direct` / `Mesh` / `Local`), `Direct Reporters`, `Mesh Reporters`, reachability status (`Reachable`: `mTLS OK` / `Unreachable` / `Local`), and last update time.
  - `show srlx device <device_name>`: Displays detailed topology attribution, LLDP reporters, and security telemetry for a specific switch.
  - `show srlx device <device_name> detail`: Displays detailed attribution, management IP, VRF, `Learned Via`, `Direct Reporters`, `Mesh Reporters`, `Reachable`, and mTLS security state.

- **Tools Mode (`tools srlx ...`)**:
  - `tools srlx clear all`: Flushes the local topology cache and triggers fresh discovery scan.
  - `tools srlx clear device <device_name>`: Clears a specific device locally and forces immediate re-validation.

- **Remote Execution (`srlx [devices...] <command...>`)**:
  - Execute commands across target switch(es).
  - Auto-completes available switch hostnames (including local switch) as well as full remote CLI commands and YANG schema arguments.

---

## 🔒 Mutual TLS (mTLS) Security & Configuration

### Why mTLS Matters
LLDP and L2 discovery protocols are unauthenticated. Firing HTTP Basic Authentication requests to unverified LLDP neighbor IP addresses leaks administrative credentials to unmanaged or rogue devices.

`srlx` solves this by enforcing **2-way Mutual TLS (mTLS)**:
- The client validates the server's certificate against the trusted Root CA (`ca.pem`). If untrusted, the client aborts the connection (Exit Code 60) **before sending any HTTP headers or credentials**.
- The server validates the client's certificate before accepting the connection.

### Automated mTLS Setup (Build Process Simplification)
When installing the Debian package (`dpkg -i srlx_0.0.1.deb`), the post-installation script automatically configures SR Linux's TLS profile (`clab-profile`) to require client certificate authentication (`authenticate-client true`).

### Manual SR Linux CLI Configuration
If configuring SR Linux manually, execute the following commands in `sr_cli`:

```text
A:admin@leaf1# enter candidate
A:admin@leaf1# set /system tls profile clab-profile trust-anchor ca.pem
A:admin@leaf1# set /system tls profile clab-profile authenticate-client true
A:admin@leaf1# commit stay
```

### Certificate Paths
`srlx` uses standard SR Linux TLS certificate paths out of the box:
- **CA Trust Bundle**: `/etc/opt/srlinux/tls/ca.pem`
- **Node Certificate**: `/etc/opt/srlinux/tls/clab-profile.pem`
- **Node Private Key**: `/etc/opt/srlinux/tls/clab-profile.key.pem`

---

## Usage Examples

### 1. `show srlx devices`
Lists all known switches in the mesh, reachability status, management IPv4 address, direct reporters, mesh reporters, and learning attribution:

```text
A:admin@leaf1# show srlx devices

======================================================================================================
 SRLX Discovered Fabric Topology (6 Nodes Discovered)
======================================================================================================
+=============+==============+=============+============================+================-----+===========+===========+
| Device Name | Mgmt IP      | Learned Via | Direct Reporters           | Mesh Reporters      | Reachable | Last Seen |
+=============+==============+=============+============================+================-----+===========+===========+
| leaf2       | 172.20.20.3  | Mesh        | spine1, spine2             | leaf3, leaf4        | mTLS OK   | 6s ago    |
| leaf3       | 172.20.20.14 | Mesh        | spine1, spine2             | leaf2, leaf4        | mTLS OK   | 6s ago    |
| leaf4       | 172.20.20.15 | Mesh        | spine1, spine2             | leaf2, leaf3        | mTLS OK   | 6s ago    |
| spine1      | 172.20.20.8  | Direct      | leaf1, leaf2, leaf3, leaf4 | spine2              | mTLS OK   | 6s ago    |
| spine2      | 172.20.20.2  | Direct      | leaf1, leaf2, leaf3, leaf4 | spine1              | mTLS OK   | 6s ago    |
| leaf1       | 172.20.20.7  | Local       | spine1, spine2             | leaf2, leaf3, leaf4 | Local     | Local     |
+-------------+--------------+-------------+----------------------------+---------------------+-----------+-----------+
```

### 2. `show srlx device <device_name>`
Displays detailed attribution, management IPv4 address, direct reporters, mesh reporters, and security state for a single device:

```text
A:admin@leaf1# show srlx device leaf1 detail

======================================================================
 Device Detail: leaf1
======================================================================
 Management Address    : 172.20.20.7
 Network Instance / VRF: mgmt
 Learned Via           : Local
 Reachable             : Local
 Direct Reporters      : spine1, spine2
 Mesh Reporters        : leaf2, leaf3, leaf4
 mTLS Security State   : Verified (CA: clab-profile, TLSv1.3)
======================================================================
```

### 3. Standalone Remote Execution (`srlx`)
Execute CLI commands across remote switches without local command execution:

```text
A:admin@leaf1# srlx leaf2 spine1 show version
======================================================================
 Remote Execution: leaf2 (srlx)
======================================================================
Hostname         : leaf2
Chassis Type     : 7220 IXR-D2
OS Version       : v24.10.1
======================================================================

======================================================================
 Remote Execution: spine1 (srlx)
======================================================================
Hostname         : spine1
Chassis Type     : 7220 IXR-D3
OS Version       : v24.10.1
======================================================================
```

### 4. Clear Topology Cache
Purge a specific device or flush the local topology graph:

```text
A:admin@leaf1# tools srlx clear device leaf2
Device 'leaf2' cleared from local SRLX topology cache.

A:admin@leaf1# tools srlx clear all
Local SRLX topology cache cleared. Triggering re-discovery scan...
```

---

## Installation & Deployment

### 1. Build Debian Package (`.deb`)
Package the suite into a clean, standalone Debian archive using Docker and nFPM:

```bash
./build-deb.sh
```
*Generates `srlx_0.0.1.deb` in the current directory.*

### 2. Deploy to Switches
Copy and install the package on target SR Linux switches:

```bash
dpkg -i srlx_0.0.1.deb
```
*The installer automatically links CLI plugins, configures mTLS client authentication, reloads `app_mgr`, and launches the daemon.*

### 3. Reload CLI Session
Exit your active SR Linux CLI session and log back in to load the plugin into `sr_cli`:

```text
A:admin@leaf1# quit
ssh admin@leaf1
```

---

## License

This project is licensed under the [MIT License](LICENSE) - feel free to use, modify, fork, and distribute it.
