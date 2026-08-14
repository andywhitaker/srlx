# SR Linux `srlx` Multi-Node Command Executor

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`srlx` is a custom Nokia SR Linux CLI plugin and topology management suite that enables network operators to execute CLI commands across neighboring SR Linux switches directly from their terminal prompt.

It includes a lightweight background daemon (`srlx-daemon.py`) managed by SR Linux `appmgr` that performs **realtime LLDP event subscriptions**, validates direct **Mutual TLS (mTLS)** reachability, and gossips node information across the fabric to maintain a resilient mesh topology view.

---

## Key Features & Highlights

- **Execute Commands From Any Node To Any / All Nodes**: srlx allows you to send any command to any or all devices and returns the output to you. No need to log into multiple devices to quickly see what another device sees!
- **Realtime LLDP Event Subscriptions**: Detects local LLDP neighbor events in **sub-millisecond time** via local Unix socket gNMI streaming.
- **Topology Gossip Engine**: Exchanges nodes over mTLS JSON-RPC across fabric peers to learn nodes multiple hops away.
- **Strict Mutual TLS (mTLS) Security**: Enforces 2-way certificate validation, protecting administrative credentials from untrusted or unmanaged devices.
- **YANG State Datastore Integration**: Exposes `/srlx/node` in SR Linux's state datastore.

---

## 🚀 Quickstart

Get a 5-node linear mesh topology up and running in minutes using the bundled Containerlab test topology:

![SRLX Test Topology](lab/lab_topology.png)

### 1. Get the SRLX Package
Download the latest `.deb` package from GitHub Releases or build it locally from source:

```bash
./build-deb.sh
```

### 2. Generate Lab CA & Deploy Topology
Generate the CA certificates using Containerlab, and deploy the test topology:

```bash
# Generate CA certificate into lab/tls/
containerlab tools cert ca create -p lab/tls

# Deploy the 5-node test topology
containerlab deploy -t lab/srlx-test.clab.yaml
```

### 3. Install `srlx` on the Switches
Copy the package to all switches in the topology and install:

```bash
for node in srl1 srl2 srl3 srl4 srl5; do
  docker cp srlx_0.0.2.deb $node:/tmp/srlx_0.0.2.deb
  docker exec $node dpkg -i /tmp/srlx_0.0.2.deb
done
```

> [!NOTE]
> If you were already connected to an active `sr_cli` session before installing, disconnect and reconnect so the CLI loads the newly registered `srlx` plugins.

### 4. Verify Mesh Discovery & Run Commands
Connect to any switch CLI (e.g. `srl1`):

```bash
docker exec -it srl1 sr_cli
```

1. **Verify Discovered Topology**:
   ```text
   A:root@srl1# show srlx devices
   ```
   *Within seconds, all 5 nodes are automatically discovered across direct LLDP neighbors and multi-hop gossip mesh with `mTLS OK` status.*

2. **Execute First Multi-Node Command**:
   ```text
   A:root@srl1# srlx show version
   ```
   *Or request structured JSON across all switches:*
   ```text
   A:root@srl1# srlx show version | as json
   ```

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

### Automated mTLS Setup & Containerlab
`srlx` automatically resolves certificates across Containerlab and production environments:

1. **Generate the Lab CA**: In your lab directory, create the lab CA using Containerlab's built-in tool:
   ```bash
   sudo containerlab tools cert ca create -p tls
   ```
2. **Configure Topology YAML**: Add the `settings` block and the CA bind mount under `kinds -> nokia_srlinux` in your topology file (`<lab-name>.clab.yaml`):
   ```yaml
   settings:
     certificate-authority:
       cert: tls/ca.pem
       key: tls/ca.key

   topology:
     kinds:
       nokia_srlinux:
         binds:
           - tls/ca.pem:/etc/opt/srlinux/tls/ca.pem:ro
   ```
3. **Deploy & Install Package**: Deploy the lab (`sudo clab deploy -t ...`) and install `srlx` (`dpkg -i srlx_0.0.2.deb`). The post-installation script automatically detects the active TLS profile (`clab-profile` or `__default__`), configures the trust anchor from `/etc/opt/srlinux/tls/ca.pem`, enables client authentication (`authenticate-client true`), and reloads the JSON-RPC listener.

### Manual SR Linux CLI Configuration
If configuring SR Linux manually via `sr_cli`:

```text
A:admin@leaf1# enter candidate
A:admin@leaf1# set /system tls profile clab-profile trust-anchor "-----BEGIN CERTIFICATE-----
...<CA PEM Content>...
-----END CERTIFICATE-----"
A:admin@leaf1# set /system tls profile clab-profile authenticate-client true
A:admin@leaf1# commit stay
```

### Dynamic Certificate Discovery Hierarchy
`srlx` automatically resolves certificates in the following priority order:
- **CA Trust Bundle**: `$SRLX_CA_CERT` $\to$ `~/.srlx.json` (`ca_cert`) $\to$ `/etc/opt/srlinux/tls/ca.pem`
- **Node Certificate & Key**: `$SRLX_CLIENT_CERT` / `$SRLX_CLIENT_KEY` $\to$ `clab-profile` (`.pem`/`.key.pem`) $\to$ `__default__` (`.pem`/`.key.pem`) $\to$ auto-pairing any matching certificate/key in `/etc/opt/srlinux/tls/`

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

### 2. `show srlx device <device_name> detail`
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
 mTLS Security State   : Verified (CA: ca.pem, Profile: clab-profile, TLSv1.3)
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

### 4. Output Format Modifiers (`| as json`, `| as yaml`, `| as table`)
`srlx` integrates natively with the SR Linux CLI output format modifier pipeline:

- **Targeted or Fabric Remote Execution as JSON**:
  ```text
  A:admin@srl1# srlx srl3 srl5 show version | as json
  {
    "srl3": {
      "basic system info": {
        "Hostname": "srl3",
        "OS": "SR Linux",
        "Software Version": "v26.7.1"
      }
    },
    "srl5": {
      "basic system info": {
        "Hostname": "srl5",
        "OS": "SR Linux",
        "Software Version": "v26.7.1"
      }
    }
  }
  ```

- **Fabric Remote Execution as YAML**:
  ```text
  A:admin@srl1# srlx srl3 info interface ethernet-1/1 | as yaml
  ---
  # Device: srl3
  ---
  name: ethernet-1/1
  admin-state: enable
  ```

- **Topology Database as JSON or YAML**:
  ```text
  A:admin@srl1# show srlx devices | as json
  A:admin@srl1# show srlx device srl5 detail | as json
  ```

### 5. Clear Topology Cache
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
*Generates `srlx_0.0.2.deb` in the current directory.*

### 2. Deploy to Switches
Copy and install the package on target SR Linux switches:

```bash
dpkg -i srlx_0.0.2.deb
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
