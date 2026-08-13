# SR Linux `srlx` Standalone CLI Plugin

`srlx` is a custom Nokia SR Linux CLI plugin that enables network operators to execute CLI commands across neighboring SR Linux switches directly from their terminal prompt **with zero local execution leakage**.

It uses **LLDP neighbor & local discovery** to discover adjacent SR Linux switches and the local device, queries them concurrently over **JSON-RPC**, formats responses in native SR Linux ASCII tables, and enforces strict **Mutual TLS (mTLS)** to prevent credential leakage to untrusted devices.

---

## Features

- **Standalone Execution (`srlx [devices...] <command...>`)**: Execute commands directly on target switches with **zero local command leakage**.
- **Local Device Inclusion**: Includes the local switch (`127.0.0.1`) automatically when broadcasting commands or as an explicit target in device lists.
- **Flexible & Preserved Sorting**:
  - **Default (No devices specified)**: Displays remote neighbors in natural alphabetical order (`leaf2`, `leaf3`, `spine1`) with the **local device printed last**.
  - **Explicit Devices Specified**: Output is displayed in the **exact order device names are supplied** (e.g. `srlx leaf3 leaf1 spine1 show version`).
- **Dynamic Tab Completion & Deduplication**: Auto-completes available switch hostnames (including the local switch) as well as full remote CLI commands and YANG schema arguments.
- **High-Speed Parallel Streaming**: Dispatches requests concurrently using Python's `ThreadPoolExecutor` and streams output back sequentially.
- **Native Table Output**: Returns human-readable CLI table formatting by requesting `"output-format": "text"` over JSON-RPC.
- **Strict Mutual TLS (mTLS) Security**: Requires 2-way certificate validation, protecting administrative credentials from untrusted or unmanaged devices.

---

## Architecture & Workflow

```
+------------------+         LLDP Discovery        +------------------+
|      leaf1       | ----------------------------> |      spine1      |
|  (CLI / srlx)    |                               |  (JSON-RPC / 443)|
+------------------+                               +------------------+
         |                                                   ^
         |              mTLS HTTPS JSON-RPC Request          |
         +---------------------------------------------------+
             1. Verify Server Cert against CA Trust Bundle
             2. Present Client Cert signed by Trusted CA
             3. Execute Command & Stream Formatted Output
```

---

## Device Configuration Prerequisites

To enable execution via `srlx`, apply the following configurations to all managed SR Linux switches in your topology:

### 1. Enable LLDP Management Address Advertising
Ensure switches advertise their management IPv4 addresses in their LLDP TLVs so neighbors can determine their HTTPS IP endpoints.

```text
--{ candidate shared default }--[ ]--
set /system lldp management-address mgmt0.0 type [ IPv4 ]
commit stay
```

### 2. Verify JSON-RPC Server State
Verify that the JSON-RPC server is enabled and bound to the management network-instance:

```text
--{ candidate shared default }--[ ]--
set /system json-rpc-server admin-state enable
set /system json-rpc-server network-instance mgmt
set /system json-rpc-server http admin-state disable
set /system json-rpc-server https admin-state enable
set /system json-rpc-server https tls-profile clab-profile
commit stay
```

---

## Mutual TLS (mTLS) Security Configuration

### Why mTLS is Required
LLDP is an unauthenticated Layer-2 protocol. If a rogue device is connected to a switch port, firing an unverified HTTP Basic Auth request to an LLDP IP address could leak administrative credentials. 

mTLS solves this by enforcing **2-way cryptographic verification**:
1. **Server Verification**: The client plugin verifies that the remote server's certificate is signed by your trusted Root CA before sending any HTTP headers or credentials.
2. **Client Verification**: The remote switch rejects any connection attempt unless the client presents a valid certificate signed by your trusted Root CA.

---

### Provisioning Certificates

#### In Production Environments
1. **Issue Certificates**: Generate node certificates (`<hostname>.pem`) and private keys (`<hostname>.key.pem`) signed by your Enterprise Private Certificate Authority (CA).
2. **Deploy Certificates**: Copy each node's certificate and key to `/etc/opt/srlinux/tls/`.
3. **CA Trust Bundle**: Concatenate all trusted Root/Intermediate CA certificates into a single trust bundle file at `/etc/opt/srlinux/tls/ca.pem`.

#### In Containerlab Environments
Containerlab **automatically generates** a private CA and provisions every container with CA-signed certificates on startup:
* **CA Trust Bundle**: `/home/awhitaker/dev/srlx/clab-srlx/.tls/ca/ca.pem` (Copy to `/etc/opt/srlinux/tls/ca.pem` on each node).
* **Node Certificate**: `/etc/opt/srlinux/tls/clab-profile.pem` (Pre-installed by Containerlab).
* **Node Private Key**: `/etc/opt/srlinux/tls/clab-profile.key.pem` (Pre-installed by Containerlab).

> *Multi-Lab Note:* If operating across multiple Containerlab deployments, concatenate all lab CA files into `/etc/opt/srlinux/tls/ca.pem` so nodes trust certificates across all labs.

---

### Enforcing mTLS on SR Linux Web Server
Configure the TLS server profile on each switch to demand client certificate authentication:

```text
--{ candidate shared default }--[ ]--
# 1. Update the TLS profile with the CA trust bundle and enforce client auth
set /system tls profile clab-profile trust-anchor "<CA_BUNDLE_PEM_CONTENTS>"
set /system tls profile clab-profile authenticate-client true
commit stay
```

---

## Credential Security & Multi-User Support

The `srlx` plugin contains **zero hardcoded passwords**. To support multi-user teams and different environments, credentials are dynamically resolved at runtime in the following priority order:

1. **Environment Variables**: `$SRLX_USER` and `$SRLX_PASS` (e.g. `export SRLX_USER="alice" SRLX_PASS="MySecret123!"`).
2. **POSIX Standard `~/.netrc`**: If present, `curl` reads credentials directly from `~/.netrc` (`chmod 600`).
3. **User JSON File (`~/.srlx.json`)**: If present, reads per-user credentials (`chmod 600`).
4. **Environment Defaults**: Defaults to `admin` / `NokiaSrl1!` if no custom credentials are set.

### Creating a Standard `~/.netrc` File
```bash
cat << 'EOF' > ~/.netrc
default login alice password MySecret123!
EOF
chmod 600 ~/.netrc
```

---

## Installation

1. **Deploy Plugin Script**:
   Copy `srlx.py` to `/etc/opt/srlinux/cli/plugins/srlx.py` on all target switches:
   ```bash
   cp srlx.py /etc/opt/srlinux/cli/plugins/srlx.py
   chmod 644 /etc/opt/srlinux/cli/plugins/srlx.py
   ```

2. **User Privileges**:
   Interactive CLI sessions run under non-root user `srlinux` (UID 1002). Ensure `sudo -n ip netns exec` is available (enabled by default on SR Linux).

3. **Reload CLI Session**:
   Exit your active SR Linux CLI session and log back in to load the new plugin into the CLI parser:
   ```text
   A:admin@leaf1# quit
   ssh admin@leaf1
   ```

---

## Usage Examples

### 1. Broadcast Command Across All Discovered Neighbors & Local Device
When no device is specified, `srlx` executes across all remote neighbors alphabetically and appends the local switch output last:

```text
A:admin@leaf1# srlx show version

======================================================================
 Device: leaf2 (IP: 172.20.20.3 | VRF/NetNS: mgmt | Port: mgmt0)
 Command: show version
======================================================================
...

======================================================================
 Device: spine1 (IP: 172.20.20.8 | VRF/NetNS: mgmt | Port: mgmt0)
 Command: show version
======================================================================
...

======================================================================
 Device: leaf1 (IP: 127.0.0.1 | VRF/NetNS: mgmt | Port: local)
 Command: show version
======================================================================
...
```

### 2. Multi-Device Execution in Specified Order
Specify target device names to execute the command across selected switches. Output is printed in the **exact order requested**:

```text
A:admin@leaf1# srlx leaf3 leaf1 spine1 show interface brief
```

---

## Troubleshooting

| Error | Root Cause | Solution |
| :--- | :--- | :--- |
| `Authentication Failed on <host>: Invalid username or password` | Credentials in `~/.netrc`, `$SRLX_USER`/`$SRLX_PASS`, or `~/.srlx.json` were rejected by remote node | Verify credentials in `~/.netrc` or environment variables |
| `Untrusted Server CA / mTLS Verification Failed` | Target node's TLS certificate is not signed by any CA in `/etc/opt/srlinux/tls/ca.pem` | Add target node's Root CA to `/etc/opt/srlinux/tls/ca.pem` trust bundle |
| `Client mTLS Verification Failed (Exit status 56)` | Target node enforces mTLS (`authenticate-client true`), but client didn't present CA-signed certificate | Verify client certificate (`/etc/opt/srlinux/tls/clab-profile.pem`) is present and valid |
| `No SRLinux devices discovered` | Remote neighbors are not advertising management IP addresses | Configure `set /system lldp management-address mgmt0.0 type [ IPv4 ]` on neighbors |
