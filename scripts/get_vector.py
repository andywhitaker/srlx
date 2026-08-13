#!/usr/bin/env python3
import socket, json
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(2.0)
    s.connect("/var/run/srlx-daemon.sock")
    s.sendall(b"{\"action\":\"get_devices\"}\n")
    data = s.recv(16384).decode().strip()
    s.close()
    print(data)
except Exception as e:
    print(json.dumps({"status": "error", "message": str(e)}))
