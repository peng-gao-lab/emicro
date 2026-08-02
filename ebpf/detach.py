from helper import try_, detach_tc
from pyroute2 import NetNS, IPRoute

import docker
import os
import sys

if len(sys.argv) != 2:
    print("Usage: python detach.py <network_name>")
    sys.exit(1)

network_name = sys.argv[1]

try_(os.unlink, "/sys/fs/bpf/access_control")
try_(os.unlink, "/sys/fs/bpf/conn_to_state_ingress")
try_(os.unlink, "/sys/fs/bpf/conn_to_state_egress")
try_(os.unlink, "/sys/fs/bpf/pid_to_state")

client = docker.from_env()
network = client.networks.get(network_name)
host_iface = "br-" + network.attrs["Id"][:12]

detach_tc("", host_iface)

for i,container in enumerate(client.containers.list()):
    ns_path = container.attrs['NetworkSettings']['SandboxKey']
    detach_tc(ns_path, "eth0")
