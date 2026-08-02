from helper import attach_probe, attach_tc, insert_multihop_policy
from helper import BPFS, NAME_TO_LABEL, B

import docker
import sys

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 attach.py <policy filename> <network name>")
        sys.exit(1)

    filename = sys.argv[1]
    network_name = sys.argv[2]

    client = docker.from_env()
    network = client.networks.get(network_name)
    host_iface = "br-" + network.attrs["Id"][:12]

    attach_probe()
    attach_tc("", host_iface, 1, "HOST")

    for i,container in enumerate(client.containers.list()):
        ns_path = container.attrs['NetworkSettings']['SandboxKey']
        name = container.attrs['Config']['Labels']['com.docker.compose.service']
        pid = container.attrs['State']['Pid']
        ip = container.attrs['NetworkSettings']['Networks'][network_name]['IPAddress']
        NAME_TO_LABEL[name] = i + 2
        attach_tc(ns_path, "eth0", i + 2, name)
        print(f"Name: {name} PID: {pid}, IP: {ip}")

    insert_multihop_policy(filename)

    print("Monitoring incoming packets... Press Ctrl+C to exit.")
    while True:
        try:
            (_, _, _, _, _, msg) = BPFS[0].trace_fields()
            print(msg.decode('utf-8'), flush=True)
        except KeyboardInterrupt:
            print("Detaching eBPF programs...")
            break
