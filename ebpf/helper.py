from ipaddress import ip_address
from create_dfa import create
from bcc import BPF

from pyroute2 import NetNS, IPRoute
import ctypes


BPFS = []
NAME_TO_LABEL = {"PUBLIC" : 1}
B = None

def attach_probe():
    global B
    B = BPF(src_file="ebpf/bpf_probe.c", cflags=["-w"])
    B.attach_kretprobe(event="inet_csk_accept", fn_name="kretprobe_inet_csk_accept")
    B.attach_kprobe(event="tcp_connect", fn_name="kprobe_tcp_connect")
    event_name = B.get_syscall_fnname("clone")
    B.attach_kretprobe(event=event_name, fn_name ="syscall_clone")

def attach_tc(ns, iface, id, container_name):
    if ns == "":
        n = IPRoute()
        idx = n.link_lookup(ifname=iface)[0]
    else:
        n = NetNS(ns)
        idx = n.link_lookup(ifname=iface)[0]

    with open("ebpf/bpf_tc.c", "r") as file:
        bpf_code = file.read().replace('#define CONTAINER_LABEL 1', f'#define CONTAINER_LABEL {id}').replace('#define CONTAINER_NAME "HOST"', f'#define CONTAINER_NAME "{container_name}"')
    b = BPF(text=bpf_code, cflags=["-w"])
    ingress = b.load_func("tc_ingress", BPF.SCHED_CLS)
    egress = b.load_func("tc_egress", BPF.SCHED_CLS)
    n.tc("add", "clsact", idx)
    if container_name != "HOST":
        n.tc("add-filter", "bpf", idx, ":1", fd=ingress.fd, name=ingress.name,
                    parent="ffff:fff2", action="ok", classid=1, direct_action=True)
    n.tc("add-filter", "bpf", idx, ":2", fd=egress.fd, name=egress.name,
            parent="ffff:fff3", action="ok", classid=1, direct_action=True)
    BPFS.append(b)

def detach_tc(ns, iface):
    if ns == "":
        n = IPRoute()
        idx = n.link_lookup(ifname=iface)[0]
    else:
        n = NetNS(ns)
        idx = n.link_lookup(ifname=iface)[0]
    try_(n.tc, "del", "clsact", idx)

def insert_multihop_policy(policy_file):
    access_control_map = B["access_control"]
    initial_state, states, transitions = create(policy_file)

    # State 0 is the initial ("START") state; every other live state is indexed
    # from 1 by its position in `states`.
    def state_index(name):
        return 0 if name == "START" else states.index(name) + 1

    print("---STATES---")
    print("0 : START_STATE")
    for i, state in enumerate(states):
        print(f"{i+1} : {state}")

    print("---ALPHABET---")
    for name, label in NAME_TO_LABEL.items():
        print(f"{label} : {name}")

    class KeyT(ctypes.Structure):
        _fields_ = [("st", ctypes.c_uint32), ("t", ctypes.c_uint32)]

    for k, v in transitions.items():
        for inp, next_state in v.items():
            key = KeyT()
            key.st = state_index(k)
            key.t = NAME_TO_LABEL[inp]
            value = ctypes.c_uint32(state_index(next_state))
            access_control_map[key] = value

def try_(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except:
        pass