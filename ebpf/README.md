This folder contains the eBPF (tracing and policy enforcement) and Python (attaching to and detaching from kernel) programs of eMicro.

- `bpf_probe.c`, `bpf_tc.c`, `multihop.h` — the in-kernel tracing and enforcement programs.
- `attach.py` / `detach.py` (driven by the top-level `Makefile`) — attach or detach the eBPF programs to a running Docker network.
- `create_dfa.py` — compiles a policy file into the DFA (state/transition map) that the eBPF programs enforce. It reuses the policy-language compiler in [`../compiler/`](../compiler/), so the full language (`match` / `startswith` / `endswith` / `contains`, `and`/`or`, `allow`/`drop`) is supported; the parallel tree-reduction is replaced by a serial merge so the agent never spawns processes.
- `access_control/` — multi-hop policies written in the eMicro policy language. Service names are alphanumeric. The bundled files are `match(...) allow;` allow-lists (one exact allowed path per rule, deny-by-default). `multihop_toy.txt` is used by the quick-start toy example; `multihop_socialnetwork*.txt` and `multihop_media.txt` are provided for reference against the DeathStarBench workloads used in the paper.
