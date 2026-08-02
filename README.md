<div align="center">

# eMicro

### Real-Time Multi-Hop Access Control for Microservices with eBPF

[![Conference](https://img.shields.io/badge/ACM%20CCS-2026-1f6feb.svg)](https://doi.org/10.1145/3830454.3832688)
[![DOI](https://img.shields.io/badge/DOI-10.1145%2F3830454.3832688-0b7285.svg)](https://doi.org/10.1145/3830454.3832688)
[![Venue](https://img.shields.io/badge/The%20Hague-Nov%2015--19%2C%202026-6f42c1.svg)](https://www.sigsac.org/ccs/CCS2026/)
[![License: CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by/4.0/)
[![eBPF](https://img.shields.io/badge/enforcement-eBPF-f9a825.svg)](https://ebpf.io/)

**[Paper](paper/emicro.pdf)** · **[Quick Start](#quick-start-toy-example)** · **[Architecture](#how-it-works)** · **[Citation](#citation)**

</div>

---

## Overview

Modern cloud applications comprise thousands of microservices whose interactions
form complex request paths. Traditional inter-service access control restricts
individual service-to-service requests, but fails to prevent **multi-hop
attacks** — where every hop appears legitimate yet the *overall path* violates
security intent. This gap leaves systems exposed to unauthorized access and data
exfiltration.

**eMicro** is a path-aware defense system that prevents such attacks while
remaining efficient and deployable. It enforces **real-time, end-to-end
multi-hop access control** through three key techniques:

1. **History-based access control** extended to capture full service-invocation
   *sequences*, not just adjacent hops.
2. **Deterministic Finite Automaton (DFA)** policy encoding that supports
   **constant-time** policy checks and compact label propagation.
3. **eBPF-based in-kernel request tracing** for transparent, low-overhead
   enforcement — **no application or library code changes required**.

### Highlights

| Metric | Result |
| --- | --- |
| Policy check latency | **~1 µs** (constant-time DFA lookup) |
| Policy storage | **50 million policies in 100 MB** |
| Label-propagation overhead | **reduced by ~90%** |
| Evaluation scale | **12M+ request workflows**, thousands of services |
| Deployment | Instrumentation-free, decentralized enforcement |

eMicro is evaluated on **[DeathStarBench](https://github.com/delimitrou/DeathStarBench)**
and on production cloud traces from **Uber, Alibaba, and ByteDance**.

---

## How It Works

eMicro combines a policy *language*, a *compiler*, and an eBPF *enforcement
layer* into an end-to-end pipeline:

```
  Multi-hop policies                Compact DFA                In-kernel enforcement
  (predicate rules)      ─────►     (state labels)    ─────►   (eBPF probes + TC)
   compiler/ · access_control/      ebpf/create_dfa.py         ebpf/bpf_probe.c
   *.txt                            (state/transition map)     ebpf/bpf_tc.c
```

### 1. Expressive multi-hop policy language
Instead of enumerating every valid request sequence (which causes *policy
explosion*), eMicro models benign workflows with path-level predicates and
logical operators that concisely capture security intent over intermediate
services. Policies are authored with predicates such as `startswith`,
`endswith`, `contains`, and `match`, combined with `and`/`or`, and terminate in
an `allow` or `drop` action. Service names are alphanumeric identifiers.

The simplest policy is an allow-list of exact service paths — one `match(...)
allow;` rule per path, with everything else denied by default. This is the form
used by the bundled policies in [`ebpf/access_control/`](ebpf/access_control/):

```text
match(PUBLIC, httpa, httpb, rpca) allow;
match(PUBLIC, httpa, httpc, rpcc) allow;
```

The same compiler (see [`compiler/`](compiler/)) — which also builds the
in-kernel enforcement DFA — supports the full language with predicate and
boolean composition:

```text
startswith(svc21, svc2) drop;
((contains(svc2) or startswith(svc14, svc3)) or contains(svc2, svc19)) drop;
((endswith(svc18, svc14, svc25) or endswith(svc19, svc15)) or ...) allow;
```

### 2. Compact DFA-based representation
The compiler compiles multi-hop policies describing valid request workflows into
a single **deterministic finite automaton**, where each state represents a valid
prefix of a service path. Requests propagate only the corresponding **DFA state
label** rather than the full request history — yielding dramatically smaller
labels and **constant-time** policy checks. A data-parallel, tree-structured
reduction merges thousands of per-policy DFAs efficiently.

### 3. Application-agnostic enforcement via eBPF
eMicro propagates DFA state labels and enforces multi-hop policies
**transparently**, without modifying application code. Leveraging eBPF, it
operates at the kernel level to propagate labels across network packets,
processes, threads, and coroutines while avoiding user/kernel context switches:

- **`ebpf/bpf_probe.c`** — kprobes/kretprobes (e.g. `inet_csk_accept`,
  `tcp_connect`) that bind connection four-tuples to multi-hop DFA state.
- **`ebpf/bpf_tc.c`** — TC (traffic-control) programs that parse packets and
  advance/verify the DFA state at line rate on ingress/egress.
- **`ebpf/multihop.h`** — shared eBPF map layout and state/transition types.

### 4. Decentralized enforcement
Enforcement stays **local and decentralized** at each service, with policies
replicated across nodes via a consensus protocol — removing the
single-point-of-failure and bottleneck of prior centralized multi-hop
access-control systems. See the [paper](paper/emicro.pdf) for the replication
design and evaluation.

---

## Repository Structure

| Path | Description |
| --- | --- |
| [`compiler/`](compiler/) | The policy-language compiler (predicates + `and`/`or` + `allow`/`drop`) that compiles rules into a DFA. Used both standalone and by the eBPF loader. Includes an example policy file. |
| [`ebpf/`](ebpf/) | eBPF tracing & enforcement programs (`bpf_probe.c`, `bpf_tc.c`, `multihop.h`), `create_dfa.py` (compiles a policy into the enforcement DFA via the compiler), and the Python attach/detach control plane. |
| [`ebpf/access_control/`](ebpf/access_control/) | Multi-hop policies (`.txt`) in the policy language, for the toy example plus the social-network and media workloads. The bundled files are `match(...) allow;` allow-lists. |
| [`apps/toy/`](apps/toy/) | A self-contained **toy** microservice cluster (Docker Compose) used by the quick start. |
| [`paper/`](paper/emicro.pdf) | The CCS '26 paper. |
| [`Makefile`](Makefile) | Convenience targets: `attach`, `detach`. |

---

## Requirements

- **[Docker Desktop](https://www.docker.com/products/docker-desktop/)** / [Docker Engine](https://docs.docker.com/engine/install/)
- **[BCC](https://github.com/iovisor/bcc/tree/master)** (installed system-wide; the eBPF programs require Linux kernel headers)
- **Python 3** (with the packages in [`requirements.txt`](requirements.txt): `docker`, `pyroute2`, and the policy compiler's `FAdo` + `lark`)

> **Note:** eBPF program loading requires a Linux host with root privileges.
> `FAdo` pulls in a sizable dependency set; a dedicated virtualenv is recommended.

---

## Quick Start (Toy Example)

The toy cluster exposes **httpa** as the public entry point with two valid
paths:

- `http://localhost:8001/1` → `httpa → httpb → rpca & rpcb`
- `http://localhost:8001/2` → `httpa → httpc → rpcc`

**1. Build and run the cluster**

```bash
cd apps/toy
docker compose build
docker compose up
```

**2. Set up the Python environment** (BCC is installed system-wide, so include
system site packages):

```bash
python3 -m venv .venv --system-site-packages
source .venv/bin/activate
pip install -r requirements.txt
```

**3. Attach the eBPF agent.** Policies live in `ebpf/access_control/`; the
network name comes from the Docker Compose file:

```bash
make attach policy=multihop_toy.txt network=toy_app_network
```

**4. Send a legitimate request** using the HTTP-A IP address printed by the
agent:

```bash
curl http://<ip-address>:8000/1
curl http://<ip-address>:8000/2
```

**5. Try a path-suffix attack.** A direct request from httpa to httpb is
**blocked**, because it was not initiated from the public entry point:

```bash
docker exec toy-httpa-1 curl http://httpb:8000
```

**6. Tear down.** Press `Ctrl+C` to stop the agent, then detach and clean up all
programs:

```bash
make detach network=toy_app_network
```

---

## Evaluation Applications

The quick-start **toy** cluster lives in [`apps/toy/`](apps/toy/). The paper
additionally evaluates eMicro on
**[DeathStarBench](https://github.com/delimitrou/DeathStarBench)**, which is not
vendored in this repository; the corresponding multi-hop policies are provided
for reference under [`ebpf/access_control/`](ebpf/access_control/)
(`multihop_socialnetwork.txt`, `multihop_media.txt`).

---

## Citation

If you use eMicro in your research, please cite our CCS '26 paper.

**BibTeX**

```bibtex
@inproceedings{putra2026emicro,
  author    = {Putra, Rizky Ramadhana and Bajaber, Osama and Tsegai, Saimon Amanuel and
               Taylor, Teryl and Araujo, Frederico and Ji, Yuede and Gao, Peng},
  title     = {{eMicro}: Real-Time Multi-Hop Access Control for Microservices with {eBPF}},
  booktitle = {Proceedings of the 2026 ACM SIGSAC Conference on Computer and
               Communications Security (CCS '26)},
  year      = {2026},
  location  = {The Hague, Netherlands},
  publisher = {Association for Computing Machinery},
  address   = {New York, NY, USA},
  numpages  = {15},
  doi       = {10.1145/3830454.3832688},
  url       = {https://doi.org/10.1145/3830454.3832688},
  isbn      = {979-8-4007-2871-6/2026/11}
}
```

**ACM Reference Format**

> Rizky Ramadhana Putra, Osama Bajaber, Saimon Amanuel Tsegai, Teryl
> Taylor, Frederico Araujo, Yuede Ji, and Peng Gao. 2026. eMicro: Real-Time Multi-Hop
> Access Control for Microservices with eBPF. In *Proceedings of the 2026 ACM
> SIGSAC Conference on Computer and Communications Security (CCS '26), November
> 15–19, 2026, The Hague, Netherlands.* ACM, New York, NY, USA, 15 pages.
> https://doi.org/10.1145/3830454.3832688

---

## Authors

Rizky Ramadhana Putra¹, Osama Bajaber², Saimon Amanuel Tsegai¹, Teryl
Taylor³, Frederico Araujo³, Yuede Ji⁴, and Peng Gao¹

<sup>¹ Virginia Tech · ² King Abdulaziz University · ³ IBM Research · ⁴ University of Texas at Arlington</sup>

## Contact

For questions, please contact **Rizky Ramadhana Putra** — [rizky@vt.edu](mailto:rizky@vt.edu).

## License

This work is licensed under a
[Creative Commons Attribution 4.0 International License (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/).
© 2026 Copyright held by the owner/author(s).
