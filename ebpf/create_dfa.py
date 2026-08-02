import os
import sys

# Reuse the full policy-language compiler in ../compiler (grammar, predicate/DFA
# construction, and union/intersection ops). We only replace its parallel
# tree-reduction with a serial merge so the eBPF agent never spawns processes.
_COMPILER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "compiler"))
if _COMPILER_DIR not in sys.path:
    sys.path.insert(0, _COMPILER_DIR)

from lark import Lark
import compiler as C

POLICY_DIR = "ebpf/access_control/"

_parser = Lark(C.grammar, start="start")


class _SerialDFATransformer(C.DFATransformer):
    """Same semantics as compiler.DFATransformer, but merges policies serially
    (deny-by-default: union the ALLOW DFAs, intersect the complemented DROP DFAs,
    then intersect the two). Avoids the ProcessPool used for large-scale compiles."""

    def start(self, items):
        allow = [x[0] for x in items if x != "NEWLINE" and x[1] == "ALLOW"]
        drop = [x[0] for x in items if x != "NEWLINE" and x[1] == "DROP"]
        allow_dfa = C.union(allow) if allow else None
        drop_dfa = C.intersection(drop) if drop else None
        if allow_dfa and drop_dfa:
            return (allow_dfa & drop_dfa).minimal()
        elif allow_dfa:
            return allow_dfa
        else:
            raise Exception("All policies are DROP, no ALLOW policy found.")


def _compile(text):
    tree = _parser.parse(text)
    alphabet = C.AlphabetGatherer().transform(tree)
    return _SerialDFATransformer().transform_with_alphabet(tree, alphabet)


def create(filename):
    """Compile a policy file into the DFA enforced in-kernel.

    Returns (initial_state, states, transitions):
      * initial_state — always "START" (mapped to eBPF state 0);
      * states        — list of the remaining live state names (indexed 1..N);
      * transitions   — {state_name: {service_name: next_state_name}}.
    Only transitions between *live* states (reachable and able to reach an
    accepting path) are emitted; every other (state, service) pair is an
    implicit reject.
    """
    with open(POLICY_DIR + filename) as f:
        text = f.read()

    dfa = _compile(text)
    delta = dict(dfa.delta)
    useful = set(dfa.usefulStates())
    if dfa.Initial not in useful:
        raise ValueError(f"{filename}: policy accepts no request path")

    def name(i):
        return "START" if i == dfa.Initial else f"q{i}"

    states = [name(i) for i in sorted(useful) if i != dfa.Initial]

    transitions = {}
    for s in useful:
        for symbol, target in delta.get(s, {}).items():
            if target not in useful:
                continue  # transition into a dead/useless state == reject
            transitions.setdefault(name(s), {})[symbol] = name(target)

    return "START", states, transitions


if __name__ == "__main__":
    initial_state, states, transitions = create("multihop_toy.txt")
    print("Initial State:", initial_state)
    print("States:")
    for s in states:
        print(" ", s)
    print("Transitions:", transitions)
