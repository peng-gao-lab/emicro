import argparse
import json
from concurrent.futures import ProcessPoolExecutor, as_completed
from FAdo.fa import DFA, NFA
from FAdo.fio import saveToJson
from functools import reduce
from lark import Transformer, Lark

class AlphabetGatherer(Transformer):
    def start(self, items):
        return set.union(*items)
        
    def policy(self, items):
        return items[0]

    def drop(self, items):
        return set()
    
    def allow(self, items):
        return set()

    def match(self, items):
        return items[0]

    def startswith(self, items):
        return items[0]

    def endswith(self, items):
        return items[0]

    def contains(self, items):
        return items[0]
    
    def and_(self, items):
        return items[0] | items[1]

    def or_(self, items):
        return items[0] | items[1]

    def ph(self, items):
        return set(items)

    def IDENT(self, tok):
        return str(tok)

    def NEWLINE(self, tok):
        return set()

def union(items):
    return reduce(lambda x, y: (x | y).minimal(), items)

def intersection(items):
    return reduce(lambda x, y: (x & y).minimal(), items)

def do_in_batch(func, items, batch_size=100, max_workers=10):
    with ProcessPoolExecutor(max_workers=max_workers) as ex:
        futures = []
        for i in range(0, len(items), batch_size):
            batch = items[i:i+batch_size]
            futures.append(ex.submit(func, batch))
        result = [f.result() for f in as_completed(futures)]

    return result

def do_tree_reduction(func, items, batch_size=10, max_workers=5):
    with ProcessPoolExecutor(max_workers=max_workers) as ex:
        while len(items) > 1:
            tasks = [[items[i], items[i+1]] for i in range(0, len(items) - 1, 2)]
            carry = items[-1] if (len(items) % 2 == 1) else None

            merged = list(ex.map(func, tasks))
            if carry is not None:
                merged.append(carry)

            items = merged

    return items[0]
            

class DFATransformer(Transformer):
    def start(self, items):
        # merge all policies with deny-by-default mechanism
        BATCH_SIZE = 10
        MAX_WORKERS = 30
        allow = [x[0] for x in items if x!="NEWLINE" and x[1] == "ALLOW"]
        drop = [x[0] for x in items if x!="NEWLINE" and x[1] == "DROP"]

        allow_dfa = do_tree_reduction(union, allow, BATCH_SIZE, MAX_WORKERS) if allow else None
        drop_dfa = do_tree_reduction(intersection, drop, BATCH_SIZE, MAX_WORKERS) if drop else None

        if allow_dfa and drop_dfa:
            return (allow_dfa & drop_dfa).minimal()
        elif allow_dfa:
            return allow_dfa
        else:
            raise Exception("All policies are DROP, no ALLOW policy found.")
        
    def policy(self, items):
        # complement if drop
        if items[1] == "DROP":
            return ~items[0], "DROP"
        elif items[1] == "ALLOW":
            return items[0], "ALLOW"
        else:
            return items[0], "ALLOW"

    def drop(self, items):
        return "DROP"
    
    def allow(self, items):
        return "ALLOW"
 
    def match(self, items):
        # build dfa
        d = DFA()
        ph = items[0]
        d.setSigma(self.alphabet)

        d.addState('q0')
        d.setInitial(0)
        for i in range(1, len(ph)+1, 1):
            d.addState(f'q{i}')
            d.addTransition(i-1, ph[i-1], i)

        d.addFinal(len(ph))

        return d

    def startswith(self, items):
        # build dfa
        d = DFA()
        ph = items[0]
        d.setSigma(self.alphabet)

        d.addState('q0')
        d.setInitial(0)
        for i in range(1, len(ph)+1, 1):
            d.addState(f'q{i}')
            d.addTransition(i-1, ph[i-1], i)
        d.addFinal(len(ph))
        
        for p in self.alphabet:
            d.addTransition(len(ph), p, len(ph))

        return d

    def endswith(self, items):
        # build nfa
        n = NFA()
        ph = items[0]
        n.setSigma(self.alphabet)

        n.addState('q0')
        n.setInitial([0])
        for p in self.alphabet:
            n.addTransition(0, p, 0)

        n.addState('q1')
        n.addTransition(0, "@epsilon", 1)
        for i in range(len(ph)):
            n.addState(f'q{i+2}')
            n.addTransition(i+1, ph[i], i+2)

        n.addFinal(len(ph)+1)
        return n.toDFA()

    def contains(self, items):
        # build nfa
        n = NFA()
        ph = items[0]
        n.setSigma(self.alphabet)
        n.addState('q0')

        n.setInitial([0])

        for p in self.alphabet:
            n.addTransition(0, p, 0)

        n.addState('q1')
        n.addTransition(0, "@epsilon", 1)
        for i in range(len(ph)):
            n.addState(f'q{i+2}')
            n.addTransition(i+1, ph[i], i+2)

        n.addFinal(len(ph)+1)

        for p in self.alphabet:
            n.addTransition(len(ph)+1, p, len(ph)+1)

        return n.toDFA()
    
    def and_(self, items):
        # intersect
        dfa = items[0] & items[1]
        return dfa.minimal()

    def or_(self, items):
        # union
        dfa = items[0] | items[1]
        return dfa.minimal()

    def ph(self, items):
        return items

    def IDENT(self, tok):
        return str(tok)

    def NEWLINE(self, tok):
        return "NEWLINE"

    def transform_with_alphabet(self, tree, alphabet):
        # set alphabet to all DFAs
        self.alphabet = alphabet
        return self.transform(tree)



grammar = r"""
    start: policy";" (NEWLINE policy";")* NEWLINE?

    policy: predicate action              -> policy

    // -------- predicates --------
    ?predicate: "(" predicate "and" predicate  ")" -> and_
        |     | "(" predicate "or"  predicate  ")"  -> or_
              | atom

    atom: "match"      "(" ph ")" -> match
        | "startswith" "(" ph ")" -> startswith
        | "endswith"   "(" ph ")" -> endswith
        | "contains"   "(" ph ")" -> contains

    // -------- action --------
    action: "drop" -> drop
          | "allow" -> allow

    // -------- PH --------
    ph: IDENT ("," IDENT)*
    IDENT: /[A-Za-z][A-Za-z0-9]*/

    NEWLINE: /(\r?\n)+/

    %import common.WS_INLINE
    %ignore WS_INLINE
"""


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description="Policy compiler")
    ap.add_argument("--file", type=str, required=True)
    args = ap.parse_args()

    parser = Lark(grammar, start="start")

    with open(args.file, 'r') as f:
        text = f.read()


    tree = parser.parse(text)

    gatherer = AlphabetGatherer()
    alphabet = gatherer.transform(tree)

    transformer = DFATransformer()
    dfa = transformer.transform_with_alphabet(tree, alphabet)
    saveToJson(f"compiled_{args.file}.json", dfa)