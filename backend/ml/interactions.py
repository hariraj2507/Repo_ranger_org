"""Deterministic numeric interactions; never consumes source or credentials."""
from itertools import combinations_with_replacement


def interaction_names(names):
    return frozenset('x:' + a + ':' + b for a, b in combinations_with_replacement(sorted(names), 2))


def expand_features(values):
    result = dict(values)
    for a, b in combinations_with_replacement(sorted(values), 2):
        if values[a] and values[b]:
            result['x:' + a + ':' + b] = values[a] * values[b]
    return result
