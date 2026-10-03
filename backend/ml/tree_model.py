"""Bounded gradient-boosted decision-tree inference over safe numeric metadata."""
import math


def validate_tree(node, depth=0):
    if not isinstance(node, dict) or depth > 6:
        raise ValueError('Invalid model tree')
    if set(node) == {'value'}:
        value=node['value']
        if type(value) not in (int,float) or not math.isfinite(value) or abs(value)>20:
            raise ValueError('Invalid tree leaf')
        return
    from .training import FEATURES
    if (set(node) != {'feature','threshold','left','right'}
            or not isinstance(node['feature'], str) or node['feature'] not in FEATURES):
        raise ValueError('Invalid tree split')
    value=node['threshold']
    if type(value) not in (int,float) or not math.isfinite(value) or not 0<=value<=1:
        raise ValueError('Invalid tree threshold')
    validate_tree(node['left'],depth+1);validate_tree(node['right'],depth+1)


def leaf_value(node, values):
    while 'value' not in node:
        node=node['left'] if values.get(node['feature'],0)<=node['threshold'] else node['right']
    return node['value']


def validate_ensemble(trees):
    if not isinstance(trees,list) or not 1<=len(trees)<=200:
        raise ValueError('Model requires between 1 and 200 trees')
    for tree in trees:validate_tree(tree)
