"""Reproducible tree training; repository splits and validation-only selection.
Usage: python -m backend.ml.tree_training DATA MODEL REPORT
No independent evaluation data is accepted for model or threshold selection.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
import math
from pathlib import Path
from .training import FEATURES, load_rows, split_sources, sample_weights, sigmoid, metrics, quality_gate
from .classifier import CandidateClassifier
from .feature_extractor import FeatureVector
from .tree_model import leaf_value


# Frozen before independent evaluation: wider leaves need multiple sources.
TRAINING_CANDIDATES = tuple(
    {'depth': depth, 'rounds': 100, 'learning_rate': .08,
     'regularization': penalty, 'min_leaf_vectors': minimum,
     'min_leaf_weight': 8., 'min_leaf_sources': sources, 'min_split_gain': .1}
    for depth in (2, 3, 4)
    for penalty, minimum, sources in ((5., 8, 2), (15., 20, 3))
)
THRESHOLD_CANDIDATES = (.35, .40, .45, .50, .55, .60, .65, .70, .75, .80, .85, .90, .95)
VALIDATION_POLICY = {
    'minimum_precision': .90, 'minimum_recall': .80,
    'minimum_specificity': .50, 'minimum_macro_specificity': .50,
    'minimum_negative_bearing_repositories': 5,
    'threshold_candidates': list(THRESHOLD_CANDIDATES),
    'objective': 'Repository/class-balanced log loss; thresholds require pooled and weighted precision, recall, specificity and equal-repository specificity.',
}


def fit_trees(rows, depth, rounds=100, *, learning_rate=.1, regularization=1.,
              min_leaf_vectors=3, min_leaf_weight=2., min_leaf_sources=1,
              min_split_gain=0.):
    """Repeated rows cannot satisfy vector or repository leaf support."""
    if (type(depth) is not int or not 1 <= depth <= 6
            or type(rounds) is not int or not 1 <= rounds <= 200
            or type(min_leaf_vectors) is not int or min_leaf_vectors < 1
            or type(min_leaf_sources) is not int or min_leaf_sources < 1
            or not 0 < learning_rate <= 1 or not math.isfinite(learning_rate)
            or not math.isfinite(regularization) or regularization <= 0
            or not math.isfinite(min_leaf_weight) or min_leaf_weight <= 0
            or not math.isfinite(min_split_gain) or min_split_gain < 0):
        raise ValueError('Invalid tree training settings')
    importance = sample_weights(rows, True, True)
    compressed = defaultdict(lambda: [0., 0., set()])
    names = sorted(FEATURES)
    for row, weight in zip(rows, importance):
        vector = tuple(row['features'].get(name, 0.) for name in names)
        compressed[vector][0] += weight
        compressed[vector][1] += weight * row['label']
        compressed[vector][2].add(row['group'])
    vectors = sorted(compressed)
    weights = [compressed[vector][0] for vector in vectors]
    targets = [compressed[vector][1] / compressed[vector][0] for vector in vectors]
    sources = [compressed[vector][2] for vector in vectors]
    values = [dict(zip(names, vector)) for vector in vectors]
    logits = [0.] * len(vectors)
    trees = []
    for _ in range(rounds):
        probabilities = [sigmoid(value) for value in logits]
        gradients = [w * (y - p) for w, y, p in zip(weights, targets, probabilities)]
        hessians = [w * p * (1 - p) for w, p in zip(weights, probabilities)]

        def build(indices, level):
            g = sum(gradients[i] for i in indices)
            h = sum(hessians[i] for i in indices)
            total_weight = sum(weights[i] for i in indices)
            leaf = {'value': learning_rate * max(-2., min(2., g / (h + regularization)))}
            if level == depth or len(indices) < 2 * min_leaf_vectors:
                return leaf
            best, gain = None, min_split_gain
            parent_sources = Counter(group for i in indices for group in sources[i])
            for column, name in enumerate(names):
                order = sorted(indices, key=lambda i: vectors[i][column])
                if vectors[order[0]][column] == vectors[order[-1]][column]:
                    continue
                gl = hl = wl = 0.
                left_sources, right_sources = Counter(), parent_sources.copy()
                for position, i in enumerate(order[:-1], 1):
                    gl += gradients[i]
                    hl += hessians[i]
                    wl += weights[i]
                    for group in sources[i]:
                        left_sources[group] += 1
                        right_sources[group] -= 1
                        if right_sources[group] == 0:
                            del right_sources[group]
                    if (position < min_leaf_vectors or len(order) - position < min_leaf_vectors
                            or wl < min_leaf_weight or total_weight - wl < min_leaf_weight
                            or len(left_sources) < min_leaf_sources or len(right_sources) < min_leaf_sources):
                        continue
                    low, high = vectors[i][column], vectors[order[position]][column]
                    if low == high:
                        continue
                    improvement = (gl * gl / (hl + regularization)
                        + (g - gl) ** 2 / (h - hl + regularization)
                        - g * g / (h + regularization))
                    if improvement > gain + 1e-9:
                        gain = improvement
                        best = (name, (low + high) / 2, order[:position], order[position:])
            if best is None:
                return leaf
            name, threshold, left, right = best
            return {'feature': name, 'threshold': threshold,
                    'left': build(left, level + 1), 'right': build(right, level + 1)}

        tree = build(list(range(len(vectors))), 0)
        trees.append(tree)
        logits = [value + leaf_value(tree, vector) for value, vector in zip(logits, values)]
    return trees


def loss(rows, classifier):
    importance = sample_weights(rows, True, True)
    total = 0.
    for row, weight in zip(rows, importance):
        score = classifier.classify(FeatureVector(row['features'])).score
        total -= weight * (row['label'] * math.log(max(1e-12, score))
                           + (1 - row['label']) * math.log(max(1e-12, 1 - score)))
    return total / sum(importance)


def _rates(rows, scores, cutoff, importance):
    tp = sum(w for r, p, w in zip(rows, scores, importance) if r['label'] and p >= cutoff)
    fp = sum(w for r, p, w in zip(rows, scores, importance) if not r['label'] and p >= cutoff)
    fn = sum(w for r, p, w in zip(rows, scores, importance) if r['label'] and p < cutoff)
    tn = sum(w for r, p, w in zip(rows, scores, importance) if not r['label'] and p < cutoff)
    return {'precision': tp / (tp + fp) if tp + fp else 0.,
            'recall': tp / (tp + fn) if tp + fn else 0.,
            'specificity': tn / (tn + fp) if tn + fp else 0.}


def select_threshold(rows, classifier):
    """Apply the fixed precision policy to development validation rows only."""
    importance = sample_weights(rows, True, True)
    scores = [classifier.classify(FeatureVector(row['features'])).score for row in rows]
    negative_by_group = defaultdict(list)
    for row, score in zip(rows, scores):
        if not row['label']:
            negative_by_group[row['group']].append(score)
    attempts = []
    for cutoff in THRESHOLD_CANDIDATES:
        pooled = _rates(rows, scores, cutoff, [1.] * len(rows))
        weighted = _rates(rows, scores, cutoff, importance)
        macro = (sum(sum(p < cutoff for p in values) / len(values)
                     for values in negative_by_group.values()) / len(negative_by_group)
                 if negative_by_group else 0.)
        passed = (len(negative_by_group) >= VALIDATION_POLICY['minimum_negative_bearing_repositories']
                  and macro >= VALIDATION_POLICY['minimum_macro_specificity']
                  and all(summary[name] >= VALIDATION_POLICY['minimum_' + name]
                          for summary in (pooled, weighted) for name in ('precision', 'recall', 'specificity')))
        attempts.append({'threshold': cutoff, 'passed': passed, 'pooled': pooled,
                         'repository_class_weighted': weighted, 'macro_specificity': macro})
    passing = [a for a in attempts if a['passed']]
    fallback = [a for a in attempts
                if all(a[field]['recall'] >= .8 for field in ('pooled', 'repository_class_weighted'))]
    best = min(passing, key=lambda a: (-a['repository_class_weighted']['recall'],
                                      -a['pooled']['recall'], a['threshold'])) if passing else (
        min(fallback, key=lambda a: (-a['repository_class_weighted']['precision'],
                                    -a['pooled']['precision'], -a['threshold']))
        if fallback else min(attempts, key=lambda a: a['threshold']))
    return {'partition': 'validation only', 'passed': bool(passing),
            'selected_threshold': best['threshold'], 'selected_metrics': best,
            'negative_bearing_repositories': len(negative_by_group),
            'fallback': (None if passing else
                         'Highest weighted precision retaining pooled and weighted recall >= .80; failed policy remains failed.'
                         if fallback else 'No fixed cutoff satisfies both recall floors; failed policy remains failed.'),
            'candidates': attempts}


def train(dataset, model_path, report_path):
    rows = load_rows(dataset)
    train_rows, validation, test = split_sources(rows)
    attempts = []
    for settings in TRAINING_CANDIDATES:
        trees = fit_trees(train_rows, **settings)
        classifier = CandidateClassifier({'bias': 0.}, trees=trees)
        measured = loss(validation, classifier)
        selection = select_threshold(validation, classifier)
        attempts.append({'settings': dict(settings), 'validation_loss': measured,
                         'validation_threshold_policy': selection, 'trees': trees})
        print(json.dumps({'settings': settings, 'validation_loss': measured,
                          'validation_policy_passed': selection['passed'],
                          'selected_threshold': selection['selected_threshold']}), flush=True)
    passing = [a for a in attempts if a['validation_threshold_policy']['passed']]
    selected = min(passing or attempts, key=lambda a: a['validation_loss'])
    trees = selected['trees']
    threshold = selected['validation_threshold_policy']['selected_threshold']
    # The existing schema 4 bias implements the frozen cutoff. No calibration
    # or active-exposure probability is claimed for these shifted triage scores.
    bias = -math.log(threshold / (1 - threshold))
    raw_classifier = CandidateClassifier({'bias': 0.}, trees=trees)
    classifier = CandidateClassifier({'bias': bias}, trees=trees)
    baseline = metrics(test, dict(CandidateClassifier._DEFAULT_WEIGHTS))
    learned = metrics(test, {}, classifier=classifier)
    settings = selected['settings']
    report = {
        'dataset_sha256': hashlib.sha256(Path(dataset).read_bytes()).hexdigest(),
        'data_scope': 'Development line-matched candidate metadata; not verified active credentials.',
        'split_groups': {name: sorted({r['group'] for r in part})
                         for name, part in zip(('train', 'validation', 'test'), (train_rows, validation, test))},
        'split_sizes': [len(part) for part in (train_rows, validation, test)],
        'split_labels': [dict(Counter(r['label'] for r in part)) for part in (train_rows, validation, test)],
        'selection': 'Minimize repository/class-balanced validation log loss among fixed configurations passing the precision policy; if none pass, minimize that loss and retain explicit policy failure. No test or independent tuning.',
        'selected_depth': settings['depth'], 'selected_settings': settings,
        'rounds': settings['rounds'], 'learning_rate': settings['learning_rate'],
        'regularization': settings['regularization'],
        'training_candidates': [{k: v for k, v in a.items() if k != 'trees'} for a in attempts],
        'validation_policy': dict(VALIDATION_POLICY),
        'validation_threshold_policy': selected['validation_threshold_policy'],
        'decision_threshold': threshold, 'runtime_logit_offset': bias,
        'score_scope': 'Decision-threshold-shifted class-balanced candidate triage scores; not natural-prevalence or active-exposure probabilities.',
        'sample_weighting': 'Inverse repository size then equal global class mass; repeated feature vectors retain original weighted mass.',
        'baseline_test': baseline, 'raw_trained_test': metrics(test, {}, classifier=raw_classifier),
        'trained_test': learned, 'candidate_quality_gate': quality_gate(baseline, learned),
        'deployment': 'Experimental opt-in only; validation or independent readiness failures do not authorize default promotion.',
    }
    model = {'schema_version': 4, 'kind': 'boosted_trees', 'weights': {'bias': bias},
             'trees': trees, 'training': report}
    Path(model_path).write_text(json.dumps(model, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(json.dumps({key: {name: report[key][name] for name in
                      ('precision', 'recall', 'specificity', 'brier', 'true_positive', 'false_positive')}
                      for key in ('baseline_test', 'trained_test')}, indent=2))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dataset')
    parser.add_argument('model')
    parser.add_argument('report')
    args = parser.parse_args()
    train(args.dataset, args.model, args.report)


if __name__ == '__main__':
    main()
