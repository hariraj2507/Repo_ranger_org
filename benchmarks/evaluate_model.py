"""Evaluate frozen model weights on an independently acquired candidate dataset."""
import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from backend.ml.classifier import CandidateClassifier
from backend.ml.training import FEATURES, load_rows, metrics, quality_gate


def feature_label_diagnostic(rows):
    """Count ambiguity in available metadata without exposing feature vectors."""
    labels = defaultdict(lambda: [0, 0])
    names = sorted(FEATURES)
    for row in rows:
        labels[tuple(row['features'].get(name, 0.0) for name in names)][row['label']] += 1
    conflicts = [counts for counts in labels.values() if all(counts)]
    return {
        'unique_feature_vectors': len(labels),
        'conflicting_label_vectors': len(conflicts),
        'rows_in_conflicting_vectors': sum(sum(counts) for counts in conflicts),
        'minority_label_rows_in_conflicting_vectors': sum(min(counts) for counts in conflicts),
        'interpretation': 'Identical available metadata can carry different labels; this is metadata ambiguity, not evidence of data leakage.',
    }


def repository_metrics(rows, weights):
    """Report equal-repository averages, excluding undefined denominators."""
    grouped = defaultdict(list)
    for row in rows:
        grouped[row['group']].append(row)
    names = ('samples', 'positive_labels', 'true_positive', 'false_positive',
             'false_negative', 'true_negative', 'precision', 'recall', 'specificity',
             'auroc', 'average_precision', 'balanced_accuracy')
    summaries = {}
    for group, members in sorted(grouped.items()):
        result = metrics(members, weights)
        summaries[group] = {name: result[name] for name in names}
        if not result['true_positive'] + result['false_positive']:
            summaries[group]['precision'] = None
        if not result['positive_labels']:
            summaries[group]['recall'] = None
    macro = {}
    counts = {}
    for name in ('precision', 'recall', 'specificity', 'auroc'):
        defined = [summary[name] for summary in summaries.values() if summary[name] is not None]
        macro[name] = sum(defined) / len(defined) if defined else None
        counts[name] = len(defined)
    return {'per_repository': summaries, 'macro': macro, 'macro_defined_repositories': counts}

def evaluate(dataset, model):
    rows=load_rows(dataset)
    trained=CandidateClassifier.from_file(model)
    metadata=json.loads(Path(model).read_text(encoding='utf-8'))
    used={g for groups in metadata.get('training',{}).get('split_groups',{}).values() for g in groups}
    groups={r['group'] for r in rows}
    if groups & used:
        raise ValueError('Evaluation repositories overlap model development partitions')
    baseline=metrics(rows,dict(CandidateClassifier._DEFAULT_WEIGHTS))
    learned=metrics(rows,trained._weights)
    return {'quality_gate':quality_gate(baseline,learned),'scope':'Independent line-labeled candidate evaluation; not active credential validation',
            'dataset_sha256':hashlib.sha256(Path(dataset).read_bytes()).hexdigest(),
            'model_sha256':hashlib.sha256(Path(model).read_bytes()).hexdigest(),
            'repositories':sorted(groups),'baseline':baseline, 'trained':learned,
            'repository_metrics': {
                'baseline': repository_metrics(rows, dict(CandidateClassifier._DEFAULT_WEIGHTS)),
                'trained': repository_metrics(rows, trained._weights),
            },
            'feature_label_diagnostic': feature_label_diagnostic(rows)}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('dataset');p.add_argument('model');p.add_argument('output')
    a=p.parse_args()
    report=evaluate(a.dataset,a.model)
    Path(a.output).write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:{m:report[k][m] for m in ('samples','precision','recall','brier','expected_calibration_error')} for k in ('baseline','trained')},indent=2))

if __name__=='__main__':main()
