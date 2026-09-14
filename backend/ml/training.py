"""Train and evaluate a logistic triage model from safe labeled feature rows.

Usage: python -m backend.ml.training dataset.jsonl model.json metrics.json
No source text or credential values are accepted as model features.
"""
import argparse
from collections import defaultdict
import hashlib
import json
import math
from pathlib import Path

from .classifier import CandidateClassifier
from .feature_extractor import FeatureVector

FEATURES = frozenset({'severity','known_signature','custom_signature','entropy_signal','validator_valid',
    'validator_invalid','validator_present','non_production_path','source_code_file','assignment_context','parsed_context'})


def sigmoid(value):
    if value >= 0:
        return 1 / (1 + math.exp(-value))
    e = math.exp(value)
    return e / (1 + e)


def load_rows(path):
    rows = [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]
    for row in rows:
        if set(row) != {'features','label','group'} or type(row['label']) is not int or row['label'] not in (0,1) or not isinstance(row['group'], str):
            raise ValueError('Rows require numeric features, binary label, and source-family group')
        if not isinstance(row['features'], dict) or set(row['features']) - FEATURES:
            raise ValueError('Unknown feature name')
        if any(type(v) not in (int,float) or not math.isfinite(v) or not 0 <= v <= 1 for v in row['features'].values()):
            raise ValueError('Features must be finite numeric values between 0 and 1')
    return rows


def split_groups(rows):
    groups = defaultdict(list)
    for row in rows:
        groups[row['group']].append(row)
    splits = [[], [], []]
    # Stratify groups by their majority label, keeping each whole source family
    # in one partition. Validation selects regularization; test stays held out.
    for label in (0,1):
        names = [name for name, members in groups.items() if int(sum(r['label'] for r in members)*2 >= len(members)) == label]
        names.sort(key=lambda name: hashlib.sha256(('reporanger-v1:'+name).encode()).hexdigest())
        if len(names) < 5:
            raise ValueError('Need at least five source-family groups in each label stratum')
        a, b = max(1, int(len(names)*.6)), max(2, int(len(names)*.8))
        for index, name in enumerate(names):
            splits[0 if index<a else 1 if index<b else 2].extend(groups[name])
    return splits


def fit(rows, regularization, steps=2000):
    weights = {name:0.0 for name in sorted(FEATURES | {'bias'})}
    for _ in range(steps):
        gradient = {name:0.0 for name in weights}
        for row in rows:
            values = {'bias':1.0, **row['features']}
            error = sigmoid(sum(weights[k]*v for k,v in values.items()))-row['label']
            for name, value in values.items():
                gradient[name] += error * value
        for name in weights:
            penalty = 0 if name=='bias' else regularization * weights[name]
            weights[name] -= .2 * (gradient[name]/len(rows)+penalty)
    return weights


def metrics(rows, weights):
    scores = [sigmoid(weights.get('bias',0)+sum(weights.get(k,0)*v for k,v in row['features'].items())) for row in rows]
    tp = sum(p>=.5 and r['label']==1 for p,r in zip(scores,rows))
    fp = sum(p>=.5 and r['label']==0 for p,r in zip(scores,rows))
    fn = sum(p<.5 and r['label']==1 for p,r in zip(scores,rows))
    return {'samples':len(rows), 'precision':tp/(tp+fp) if tp+fp else 0,
            'recall':tp/(tp+fn) if tp+fn else 0,
            'brier':sum((p-r['label'])**2 for p,r in zip(scores,rows))/len(rows),
            'log_loss':-sum(r['label']*math.log(max(1e-12,p))+(1-r['label'])*math.log(max(1e-12,1-p)) for p,r in zip(scores,rows))/len(rows)}


def train(dataset, model_path, metrics_path):
    rows=load_rows(dataset)
    train_rows, validation, test = split_groups(rows)
    candidates=[(penalty,fit(train_rows,penalty)) for penalty in (.001,.01,.1)]
    penalty,weights=min(candidates,key=lambda pair:metrics(validation,pair[1])['log_loss'])
    baseline=metrics(test,dict(CandidateClassifier._DEFAULT_WEIGHTS))
    learned=metrics(test,weights)
    report={'dataset_sha256':hashlib.sha256(Path(dataset).read_bytes()).hexdigest(),
            'data_scope':'Synthetic labeled metadata; not independently labeled production credentials',
            'split_groups':{'train':sorted({r['group'] for r in train_rows}),
                            'validation':sorted({r['group'] for r in validation}), 'test':sorted({r['group'] for r in test})},
            'split_sizes':[len(train_rows),len(validation),len(test)],
            'regularization':penalty, 'baseline_test':baseline, 'trained_test':learned,
            'deployment':'experimental_opt_in; production promotion requires independent real-world evaluation'}
    model={'schema_version':1,'kind':'logistic','weights':weights,'training':report}
    Path(model_path).write_text(json.dumps(model,indent=2,sort_keys=True)+'\n')
    Path(metrics_path).write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dataset'); parser.add_argument('model'); parser.add_argument('metrics')
    args=parser.parse_args()
    report=train(args.dataset,args.model,args.metrics)
    print(json.dumps(report,indent=2))

if __name__=='__main__':
    main()
