"""Train and evaluate a logistic triage model from safe labeled feature rows.

Usage: python -m backend.ml.training dataset.jsonl model.json metrics.json
No source text or credential values are accepted as model features.
"""
import argparse
from collections import defaultdict, Counter
import hashlib
import json
import math
from pathlib import Path

from .classifier import CandidateClassifier
from .feature_extractor import FeatureVector
from backend.detectors.finding import VALUE_SHAPE_FEATURES

FEATURES = frozenset({'severity','known_signature','custom_signature','entropy_signal','validator_valid',
    'validator_invalid','validator_present','non_production_path','source_code_file','assignment_context','parsed_context',
    'public_identifier_context', 'placeholder_context', 'comment_context', 'jwt_structure', 'test_context', 'test_value_context', 'reference_context'}) | frozenset(VALUE_SHAPE_FEATURES)


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


def split_sources(rows):
    """Deterministic whole-repository split, independent of labels and outcomes."""
    groups = defaultdict(list)
    for row in rows:
        groups[row['group']].append(row)
    if len(groups) < 10:
        raise ValueError('External training requires at least ten repositories with labeled candidates')
    names = sorted(groups, key=lambda name: (-len(groups[name]), hashlib.sha256(('reporanger-external-v2:' + name).encode()).hexdigest()))
    partitions = [[], [], []]
    targets = [.6 * len(rows), .2 * len(rows), .2 * len(rows)]
    for name in names:
        index = min(range(3), key=lambda i: len(partitions[i]) / targets[i])
        partitions[index].extend(groups[name])
    return partitions


def sample_weights(rows, balance_groups=False, balance_classes=False):
    """Normalize repository weights, optionally giving each label equal mass."""
    groups = Counter(r['group'] for r in rows)
    weights = [len(rows)/(len(groups)*groups[r['group']]) if balance_groups else 1.0 for r in rows]
    if balance_classes:
        masses = defaultdict(float)
        for row, weight in zip(rows, weights):
            masses[row['label']] += weight
        if set(masses) != {0, 1}:
            raise ValueError('Class balancing requires positive and negative labels')
        weights = [weight * len(rows)/(2 * masses[row['label']]) for row, weight in zip(rows, weights)]
    return weights


def weighted_log_loss(rows, weights, balance_groups=False, balance_classes=False):
    importance = sample_weights(rows, balance_groups, balance_classes)
    total = 0.0
    for row, weight in zip(rows, importance):
        score = sigmoid(weights.get('bias',0) + sum(weights.get(k,0)*v for k,v in row['features'].items()))
        total -= weight * (row['label'] * math.log(max(1e-12,score)) + (1-row['label']) * math.log(max(1e-12,1-score)))
    return total / sum(importance)



def calibrate(rows, weights, balance_groups=False, balance_classes=False):
    """Fit positive Platt scale and offset on validation data only."""
    if {r['label'] for r in rows} != {0,1}:
        raise ValueError('Calibration requires positive and negative validation labels')
    importance = sample_weights(rows, balance_groups, balance_classes)
    logits = [weights.get('bias',0) + sum(weights.get(k,0)*v for k,v in r['features'].items()) for r in rows]
    scale, offset = 1.0, 0.0
    for _ in range(1000):
        errors = [(sigmoid(scale*x + offset)-r['label'])*w for x,r,w in zip(logits,rows,importance)]
        scale = min(10.0, max(.05, scale - .05*sum(e*x for e,x in zip(errors,logits))/len(rows)))
        offset = min(10.0, max(-10.0, offset - .05*sum(errors)/len(rows)))
    result = {k:v*scale for k,v in weights.items()}
    result['bias'] = result.get('bias',0) + offset
    return result, {'method':'Platt scaling on validation partition only', 'scale':scale, 'offset':offset}


def fit(rows, regularization, steps=2000, balance_groups=False, balance_classes=False, feature_names=None):
    weights = {name:0.0 for name in sorted((FEATURES if feature_names is None else feature_names) | {'bias'})}
    importance = sample_weights(rows, balance_groups, balance_classes)
    # Repeated metadata vectors need one gradient contribution per label/vector.
    # Sum their original sample weights so this does not change the objective.
    grouped = defaultdict(float)
    for row, weight in zip(rows, importance):
        values = tuple(sorted({'bias': 1.0, **row['features']}.items()))
        grouped[(values, row['label'])] += weight
    for _ in range(steps):
        gradient = {name:0.0 for name in weights}
        for (values, label), weight in grouped.items():
            error = (sigmoid(sum(weights[k]*v for k,v in values))-label) * weight
            for name, value in values:
                gradient[name] += error * value
        for name in weights:
            penalty = 0 if name=='bias' else regularization * weights[name]
            weights[name] -= .2 * (gradient[name]/len(rows)+penalty)
    return weights


def ranking_metrics(labels, scores):
    """AUROC and average precision with equal scores evaluated as one group."""
    grouped = defaultdict(lambda: [0, 0])
    for label, score in zip(labels, scores):
        grouped[score][label] += 1
    positives = sum(counts[1] for counts in grouped.values())
    negatives = sum(counts[0] for counts in grouped.values())
    negatives_below = concordant = 0
    for score in sorted(grouped):
        negative, positive = grouped[score]
        concordant += positive * (negatives_below + .5 * negative)
        negatives_below += negative
    seen = true_positive = 0
    average_precision = 0.0
    for score in sorted(grouped, reverse=True):
        negative, positive = grouped[score]
        seen += negative + positive
        true_positive += positive
        if positives:
            average_precision += (positive / positives) * (true_positive / seen)
    return {
        'auroc': concordant / (positives * negatives) if positives and negatives else None,
        'average_precision': average_precision if positives else None,
    }


def metrics(rows, weights, promotion_threshold=None, feature_transform=None, classifier=None):
    if not rows:
        raise ValueError('Evaluation requires nonempty labeled rows')
    scorer = classifier or CandidateClassifier(weights, promotion_threshold=promotion_threshold, feature_transform=feature_transform)
    scores = [scorer.classify(FeatureVector(row['features'])).score for row in rows]
    tp = sum(p>=.5 and r['label']==1 for p,r in zip(scores,rows))
    fp = sum(p>=.5 and r['label']==0 for p,r in zip(scores,rows))
    fn = sum(p<.5 and r['label']==1 for p,r in zip(scores,rows))
    tn = sum(p<.5 and r['label']==0 for p,r in zip(scores,rows))
    specificity = tn/(tn+fp) if tn+fp else None
    recall = tp/(tp+fn) if tp+fn else 0
    ranking = ranking_metrics([r['label'] for r in rows], scores)
    bins = []
    for i in range(10):
        indexes = [j for j,p in enumerate(scores) if min(9,int(p*10)) == i]
        bins.append({'lower':i/10, 'upper':(i+1)/10, 'samples':len(indexes),
                     'mean_score':sum(scores[j] for j in indexes)/len(indexes) if indexes else None,
                     'positive_rate':sum(rows[j]['label'] for j in indexes)/len(indexes) if indexes else None})
    ece = sum(b['samples']*abs(b['mean_score']-b['positive_rate']) for b in bins if b['samples'])/len(rows)
    # Audit the existing confidence/risk policy by observed candidate labels.
    # The observed rates do not turn triage scores into exposure probabilities.
    from .confidence_engine import ConfidenceEngine
    classifier = scorer
    risk_bands = {name:{'samples':0,'positive':0} for name in ('low','medium','high','critical')}
    for row in rows:
        features=FeatureVector(row['features'])
        confidence=ConfidenceEngine().assess(classifier.classify(features),features).score
        severity=features.value('severity')
        risk=.45*severity+.55*confidence
        level='critical' if risk>=.85 or (severity==1 and confidence>=.65) else 'high' if risk>=.65 else 'medium' if risk>=.4 else 'low'
        risk_bands[level]['samples'] += 1
        risk_bands[level]['positive'] += row['label']
    return {'samples':len(rows), 'positive_labels':sum(r['label'] for r in rows), 'true_positive':tp,'false_positive':fp,'false_negative':fn,'true_negative':tn, 'specificity':specificity,
            'predicts_only_one_class':all(p>=.5 for p in scores) or all(p<.5 for p in scores),
            'precision':tp/(tp+fp) if tp+fp else 0,
            'recall':recall, **ranking,
            'balanced_accuracy':(recall + specificity)/2 if tp+fn and specificity is not None else None,
            'expected_calibration_error':ece,'reliability_bins':bins,'risk_band_label_counts':risk_bands,
            'brier':sum((p-r['label'])**2 for p,r in zip(scores,rows))/len(rows),
            'log_loss':-sum(r['label']*math.log(max(1e-12,p))+(1-r['label'])*math.log(max(1e-12,1-p)) for p,r in zip(scores,rows))/len(rows)}


def quality_gate(baseline, learned):
    reasons=[]
    if learned['samples']<50: reasons.append('fewer_than_50_evaluation_candidates')
    if learned['positive_labels']<10 or learned['samples']-learned['positive_labels']<10:
        reasons.append('fewer_than_10_labels_in_each_class')
    if learned.get('predicts_only_one_class'): reasons.append('classifier_predicts_only_one_class')
    if learned.get('specificity') is None or learned['specificity']<.5: reasons.append('specificity_below_50_percent')
    if learned['precision']<baseline['precision']: reasons.append('precision_regression')
    if learned['recall']<baseline['recall']: reasons.append('recall_regression')
    if learned['brier']>=baseline['brier']: reasons.append('no_brier_improvement')
    return {'passed':not reasons, 'reasons':reasons, 'scope':'Candidate triage gate only; not a production certification'}


def train(dataset, model_path, metrics_path, external=False, guarded=False):
    if guarded and not external:
        raise ValueError('Guarded selection requires external repository partitions')
    rows=load_rows(dataset)
    train_rows, validation, test = split_sources(rows) if external else split_groups(rows)
    if {r['label'] for r in train_rows} != {0,1}:
        raise ValueError('Training requires both positive and negative examples')
    candidates=[(penalty,fit(train_rows,penalty, steps=800 if external else 2000, balance_groups=external, balance_classes=external)) for penalty in (.001,.01,.1)]
    penalty,weights=min(candidates,key=lambda pair:weighted_log_loss(validation,pair[1],balance_groups=external,balance_classes=external))
    calibration = None
    if external:
        weights, calibration = calibrate(validation, weights, balance_groups=True, balance_classes=True)
    threshold, selection = None, None
    if guarded:
        baseline_validation = metrics(validation, dict(CandidateClassifier._DEFAULT_WEIGHTS))
        attempts = []
        for cutoff in (.5, .6, .7, .8, .9, .95, 1.0):
            measured = metrics(validation, weights, promotion_threshold=cutoff)
            attempts.append({'threshold': cutoff, 'metrics': measured, 'gate': quality_gate(baseline_validation, measured)})
        passing = [a for a in attempts if a['gate']['passed']]
        best = min(passing, key=lambda a: (-a['metrics']['recall'], a['metrics']['brier'], -a['threshold'])) if passing else attempts[-1]
        threshold = best['threshold']
        selection = {'partition': 'validation only', 'passed': bool(passing), 'selected_threshold': threshold, 'candidates': attempts}
    baseline=metrics(test,dict(CandidateClassifier._DEFAULT_WEIGHTS))
    learned=metrics(test,weights,promotion_threshold=threshold)
    report={'dataset_sha256':hashlib.sha256(Path(dataset).read_bytes()).hexdigest(),
            'data_scope':'External line-matched candidate metadata, not verified active credentials' if external else 'Synthetic labeled metadata; not independently labeled production credentials',
            'calibration':calibration, 'sample_weighting':'inverse repository size, then equal total class mass in fit, validation selection and calibration' if external else 'equal row weight',
            'split_groups':{'train':sorted({r['group'] for r in train_rows}),
                            'validation':sorted({r['group'] for r in validation}), 'test':sorted({r['group'] for r in test})},
            'split_sizes':[len(train_rows),len(validation),len(test)],
            'split_labels':[dict(Counter(r['label'] for r in part)) for part in (train_rows,validation,test)],
            'calibration_scope':'Class-balanced candidate triage scores; not natural-prevalence or active-exposure probabilities' if external else 'Synthetic metadata',
            'regularization':penalty, 'guard_selection':selection, 'baseline_test':baseline, 'trained_test':learned,
            'deployment':'experimental_opt_in; production promotion requires independent real-world evaluation',
            'candidate_quality_gate':quality_gate(baseline, learned)}
    model={'schema_version':2 if guarded else 1,'kind':'guarded_logistic' if guarded else 'logistic','weights':weights,'training':report}
    if guarded:
        model['promotion_threshold'] = threshold
        model['promotion_policy'] = CandidateClassifier.PROMOTION_POLICY
    Path(model_path).write_text(json.dumps(model,indent=2,sort_keys=True)+'\n')
    Path(metrics_path).write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dataset'); parser.add_argument('model'); parser.add_argument('metrics')
    parser.add_argument('--external', action='store_true', help='Use repository-group splits and validation-only Platt calibration')
    parser.add_argument('--guarded', action='store_true', help='Retain baseline scores; select validation-only ML promotion threshold')
    args=parser.parse_args()
    report=train(args.dataset,args.model,args.metrics,args.external,args.guarded)
    print(json.dumps({k:report[k] for k in ('split_sizes','regularization','candidate_quality_gate','deployment')},indent=2))

if __name__=='__main__':
    main()
