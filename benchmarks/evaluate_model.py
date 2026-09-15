"""Evaluate frozen model weights on an independently acquired candidate dataset."""
import argparse
import hashlib
import json
from pathlib import Path
from backend.ml.classifier import CandidateClassifier
from backend.ml.training import load_rows, metrics

def evaluate(dataset, model):
    rows=load_rows(dataset)
    trained=CandidateClassifier.from_file(model)
    metadata=json.loads(Path(model).read_text(encoding='utf-8'))
    used={g for groups in metadata.get('training',{}).get('split_groups',{}).values() for g in groups}
    groups={r['group'] for r in rows}
    if groups & used:
        raise ValueError('Evaluation repositories overlap model development partitions')
    return {'scope':'Independent line-labeled candidate evaluation; not active credential validation',
            'dataset_sha256':hashlib.sha256(Path(dataset).read_bytes()).hexdigest(),
            'model_sha256':hashlib.sha256(Path(model).read_bytes()).hexdigest(),
            'repositories':sorted(groups),'baseline':metrics(rows,dict(CandidateClassifier._DEFAULT_WEIGHTS)),
            'trained':metrics(rows,trained._weights)}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('dataset');p.add_argument('model');p.add_argument('output')
    a=p.parse_args()
    report=evaluate(a.dataset,a.model)
    Path(a.output).write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:{m:report[k][m] for m in ('samples','precision','recall','brier','expected_calibration_error')} for k in ('baseline','trained')},indent=2))

if __name__=='__main__':main()
