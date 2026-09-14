"""Reproducible offline detection benchmark; synthetic data only."""
import json
from pathlib import Path
from datetime import datetime, timezone
from backend.detectors.detection_engine import DetectionEngine
from backend.scanner.models import FileMetadata, NormalizedTextFile, ParsedRepository, RepositoryMetadata


def evaluate():
    base=Path(__file__).resolve().parents[1]
    cases=json.loads((base/'tests/fixtures/accuracy_cases.json').read_text())
    cases+=json.loads((base/'benchmarks/additional_cases.json').read_text())
    tp=fp=tn=fn=0
    failures=[]
    for case in cases:
        source=case['source']
        file=NormalizedTextFile(FileMetadata(case['path'],len(source.encode()),datetime.now(timezone.utc),'utf-8'),source)
        result=DetectionEngine().scan(ParsedRepository(RepositoryMetadata('benchmark','benchmark'),(file,)))
        predicted=bool(result.findings)
        expected=case['expected']
        tp+=predicted and expected; fp+=predicted and not expected
        tn+=not predicted and not expected; fn+=not predicted and expected
        if predicted!=expected:
            failures.append(case['name'])
    return {'scope':'Synthetic development fixtures, not an independent production benchmark',
            'samples':len(cases),'true_positive':tp,'false_positive':fp,'true_negative':tn,'false_negative':fn,
            'precision':tp/(tp+fp) if tp+fp else 0,'recall':tp/(tp+fn) if tp+fn else 0,'failures':failures}

if __name__=='__main__':
    report=evaluate()
    print(json.dumps(report,indent=2))
    raise SystemExit(bool(report['failures']))
