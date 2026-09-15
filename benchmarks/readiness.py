"""Explicit minimum acceptance checks for a stable detector release.

These project thresholds are necessary, not sufficient, for production readiness.
"""
import argparse,json
from pathlib import Path

def assess(report):
    counts=report['counts']
    reasons=[]
    if report['selected_repositories']<20:reasons.append('need_at_least_20_independent_repositories')
    if counts.get('annotations_T',0)<100:reasons.append('need_at_least_100_positive_annotations')
    if counts.get('annotations_F',0)<100:reasons.append('need_at_least_100_negative_annotations')
    if (report.get('positive_annotation_recall') or 0)<.8:reasons.append('positive_annotation_recall_below_80_percent')
    if (report.get('labeled_alert_precision') or 0)<.9:reasons.append('labeled_alert_precision_below_90_percent')
    if any(counts.get(k,0) for k in ('missing_files','oversized_files','undecodable_files','invalid_label_files','repository_errors')):
        reasons.append('incomplete_evaluation')
    return {'passed':not reasons,'reasons':reasons,'scope':'Minimum detector evidence only; not a certification of active-exposure accuracy or operational readiness'}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('report');p.add_argument('--require-ready',action='store_true')
    a=p.parse_args();result=assess(json.loads(Path(a.report).read_text(encoding='utf-8-sig')))
    print(json.dumps(result,indent=2))
    return int(a.require_ready and not result['passed'])
if __name__=='__main__':raise SystemExit(main())
