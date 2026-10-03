"""Reproducible stdlib tree training; repository splits and validation-only selection.
Usage: python -m backend.ml.tree_training DATA MODEL REPORT
"""
import argparse, hashlib, json, math
from collections import defaultdict
from pathlib import Path
from .training import FEATURES,load_rows,split_sources,sample_weights,sigmoid,metrics,quality_gate
from .classifier import CandidateClassifier
from .feature_extractor import FeatureVector
from .tree_model import leaf_value


def fit_trees(rows, depth, rounds=100):
    importance=sample_weights(rows,True,True)
    compressed=defaultdict(lambda:[0.,0.])
    names=sorted(FEATURES)
    for row,w in zip(rows,importance):
        vector=tuple(row['features'].get(name,0.) for name in names)
        compressed[vector][0]+=w;compressed[vector][1]+=w*row['label']
    vectors=list(compressed);weights=[compressed[v][0] for v in vectors]
    targets=[compressed[v][1]/compressed[v][0] for v in vectors]
    values=[dict(zip(names,v)) for v in vectors]
    logits=[0.]*len(vectors);trees=[]
    for _ in range(rounds):
        probabilities=[sigmoid(x) for x in logits]
        gradients=[w*(y-p) for w,y,p in zip(weights,targets,probabilities)]
        hessians=[w*p*(1-p) for w,p in zip(weights,probabilities)]
        def build(indices, level):
            g=sum(gradients[i] for i in indices);h=sum(hessians[i] for i in indices)
            total_weight=sum(weights[i] for i in indices)
            leaf={'value':.1*max(-2.,min(2.,g/(h+1.)))}
            if level==depth or len(indices)<6:return leaf
            best=None;gain=0.
            for column,name in enumerate(names):
                order=sorted(indices,key=lambda i:vectors[i][column])
                gl=hl=wl=0.
                for position,i in enumerate(order[:-1],1):
                    gl+=gradients[i];hl+=hessians[i];wl+=weights[i]
                    if position<3 or len(order)-position<3 or wl<2 or total_weight-wl<2:continue
                    low,high=vectors[i][column],vectors[order[position]][column]
                    if low==high:continue
                    improvement=gl*gl/(hl+1.)+(g-gl)**2/(h-hl+1.)-g*g/(h+1.)
                    if improvement>gain+1e-9:
                        gain=improvement;best=(name,(low+high)/2,order[:position],order[position:])
            if best is None:return leaf
            name,threshold,left,right=best
            return {'feature':name,'threshold':threshold,'left':build(left,level+1),'right':build(right,level+1)}
        tree=build(list(range(len(vectors))),0);trees.append(tree)
        logits=[x+leaf_value(tree,v) for x,v in zip(logits,values)]
    return trees


def loss(rows, classifier):
    importance=sample_weights(rows,True,True)
    total=0.
    for row,w in zip(rows,importance):
        p=classifier.classify(FeatureVector(row['features'])).score
        total-=w*(row['label']*math.log(max(1e-12,p))+(1-row['label'])*math.log(max(1e-12,1-p)))
    return total/sum(importance)


def train(dataset,model_path,report_path):
    rows=load_rows(dataset);a,b,c=split_sources(rows)
    attempts=[]
    for depth in (2,3,4):
        trees=fit_trees(a,depth)
        classifier=CandidateClassifier({'bias':0.},trees=trees)
        measured=loss(b,classifier);attempts.append((measured,depth,trees))
        print('depth',depth,'validation loss',measured,flush=True)
    _,depth,trees=min(attempts,key=lambda x:x[0])
    classifier=CandidateClassifier({'bias':0.},trees=trees)
    baseline=metrics(c,dict(CandidateClassifier._DEFAULT_WEIGHTS));trained=metrics(c,{},classifier=classifier)
    report={'dataset_sha256':hashlib.sha256(Path(dataset).read_bytes()).hexdigest(),'split_groups':{name:sorted({r['group'] for r in part}) for name,part in zip(('train','validation','test'),(a,b,c))},'split_sizes':[len(x) for x in (a,b,c)],'selection':'Minimum repository/class-balanced validation log loss; no test tuning','selected_depth':depth,'rounds':100,'learning_rate':.1,'regularization':1.,'sample_weighting':'inverse repository size then equal class mass','baseline_test':baseline,'trained_test':trained,'candidate_quality_gate':quality_gate(baseline,trained),'deployment':'experimental pending independent evaluation'}
    model={'schema_version':4,'kind':'boosted_trees','weights':{'bias':0.},'trees':trees,'training':report}
    Path(model_path).write_text(json.dumps(model,indent=2,sort_keys=True)+'\n',encoding='utf8')
    Path(report_path).write_text(json.dumps(report,indent=2,sort_keys=True)+'\n',encoding='utf8')
    print(json.dumps({key:{k:report[key][k] for k in ('precision','recall','brier','true_positive','false_positive')} for key in ('baseline_test','trained_test')},indent=2))
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dataset');parser.add_argument('model');parser.add_argument('report')
    args=parser.parse_args();train(args.dataset,args.model,args.report)

if __name__=='__main__':main()
