from __future__ import annotations

import json
from pathlib import Path

import pytest

from linen.dispatcher.analysis import single_agent
from linen.dispatcher.analysis.artifacts import snapshot_source
from linen.dispatcher.config import ReconConfig, ReviewSandboxConfig
from linen.dispatcher.runtime.process import ProcessResult
from test_audit_pipeline import config


def report(code="private = 1", file="api.py"):
    return {'summary':'bounded inspection', 'findings':[{'id':'a','title':'candidate','description':'source claim',
            'category':'authorization','cwe':'639','citations':[{'file':file,'line_start':1,'line_end':1,'code':code}]}],
            'protected_paths':[], 'unassessed_paths':[]}


def source(tmp_path):
    root = tmp_path / 'target'
    root.mkdir()
    (root / 'api.py').write_text('private = 1\n')
    return root


@pytest.mark.parametrize('case', ['outside','wrong_bytes','wrong_range','duplicate'])
def test_single_agent_report_rejects_unbound_evidence(tmp_path, case):
    target = source(tmp_path)
    snapshot = snapshot_source(target, tmp_path/'frozen', ReconConfig(), tmp_path/'artifacts')
    value = report()
    citation = value['findings'][0]['citations'][0]
    if case == 'outside': citation['file'] = '../evaluator/truth.json'
    elif case == 'wrong_bytes': citation['code'] = 'private = 0'
    elif case == 'wrong_range': citation['line_end'] = 99
    else: value['protected_paths'] = value['findings']
    with pytest.raises(ValueError):
        single_agent.validate_baseline_report(json.dumps(value), tmp_path/'frozen', snapshot)


def test_single_agent_is_one_fresh_process_with_no_peer_or_repair_call(tmp_path, monkeypatch):
    target = source(tmp_path)
    cfg = config(tmp_path)
    cfg.workers[0].type = 'claudecode'
    cfg.audit.review_sandbox = ReviewSandboxConfig(enabled=True, image='test-image', network='none')
    config_path = tmp_path/'config.yaml'
    config_path.write_text('fixture configuration')
    starts = []

    class Process:
        image_id = 'sha256:' + 'a'*64
        name = 'fixture-container'

        def __init__(self, sandbox, frozen, snapshot, output, argv, env, timeout, inputs):
            self.argv = argv
            assert frozen != target and snapshot['files'] == {'api.py':single_agent.digest(b'private = 1\n')}
            assert set(inputs) == {'response-schema.json'}

        def start(self): starts.append(self.argv)
        def communicate(self, timeout): return ProcessResult(0, json.dumps(report()), '')
        def kill(self): pass
        def cancel(self, reason): pass

    monkeypatch.setattr(single_agent, 'DockerReviewProcess', Process)
    result = single_agent.run_single_agent(cfg, config_path, cfg.workers[0].name, target, tmp_path/'result')
    assert result['status'] == 'completed' and result['phase_count'] == 1 and len(starts) == 1
    assert 'protected_paths' in json.loads((tmp_path/'result/report.json').read_text())
    with pytest.raises(ValueError, match='fresh'):
        single_agent.run_single_agent(cfg, config_path, cfg.workers[0].name, target, tmp_path/'result')
