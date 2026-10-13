from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
from pathlib import Path
import shutil
import sys
from threading import Barrier, BrokenBarrierError

import pytest

from linen.dispatcher.analysis.case_benchmark import TruthSet


SUITE = Path(__file__).parents[3] / "examples" / "benchmark-capabilities"


@pytest.fixture
def target(tmp_path, monkeypatch):
    # Imports run against a temporary copy so pycache cannot change the frozen
    # source inventory in the checked-in benchmark target.
    copied = tmp_path / "target"
    shutil.copytree(SUITE / "target", copied)
    name = "linen_capability_fixture"
    spec = importlib.util.spec_from_file_location(name, copied / "__init__.py",
                                                submodule_search_locations=[str(copied)])
    package = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, package)
    spec.loader.exec_module(package)
    api = importlib.import_module(name + ".api")
    store = importlib.import_module(name + ".store")
    yield api, store
    for key in list(sys.modules):
        if key.startswith(name + "."):
            del sys.modules[key]


def test_cross_file_object_permission_pair(target):
    api, models = target
    store = models.Store({"d1": models.Document("owner", "tenant-a", "private")}, {})
    actor = models.Principal("other-user", "tenant-a")
    assert api.case_001(actor, "d1", store) == "private"
    with pytest.raises(PermissionError):
        api.case_002(actor, "d1", store)
    assert api.case_002(models.Principal("owner", "tenant-a"), "d1", store) == "private"


def test_tenant_local_identity_pair(target):
    api, models = target
    store = models.Store({"d1": models.Document("owner", "tenant-a", "private")}, {})
    actor = models.Principal("owner", "tenant-b")
    assert api.case_003(actor, "d1", store) == "private"
    with pytest.raises(PermissionError):
        api.case_004(actor, "d1", store)


def test_catalog_price_pair(target):
    api, models = target
    actor = models.Principal("buyer", "tenant-a")
    store = models.Store({}, {"product": 100})
    assert api.case_005(actor, "product", 1, store)["fulfilled"] is True
    with pytest.raises(PermissionError):
        api.case_006(actor, "product", 1, store)
    assert api.case_006(actor, "product", 100, store)["charged"] == 100


def test_concurrent_withdrawal_pair_uses_the_same_probe(target):
    api, models = target

    def probe(entrypoint):
        account = models.Account(200)
        start = Barrier(2)
        integration = Barrier(2)

        def authorize(_amount):
            try:
                integration.wait(timeout=2)
            except BrokenBarrierError:
                # The serialized control reaches the integration only once;
                # its second withdrawal is denied before authorization.
                pass
            return True

        def withdraw():
            start.wait(timeout=2)
            return entrypoint(account, 150, authorize)

        with ThreadPoolExecutor(max_workers=2) as executor:
            attempts = [executor.submit(withdraw) for _ in range(2)]
            outcomes = [attempt.result(timeout=5) for attempt in attempts]
        return sum(outcomes), account.balance

    assert probe(api.case_007) == (2, -100)
    assert probe(api.case_008) == (1, 50)


def test_capability_truth_is_outside_target_and_describes_all_pairs():
    truth = TruthSet.model_validate(json.loads((SUITE / "evaluator" / "truth.json").read_text()))
    assert len(truth.expected) == len(truth.negative_controls) == 4
    assert {case.category for case in truth.labels} == {
        "object-authorization", "tenant-isolation", "business-price", "concurrency",
    }
    assert not list((SUITE / "target").rglob("*truth*"))
