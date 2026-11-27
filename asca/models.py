"""Local model weights: where they came from, whether they changed on disk, and code that runs when they load.
Rules ``model.*`` (Hugging Face hub cache and Ollama).

Grounding:
- JFrog (Nov 24 2026): the ARTEX agent published Hugging Face models whose ``config.json`` ``auto_map`` sends
  ``AutoConfig``/``AutoModel`` to bundled Python that steals ``/proc/1/environ``, the environment and Kubernetes
  service-account tokens, and commits the loot to a Hub repo through the commit API with a base64-hidden ``hf_``
  token. The same payload sat in legacy-torch pickles (``GLOBAL __builtin__ exec``) and a chat template tried Jinja
  sandbox escapes. The second model had **no weights at all**, so pickle scanners stayed quiet, and it fired on
  ``AutoConfig.from_pretrained(..., trust_remote_code=True)`` alone.
- Microsoft Research and CrowdStrike: backdoored open-weight checkpoints and LoRA adapters. The defence they name is
  provenance plus comparing against the original weights.

Both caches store files under their content hash (Hugging Face: ``blobs/<sha256>`` for LFS files, git's blob sha1
for small ones; Ollama: ``blobs/sha256-<hex>``), so asca can prove a file is what was downloaded without asking
anyone. It can't tell whether the publisher itself uploaded a backdoored model.

| Finding | Severity |
|---|---|
| a cached file matches a published malicious-model hash, a repo of the ARTEX account, or its payload marker | critical |
| ``model.blob-mismatch``: a cached file's content no longer matches the hash it was stored under | high |
| ``model.remote-code``: code a model loads (``auto_map``) reads ``/proc/1/environ``, service-account tokens or cloud metadata, posts to the Hub commit API, or hides a base64 ``hf_`` token | high |
| ``model.pickle-code``: a pickle weight file imports ``exec``/``eval``/``os.system``/``subprocess`` | high |
| ``model.chat-template-injection``: a chat template reaches for ``__globals__``/``__subclasses__``/``__mro__``/``popen`` | high |
| ``model.weightless-remote-code``: ``auto_map`` code and the Hub said there are no weights (``.no_exist``) | medium (weights never fetched: low) |
| ``model.lookalike-publisher``: an org name one character away from a well-known publisher (``meta-1lama``) | medium |
| ``model.hash-budget``: files not hashed because the byte budget ran out | low |

Read-only: nothing is imported, unpickled, rendered or contacted. Files are hashed under a byte budget, smallest
first, so configs, code and adapters are always covered before multi-GB weights.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import fsutil
from .model import Finding, Severity

JFROG = ("https://research.jfrog.com/post/the-agent-that-robbed-itself-an-ai-driven-hugging-face-malware-"
         "campaign-leaks-its-own-operator/")
MiB = 1024 * 1024
DEFAULT_HASH_BUDGET = 2048 * MiB
TEXT_CAP = 2 * MiB              # .py / json read as text
PICKLE_SCAN = 16 * MiB          # bytes of a pickle weight file searched for code imports

# JFrog's IOC table (sha256 of each file).
MALICIOUS_SHA256 = {
    "ceb5816fac7cbd886b096c7f0c0402913488ca0f967b617d3a7e25508032e6a8": "configuration_evil.py (mistral-7b-utterance)",
    "b068b5a2ec3a6a13deef686173935330fb2f7fd2b3fb1f34aa2b6e359624de19": "modeling_evil.py (mistral-7b-utterance)",
    "ed89685e8c16d0cb6dc218d0972e7a0a9e292f9b98f6b0ef0b2ab340d06d34e3": "configuration_evil.py (llama-3.2-1b-tuned)",
    "79b47fe688932507fa013de36c057846916f586b3893f2fae3fc364cbd5d7c9e": "modeling_evil.py (llama-3.2-1b-tuned)",
    "2bf25c4c3aa1e2efdff4ae9ee7e1434e279115608eb7a176e4e50e874c07c50d": "pytorch_model.bin (llama-3.2-1b-tuned)",
    "783f54898ba4b828e14a2e5ab3c50968bca0883b0fc0309c24876c9c7f99e841": "pytorch_model_zip.bin (llama-3.2-1b-tuned)",
    "b43e7d812ab6541bfce4f85b2a19ba051f1b560b581aa203754e088fe2367961": "evil_tok.py (toktest repos)",
}
MALICIOUS_ORGS = {"hfusr5488184", "akashdutta1030", "probeorg9x7y2"}
MARKERS = ("RCE43861",)

# Code a model loads at from_pretrained/AutoConfig time: the ARTEX payload's shapes.
REMOTE_SIGNALS = [
    (re.compile(r"/proc/(?:1|self|\{[^}]*\}|\"\s*\+[^+]+\+\s*\")/environ"), "reads a process environment (/proc/*/environ)"),
    (re.compile(r"serviceaccount/token|/var/run/secrets/kubernetes\.io"), "reads the Kubernetes service-account token"),
    (re.compile(r"169\.254\.169\.254|metadata\.google\.internal|fd00:ec2::254"), "queries cloud instance metadata"),
    (re.compile(r"/api/(?:models|datasets|spaces)/[^\s\"']*/commit\b|/commit/main\b"), "posts to the Hugging Face commit API"),
    (re.compile(r"[\"']aGZf[A-Za-z0-9+/]{20,}={0,2}[\"']"), "holds a base64-encoded `hf_` token"),
]
SSTI = re.compile(r"__globals__|__subclasses__|__mro__|__builtins__|__import__|\.popen\s*\(|os\.system|"
                  r"(?:lipsum|cycler|joiner|namespace|self)\s*\.\s*__")
PICKLE_CODE = re.compile(
    rb"c(?:__builtin__|builtins|os|posix|nt|subprocess|runpy|commands|pty|socket)\n"
    rb"(?:exec|eval|system|popen|Popen|run|call|check_output|getoutput|_run_code|__import__|spawn|create_connection)\n"
    rb"|\x8c[\x02-\x0b](?:__builtin__|builtins|os|posix|nt|subprocess|runpy|pty|socket)\x94?"
    rb"\x8c[\x03-\x11](?:exec|eval|system|popen|Popen|run|call|check_output|getoutput|_run_code|__import__|spawn)\x94?\x93")
WEIGHT_SUFFIXES = (".safetensors", ".bin", ".pt", ".pth", ".gguf", ".h5", ".msgpack", ".onnx", ".ckpt", ".npz",
                   ".tflite", ".mlmodel", ".pkl")
PICKLE_SUFFIXES = (".bin", ".pt", ".pth", ".ckpt", ".pkl", ".pickle")
NO_WEIGHT_MARKERS = ("model.safetensors", "pytorch_model.bin", "model.safetensors.index.json",
                     "pytorch_model.bin.index.json")

# Well-known publishers whose names are worth impersonating (Hugging Face orgs, compared case-insensitively).
OFFICIAL_ORGS = ["meta-llama", "mistralai", "google", "microsoft", "Qwen", "deepseek-ai", "openai", "nvidia",
                 "ibm-granite", "allenai", "HuggingFaceTB", "HuggingFaceH4", "tiiuae", "stabilityai", "bigcode",
                 "EleutherAI", "01-ai", "THUDM", "zai-org", "moonshotai", "MiniMaxAI", "apple", "CohereForAI",
                 "CohereLabs", "black-forest-labs", "unsloth", "bartowski", "lmstudio-community", "TheBloke",
                 "facebook", "sentence-transformers", "BAAI", "intfloat", "nomic-ai", "jinaai", "ggml-org",
                 "NousResearch", "hf-internal-testing", "Salesforce", "amazon", "xai-org", "openbmb", "internlm"]
_CONFUSE = str.maketrans({"0": "o", "1": "l", "i": "l", "3": "e", "5": "s", "_": "", "-": "", ".": ""})


@dataclass
class Snapshot:
    repo_type: str          # models | datasets | spaces
    repo_id: str            # org/name
    org: str
    commit: str
    path: Path
    refs: list[str] = field(default_factory=list)       # branch/tag names pointing at this commit
    files: dict[str, Path] = field(default_factory=dict)    # relative name -> path in snapshot
    blobs: dict[str, str] = field(default_factory=dict)     # relative name -> blob name (content hash) if linked
    no_exist: set[str] = field(default_factory=set)


@dataclass
class OllamaModel:
    name: str               # registry/namespace/model:tag
    publisher: str
    manifest: Path
    digest: str             # sha256 of the manifest file
    layers: list[tuple[str, str, int]] = field(default_factory=list)    # (mediaType, sha256 hex, size)


# ------------------------------------------------------------------ discovery
def hf_caches(home: Path, env: dict) -> list[Path]:
    cands = []
    for k in ("HF_HUB_CACHE", "HUGGINGFACE_HUB_CACHE", "TRANSFORMERS_CACHE"):
        if env.get(k):
            cands.append(Path(env[k]).expanduser())
    if env.get("HF_HOME"):
        cands.append(Path(env["HF_HOME"]).expanduser() / "hub")
    if env.get("XDG_CACHE_HOME"):
        cands.append(Path(env["XDG_CACHE_HOME"]).expanduser() / "huggingface" / "hub")
    cands.append(home / ".cache" / "huggingface" / "hub")
    out = []
    for c in cands:
        if fsutil.is_dir(c) and c not in out:
            out.append(c)
    return out


def ollama_dirs(home: Path, env: dict, root: Path | None = Path("/")) -> list[Path]:
    cands = [Path(env["OLLAMA_MODELS"]).expanduser()] if env.get("OLLAMA_MODELS") else []
    cands.append(home / ".ollama" / "models")
    if root is not None:
        cands += fsutil.system(root / "usr/share/ollama/.ollama/models", root / "var/lib/ollama/.ollama/models")
    out = []
    for c in cands:
        if fsutil.is_dir(c / "manifests") and c not in out:
            out.append(c)
    return out


def _safe_iter(d: Path):
    try:
        return sorted(d.iterdir())
    except OSError:
        return []


def hf_snapshots(cache: Path) -> list[Snapshot]:
    out = []
    for repo in _safe_iter(cache):
        m = re.match(r"^(models|datasets|spaces)--(.+)$", repo.name)
        if not m or not repo.is_dir():
            continue
        parts = m.group(2).split("--")
        repo_id = "/".join(parts)
        org = parts[0] if len(parts) > 1 else ""
        refs: dict[str, list[str]] = {}
        refdir = repo / "refs"
        if fsutil.is_dir(refdir):
            for p in refdir.rglob("*"):
                try:
                    if p.is_file():
                        refs.setdefault(p.read_text(encoding="utf-8", errors="replace").strip(), []).append(
                            p.relative_to(refdir).as_posix())
                except OSError:
                    continue
        for snap in _safe_iter(repo / "snapshots"):
            if not snap.is_dir():
                continue
            s = Snapshot(m.group(1), repo_id, org, snap.name, snap, refs=sorted(refs.get(snap.name, [])))
            for p in snap.rglob("*"):
                try:
                    if p.is_dir() and not p.is_symlink():
                        continue
                    rel = p.relative_to(snap).as_posix()
                    s.files[rel] = p
                    if p.is_symlink():
                        s.blobs[rel] = os.readlink(p)
                except OSError:
                    continue
            ne = repo / ".no_exist" / snap.name
            if fsutil.is_dir(ne):
                s.no_exist = {p.relative_to(ne).as_posix() for p in ne.rglob("*") if p.is_file()}
            out.append(s)
    return out


def ollama_models(models_dir: Path) -> tuple[list[OllamaModel], list[str]]:
    out, errors = [], []
    man = models_dir / "manifests"
    for p in sorted(man.rglob("*")) if fsutil.is_dir(man) else []:
        try:
            if not p.is_file():
                continue
            raw = p.read_bytes()
        except OSError:
            continue
        try:
            doc = json.loads(raw)
        except ValueError:
            errors.append(str(p))
            continue
        rel = p.relative_to(man).parts
        if len(rel) < 3:
            continue
        registry, namespace, model, tag = (rel[0], rel[1], "/".join(rel[2:-1]), rel[-1]) if len(rel) >= 4 \
            else (rel[0], "", rel[1], rel[2])
        publisher = "ollama" if (registry == "registry.ollama.ai" and namespace == "library") else \
            (namespace or registry)
        m = OllamaModel(f"{registry}/{namespace}/{model}:{tag}".replace("//", "/"), publisher, p,
                        hashlib.sha256(raw).hexdigest())
        for layer in ([doc.get("config")] if isinstance(doc.get("config"), dict) else []) + \
                [x for x in doc.get("layers") or [] if isinstance(x, dict)]:
            d = str(layer.get("digest", ""))
            if d.startswith("sha256:") and re.fullmatch(r"[0-9a-f]{64}", d[7:]):
                m.layers.append((str(layer.get("mediaType", "")), d[7:], int(layer.get("size") or 0)))
        out.append(m)
    return out, errors


def ollama_blob(models_dir: Path, hexd: str) -> Path | None:
    for name in (f"sha256-{hexd}", f"sha256:{hexd}"):
        p = models_dir / "blobs" / name
        if fsutil.is_file(p):
            return p
    return None


# ------------------------------------------------------------------ hashing
class Budget:
    def __init__(self, total: int):
        self.total = total
        self.used = 0
        self.skipped_files = 0
        self.skipped_bytes = 0

    def take(self, n: int) -> bool:
        if self.used + n > self.total:
            self.skipped_files += 1
            self.skipped_bytes += n
            return False
        self.used += n
        return True


def file_digest(p: Path, algo: str) -> str:
    """sha256 of the content, or git's blob sha1 ("blob <len>\\0" + content)."""
    if algo == "git":
        h = hashlib.sha1()
        h.update(b"blob %d\x00" % p.stat().st_size)
    else:
        h = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(MiB):
            h.update(chunk)
    return h.hexdigest()


def _algo_for(name: str) -> str | None:
    if re.fullmatch(r"[0-9a-f]{64}", name):
        return "sha256"
    if re.fullmatch(r"[0-9a-f]{40}", name):
        return "git"
    return None


def _read_text(p: Path, cap: int = TEXT_CAP) -> str:
    try:
        with open(p, "rb") as f:
            return f.read(cap).decode("utf-8", "replace")
    except OSError:
        return ""


def lookalike(org: str) -> str | None:
    """The official org this name imitates, or None."""
    if not org:
        return None
    low = org.lower()
    norm = low.translate(_CONFUSE).replace("rn", "m")
    for off in OFFICIAL_ORGS:
        o = off.lower()
        if low == o:
            return None
        on = o.translate(_CONFUSE).replace("rn", "m")
        if len(on) >= 5 and (norm == on or _one_edit(norm, on)):
            return off
    return None


def _one_edit(a: str, b: str) -> bool:
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        return len(diff) == 1 or (len(diff) == 2 and diff[1] == diff[0] + 1
                                  and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]])
    s, t = (a, b) if len(a) < len(b) else (b, a)
    i = 0
    while i < len(s) and s[i] == t[i]:
        i += 1
    return s[i:] == t[i + 1:]


# ------------------------------------------------------------------ checks
def _auto_map_modules(snap: Snapshot) -> dict[str, str]:
    """module file -> where it's referenced (config.json / tokenizer_config.json / processor configs)."""
    out = {}
    for cfg in ("config.json", "tokenizer_config.json", "processor_config.json", "preprocessor_config.json",
                "feature_extractor_config.json", "image_processor_config.json"):
        p = snap.files.get(cfg)
        if not p:
            continue
        try:
            doc = json.loads(_read_text(p))
        except ValueError:
            continue
        am = doc.get("auto_map") if isinstance(doc, dict) else None
        if not isinstance(am, dict):
            continue
        for v in am.values():
            for ref in (v if isinstance(v, list) else [v]):
                if isinstance(ref, str) and "." in ref:
                    mod = ref.split("--")[-1].rsplit(".", 1)[0]        # "org/repo--module.Class" -> module
                    out[mod.replace(".", "/") + ".py"] = cfg
    return out


def _templates(snap: Snapshot) -> list[tuple[str, str]]:
    out = []
    p = snap.files.get("tokenizer_config.json")
    if p:
        try:
            doc = json.loads(_read_text(p))
        except ValueError:
            doc = {}
        ct = doc.get("chat_template") if isinstance(doc, dict) else None
        if isinstance(ct, str):
            out.append(("tokenizer_config.json#chat_template", ct))
        elif isinstance(ct, list):
            out += [(f"tokenizer_config.json#chat_template.{t.get('name', i)}", str(t.get("template", "")))
                    for i, t in enumerate(ct) if isinstance(t, dict)]
    for rel, fp in snap.files.items():
        if rel.endswith(".jinja"):
            out.append((rel, _read_text(fp)))
    return out


def _f(rule, sev, title, loc, subject, detail, fix) -> Finding:
    return Finding(rule=rule, category="model", severity=sev, title=title, location=str(loc), subject=subject,
                   detail=detail, remediation=fix)


REMOVE_FIX = ("Delete this repo from the cache (`huggingface-cli delete-cache`, or remove the `models--...` folder). If "
              "anything loaded it with trust_remote_code=True, or unpickled its weights, treat that machine's "
              "environment variables, cloud credentials and tokens as stolen and rotate them.")


def audit_snapshot(snap: Snapshot, cache: Path, budget: Budget, out: list[Finding], stats: dict) -> None:
    repo = f"{snap.repo_id}@{snap.commit[:12]}"
    loc = snap.path
    if snap.org.lower() in MALICIOUS_ORGS:
        out.append(_f("model.known-malicious", Severity.CRITICAL,
                      f"Hugging Face cache holds {snap.repo_id}, from the account behind the ARTEX model campaign",
                      loc, f"org:{snap.repo_id}", f"JFrog tied `{snap.org}` to models that steal environment "
                      f"variables and cloud tokens on load and commit them to a Hub repo ({JFROG}).", REMOVE_FIX))
    if (lk := lookalike(snap.org)) and snap.repo_type == "models":
        out.append(_f("model.lookalike-publisher", Severity.MEDIUM,
                      f"{snap.repo_id}: publisher `{snap.org}` looks like `{lk}`", loc, f"lookalike:{snap.org}",
                      f"The org name is one character (or a 0/O, 1/l swap) away from `{lk}`. Look-alike orgs are "
                      f"how copies of popular models with changed weights or added code get downloaded.",
                      "Check the repo on huggingface.co. If it isn't the publisher you meant, delete it from the "
                      "cache and load the official one."))
    # integrity: snapshot links must point into this repo's blobs, and blob content must match its name
    blobs_dir = snap.path.parent.parent / "blobs"
    small_first = sorted(snap.files.items(), key=lambda kv: _size(kv[1]))
    for rel, fp in small_first:
        target = snap.blobs.get(rel)
        if target is not None:
            resolved = (fp.parent / target)
            try:
                inside = os.path.normpath(str(resolved)).startswith(os.path.normpath(str(blobs_dir)) + os.sep)
            except ValueError:
                inside = False
            if not inside:
                out.append(_f("model.blob-mismatch", Severity.HIGH,
                              f"{snap.repo_id}: `{rel}` points outside the model cache", fp, f"{repo}:{rel}:link",
                              f"Snapshot files are links into `blobs/`; this one points to `{target}`. A swapped "
                              f"link loads a different file than the one downloaded.",
                              "Delete the repo from the cache and download it again."))
                continue
            name = Path(target).name
            algo = _algo_for(name)
            if name in MALICIOUS_SHA256:
                out.append(_f("model.known-malicious", Severity.CRITICAL,
                              f"{snap.repo_id}: `{rel}` is a published malicious-model file "
                              f"({MALICIOUS_SHA256[name]})", fp, f"{repo}:{rel}:ioc",
                              f"sha256 {name[:16]}… is in JFrog's IOC list for the ARTEX model campaign ({JFROG}).",
                              REMOVE_FIX))
            if algo is None or not fsutil.is_file(resolved):
                continue
            size = _size(resolved)
            if not budget.take(size):
                continue
            stats["model_files_hashed"] = stats.get("model_files_hashed", 0) + 1
            try:
                got = file_digest(resolved, algo)
            except OSError:
                continue
            if got != name:
                out.append(_f("model.blob-mismatch", Severity.HIGH,
                              f"{snap.repo_id}: `{rel}` changed after it was downloaded", fp, f"{repo}:{rel}",
                              f"It's stored under its {'sha256' if algo == 'sha256' else 'git blob sha1'} "
                              f"`{name[:16]}…`, but the content now hashes to `{got[:16]}…`. Someone or something "
                              f"rewrote the file in place, which is how an edited model goes unnoticed (Microsoft "
                              f"Research's weight-edit backdoors are detected by comparing with the original).",
                              "Delete the repo from the cache and download it again, then find out what wrote to the "
                              "cache folder."))
            continue
        # not a link (Windows copies, or a file dropped into the snapshot): can only check the IOC hashes cheaply
        stats["model_files_unlinked"] = stats.get("model_files_unlinked", 0) + 1
    # code that runs on load
    modules = _auto_map_modules(snap)
    py_files = {rel: fp for rel, fp in snap.files.items() if rel.endswith(".py")}
    for rel, fp in py_files.items():
        text = _read_text(fp)
        try:
            digest = file_digest(fp, "sha256") if _size(fp) <= TEXT_CAP else ""
        except OSError:
            digest = ""
        if digest in MALICIOUS_SHA256 or any(m in text for m in MARKERS):
            out.append(_f("model.known-malicious", Severity.CRITICAL,
                          f"{snap.repo_id}: `{rel}` is the ARTEX model-campaign payload", fp, f"{repo}:{rel}:ioc",
                          (f"sha256 matches {MALICIOUS_SHA256[digest]} in JFrog's IOC list" if digest in
                           MALICIOUS_SHA256 else "it carries the campaign's payload marker")
                          + f" ({JFROG}).", REMOVE_FIX))
            continue
        hits = [what for rx, what in REMOTE_SIGNALS if rx.search(text)]
        if hits:
            how = (f"`auto_map` in {modules[rel]} loads it, so it runs on from_pretrained(trust_remote_code=True)"
                   if rel in modules else "it ships with the model's code")
            out.append(_f("model.remote-code", Severity.HIGH,
                          f"{snap.repo_id}: model code `{rel}` {hits[0]}", fp, f"{repo}:{rel}",
                          f"{how}. It {', '.join(hits)}. That's the shape of the ARTEX payload JFrog found in "
                          f"Hugging Face models: steal the environment and tokens, then commit them to a Hub repo "
                          f"({JFROG}).", REMOVE_FIX))
    present = [m for m in modules if m in py_files]
    if present and not any(r.lower().endswith(WEIGHT_SUFFIXES) for r in snap.files):
        confirmed = bool(snap.no_exist & set(NO_WEIGHT_MARKERS))
        out.append(_f("model.weightless-remote-code", Severity.MEDIUM if confirmed else Severity.LOW,
                      f"{snap.repo_id}: remote code (`{present[0]}`) and "
                      + ("the Hub says it has no weights" if confirmed else "no weights in the cache"),
                      snap.path, f"{repo}:weightless",
                      ("The Hub answered 'not found' for the weight files (recorded in `.no_exist`). "
                       if confirmed else "Weights may simply not have been downloaded (AutoConfig fetches only the "
                                         "config and its code). ")
                      + "A model whose only content is code that runs at load time is how JFrog's second ARTEX model "
                        f"got past pickle scanning ({JFROG}).",
                      "Open the .py files and check what they do before anything loads this repo with "
                      "trust_remote_code=True."))
    for where, tmpl in _templates(snap):
        if m := SSTI.search(tmpl):
            out.append(_f("model.chat-template-injection", Severity.HIGH,
                          f"{snap.repo_id}: chat template reaches Python internals (`{m.group(0).strip()}`)",
                          snap.path / where.split("#")[0], f"{repo}:{where}",
                          f"{where} contains a Jinja sandbox escape pattern. transformers renders templates in a "
                          f"sandbox, but inference servers that render them with plain Jinja run the code (JFrog's "
                          f"ARTEX models tried to run `id`, `env` and read /proc/1/environ this way, {JFROG}).",
                          REMOVE_FIX))
    for rel, fp in snap.files.items():
        if not rel.lower().endswith(PICKLE_SUFFIXES):
            continue
        try:
            with open(fp, "rb") as f:
                head = f.read(PICKLE_SCAN)
        except OSError:
            continue
        if m := PICKLE_CODE.search(head):
            shown = re.sub(rb"[^\x20-\x7e]+", b" ", m.group(0)).decode().strip()
            out.append(_f("model.pickle-code", Severity.HIGH,
                          f"{snap.repo_id}: weight file `{rel}` imports `{shown}` when unpickled", fp,
                          f"{repo}:{rel}:pickle",
                          "Loading it with pickle, or torch.load(weights_only=False) / PyTorch before 2.6, runs that "
                          f"call. JFrog's first ARTEX model hid its payload this way ({JFROG}).", REMOVE_FIX))


def _size(p: Path) -> int:
    try:
        return p.stat().st_size
    except OSError:
        return 0


def audit_ollama(models_dir: Path, budget: Budget, out: list[Finding], stats: dict) -> list[OllamaModel]:
    models, errors = ollama_models(models_dir)
    seen: set[str] = set()
    for m in sorted(models, key=lambda m: m.name):
        if (lk := lookalike(m.publisher)) and m.publisher != "ollama":
            out.append(_f("model.lookalike-publisher", Severity.MEDIUM, f"Ollama model {m.name}: namespace "
                          f"`{m.publisher}` looks like `{lk}`", m.manifest, f"lookalike:ollama:{m.publisher}",
                          f"The namespace is one character away from `{lk}`.",
                          "Check where it came from; pull the official model instead."))
        for media, hexd, size in sorted(m.layers, key=lambda x: x[2]):
            if hexd in seen:
                continue
            seen.add(hexd)
            blob = ollama_blob(models_dir, hexd)
            if blob is None:
                continue
            real = _size(blob)
            if size and real != size:
                out.append(_f("model.blob-mismatch", Severity.HIGH, f"Ollama {m.name}: a layer's size changed",
                              blob, f"ollama:{hexd}:size", f"The manifest says {size} bytes, the blob has {real}.",
                              "Remove the model (`ollama rm`) and pull it again."))
                continue
            if not budget.take(real):
                continue
            stats["model_files_hashed"] = stats.get("model_files_hashed", 0) + 1
            try:
                got = file_digest(blob, "sha256")
            except OSError:
                continue
            if got != hexd:
                out.append(_f("model.blob-mismatch", Severity.HIGH,
                              f"Ollama {m.name}: a {media.rsplit('.', 1)[-1]} layer changed after it was pulled",
                              blob, f"ollama:{hexd}",
                              f"Stored as sha256 `{hexd[:16]}…`, content hashes to `{got[:16]}…`.",
                              "Remove the model (`ollama rm`), pull it again, and find out what wrote to the "
                              "models folder."))
    if errors:
        out.append(_f("scanner.parse-error", Severity.LOW, f"{len(errors)} Ollama manifest(s) couldn't be parsed",
                      errors[0], "ollama-manifests", "; ".join(errors[:5]), "Their layers weren't checked."))
    return models


def audit(home: Path, stats: dict, *, env: dict | None = None, root: Path | None = Path("/"),
          hash_budget: int = DEFAULT_HASH_BUDGET) -> list[Finding]:
    env = dict(os.environ) if env is None else env
    out: list[Finding] = []
    budget = Budget(hash_budget)
    snaps = 0
    for cache in hf_caches(home, env):
        for s in hf_snapshots(cache):
            snaps += 1
            audit_snapshot(s, cache, budget, out, stats)
    om = 0
    for d in ollama_dirs(home, env, root):
        om += len(audit_ollama(d, budget, out, stats))
    stats["hf_snapshots"] = snaps
    stats["ollama_models"] = om
    if budget.skipped_files:
        out.append(_f("model.hash-budget", Severity.LOW, "Model file hashing stopped at its budget", "model-cache",
                      "budget", f"{budget.skipped_files} file(s) (~{budget.skipped_bytes // MiB} MiB) weren't hashed "
                      f"after {budget.used // MiB} MiB (smallest files first, so configs and code were covered).",
                      "Raise --model-hash-budget-mb to verify the large weight files too."))
    # dedupe (the same cache reachable through two variables)
    seen, uniq = set(), []
    for f in out:
        if f.fingerprint not in seen:
            seen.add(f.fingerprint)
            uniq.append(f)
    return uniq
