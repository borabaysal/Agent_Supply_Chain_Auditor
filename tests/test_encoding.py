"""asca's own file I/O always names its encoding (Windows would otherwise use cp1252 and crash on ✅ or →)."""
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BINARY_OPENERS = {"os", "tarfile", "zipfile", "gzip", "sqlite3", "io"}


def _offenders(root: Path):
    for p in sorted(root.rglob("*.py")):
        tree = ast.parse(p.read_text(encoding="utf-8"))
        for n in ast.walk(tree):
            if not isinstance(n, ast.Call):
                continue
            kws = {k.arg for k in n.keywords}
            f = n.func
            name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
            if name in ("read_text", "write_text"):
                positional = len(n.args) >= (2 if name == "write_text" else 1)
                if "encoding" not in kws and not positional:
                    yield f"{p.relative_to(ROOT)}:{n.lineno} {name}"
            elif name == "open" and not (isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name)
                                         and f.value.id in BINARY_OPENERS):
                margs = n.args[1:2] if isinstance(f, ast.Name) else n.args[0:1]
                mode = next((k.value.value for k in n.keywords if k.arg == "mode" and isinstance(k.value, ast.Constant)),
                            margs[0].value if margs and isinstance(margs[0], ast.Constant) else "r")
                if "b" not in str(mode) and "encoding" not in kws:
                    yield f"{p.relative_to(ROOT)}:{n.lineno} open({mode!r})"
            elif name == "run" and isinstance(f, ast.Attribute) and getattr(f.value, "id", "") == "subprocess":
                if ({"text", "universal_newlines"} & kws) and "encoding" not in kws:
                    yield f"{p.relative_to(ROOT)}:{n.lineno} subprocess.run(text=True)"


def test_asca_text_io_names_its_encoding():
    assert list(_offenders(ROOT / "asca")) == []


def test_checker_catches_a_missing_encoding(tmp_path):
    (tmp_path / "m.py").write_text("from pathlib import Path\nPath('x').read_text()\nopen('y')\nopen('z', 'rb')\n",
                                   encoding="utf-8")
    global ROOT
    old, ROOT = ROOT, tmp_path
    try:
        assert len(list(_offenders(tmp_path))) == 2
    finally:
        ROOT = old
