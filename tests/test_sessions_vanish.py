"""A transcript deleted between listing and reading (rotating logs, cron output) isn't 'unreadable'."""
from asca import sessions

from test_sessions_stray import ANT, _audit, _env_read_line, _hermes


def test_file_deleted_mid_scan_is_skipped_not_unreadable(tmp_path, monkeypatch):
    h = _hermes(tmp_path)
    (h / "sessions" / "gone.jsonl").write_text(_env_read_line(ANT), encoding="utf-8")

    def wrap(real):
        def vanish(fp, *a, **k):
            if str(fp).endswith("gone.jsonl"):
                raise FileNotFoundError(2, "No such file or directory", str(fp))
            return real(fp, *a, **k)
        return vanish

    monkeypatch.setattr(sessions, "_read_small", wrap(sessions._read_small))       # small files (thread pool)
    monkeypatch.setattr(sessions, "_scan_text_file", wrap(sessions._scan_text_file))
    f, _ = _audit(tmp_path / "home", h)
    assert not [x for x in f if x.rule == "scanner.parse-error"]
